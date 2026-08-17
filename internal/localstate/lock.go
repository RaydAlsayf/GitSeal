package localstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

type lockRecord struct {
	Version   int    `yaml:"version"`
	Token     string `yaml:"token"`
	PID       int    `yaml:"pid"`
	ProcessID string `yaml:"process_start_identity"`
	Operation string `yaml:"operation"`
}

type Lock struct {
	root     *safefile.Root
	path     pathpolicy.Path
	token    string
	file     *os.File
	identity os.FileInfo
}

func Acquire(directory, operation string) (lock *Lock, resultErr error) {
	if operation == "" || len(operation) > 100 {
		return nil, errors.New("invalid lock operation")
	}
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, errors.New("lock directory must be absolute")
	}
	// A lock is useful only if its exact acquired object can later be released
	// without a check-to-unlink race. Gate the entire lifecycle before directory
	// creation, candidate allocation, or any caller mutation.
	if err := requireLocalStateMutationSafety(); err != nil {
		return nil, err
	}
	if err := prepareDirectory(directory); err != nil {
		return nil, err
	}
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes[:])
	record := lockRecord{Version: Version, Token: token, PID: os.Getpid(), ProcessID: currentProcessIdentity(), Operation: operation}
	if record.ProcessID == "unknown" {
		return nil, errors.New("operating-system process creation identity is unavailable; refusing lock acquisition")
	}
	data, err := strictyaml.Encode(record)
	if err != nil {
		return nil, err
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	keepRoot := false
	var candidate *safefile.Candidate
	published := false
	defer func() {
		if candidate != nil && !published {
			if abortErr := candidate.Abort(); abortErr != nil {
				resultErr = errors.Join(resultErr, errors.New("lock acquisition left an owned temporary candidate requiring manual reconciliation"), abortErr)
			}
		}
		if !keepRoot {
			resultErr = errors.Join(resultErr, root.Close())
		}
	}()
	lockPath, err := pathpolicy.Parse("lock.yaml")
	if err != nil {
		return nil, err
	}
	if existing, openErr := root.OpenSensitiveRead(lockPath); openErr == nil {
		return nil, errors.Join(errors.New("GitSeal lock is already held or requires conservative stale-lock recovery"), existing.Close())
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect existing GitSeal lock: %w", openErr)
	}
	candidate, err = root.NewCandidate(lockPath, safefile.SensitiveData)
	if err != nil {
		return nil, err
	}
	if err := writeFull(candidate, data); err != nil {
		return nil, err
	}
	if err := candidate.FlushClose(); err != nil {
		return nil, err
	}
	// Bind the future lock to the exact invocation-owned candidate inode before
	// publication. A post-publication pathname open must identify this same
	// object and contain these exact bytes; merely seeing some regular lock file
	// at the final name is not sufficient ownership evidence.
	owned, err := candidate.OpenUnpublished()
	if err != nil {
		return nil, err
	}
	ownedInfo, statErr := owned.Stat()
	ownedCloseErr := owned.Close()
	if statErr != nil || ownedCloseErr != nil || !ownedInfo.Mode().IsRegular() {
		return nil, errors.Join(errors.New("lock candidate could not be bound to a regular file identity"), statErr, ownedCloseErr)
	}
	if err := candidate.Publish(context.Background(), false); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("GitSeal lock is already held or requires conservative stale-lock recovery")
		}
		return nil, err
	}
	published = true
	file, err := root.OpenSensitiveRead(lockPath)
	if err != nil {
		return nil, errors.Join(errors.New("GitSeal lock was published but could not be rebound; it remains conservatively held"), err)
	}
	info, statErr := file.Stat()
	observed, readErr := readBoundedReader(file, 4096)
	if statErr != nil || readErr != nil || !info.Mode().IsRegular() || !os.SameFile(ownedInfo, info) || !bytes.Equal(observed, data) {
		closeErr := file.Close()
		return nil, errors.Join(errors.New("published lock identity or contents changed before ownership was bound; the lock remains conservatively held"), statErr, readErr, closeErr)
	}
	keepRoot = true
	return &Lock{root: root, path: lockPath, token: token, file: file, identity: info}, nil
}

func (l *Lock) Release() (resultErr error) {
	if l == nil {
		return nil
	}
	if l.root == nil || l.file == nil || l.identity == nil {
		return errors.New("lock has no bound file identity")
	}
	root := l.root
	held := l.file
	// A failed identity/token recheck or checked removal leaves lock.yaml in
	// place. Close the invocation's handles on every terminal Release result and
	// join close failures instead of leaking them or hiding a durability error.
	defer func() {
		resultErr = errors.Join(resultErr, held.Close(), root.Close())
		l.file = nil
		l.root = nil
		l.identity = nil
	}()
	file, err := l.root.OpenSensitiveRead(l.path)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	data, readErr := readBoundedReader(file, 4096)
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || !os.SameFile(l.identity, info) {
		return errors.Join(errors.New("lock could not be safely revalidated before release; it remains conservatively held"), statErr, readErr, closeErr)
	}
	var record lockRecord
	if err := strictyaml.Decode(data, &record); err != nil {
		return errors.New("invalid lock record; refusing release and preserving the lock")
	}
	if err := validateLockRecord(record); err != nil {
		return errors.New("invalid lock record; refusing release and preserving the lock")
	}
	processIdentity := currentProcessIdentity()
	if record.Token != l.token || record.PID != os.Getpid() || processIdentity == "unknown" || record.ProcessID != processIdentity {
		return errors.New("lock ownership changed; refusing release and preserving the lock")
	}
	if err := l.root.RemoveOpened(l.path, l.file, safefile.SensitiveData); err != nil {
		return fmt.Errorf("identity-checked lock removal failed; the lock remains conservatively held: %w", err)
	}
	return nil
}

func readBoundedReader(file io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("bounded input exceeds its byte limit")
	}
	return data, nil
}

func validateLockRecord(record lockRecord) error {
	if record.Version != Version || record.PID <= 0 || record.Token == "" || len(record.Token) != 64 || record.ProcessID == "" || record.ProcessID == "unknown" || record.Operation == "" || len(record.Operation) > 100 {
		return errors.New("invalid GitSeal lock record")
	}
	decoded, err := hex.DecodeString(record.Token)
	if err != nil || len(decoded) != 32 || !bytes.Equal([]byte(hex.EncodeToString(decoded)), []byte(record.Token)) {
		return errors.New("invalid GitSeal lock token")
	}
	return nil
}

func writeFull(file io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
