// Package safefile owns rooted repository file access and publication. It
// deliberately fails closed when a platform-specific sensitive publication
// boundary has not been proven.
package safefile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
)

type Sensitivity uint8

const (
	PublicData Sensitivity = iota
	SensitiveData
)

// ErrIdentityBoundRemovalUnavailable means the platform cannot atomically
// remove a directory entry only when it still names a previously opened file
// identity. Callers must preserve the object and fail closed; a final pathname
// check followed by unlink is not an acceptable substitute.
var ErrIdentityBoundRemovalUnavailable = errors.New("identity-bound removal is unavailable on this platform")

// ErrSafePublicationUnavailable reports that the platform cannot prove the
// required atomic publication invariant. Callers must not downgrade this to a
// pathname replacement or copy/delete fallback.
var ErrSafePublicationUnavailable = errors.New("safe atomic publication is unavailable on this platform")

type Root struct {
	path     string
	root     *os.Root
	identity rootIdentity
}

type Candidate struct {
	owner               *Root
	temporary           string
	destination         string
	file                *os.File
	hasher              *digest.HashingWriter
	identity            fileIdentity
	destinationSnapshot destinationSnapshot
	sensitivity         Sensitivity
	closed              bool
}

// destinationSnapshot binds replacement authority to the exact destination
// object and bytes observed before the temporary file is created. An absent
// destination is also a meaningful snapshot: a racing creator is never
// reinterpreted as an object that the caller authorized GitSeal to replace.
type destinationSnapshot struct {
	exists   bool
	identity fileIdentity
	sum      digest.Sum
}

func OpenRoot(name string) (*Root, error) {
	if name == "" {
		return nil, errors.New("root path is empty")
	}
	if !filepath.IsAbs(name) {
		return nil, errors.New("root path must be absolute")
	}
	name = filepath.Clean(name)
	before, err := captureRootIdentity(name)
	if err != nil {
		return nil, fmt.Errorf("capture worktree identity: %w", err)
	}
	opened, err := os.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open rooted worktree: %w", err)
	}
	bound, boundErr := captureOpenedRootIdentity(opened)
	after, err := captureRootIdentity(name)
	if boundErr != nil || err != nil || !sameRootIdentity(before, bound) || !sameRootIdentity(before, after) {
		return nil, errors.Join(errors.New("worktree root changed while it was being opened"), boundErr, err, opened.Close())
	}
	return &Root{path: name, root: opened, identity: before}, nil
}

func (r *Root) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	root := r.root
	r.root = nil
	return root.Close()
}

func (r *Root) OpenRead(configured pathpolicy.Path) (*os.File, error) {
	return r.openRead(configured, PublicData)
}

// OpenSensitiveRead applies the same rooted/link/identity checks as OpenRead
// and additionally requires the platform's private-file protection boundary.
// Windows deliberately rejects this until its DACL and named-stream checks are
// implemented and tested on real NTFS.
func (r *Root) OpenSensitiveRead(configured pathpolicy.Path) (*os.File, error) {
	return r.openRead(configured, SensitiveData)
}

func (r *Root) openRead(configured pathpolicy.Path, sensitivity Sensitivity) (*os.File, error) {
	if !validSensitivity(sensitivity) {
		return nil, errors.New("invalid file sensitivity")
	}
	if err := r.Revalidate(); err != nil {
		return nil, err
	}
	if err := r.validateParents(configured.String()); err != nil {
		return nil, err
	}
	file, _, err := r.openValidated(configured.String(), sensitivity)
	return file, err
}

func (r *Root) OpenControlRead(name string) (*os.File, error) {
	relative, err := controlPath(name)
	if err != nil {
		return nil, err
	}
	if err := r.Revalidate(); err != nil {
		return nil, err
	}
	if err := r.validateParents(relative); err != nil {
		return nil, err
	}
	file, _, err := r.openValidated(relative, PublicData)
	return file, err
}

func (r *Root) EnsureControlDirectory() error {
	if err := r.Revalidate(); err != nil {
		return err
	}
	err := r.root.Mkdir(".gitseal", 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := r.root.Lstat(".gitseal")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New(".gitseal is not a real directory")
	}
	return validatePathObject(r.root, ".gitseal", info)
}

func (r *Root) Revalidate() error {
	current, err := captureRootIdentity(r.path)
	if err != nil || !sameRootIdentity(r.identity, current) {
		return errors.New("worktree root pathname no longer identifies the opened root")
	}
	return nil
}

func (r *Root) TemporaryResidues(max int) ([]string, error) {
	if max <= 0 {
		return nil, errors.New("invalid residue limit")
	}
	var residues []string
	err := fs.WalkDir(r.root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasPrefix(strings.ToLower(path.Base(name)), pathpolicy.ReservedTemporaryPrefix) {
			if len(residues) >= max {
				return errors.New("temporary residue enumeration exceeded its limit")
			}
			residues = append(residues, name)
		}
		return nil
	})
	return residues, err
}

func (r *Root) NewCandidate(destination pathpolicy.Path, sensitivity Sensitivity) (*Candidate, error) {
	return r.newCandidate(destination.String(), sensitivity)
}

func (r *Root) NewControlCandidate(name string, sensitivity Sensitivity) (*Candidate, error) {
	relative, err := controlPath(name)
	if err != nil {
		return nil, err
	}
	if err := r.EnsureControlDirectory(); err != nil {
		return nil, err
	}
	return r.newCandidate(relative, sensitivity)
}

func (r *Root) newCandidate(destination string, sensitivity Sensitivity) (*Candidate, error) {
	if !validSensitivity(sensitivity) {
		return nil, errors.New("invalid file sensitivity")
	}
	if err := preflightCandidateSecurity(sensitivity); err != nil {
		return nil, err
	}
	if err := r.Revalidate(); err != nil {
		return nil, err
	}
	if err := r.validateParents(destination); err != nil {
		return nil, err
	}
	snapshot, err := r.snapshotDestination(destination, sensitivity)
	if err != nil {
		return nil, err
	}
	directory := path.Dir(destination)
	if directory == "." {
		directory = ""
	}
	for range 16 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, errors.New("generate temporary filename")
		}
		name := pathpolicy.ReservedTemporaryPrefix + hex.EncodeToString(random[:])
		temporary := name
		if directory != "" {
			temporary = directory + "/" + name
		}
		mode := os.FileMode(0o600)
		if sensitivity == PublicData {
			mode = 0o644
		}
		file, err := r.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := establishCandidateSecurity(file, sensitivity); err != nil {
			return nil, errors.Join(err, file.Close(), fmt.Errorf("reserved temporary residue %q was retained because identity-bound cleanup is unavailable", temporary))
		}
		identity, err := captureFileIdentity(file)
		if err != nil || !sameFileSystem(r.identity, identity) {
			return nil, errors.Join(errors.New("temporary file is not bound to the worktree filesystem"), err, file.Close(), fmt.Errorf("reserved temporary residue %q was retained because identity-bound cleanup is unavailable", temporary))
		}
		hasher := digest.NewHashingWriter(file)
		return &Candidate{owner: r, temporary: temporary, destination: destination, file: file, hasher: hasher, identity: identity, destinationSnapshot: snapshot, sensitivity: sensitivity}, nil
	}
	return nil, errors.New("could not allocate an exclusive temporary name")
}

func (c *Candidate) Write(p []byte) (int, error) {
	if c == nil || c.closed || c.hasher == nil {
		return 0, errors.New("candidate is not writable")
	}
	if c.hasher.BytesWritten()+int64(len(p)) > limits.DefaultFileBytes {
		return 0, fmt.Errorf("candidate exceeds %d-byte local limit", limits.DefaultFileBytes)
	}
	return c.hasher.Write(p)
}

func (c *Candidate) FlushClose() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	if err := c.file.Sync(); err != nil {
		return errors.Join(err, c.file.Close())
	}
	if err := validateOpenFile(c.file, c.sensitivity); err != nil {
		return errors.Join(err, c.file.Close())
	}
	identity, err := captureFileIdentity(c.file)
	if err != nil || !sameFileIdentity(c.identity, identity) {
		return errors.Join(errors.New("temporary file identity changed before close"), err, c.file.Close())
	}
	return c.file.Close()
}

func (c *Candidate) Sum() digest.Sum {
	if c == nil || c.hasher == nil {
		return digest.Sum{}
	}
	return c.hasher.Sum()
}

// RequireDestination binds a caller's earlier policy/conflict decision to the
// destination snapshot captured immediately before candidate creation. It is
// used when overwriting a user-visible plaintext or ciphertext whose exact
// prior digest participated in authorization.
func (c *Candidate) RequireDestination(exists bool, expected digest.Sum) error {
	if c == nil {
		return errors.New("missing publication candidate")
	}
	if c.destinationSnapshot.exists != exists {
		return errors.New("destination existence changed before candidate creation")
	}
	if exists && c.destinationSnapshot.sum != expected {
		return errors.New("destination digest changed before candidate creation")
	}
	return nil
}

func (c *Candidate) OpenUnpublished() (*os.File, error) {
	if c == nil || c.owner == nil || !c.closed {
		return nil, errors.New("candidate must be closed before it can be reopened")
	}
	file, identity, err := c.owner.openValidated(c.temporary, c.sensitivity)
	if err != nil {
		return nil, err
	}
	if !sameFileIdentity(c.identity, identity) {
		return nil, errors.Join(errors.New("temporary pathname no longer identifies the candidate"), file.Close())
	}
	sum, err := HashExactFile(file, limits.DefaultFileBytes)
	if err != nil || sum != c.Sum() {
		return nil, errors.Join(errors.New("temporary candidate digest could not be reconciled"), err, file.Close())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (c *Candidate) Abort() error {
	if c == nil || c.owner == nil {
		return nil
	}
	var closeErr error
	if !c.closed && c.file != nil {
		closeErr = c.file.Close()
		c.closed = true
	}
	file, identity, err := c.owner.openValidated(c.temporary, c.sensitivity)
	if errors.Is(err, os.ErrNotExist) {
		return closeErr
	}
	if err != nil {
		return errors.Join(closeErr, err)
	}
	openedCloseErr := file.Close()
	if !sameFileIdentity(c.identity, identity) {
		return errors.Join(closeErr, openedCloseErr, errors.New("temporary pathname identity changed; refusing cleanup"))
	}
	// There is no portable atomic "unlink this exact open file identity"
	// primitive. A check followed by pathname removal can delete an unfamiliar
	// object swapped into the reserved name at the final boundary. Retaining a
	// bounded, ignored, invocation-owned residue is safer; doctor reports it and
	// Git/tree validation prevents it from being committed.
	return errors.Join(closeErr, openedCloseErr, fmt.Errorf("%w: unpublished candidate %q was retained", ErrIdentityBoundRemovalUnavailable, c.temporary))
}

func (c *Candidate) Publish(ctx context.Context, replace bool) error {
	if c == nil || c.owner == nil {
		return errors.New("missing publication candidate")
	}
	if !c.closed {
		return errors.New("candidate must be flushed and closed before publication")
	}
	if err := c.owner.Revalidate(); err != nil {
		return err
	}
	if err := c.owner.validateParents(c.destination); err != nil {
		return err
	}
	if err := c.revalidateDestination(replace); err != nil {
		return err
	}
	file, identity, err := c.owner.openValidated(c.temporary, c.sensitivity)
	if err != nil {
		return err
	}
	sum, hashErr := HashExactFile(file, limits.DefaultFileBytes)
	closeErr := file.Close()
	if !sameFileIdentity(c.identity, identity) || hashErr != nil || closeErr != nil || sum != c.Sum() {
		return errors.New("temporary candidate identity or digest changed before publication")
	}
	return publishPlatform(ctx, c, replace)
}

func (r *Root) snapshotDestination(name string, sensitivity Sensitivity) (destinationSnapshot, error) {
	file, identity, err := r.openValidated(name, sensitivity)
	if errors.Is(err, os.ErrNotExist) {
		return destinationSnapshot{}, nil
	}
	if err != nil {
		return destinationSnapshot{}, fmt.Errorf("inspect replacement destination: %w", err)
	}
	sum, hashErr := HashExactFile(file, limits.DefaultFileBytes)
	closeErr := file.Close()
	if hashErr != nil {
		return destinationSnapshot{}, fmt.Errorf("hash replacement destination: %w", hashErr)
	}
	if closeErr != nil {
		return destinationSnapshot{}, fmt.Errorf("close replacement destination: %w", closeErr)
	}
	return destinationSnapshot{exists: true, identity: identity, sum: sum}, nil
}

func (c *Candidate) revalidateDestination(replace bool) error {
	if !replace && c.destinationSnapshot.exists {
		return errors.New("destination already existed when create-if-absent publication began")
	}
	file, identity, err := c.owner.openValidated(c.destination, c.sensitivity)
	if errors.Is(err, os.ErrNotExist) {
		if c.destinationSnapshot.exists {
			return errors.New("replacement destination disappeared before publication")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reopen replacement destination: %w", err)
	}
	sum, hashErr := HashExactFile(file, limits.DefaultFileBytes)
	closeErr := file.Close()
	if hashErr != nil || closeErr != nil {
		return errors.New("replacement destination could not be streamed exactly before publication")
	}
	if !c.destinationSnapshot.exists {
		return errors.New("destination appeared after publication began; refusing overwrite")
	}
	if !sameFileIdentity(c.destinationSnapshot.identity, identity) || c.destinationSnapshot.sum != sum {
		return errors.New("replacement destination identity or digest changed before publication")
	}
	return nil
}

func (r *Root) openValidated(name string, sensitivity Sensitivity) (*os.File, fileIdentity, error) {
	linkInfo, err := r.root.Lstat(name)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fileIdentity{}, errors.New("symbolic-link or reparse-point file is not allowed")
	}
	if err := validatePathObject(r.root, name, linkInfo); err != nil {
		return nil, fileIdentity{}, err
	}
	file, err := r.root.Open(name)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	openInfo, err := file.Stat()
	if err != nil || !openInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openInfo) {
		return nil, fileIdentity{}, errors.Join(errors.New("pathname changed or is not a regular file"), err, file.Close())
	}
	if err := validateOpenFile(file, sensitivity); err != nil {
		return nil, fileIdentity{}, errors.Join(err, file.Close())
	}
	identity, err := captureFileIdentity(file)
	if err != nil || !sameFileSystem(r.identity, identity) {
		return nil, fileIdentity{}, errors.Join(errors.New("file crosses the opened root filesystem boundary"), err, file.Close())
	}
	return file, identity, nil
}

// RemoveOpened removes configured only if its current rooted pathname still
// identifies the caller's already-open file. It is intended for invocation-
// owned control objects such as local locks, never prefix-based cleanup.
func (r *Root) RemoveOpened(configured pathpolicy.Path, expected *os.File, sensitivity Sensitivity) error {
	if expected == nil || !validSensitivity(sensitivity) {
		return errors.New("invalid checked removal request")
	}
	if err := r.Revalidate(); err != nil {
		return err
	}
	if err := r.validateParents(configured.String()); err != nil {
		return err
	}
	expectedIdentity, err := captureFileIdentity(expected)
	if err != nil {
		return err
	}
	current, currentIdentity, err := r.openValidated(configured.String(), sensitivity)
	if err != nil {
		return err
	}
	closeErr := current.Close()
	if closeErr != nil || !sameFileIdentity(expectedIdentity, currentIdentity) {
		return errors.New("pathname identity changed; refusing removal")
	}
	return removeOwnedTemporary(r, configured.String(), expectedIdentity)
}

func (r *Root) validateParents(configured string) error {
	parts := strings.Split(configured, "/")
	current := ""
	for idx, part := range parts[:len(parts)-1] {
		if idx > 0 {
			current += "/"
		}
		current += part
		info, err := r.root.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect path parent %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("path parent %q is not a regular directory", current)
		}
		if err := validatePathObject(r.root, current, info); err != nil {
			return err
		}
		opened, err := r.root.Open(current)
		if err != nil {
			return fmt.Errorf("open path parent %q: %w", current, err)
		}
		openedInfo, statErr := opened.Stat()
		identity, identityErr := captureFileIdentity(opened)
		closeErr := opened.Close()
		if statErr != nil || identityErr != nil || closeErr != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) || !sameFileSystem(r.identity, identity) {
			return fmt.Errorf("path parent %q changed or crosses the root filesystem boundary", current)
		}
	}
	return nil
}

func validSensitivity(value Sensitivity) bool {
	return value == PublicData || value == SensitiveData
}

func controlPath(name string) (string, error) {
	switch name {
	case "config.yaml", "recipients.yaml", "manifest.yaml":
		return ".gitseal/" + name, nil
	default:
		return "", errors.New("unknown GitSeal control file")
	}
}

// HashExactFile hashes the exact bytes returned through one open handle and
// detects common concurrent mutation evidence before accepting the result.
func HashExactFile(file *os.File, max int64) (digest.Sum, error) {
	before, err := file.Stat()
	if err != nil {
		return digest.Sum{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return digest.Sum{}, err
	}
	sum, count, err := digest.Reader(file, max)
	if err != nil {
		return digest.Sum{}, err
	}
	after, err := file.Stat()
	if err != nil {
		return digest.Sum{}, err
	}
	if before.Size() != after.Size() || before.ModTime() != after.ModTime() || count != after.Size() || !os.SameFile(before, after) {
		return digest.Sum{}, errors.New("file changed while it was being streamed")
	}
	return sum, nil
}
