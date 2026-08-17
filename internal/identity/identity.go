// Package identity implements the local native-hybrid identity lifecycle. It
// never accepts private material through flags or environment values.
package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

var validName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type Record struct {
	Name        string
	Path        string
	Identity    agefile.HybridIdentity
	Recipient   string
	Fingerprint string
}

func Directory() (string, error) {
	directory, err := platformDirectory()
	if err != nil {
		return "", err
	}
	if repositoryStorageAncestor(directory) != "" {
		return "", errors.New("identity storage resolves inside a Git worktree or administrative directory")
	}
	if knownCloudStorageAncestor(directory) != "" {
		return "", errors.New("identity storage resolves inside a known cloud-synchronization location; V1 has no persisted location-risk acceptance")
	}
	if err := validateIdentityFilesystem(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func knownCloudStorageAncestor(name string) string {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return ""
	}
	var candidates []string
	for _, environmentName := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial", "DROPBOX_HOME", "GOOGLE_DRIVE", "BOX_HOME", "NEXTCLOUD_HOME"} {
		if value := os.Getenv(environmentName); value != "" && filepath.IsAbs(value) {
			candidates = append(candidates, value)
		}
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && filepath.IsAbs(home) {
		for _, relative := range []string{
			"OneDrive", "Dropbox", "Google Drive", "GoogleDrive", "Box", "Nextcloud",
			filepath.Join("Library", "Mobile Documents"), filepath.Join("Library", "CloudStorage"),
		} {
			candidates = append(candidates, filepath.Join(home, relative))
		}
	}
	for _, candidate := range candidates {
		relative, relErr := filepath.Rel(filepath.Clean(candidate), absolute)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.Clean(candidate)
		}
	}
	return ""
}

func repositoryStorageAncestor(name string) string {
	current, err := filepath.Abs(name)
	if err != nil {
		return ""
	}
	for {
		if strings.EqualFold(filepath.Base(current), ".git") {
			return current
		}
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return current
		}
		if head, headErr := os.Lstat(filepath.Join(current, "HEAD")); headErr == nil && head.Mode().IsRegular() {
			if objects, objectsErr := os.Lstat(filepath.Join(current, "objects")); objectsErr == nil && objects.IsDir() {
				if refs, refsErr := os.Lstat(filepath.Join(current, "refs")); refsErr == nil && refs.IsDir() {
					return current
				}
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func Path(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("identity name must match [a-z][a-z0-9_-]{0,31}")
	}
	directory, err := Directory()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, name+".txt"), nil
}

func Create(ctx context.Context, name string) (record Record, resultErr error) {
	finalPath, err := Path(name)
	if err != nil {
		return Record{}, err
	}
	directory := filepath.Dir(finalPath)
	if err := prepareDirectory(directory); err != nil {
		return Record{}, err
	}
	if _, err := os.Lstat(finalPath); err == nil {
		return Record{}, errors.New("identity already exists; GitSeal never rotates or overwrites implicitly")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, err
	}
	generated, err := agefile.GenerateHybridIdentity()
	if err != nil {
		return Record{}, err
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		return Record{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	relative, _ := pathpolicy.Parse(filepath.Base(finalPath))
	candidate, err := root.NewCandidate(relative, safefile.SensitiveData)
	if err != nil {
		return Record{}, err
	}
	published := false
	defer func() {
		if !published {
			if abortErr := candidate.Abort(); abortErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("identity creation left an owned temporary candidate requiring manual reconciliation: %w", abortErr))
			}
		}
	}()
	if err := generated.WritePrivate(candidate); err != nil {
		return Record{}, err
	}
	if err := candidate.FlushClose(); err != nil {
		return Record{}, err
	}
	if err := candidate.Publish(ctx, false); err != nil {
		return Record{}, err
	}
	published = true
	record, err = Load(name)
	if err != nil {
		return Record{}, fmt.Errorf("identity final-path validation failed: %w", err)
	}
	if record.Recipient != generated.CanonicalRecipient() {
		return Record{}, errors.New("identity final path does not contain the generated identity")
	}
	if err := roundTrip(record.Identity); err != nil {
		return Record{}, fmt.Errorf("identity round-trip self-test failed: %w", err)
	}
	return record, nil
}

func Load(name string) (record Record, resultErr error) {
	identityPath, err := Path(name)
	if err != nil {
		return Record{}, err
	}
	directory := filepath.Dir(identityPath)
	if err := preparePlatformDirectory(directory); err != nil {
		return Record{}, err
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		return Record{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	relative, _ := pathpolicy.Parse(filepath.Base(identityPath))
	file, err := root.OpenSensitiveRead(relative)
	if err != nil {
		return Record{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Record{}, errors.New("identity path is not a regular file")
	}
	if err := validatePrivateFile(file, info); err != nil {
		return Record{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return Record{}, err
	}
	if len(data) > 4096 {
		return Record{}, errors.New("identity file exceeds the maximum expected size")
	}
	parsed, err := agefile.ParseHybridIdentityFile(data)
	clear(data)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Name: name, Path: identityPath, Identity: parsed,
		Recipient: parsed.CanonicalRecipient(), Fingerprint: parsed.Fingerprint().Grouped(),
	}, nil
}

func roundTrip(identity agefile.HybridIdentity) error {
	recipients, err := agefile.NewHybridRecipients([]string{identity.CanonicalRecipient()})
	if err != nil {
		return err
	}
	plan, err := agefile.NewEncryptionPlan(recipients, identity)
	if err != nil {
		return err
	}
	plaintext := []byte("GitSeal identity self-test v1")
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, bytes.NewReader(plaintext)); err != nil {
		return err
	}
	if err := plan.AuthenticateCandidate(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len())); err != nil {
		return err
	}
	engine, _ := agefile.NewEngine(1)
	var recovered bytes.Buffer
	if err := engine.Decrypt(&recovered, bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), identity); err != nil {
		return err
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		return errors.New("self-test plaintext mismatch")
	}
	clear(plaintext)
	return nil
}

func prepareDirectory(directory string) error {
	return preparePlatformDirectory(directory)
}
