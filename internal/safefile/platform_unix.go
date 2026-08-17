//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package safefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"syscall"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
)

type rootIdentity struct {
	device uint64
	inode  uint64
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

func captureRootIdentity(name string) (rootIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Lstat(name, &stat); err != nil {
		return rootIdentity{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Mode&syscall.S_IFLNK != 0 {
		return rootIdentity{}, errors.New("worktree root pathname is not a real directory")
	}
	return rootIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func sameRootIdentity(a, b rootIdentity) bool {
	return a == b
}

func captureOpenedRootIdentity(root *os.Root) (rootIdentity, error) {
	file, err := root.Open(".")
	if err != nil {
		return rootIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return rootIdentity{}, errors.Join(errors.New("opened root is not a directory"), err, file.Close())
	}
	identity, err := captureFileIdentity(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return rootIdentity{}, errors.Join(err, closeErr)
	}
	return rootIdentity{device: identity.device, inode: identity.inode}, nil
}

func captureFileIdentity(file *os.File) (fileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("filesystem did not expose a stable file identity")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func sameFileIdentity(a, b fileIdentity) bool { return a == b }

func sameFileSystem(root rootIdentity, file fileIdentity) bool { return root.device == file.device }

func validatePathObject(_ *os.Root, _ string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic-link path component is not allowed")
	}
	return nil
}

func validateOpenFile(file *os.File, sensitivity Sensitivity) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("opened object is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("files with multiple hard links are not supported")
	}
	if sensitivity == SensitiveData && info.Mode().Perm() != 0o600 {
		return errors.New("sensitive file permissions are not exactly 0600")
	}
	return nil
}

func establishCandidateSecurity(file *os.File, sensitivity Sensitivity) error {
	if sensitivity == SensitiveData {
		if err := file.Chmod(0o600); err != nil {
			return err
		}
	}
	return validateOpenFile(file, sensitivity)
}

func preflightCandidateSecurity(Sensitivity) error { return nil }

func removeOwnedTemporary(owner *Root, temporary string, expected fileIdentity) error {
	_ = owner
	_ = temporary
	_ = expected
	return ErrIdentityBoundRemovalUnavailable
}

type relativeFileState struct {
	exists   bool
	identity fileIdentity
	sum      digest.Sum
	links    uint64
}

func publishPlatform(ctx context.Context, candidate *Candidate, replace bool) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	parentName := path.Dir(candidate.destination)
	parent, err := openPublicationParent(candidate.owner, parentName)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	temporaryName := path.Base(candidate.temporary)
	destinationName := path.Base(candidate.destination)
	if temporaryName == "." || destinationName == "." || temporaryName == destinationName {
		return errors.New("invalid publication basenames")
	}
	temporaryBefore, err := inspectRelativeFile(parent, temporaryName, candidate.sensitivity)
	if err != nil {
		return fmt.Errorf("inspect publication candidate through bound parent: %w", err)
	}
	candidateBefore := relativeFileState{exists: true, identity: candidate.identity, sum: candidate.Sum(), links: 1}
	if !sameRelativeState(temporaryBefore, candidateBefore) {
		return errors.New("bound parent does not contain the expected publication candidate")
	}
	destinationBefore, err := inspectRelativeFile(parent, destinationName, candidate.sensitivity)
	if err != nil {
		return fmt.Errorf("inspect destination through bound parent: %w", err)
	}
	expectedDestination := relativeFileState{}
	if candidate.destinationSnapshot.exists {
		expectedDestination = relativeFileState{
			exists: true, identity: candidate.destinationSnapshot.identity,
			sum: candidate.destinationSnapshot.sum, links: 1,
		}
	}
	if !sameRelativeState(destinationBefore, expectedDestination) {
		return errors.New("destination changed before the handle-relative publication call")
	}
	if destinationBefore.exists && !replace {
		return errors.New("create-if-absent publication cannot replace an existing destination")
	}
	if replace || destinationBefore.exists {
		return errors.New("existing-destination Unix replacement is disabled: no reviewed primitive can atomically bind the expected destination identity without a destructive pathname-cleanup race")
	}
	// Confirm that this filesystem accepts a directory flush before making a
	// new name visible. We never silently downgrade durability on a filesystem
	// that rejects the required operation.
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("publication parent does not support the required durability flush: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// RENAME_NOREPLACE (Linux) / RENAME_EXCL (macOS) atomically consumes the
	// candidate name and cannot overwrite a raced-in destination. No unlink or
	// rollback by pathname is attempted.
	if err := publishRelativeNoReplace(parent, temporaryName, destinationName); err != nil {
		return fmt.Errorf("atomic create-if-absent publication failed: %w", err)
	}

	boundFinal, err := inspectRelativeFile(parent, destinationName, candidate.sensitivity)
	if err != nil || !sameRelativeState(boundFinal, candidateBefore) {
		return errors.Join(errors.New("publication state is ambiguous after atomic create-if-absent; no pathname was deleted"), err)
	}
	if temporaryAfter, inspectErr := inspectRelativeFile(parent, temporaryName, candidate.sensitivity); inspectErr != nil || temporaryAfter.exists {
		return errors.Join(errors.New("publication became visible but the candidate name was not atomically consumed; no pathname was deleted"), inspectErr)
	}
	file, identity, err := candidate.owner.openValidated(candidate.destination, candidate.sensitivity)
	if err != nil {
		return errors.New("publication became visible but the configured final path could not be reopened for reconciliation")
	}
	if !sameFileIdentity(candidate.identity, identity) {
		return errors.Join(errors.New("publication became visible but the configured pathname does not identify the candidate"), file.Close())
	}
	sum, err := HashExactFile(file, limits.DefaultFileBytes)
	closeErr := file.Close()
	if err != nil || closeErr != nil || sum != candidate.Sum() {
		return errors.New("publication became visible but its final digest or close could not be reconciled")
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("published file is visible and reconciled, but its parent directory flush failed: %w", err)
	}
	return nil
}

func openPublicationParent(owner *Root, name string) (*os.File, error) {
	linkInfo, err := owner.root.Lstat(name)
	if err != nil || !linkInfo.IsDir() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("publication parent is missing, linked, or not a directory")
	}
	if err := validatePathObject(owner.root, name, linkInfo); err != nil {
		return nil, err
	}
	parent, err := owner.root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := parent.Stat()
	identity, identityErr := captureFileIdentity(parent)
	recheck, recheckErr := owner.root.Lstat(name)
	if statErr != nil || identityErr != nil || recheckErr != nil || !opened.IsDir() || !os.SameFile(linkInfo, opened) || !os.SameFile(opened, recheck) || !sameFileSystem(owner.identity, identity) {
		return nil, errors.Join(errors.New("publication parent changed while its handle was being bound"), statErr, identityErr, recheckErr, parent.Close())
	}
	return parent, nil
}

func inspectRelativeFile(parent *os.File, name string, sensitivity Sensitivity) (state relativeFileState, resultErr error) {
	file, err := openRelativeNoFollow(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return relativeFileState{}, nil
	}
	if err != nil {
		return relativeFileState{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return relativeFileState{}, errors.New("relative publication object is not a regular non-link file")
	}
	if sensitivity == SensitiveData && info.Mode().Perm() != 0o600 {
		return relativeFileState{}, errors.New("relative sensitive publication object is not mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return relativeFileState{}, errors.New("relative publication object has no stable Unix identity")
	}
	identity, err := captureFileIdentity(file)
	if err != nil {
		return relativeFileState{}, err
	}
	parentIdentity, err := captureFileIdentity(parent)
	if err != nil || identity.device != parentIdentity.device {
		return relativeFileState{}, errors.New("relative publication object crosses the bound parent filesystem")
	}
	sum, err := HashExactFile(file, limits.DefaultFileBytes)
	if err != nil {
		return relativeFileState{}, err
	}
	return relativeFileState{exists: true, identity: identity, sum: sum, links: uint64(stat.Nlink)}, nil
}

func sameRelativeState(actual, expected relativeFileState) bool {
	if actual.exists != expected.exists {
		return false
	}
	return !actual.exists || (sameFileIdentity(actual.identity, expected.identity) && actual.sum == expected.sum && actual.links == expected.links)
}
