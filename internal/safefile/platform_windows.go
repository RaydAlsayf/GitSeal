//go:build windows

package safefile

import (
	"context"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type rootIdentity struct {
	volume uint64
	fileID [16]byte
}

type fileIdentity struct {
	volume uint64
	fileID [16]byte
}

type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func captureRootIdentity(name string) (identity rootIdentity, resultErr error) {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return rootIdentity{}, err
	}
	handle, err := windows.CreateFile(path, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return rootIdentity{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(handle)) }()
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return rootIdentity{}, err
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return rootIdentity{}, errors.New("worktree root pathname is a reparse point")
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return rootIdentity{}, errors.New("worktree root pathname is not a directory")
	}
	var id fileIDInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return rootIdentity{}, err
	}
	return rootIdentity{volume: id.VolumeSerialNumber, fileID: id.FileID}, nil
}

func sameRootIdentity(a, b rootIdentity) bool { return a == b }

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
	return rootIdentity{volume: identity.volume, fileID: identity.fileID}, nil
}

func captureFileIdentity(file *os.File) (fileIdentity, error) {
	var id fileIDInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{volume: id.VolumeSerialNumber, fileID: id.FileID}, nil
}

func sameFileIdentity(a, b fileIdentity) bool { return a == b }

func sameFileSystem(root rootIdentity, file fileIdentity) bool { return root.volume == file.volume }

func validatePathObject(_ *os.Root, _ string, info os.FileInfo) error {
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return errors.New("filesystem did not expose Windows file attributes")
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse or symbolic-link path component is not allowed")
	}
	return nil
}

func validateOpenFile(file *os.File, sensitivity Sensitivity) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("opened object is not a regular file")
	}
	var byHandle syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &byHandle); err != nil {
		return err
	}
	if byHandle.NumberOfLinks != 1 {
		return errors.New("files with multiple hard links are not supported")
	}
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return err
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse-point files are not supported")
	}
	if sensitivity == SensitiveData {
		return errors.New("sensitive Windows ACL/stream publication boundary is not yet implemented; refusing publication")
	}
	return nil
}

func establishCandidateSecurity(file *os.File, sensitivity Sensitivity) error {
	if sensitivity == SensitiveData {
		return errors.New("restrictive Windows DACL creation is not yet implemented; refusing sensitive candidate")
	}
	return validateOpenFile(file, sensitivity)
}

func preflightCandidateSecurity(sensitivity Sensitivity) error {
	if sensitivity == SensitiveData {
		return errors.New("restrictive Windows DACL creation is not yet implemented; refusing sensitive candidate before temporary allocation")
	}
	return nil
}

func removeOwnedTemporary(owner *Root, temporary string, expected fileIdentity) error {
	_ = owner
	_ = temporary
	_ = expected
	return ErrIdentityBoundRemovalUnavailable
}

func publishPlatform(ctx context.Context, candidate *Candidate, replace bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Go's rooted rename contains path traversal, but its Windows replacement
	// operation cannot atomically bind the destination to the identity and
	// digest approved above. The create-only hard-link path also requires a
	// pathname unlink of the candidate name. Until reviewed handle-relative
	// conditional primitives are implemented, fail before making any name
	// visible for public as well as sensitive data.
	_ = candidate
	_ = replace
	return ErrSafePublicationUnavailable
}
