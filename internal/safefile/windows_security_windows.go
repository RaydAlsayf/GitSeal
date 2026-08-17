//go:build windows

package safefile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These helpers are intentionally not wired into SensitiveData yet. They make
// the Windows checks independently reviewable while the externally reachable
// boundary remains fail closed pending adversarial testing on unsandboxed NTFS.

const (
	windowsStreamInfoHeaderBytes = 24
	windowsMaxStreamInfoBytes    = 64 << 10
	windowsMaxFinalPathUTF16     = 32768
	windowsVolumeNameGUID        = 0x1
)

type windowsVolumeInspection struct {
	FileSystem             string
	Flags                  uint32
	MaximumComponentLength uint32
	VolumeRoot             string
	DriveType              uint32
}

func inspectWindowsVolume(handle windows.Handle) (windowsVolumeInspection, error) {
	var fileSystem [64]uint16
	var flags uint32
	var maximumComponentLength uint32
	if err := windows.GetVolumeInformationByHandle(
		handle,
		nil,
		0,
		nil,
		&maximumComponentLength,
		&flags,
		&fileSystem[0],
		uint32(len(fileSystem)),
	); err != nil {
		return windowsVolumeInspection{}, fmt.Errorf("inspect volume by handle: %w", err)
	}

	root, err := windowsVolumeRootByHandle(handle)
	if err != nil {
		return windowsVolumeInspection{}, err
	}
	rootUTF16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windowsVolumeInspection{}, fmt.Errorf("encode volume root: %w", err)
	}
	return windowsVolumeInspection{
		FileSystem:             windows.UTF16ToString(fileSystem[:]),
		Flags:                  flags,
		MaximumComponentLength: maximumComponentLength,
		VolumeRoot:             root,
		DriveType:              windows.GetDriveType(rootUTF16),
	}, nil
}

func windowsVolumeRootByHandle(handle windows.Handle) (string, error) {
	required, err := windows.GetFinalPathNameByHandle(handle, nil, 0, windowsVolumeNameGUID)
	if err != nil {
		return "", fmt.Errorf("resolve handle volume name: %w", err)
	}
	if required == 0 || required > windowsMaxFinalPathUTF16 {
		return "", errors.New("handle volume name exceeded its bound")
	}
	buffer := make([]uint16, required+1)
	written, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), windowsVolumeNameGUID)
	if err != nil {
		return "", fmt.Errorf("resolve handle volume name: %w", err)
	}
	if written == 0 || written >= uint32(len(buffer)) {
		return "", errors.New("handle volume name changed or exceeded its bound")
	}
	finalPath := windows.UTF16ToString(buffer[:written])
	const volumePrefix = `\\?\Volume{`
	if !strings.HasPrefix(strings.ToLower(finalPath), strings.ToLower(volumePrefix)) {
		return "", errors.New("handle did not resolve to a local volume GUID path")
	}
	end := strings.Index(finalPath[len(volumePrefix):], `}\`)
	if end < 0 {
		return "", errors.New("handle returned a malformed volume GUID path")
	}
	end += len(volumePrefix) + 2
	return finalPath[:end], nil
}

func validateWindowsVolumeForSensitiveData(inspection windowsVolumeInspection) error {
	if inspection.DriveType != windows.DRIVE_FIXED {
		return errors.New("sensitive Windows data requires a fixed local volume")
	}
	if !strings.EqualFold(inspection.FileSystem, "NTFS") {
		return errors.New("sensitive Windows data requires an NTFS volume")
	}
	if inspection.Flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return errors.New("volume does not report persistent ACL enforcement")
	}
	if inspection.Flags&windows.FILE_NAMED_STREAMS == 0 {
		return errors.New("volume does not report named-stream support")
	}
	if inspection.Flags&windows.FILE_READ_ONLY_VOLUME != 0 {
		return errors.New("volume is read-only")
	}
	if inspection.MaximumComponentLength == 0 {
		return errors.New("volume returned an invalid component-length limit")
	}
	if inspection.VolumeRoot == "" {
		return errors.New("volume root was not identity-bound to the inspected handle")
	}
	return nil
}

type windowsStreamInspection struct {
	Name           string
	Size           int64
	AllocationSize int64
}

func inspectWindowsStreams(handle windows.Handle) ([]windowsStreamInspection, error) {
	for size := 4096; size <= windowsMaxStreamInfoBytes; size *= 2 {
		buffer := make([]byte, size)
		err := windows.GetFileInformationByHandleEx(handle, windows.FileStreamInfo, &buffer[0], uint32(len(buffer)))
		if err == nil {
			return parseWindowsStreamInfo(buffer)
		}
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil, nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("enumerate streams by handle: %w", err)
		}
	}
	return nil, fmt.Errorf("stream metadata exceeded the %d-byte limit", windowsMaxStreamInfoBytes)
}

// parseWindowsStreamInfo validates the variable-length FILE_STREAM_INFO list.
// Microsoft specifies byte-counted UTF-16 names and 8-byte-aligned successor
// offsets; neither field is trusted here.
func parseWindowsStreamInfo(buffer []byte) ([]windowsStreamInspection, error) {
	if len(buffer) > windowsMaxStreamInfoBytes {
		return nil, errors.New("stream metadata exceeds its parser bound")
	}
	if len(buffer) < windowsStreamInfoHeaderBytes {
		return nil, errors.New("stream metadata is truncated")
	}
	streams := make([]windowsStreamInspection, 0, 4)
	for offset, entries := 0, 0; ; entries++ {
		if entries > len(buffer)/windowsStreamInfoHeaderBytes {
			return nil, errors.New("stream metadata contains too many entries")
		}
		if offset < 0 || len(buffer)-offset < windowsStreamInfoHeaderBytes {
			return nil, errors.New("stream metadata entry is truncated")
		}
		entry := buffer[offset:]
		next := binary.LittleEndian.Uint32(entry[0:4])
		nameBytes := binary.LittleEndian.Uint32(entry[4:8])
		entryBytes := len(entry)
		if next != 0 {
			if next%8 != 0 || next < windowsStreamInfoHeaderBytes || uint64(next) > uint64(len(entry)) {
				return nil, errors.New("stream metadata has an invalid successor offset")
			}
			entryBytes = int(next)
		}
		if nameBytes == 0 || nameBytes%2 != 0 || uint64(nameBytes) > uint64(entryBytes-windowsStreamInfoHeaderBytes) {
			return nil, errors.New("stream metadata has an invalid UTF-16 name length")
		}
		nameEnd := windowsStreamInfoHeaderBytes + int(nameBytes)
		name, err := decodeWindowsUTF16Strict(entry[windowsStreamInfoHeaderBytes:nameEnd])
		if err != nil {
			return nil, fmt.Errorf("decode stream name: %w", err)
		}
		size := int64(binary.LittleEndian.Uint64(entry[8:16]))
		allocationSize := int64(binary.LittleEndian.Uint64(entry[16:24]))
		if size < 0 || allocationSize < 0 {
			return nil, errors.New("stream metadata reports a negative size")
		}
		streams = append(streams, windowsStreamInspection{Name: name, Size: size, AllocationSize: allocationSize})
		if next == 0 {
			break
		}
		offset += int(next)
	}
	return streams, nil
}

func decodeWindowsUTF16Strict(encoded []byte) (string, error) {
	if len(encoded) == 0 || len(encoded)%2 != 0 {
		return "", errors.New("invalid UTF-16 byte count")
	}
	units := make([]uint16, len(encoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(encoded[index*2:])
		if units[index] == 0 {
			return "", errors.New("UTF-16 value contains NUL")
		}
	}
	for index := 0; index < len(units); index++ {
		switch {
		case 0xD800 <= units[index] && units[index] <= 0xDBFF:
			if index+1 >= len(units) || units[index+1] < 0xDC00 || units[index+1] > 0xDFFF {
				return "", errors.New("UTF-16 value contains an unpaired high surrogate")
			}
			index++
		case 0xDC00 <= units[index] && units[index] <= 0xDFFF:
			return "", errors.New("UTF-16 value contains an unpaired low surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

func validateWindowsDataStreams(streams []windowsStreamInspection, requireUnnamed bool) error {
	seenUnnamed := false
	for _, stream := range streams {
		if stream.Name != "::$DATA" {
			return fmt.Errorf("unexpected Windows stream %q", stream.Name)
		}
		if seenUnnamed {
			return errors.New("duplicate unnamed Windows data stream")
		}
		seenUnnamed = true
	}
	if requireUnnamed && !seenUnnamed {
		return errors.New("unnamed Windows data stream is missing")
	}
	return nil
}

type windowsTokenProfileInspection struct {
	EffectiveSID      string
	ProcessSID        string
	Profile           string
	LocalAppData      string
	SameActingUser    bool
	LocalAppDataBound bool
}

func inspectWindowsTokenProfile() (inspection windowsTokenProfileInspection, resultErr error) {
	effectiveUser, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || effectiveUser == nil || effectiveUser.User.Sid == nil || !effectiveUser.User.Sid.IsValid() {
		return windowsTokenProfileInspection{}, errors.New("query effective Windows token user")
	}
	var processToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &processToken); err != nil {
		return windowsTokenProfileInspection{}, fmt.Errorf("open process token: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, processToken.Close()) }()
	processUser, err := processToken.GetTokenUser()
	if err != nil || processUser == nil || processUser.User.Sid == nil || !processUser.User.Sid.IsValid() {
		return windowsTokenProfileInspection{}, errors.New("query process Windows token user")
	}
	profile, err := processToken.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(profile) {
		return windowsTokenProfileInspection{}, errors.New("resolve current Windows profile")
	}
	localAppData, err := processToken.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(localAppData) {
		return windowsTokenProfileInspection{}, errors.New("resolve current Windows LocalAppData")
	}
	effectiveSID := effectiveUser.User.Sid.String()
	processSID := processUser.User.Sid.String()
	if effectiveSID == "" || processSID == "" {
		return windowsTokenProfileInspection{}, errors.New("render Windows token SID")
	}
	return windowsTokenProfileInspection{
		EffectiveSID:      effectiveSID,
		ProcessSID:        processSID,
		Profile:           filepath.Clean(profile),
		LocalAppData:      filepath.Clean(localAppData),
		SameActingUser:    effectiveUser.User.Sid.Equals(processUser.User.Sid),
		LocalAppDataBound: windowsPathStrictlyWithin(profile, localAppData),
	}, nil
}

func validateWindowsTokenProfileForSensitiveData(inspection windowsTokenProfileInspection) error {
	if inspection.EffectiveSID == "" || inspection.ProcessSID == "" || inspection.EffectiveSID != inspection.ProcessSID || !inspection.SameActingUser {
		return errors.New("effective Windows token does not match the process profile identity")
	}
	if inspection.Profile == "" || inspection.LocalAppData == "" || !inspection.LocalAppDataBound || !windowsPathStrictlyWithin(inspection.Profile, inspection.LocalAppData) {
		return errors.New("Windows LocalAppData is not bound beneath the acting profile")
	}
	return nil
}

func windowsPathStrictlyWithin(parent, child string) bool {
	if !filepath.IsAbs(parent) || !filepath.IsAbs(child) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil || relative == "." || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

type windowsACEInspection struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   string
}

type windowsDACLInspection struct {
	OwnerSID       string
	OwnerDefaulted bool
	Protected      bool
	DACLDefaulted  bool
	ACEs           []windowsACEInspection
}

func inspectWindowsDACL(handle windows.Handle) (windowsDACLInspection, error) {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		if err != nil {
			return windowsDACLInspection{}, fmt.Errorf("query handle security descriptor: %w", err)
		}
		return windowsDACLInspection{}, errors.New("handle has no security descriptor")
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || owner.String() == "" {
		return windowsDACLInspection{}, errors.New("security descriptor has no valid owner")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return windowsDACLInspection{}, fmt.Errorf("query security descriptor control: %w", err)
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return windowsDACLInspection{}, errors.New("security descriptor has no restrictive DACL")
	}
	inspection := windowsDACLInspection{
		OwnerSID:       owner.String(),
		OwnerDefaulted: ownerDefaulted,
		Protected:      control&windows.SE_DACL_PROTECTED != 0,
		DACLDefaulted:  daclDefaulted,
		ACEs:           make([]windowsACEInspection, 0, dacl.AceCount),
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return windowsDACLInspection{}, errors.New("read DACL access-control entry")
		}
		entry := windowsACEInspection{Type: ace.Header.AceType, Flags: ace.Header.AceFlags}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			const minimumSIDBytes = 8
			sidOffset := unsafe.Offsetof(ace.SidStart)
			if uintptr(ace.Header.AceSize) < sidOffset+minimumSIDBytes {
				return windowsDACLInspection{}, errors.New("DACL entry is truncated")
			}
			sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + sidOffset))
			if !sid.IsValid() || uintptr(sid.Len()) > uintptr(ace.Header.AceSize)-sidOffset || sid.String() == "" {
				return windowsDACLInspection{}, errors.New("DACL entry contains an invalid SID")
			}
			entry.Mask = uint32(ace.Mask)
			entry.SID = sid.String()
		}
		inspection.ACEs = append(inspection.ACEs, entry)
	}
	return inspection, nil
}

type windowsDACLPolicy struct {
	OwnerSID string
	ACEs     []windowsACEInspection
}

// validateWindowsProtectedDACL is deliberately exact: a future caller must
// make an explicit, reviewed choice for every accepted principal, mask, and
// inheritance flag. It does not silently bless Administrators or inherited
// access.
func validateWindowsProtectedDACL(inspection windowsDACLInspection, policy windowsDACLPolicy) error {
	if policy.OwnerSID == "" || inspection.OwnerSID != policy.OwnerSID {
		return errors.New("Windows object owner does not match the acting identity")
	}
	if inspection.OwnerDefaulted || inspection.DACLDefaulted || !inspection.Protected {
		return errors.New("Windows object does not have an explicit protected DACL")
	}
	if len(inspection.ACEs) != len(policy.ACEs) {
		return errors.New("Windows object DACL has an unexpected entry count")
	}
	used := make([]bool, len(policy.ACEs))
	for _, actual := range inspection.ACEs {
		if actual.Type != windows.ACCESS_ALLOWED_ACE_TYPE || actual.Flags&windows.INHERITED_ACE != 0 || actual.SID == "" {
			return errors.New("Windows object DACL contains an unsupported entry")
		}
		matched := false
		for index, expected := range policy.ACEs {
			if !used[index] && actual == expected {
				used[index] = true
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("Windows object DACL grants unreviewed access")
		}
	}
	return nil
}
