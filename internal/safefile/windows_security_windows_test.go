//go:build windows

package safefile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestParseWindowsStreamInfo(t *testing.T) {
	first := encodeWindowsStreamEntry(t, "::$DATA", 0, 12, 16)
	firstLength := alignWindowsStreamEntry(len(first))
	first = append(first, make([]byte, firstLength-len(first))...)
	binary.LittleEndian.PutUint32(first[0:4], uint32(firstLength))
	second := encodeWindowsStreamEntry(t, ":audit:$DATA", 0, 7, 8)
	streams, err := parseWindowsStreamInfo(append(first, second...))
	if err != nil {
		t.Fatal(err)
	}
	want := []windowsStreamInspection{
		{Name: "::$DATA", Size: 12, AllocationSize: 16},
		{Name: ":audit:$DATA", Size: 7, AllocationSize: 8},
	}
	if !reflect.DeepEqual(streams, want) {
		t.Fatalf("streams = %#v, want %#v", streams, want)
	}
	if err := validateWindowsDataStreams(streams[:1], true); err != nil {
		t.Fatalf("default stream rejected: %v", err)
	}
	if err := validateWindowsDataStreams(streams, true); err == nil {
		t.Fatal("named stream was accepted")
	}
}

func TestParseWindowsStreamInfoRejectsHostileMetadata(t *testing.T) {
	valid := encodeWindowsStreamEntry(t, "::$DATA", 0, 1, 1)
	oddName := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(oddName[4:8], 3)
	overlongName := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(overlongName[4:8], uint32(len(valid)))
	misalignedNext := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(misalignedNext[0:4], 25)
	shortNext := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(shortNext[0:4], 16)
	farNext := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(farNext[0:4], uint32(len(valid)+8))
	negativeSize := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint64(negativeSize[8:16], ^uint64(0))
	nulName := encodeWindowsStreamEntry(t, ":a:$DATA", 0, 1, 1)
	binary.LittleEndian.PutUint16(nulName[windowsStreamInfoHeaderBytes+2:], 0)
	unpaired := encodeWindowsStreamEntryRaw([]uint16{':', 0xD800, ':', '$', 'D', 'A', 'T', 'A'}, 0, 0, 0)

	for name, input := range map[string][]byte{
		"truncated":          make([]byte, windowsStreamInfoHeaderBytes-1),
		"oversized":          make([]byte, windowsMaxStreamInfoBytes+1),
		"odd name":           oddName,
		"overlong name":      overlongName,
		"misaligned next":    misalignedNext,
		"short next":         shortNext,
		"far next":           farNext,
		"negative size":      negativeSize,
		"embedded NUL":       nulName,
		"unpaired surrogate": unpaired,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWindowsStreamInfo(input); err == nil {
				t.Fatal("hostile stream metadata was accepted")
			}
		})
	}
}

func FuzzParseWindowsStreamInfo(f *testing.F) {
	f.Add(encodeWindowsStreamEntryRaw(utf16.Encode([]rune("::$DATA")), 0, 1, 8))
	f.Add([]byte{})
	f.Add(make([]byte, windowsStreamInfoHeaderBytes))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > windowsMaxStreamInfoBytes {
			return
		}
		streams, err := parseWindowsStreamInfo(input)
		if err != nil {
			return
		}
		for _, stream := range streams {
			if stream.Name == "" || stream.Size < 0 || stream.AllocationSize < 0 {
				t.Fatal("parser accepted an invalid stream result")
			}
		}
	})
}

func TestValidateWindowsDataStreams(t *testing.T) {
	if err := validateWindowsDataStreams(nil, false); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsDataStreams(nil, true); err == nil {
		t.Fatal("missing default stream was accepted")
	}
	duplicate := []windowsStreamInspection{{Name: "::$DATA"}, {Name: "::$DATA"}}
	if err := validateWindowsDataStreams(duplicate, true); err == nil {
		t.Fatal("duplicate default stream was accepted")
	}
}

func TestValidateWindowsVolumeForSensitiveData(t *testing.T) {
	valid := windowsVolumeInspection{
		FileSystem:             "NTFS",
		Flags:                  windows.FILE_PERSISTENT_ACLS | windows.FILE_NAMED_STREAMS,
		MaximumComponentLength: 255,
		VolumeRoot:             `\\?\Volume{00000000-0000-0000-0000-000000000000}\`,
		DriveType:              windows.DRIVE_FIXED,
	}
	if err := validateWindowsVolumeForSensitiveData(valid); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*windowsVolumeInspection){
		"remote":             func(value *windowsVolumeInspection) { value.DriveType = windows.DRIVE_REMOTE },
		"ReFS":               func(value *windowsVolumeInspection) { value.FileSystem = "ReFS" },
		"no ACLs":            func(value *windowsVolumeInspection) { value.Flags &^= windows.FILE_PERSISTENT_ACLS },
		"no streams":         func(value *windowsVolumeInspection) { value.Flags &^= windows.FILE_NAMED_STREAMS },
		"read only":          func(value *windowsVolumeInspection) { value.Flags |= windows.FILE_READ_ONLY_VOLUME },
		"no component bound": func(value *windowsVolumeInspection) { value.MaximumComponentLength = 0 },
		"no root":            func(value *windowsVolumeInspection) { value.VolumeRoot = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			inspection := valid
			mutate(&inspection)
			if err := validateWindowsVolumeForSensitiveData(inspection); err == nil {
				t.Fatal("unsupported volume was accepted")
			}
		})
	}
}

func TestValidateWindowsProtectedDACL(t *testing.T) {
	const (
		userSID   = "S-1-5-21-1000"
		systemSID = "S-1-5-18"
	)
	user := windowsACEInspection{Type: windows.ACCESS_ALLOWED_ACE_TYPE, Mask: 0x1f01ff, SID: userSID}
	system := windowsACEInspection{Type: windows.ACCESS_ALLOWED_ACE_TYPE, Mask: 0x1f01ff, SID: systemSID}
	valid := windowsDACLInspection{OwnerSID: userSID, Protected: true, ACEs: []windowsACEInspection{system, user}}
	policy := windowsDACLPolicy{OwnerSID: userSID, ACEs: []windowsACEInspection{user, system}}
	if err := validateWindowsProtectedDACL(valid, policy); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*windowsDACLInspection){
		"wrong owner":   func(value *windowsDACLInspection) { value.OwnerSID = systemSID },
		"default owner": func(value *windowsDACLInspection) { value.OwnerDefaulted = true },
		"default DACL":  func(value *windowsDACLInspection) { value.DACLDefaulted = true },
		"unprotected":   func(value *windowsDACLInspection) { value.Protected = false },
		"inherited":     func(value *windowsDACLInspection) { value.ACEs[0].Flags = windows.INHERITED_ACE },
		"deny entry":    func(value *windowsDACLInspection) { value.ACEs[0].Type = windows.ACCESS_DENIED_ACE_TYPE },
		"wrong mask":    func(value *windowsDACLInspection) { value.ACEs[0].Mask = 1 },
		"extra principal": func(value *windowsDACLInspection) {
			value.ACEs = append(value.ACEs, windowsACEInspection{Type: windows.ACCESS_ALLOWED_ACE_TYPE, Mask: 1, SID: "S-1-1-0"})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			inspection := valid
			inspection.ACEs = append([]windowsACEInspection(nil), valid.ACEs...)
			mutate(&inspection)
			if err := validateWindowsProtectedDACL(inspection, policy); err == nil {
				t.Fatal("unsafe DACL was accepted")
			}
		})
	}
}

func TestWindowsPathStrictlyWithin(t *testing.T) {
	if !windowsPathStrictlyWithin(`C:\Users\alice`, `C:\Users\alice\AppData\Local`) {
		t.Fatal("valid descendant was rejected")
	}
	for _, candidate := range []string{`C:\Users\alice`, `C:\Users\alice2`, `C:\Users\alice\..\bob`, `D:\Users\alice`} {
		if windowsPathStrictlyWithin(`C:\Users\alice`, candidate) {
			t.Fatalf("non-descendant %q was accepted", candidate)
		}
	}
}

func TestValidateWindowsTokenProfileForSensitiveData(t *testing.T) {
	valid := windowsTokenProfileInspection{
		EffectiveSID:      "S-1-5-21-1000",
		ProcessSID:        "S-1-5-21-1000",
		Profile:           `C:\Users\alice`,
		LocalAppData:      `C:\Users\alice\AppData\Local`,
		SameActingUser:    true,
		LocalAppDataBound: true,
	}
	if err := validateWindowsTokenProfileForSensitiveData(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*windowsTokenProfileInspection){
		"different SID":   func(value *windowsTokenProfileInspection) { value.EffectiveSID = "S-1-5-21-2000" },
		"mismatch flag":   func(value *windowsTokenProfileInspection) { value.SameActingUser = false },
		"outside profile": func(value *windowsTokenProfileInspection) { value.LocalAppData = `C:\Users\bob\AppData\Local` },
		"unbound flag":    func(value *windowsTokenProfileInspection) { value.LocalAppDataBound = false },
	} {
		t.Run(name, func(t *testing.T) {
			inspection := valid
			mutate(&inspection)
			if err := validateWindowsTokenProfileForSensitiveData(inspection); err == nil {
				t.Fatal("unbound token/profile state was accepted")
			}
		})
	}
}

func TestInspectWindowsSecurityMetadataByHandle(t *testing.T) {
	directoryName := t.TempDir()
	directory, err := os.Open(directoryName)
	if err != nil {
		t.Fatal(err)
	}
	directoryStreams, err := inspectWindowsStreams(windows.Handle(directory.Fd()))
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("inspect directory streams: %v; close: %v", err, closeErr)
	}
	if err := validateWindowsDataStreams(directoryStreams, false); err != nil {
		t.Fatal(err)
	}

	file, err := os.CreateTemp(directoryName, "gitseal-windows-inspection-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("test"); err != nil {
		t.Fatal(err)
	}
	handle := windows.Handle(file.Fd())
	volume, err := inspectWindowsVolume(handle)
	if err != nil {
		t.Fatal(err)
	}
	if volume.FileSystem == "" || volume.VolumeRoot == "" {
		t.Fatal("volume inspection returned an incomplete result")
	}
	streams, err := inspectWindowsStreams(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsDataStreams(streams, true); err != nil {
		t.Fatal(err)
	}
	dacl, err := inspectWindowsDACL(handle)
	if err != nil {
		t.Fatal(err)
	}
	if dacl.OwnerSID == "" {
		t.Fatal("DACL inspection did not report an owner")
	}
	token, err := inspectWindowsTokenProfile()
	if err != nil {
		t.Fatal(err)
	}
	if token.EffectiveSID == "" || token.ProcessSID == "" || token.Profile == "" || token.LocalAppData == "" {
		t.Fatal("token/profile inspection returned an incomplete result")
	}
}

func TestInspectWindowsStreamsRejectsADS(t *testing.T) {
	name := filepath.Join(t.TempDir(), "gitseal-stream-test")
	if err := os.WriteFile(name, []byte("default"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name+":gitseal-test", []byte("alternate"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	streams, err := inspectWindowsStreams(windows.Handle(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsDataStreams(streams, true); err == nil {
		t.Fatal("alternate data stream was accepted")
	}
}

func encodeWindowsStreamEntry(t *testing.T, name string, next uint32, size, allocation int64) []byte {
	t.Helper()
	return encodeWindowsStreamEntryRaw(utf16.Encode([]rune(name)), next, size, allocation)
}

func encodeWindowsStreamEntryRaw(name []uint16, next uint32, size, allocation int64) []byte {
	entry := make([]byte, windowsStreamInfoHeaderBytes+len(name)*2)
	binary.LittleEndian.PutUint32(entry[0:4], next)
	binary.LittleEndian.PutUint32(entry[4:8], uint32(len(name)*2))
	binary.LittleEndian.PutUint64(entry[8:16], uint64(size))
	binary.LittleEndian.PutUint64(entry[16:24], uint64(allocation))
	for index, value := range name {
		binary.LittleEndian.PutUint16(entry[windowsStreamInfoHeaderBytes+index*2:], value)
	}
	return entry
}

func alignWindowsStreamEntry(length int) int { return (length + 7) &^ 7 }
