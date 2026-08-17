package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

func TestStateStrictRoundTrip(t *testing.T) {
	p := digest.Bytes([]byte("plain")).Hex()
	c := digest.Bytes([]byte("cipher")).Hex()
	s := Empty()
	s.TrustedRetainedSafetySHA256 = digest.Bytes([]byte("retained safety")).Hex()
	s.Files[".env"] = FileBaseline{PlaintextSHA256: p, CiphertextSHA256: c}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil || parsed.Files[".env"].PlaintextSHA256 != p {
		t.Fatalf("Parse = %#v, %v", parsed, err)
	}
}

func TestStateV1IsMigrationOnlyAndPreservesExistingTrust(t *testing.T) {
	plain := digest.Bytes([]byte("plain")).Hex()
	cipher := digest.Bytes([]byte("cipher")).Hex()
	recipients := digest.Bytes([]byte("recipients")).Hex()
	membership := digest.Bytes([]byte("membership")).Hex()
	mappings := digest.Bytes([]byte("mappings")).Hex()
	data := []byte("version: 1\n" +
		"trusted_recipients_sha256: " + recipients + "\n" +
		"trusted_membership_policy_sha256: " + membership + "\n" +
		"trusted_mappings_sha256: " + mappings + "\n" +
		"files:\n  secret:\n    plaintext_sha256: " + plain + "\n    ciphertext_sha256: " + cipher + "\n")
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "requires explicit retained-safety trust migration") {
		t.Fatalf("normal v1 parse error = %v", err)
	}
	legacy, err := ParseStateV1ForMigration(data)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Version != LegacyStateVersion || legacy.TrustedRecipientsSHA256 != recipients ||
		legacy.TrustedMembershipPolicySHA256 != membership || legacy.TrustedMappingsSHA256 != mappings ||
		legacy.TrustedRetainedSafetySHA256 != "" || legacy.Files["secret"].PlaintextSHA256 != plain {
		t.Fatalf("legacy state was not preserved exactly: %#v", legacy)
	}
	legacy.Version = StateVersion
	legacy.TrustedRetainedSafetySHA256 = digest.Bytes([]byte("reviewed retained safety")).Hex()
	if _, err := legacy.Marshal(); err != nil {
		t.Fatalf("explicitly upgraded state did not marshal: %v", err)
	}
}

func TestStateSchemasRequireExplicitFilesAndRejectAmbiguity(t *testing.T) {
	for _, data := range []string{
		"version: 2\n",
		"version: 2\nfiles: null\n",
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("current state with missing/null files accepted: %q", data)
		}
	}
	for _, data := range []string{
		"version: 1\n",
		"version: 1\nfiles: null\n",
		"version: 1\ntrusted_retained_safety_sha256: " + digest.Bytes([]byte("unexpected")).Hex() + "\nfiles: {}\n",
	} {
		if _, err := ParseStateV1ForMigration([]byte(data)); err == nil {
			t.Errorf("ambiguous legacy state accepted: %q", data)
		}
	}
}

func TestTrustMatchesIncludesRetainedSafety(t *testing.T) {
	recipients := digest.Bytes([]byte("recipients"))
	membership := digest.Bytes([]byte("membership"))
	mappings := digest.Bytes([]byte("mappings"))
	retained := digest.Bytes([]byte("retained"))
	state := Empty()
	state.TrustedRecipientsSHA256 = recipients.Hex()
	state.TrustedMembershipPolicySHA256 = membership.Hex()
	state.TrustedMappingsSHA256 = mappings.Hex()
	state.TrustedRetainedSafetySHA256 = retained.Hex()
	if ok, changes := TrustMatches(state, recipients, membership, mappings, retained); !ok || len(changes) != 0 {
		t.Fatalf("matching trust = %v, %v", ok, changes)
	}
	changed := digest.Bytes([]byte("changed retained"))
	if ok, changes := TrustMatches(state, recipients, membership, mappings, changed); ok || len(changes) != 1 || changes[0] != "retained safety" {
		t.Fatalf("retained change = %v, %v", ok, changes)
	}
}

func TestLockExclusiveAndOwnerRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir, "test")
	if errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, dir)
		return
	}
	if runtime.GOOS == "windows" {
		if err == nil {
			_ = first.Release()
			t.Fatal("Windows lock acquisition unexpectedly crossed the unavailable sensitive-publication boundary")
		}
		if !strings.Contains(err.Error(), "Windows protected local-state directory DACL boundary") {
			t.Fatalf("Windows lock refusal = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir, "other"); err == nil {
		t.Fatal("second lock acquisition succeeded")
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(dir, "again")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateSaveLoadAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gitseal")
	state := Empty()
	digestValue := digest.Bytes([]byte("value")).Hex()
	state.Files["secret.txt"] = FileBaseline{PlaintextSHA256: digestValue, CiphertextSHA256: digestValue}
	err := Save(t.Context(), dir, &state)
	if errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, dir)
		return
	}
	if runtime.GOOS == "windows" {
		if err == nil || !strings.Contains(err.Error(), "Windows protected local-state directory DACL boundary") {
			t.Fatalf("Windows Save refusal = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded.Files["secret.txt"] != state.Files["secret.txt"] {
		t.Fatalf("Load = %#v, %v", loaded, err)
	}
	directoryInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %v", directoryInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(filepath.Join(dir, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v", fileInfo.Mode().Perm())
	}
}

func TestLockReleaseRefusesPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lock acquisition deliberately fails closed before publication")
	}
	dir := filepath.Join(t.TempDir(), "gitseal")
	lock, err := Acquire(dir, "test")
	if errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, dir)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lock.yaml")
	displaced := filepath.Join(dir, "held-lock.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err == nil {
		t.Fatal("release removed a replacement pathname")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
		t.Fatalf("replacement lock was not preserved: %q, %v", got, err)
	}
	if got, err := os.ReadFile(displaced); err != nil || string(got) != string(data) {
		t.Fatalf("displaced owned lock was not preserved: %q, %v", got, err)
	}
	if err := lock.Release(); err == nil {
		t.Fatal("release retry unexpectedly reused closed ownership handles")
	}
}

func TestLockReleaseRefusesTokenSubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lock acquisition deliberately fails closed before publication")
	}
	dir := filepath.Join(t.TempDir(), "gitseal")
	lock, err := Acquire(dir, "test")
	if errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, dir)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lock.yaml")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record lockRecord
	if err := strictyaml.Decode(original, &record); err != nil {
		t.Fatal(err)
	}
	if record.Token[0] == '0' {
		record.Token = "1" + record.Token[1:]
	} else {
		record.Token = "0" + record.Token[1:]
	}
	substituted, err := strictyaml.Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := writeFull(file, substituted)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "ownership changed") {
		t.Fatalf("token-substituted release = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(substituted) {
		t.Fatalf("token-substituted lock was not preserved: %q, %v", got, err)
	}
	if err := lock.Release(); err == nil {
		t.Fatal("release retry unexpectedly reused closed ownership handles")
	}
}

func TestReadBoundedReaderRejectsOversize(t *testing.T) {
	if _, err := readBoundedReader(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized lock record accepted")
	}
}

func TestLockReleasePreservesMalformedSameIdentityRecord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lock acquisition deliberately fails closed before publication")
	}
	dir := filepath.Join(t.TempDir(), "gitseal")
	lock, err := Acquire(dir, "test")
	if errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, dir)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lock.yaml")
	malformed := []byte("version: [\n")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := writeFull(file, malformed)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "invalid lock record") {
		t.Fatalf("malformed-record release = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(malformed) {
		t.Fatalf("malformed lock was not preserved: %q, %v", got, err)
	}
	if err := lock.Release(); err == nil {
		t.Fatal("release retry unexpectedly reused closed ownership handles")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestReadBoundedRejectsFinalSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows sensitive reads deliberately fail closed at the DACL boundary")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	link := filepath.Join(dir, "state.yaml")
	if err := os.WriteFile(target, []byte("version: 1\nfiles: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("local state final-path symlink accepted")
	}
}

func TestStateSaveRejectsStaleLoadedRevision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows local state deliberately fails closed before sensitive publication")
	}
	directory := filepath.Join(t.TempDir(), "gitseal")
	initial := Empty()
	if err := Save(t.Context(), directory, &initial); errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		assertNoLocalStateMutation(t, directory)
		return
	} else if err != nil {
		t.Fatal(err)
	}
	first, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	value := digest.Bytes([]byte("first update")).Hex()
	first.Files["first"] = FileBaseline{PlaintextSHA256: value, CiphertextSHA256: value}
	if err := Save(t.Context(), directory, &first); err != nil {
		t.Fatal(err)
	}
	other := digest.Bytes([]byte("stale update")).Hex()
	stale.Files["stale"] = FileBaseline{PlaintextSHA256: other, CiphertextSHA256: other}
	if err := Save(t.Context(), directory, &stale); err == nil {
		t.Fatal("stale local-state revision overwrote a newer update")
	}
	loaded, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Files["first"]; !ok {
		t.Fatal("newer local-state update was not preserved")
	}
	if _, ok := loaded.Files["stale"]; ok {
		t.Fatal("stale local-state update became visible")
	}
}

func assertNoLocalStateMutation(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("inspect refused local-state directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("fail-closed local-state operation created entries: %v", entries)
	}
}
