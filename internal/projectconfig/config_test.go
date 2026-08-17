package projectconfig

import (
	"bytes"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
)

func recipient(t *testing.T) string {
	t.Helper()
	i, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i.CanonicalRecipient()
}

func TestProjectRoundTripCanonical(t *testing.T) {
	p := Project{
		Version: ProjectVersion,
		ProtectedFiles: []ProtectedFile{
			{Source: "z", Encrypted: "z.age"},
			{Source: "a", Encrypted: "a.age"},
		},
		RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{"old/z", "old/a"}, BinaryArtifacts: []string{"old/z.age", "old/a.age"}},
	}
	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProject(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := parsed.Marshal()
	if !bytes.Equal(data, again) {
		t.Fatalf("noncanonical round trip:\n%s\n%s", data, again)
	}
	if parsed.ProtectedFiles[0].Source != "a" {
		t.Fatal("mappings were not sorted")
	}
}

func TestRecipientsStrict(t *testing.T) {
	r := recipient(t)
	valid := Recipients{Version: RecipientsVersion, Members: []Member{{ID: "alice", Name: "Alice", Recipient: r}}}
	data, err := valid.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, typed, err := ParseRecipients(data); err != nil || typed.Len() != 1 {
		t.Fatalf("ParseRecipients = %d, %v", typed.Len(), err)
	}
	invalid := []Recipients{
		{Version: 2},
		{Version: 1, Members: []Member{{ID: "Bad", Name: "Alice", Recipient: r}}},
		{Version: 1, Members: []Member{{ID: "a", Name: "A\nB", Recipient: r}}},
		{Version: 1, Members: []Member{{ID: "a", Name: "A", Recipient: r}, {ID: "a", Name: "B", Recipient: recipient(t)}}},
		{Version: 1, Members: []Member{{ID: "a", Name: "A", Recipient: r}, {ID: "b", Name: "B", Recipient: r}}},
	}
	for _, value := range invalid {
		if _, err := value.Marshal(); err == nil {
			t.Errorf("invalid recipients accepted: %#v", value)
		}
	}
}

func TestRetainedCollisions(t *testing.T) {
	p := EmptyProject()
	p.ProtectedFiles = []ProtectedFile{{Source: "a", Encrypted: "a.age"}}
	p.RetainedSafety.IgnoredPlaintext = []string{"A"}
	if err := p.Validate(); err == nil {
		t.Fatal("retained case-fold collision accepted")
	}
}

func TestProjectV1IsMigrationOnly(t *testing.T) {
	data := []byte("version: 1\nprotected_files: []\nretained_safety:\n  ignored_plaintext: []\n  binary_artifacts: []\n")
	if _, err := ParseProject(data); err == nil || !bytes.Contains([]byte(err.Error()), []byte("requires explicit retained-safety trust migration")) {
		t.Fatalf("normal v1 parse error = %v", err)
	}
	legacy, err := ParseProjectV1ForMigration(data)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Version != LegacyProjectVersion || legacy.RetainedSafetyDigest() != EmptyProject().RetainedSafetyDigest() {
		t.Fatalf("legacy migration parse = %#v", legacy)
	}
	if _, err := ParseProjectV1ForMigration(mustProjectYAML(t, EmptyProject())); err == nil {
		t.Fatal("current project schema entered the legacy migration parser")
	}
}

func TestProjectRequiresExplicitNonNullSequences(t *testing.T) {
	tests := []string{
		"version: 2\nretained_safety:\n  ignored_plaintext: []\n  binary_artifacts: []\n",
		"version: 2\nprotected_files: null\nretained_safety:\n  ignored_plaintext: []\n  binary_artifacts: []\n",
		"version: 2\nprotected_files: []\n",
		"version: 2\nprotected_files: []\nretained_safety: null\n",
		"version: 2\nprotected_files: []\nretained_safety:\n  binary_artifacts: []\n",
		"version: 2\nprotected_files: []\nretained_safety:\n  ignored_plaintext: null\n  binary_artifacts: []\n",
		"version: 2\nprotected_files: []\nretained_safety:\n  ignored_plaintext: []\n",
		"version: 2\nprotected_files: []\nretained_safety:\n  ignored_plaintext: []\n  binary_artifacts: null\n",
	}
	for _, data := range tests {
		if _, err := ParseProject([]byte(data)); err == nil {
			t.Errorf("project with omitted or null required value was accepted:\n%s", data)
		}
	}
}

func TestRecipientsRequireExplicitMembers(t *testing.T) {
	for _, data := range []string{"version: 1\n", "version: 1\nmembers: null\n"} {
		if _, _, err := ParseRecipients([]byte(data)); err == nil {
			t.Errorf("recipients with missing/null members accepted: %q", data)
		}
	}
}

func mustProjectYAML(t *testing.T, project Project) []byte {
	t.Helper()
	data, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProjectRejectsManagedControlAndAncestorCollisions(t *testing.T) {
	tests := []Project{
		{Version: ProjectVersion, ProtectedFiles: []ProtectedFile{{Source: "secret", Encrypted: ".gitignore"}}, RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{}, BinaryArtifacts: []string{}}},
		{Version: ProjectVersion, ProtectedFiles: []ProtectedFile{{Source: ".gitattributes/secret", Encrypted: "secret.age"}}, RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{}, BinaryArtifacts: []string{}}},
		{Version: ProjectVersion, ProtectedFiles: []ProtectedFile{{Source: "dir", Encrypted: "dir/artifact.age"}}, RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{}, BinaryArtifacts: []string{}}},
		{Version: ProjectVersion, ProtectedFiles: []ProtectedFile{}, RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{".GITIGNORE"}, BinaryArtifacts: []string{}}},
	}
	for _, project := range tests {
		if err := project.Validate(); err == nil {
			t.Errorf("managed-control or ancestor collision accepted: %#v", project)
		}
	}
}

func FuzzParseProject(f *testing.F) {
	f.Add([]byte("version: 2\nprotected_files: []\nretained_safety:\n  ignored_plaintext: []\n  binary_artifacts: []\n"))
	f.Add([]byte("version: &v 1\nprotected_files: *v\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseProject(data)
		_, _ = ParseProjectV1ForMigration(data)
	})
}
