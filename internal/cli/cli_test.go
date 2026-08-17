package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/app"
	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

func TestVersionJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), []string{"version", "--json"})
	if code != exitcode.Success || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var value map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value["schema_version"] != float64(1) || value["version"] != Version || value["schema_range"] != SchemaRange || value["json_schema_range"] != "1" {
		t.Fatalf("unexpected version output: %#v", value)
	}
}

func TestCryptoResultJSONUsesStableLowercaseFields(t *testing.T) {
	data, err := json.Marshal(struct {
		SchemaVersion int                `json:"schema_version"`
		Completed     []app.CryptoResult `json:"completed"`
	}{
		SchemaVersion: 1,
		Completed: []app.CryptoResult{{
			Source:             "secrets/example.txt",
			Encrypted:          "secrets/example.txt.age",
			PlaintextSHA256:    strings.Repeat("a", 64),
			CiphertextSHA256:   strings.Repeat("b", 64),
			RecipientSetSHA256: strings.Repeat("c", 64),
			StateSaved:         true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	completed, ok := document["completed"].([]any)
	if !ok || len(completed) != 1 {
		t.Fatalf("completed = %#v", document["completed"])
	}
	entry, ok := completed[0].(map[string]any)
	if !ok {
		t.Fatalf("entry = %#v", completed[0])
	}
	for _, name := range []string{"source", "encrypted", "ciphertext_sha256", "recipient_set_sha256", "state_saved"} {
		if _, ok := entry[name]; !ok {
			t.Errorf("missing JSON field %q in %s", name, data)
		}
	}
	for _, forbidden := range []string{"plaintext_sha256", "Source", "Encrypted", "PlaintextSHA256", "CiphertextSHA256", "RecipientSetSHA256", "StateSaved"} {
		if _, ok := entry[forbidden]; ok {
			t.Errorf("unexpected JSON field %q in %s", forbidden, data)
		}
	}
}

func TestCryptoHumanOutputDoesNotDisclosePlaintextDigest(t *testing.T) {
	plaintextDigest := strings.Repeat("a", 64)
	var output bytes.Buffer
	printCrypto(&output, app.CryptoResult{
		Source:             "secret.txt",
		Encrypted:          "secret.txt.age",
		PlaintextSHA256:    plaintextDigest,
		CiphertextSHA256:   strings.Repeat("b", 64),
		RecipientSetSHA256: strings.Repeat("c", 64),
		StateSaved:         true,
	})
	if strings.Contains(output.String(), plaintextDigest) || strings.Contains(output.String(), "plaintext_sha256") {
		t.Fatalf("plaintext digest escaped into human output: %q", output.String())
	}
}

func TestMemberListJSONShapeAndFullRecipientBoundary(t *testing.T) {
	list := app.MemberList{
		SchemaVersion:           1,
		Members:                 []app.MemberInfo{{ID: "alice", Name: "Alice", Recipient: "public-recipient", Fingerprint: "fingerprint"}},
		RecipientSetFingerprint: "set-fingerprint",
	}
	for _, test := range []struct {
		name          string
		full          bool
		wantRecipient bool
	}{{"default", false, false}, {"full", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := writeJSON(&output, memberListForJSON(list, test.full)); err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(output.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
			if value["schema_version"] != float64(1) || value["recipient_set_fingerprint"] != "set-fingerprint" {
				t.Fatalf("unexpected member-list envelope: %#v", value)
			}
			members := value["members"].([]any)
			member := members[0].(map[string]any)
			_, hasRecipient := member["recipient"]
			if hasRecipient != test.wantRecipient {
				t.Fatalf("recipient present=%t, want %t: %#v", hasRecipient, test.wantRecipient, member)
			}
		})
	}
}

func TestDestructiveOverrideFlagsRequireOneExactFile(t *testing.T) {
	digest := strings.Repeat("0", 64)
	tests := []struct {
		name string
		args []string
	}{
		{"encrypt force without file", []string{"encrypt", "--force"}},
		{"encrypt force all", []string{"encrypt", "--all", "--force"}},
		{"decrypt force without file", []string{"decrypt", "--force"}},
		{"decrypt force all", []string{"decrypt", "--all", "--force"}},
		{"decrypt accept without file", []string{"decrypt", "--accept-incoming", digest}},
		{"decrypt accept all", []string{"decrypt", "--all", "--accept-incoming", digest}},
		{"decrypt recovery without file", []string{"decrypt", "--recover-without-manifest"}},
		{"decrypt recovery all", []string{"decrypt", "--all", "--recover-without-manifest"}},
		{"sync accept without file", []string{"sync", "--accept-incoming", digest}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), test.args)
			if code != exitcode.InvalidConfig {
				t.Fatalf("code=%d, want %d; stdout=%q stderr=%q", code, exitcode.InvalidConfig, stdout.String(), stderr.String())
			}
		})
	}
}

func TestIncomingDigestFlagsAreStrict(t *testing.T) {
	for _, args := range [][]string{
		{"decrypt", "--accept-incoming", strings.Repeat("A", 64), "secret"},
		{"sync", "--accept-incoming", "abcd", "secret"},
	} {
		var stdout, stderr bytes.Buffer
		code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), args)
		if code != exitcode.InvalidConfig {
			t.Fatalf("args=%v code=%d, want %d; stdout=%q stderr=%q", args, code, exitcode.InvalidConfig, stdout.String(), stderr.String())
		}
	}
}

func TestHookJSONHasVersionedEnvelopeOnFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), []string{"hook", "run", "--json", "not-a-hook"})
	if code != exitcode.InvalidConfig {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var value map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value["schema_version"] != float64(1) || value["hook"] != "not-a-hook" {
		t.Fatalf("unexpected hook JSON: %#v", value)
	}
}

func TestUnsupportedSchemaFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), []string{"status", "--schema-version", "2"})
	if code != exitcode.InvalidConfig {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestDiagnosticEscapesTerminalControls(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: t.TempDir()}).Run(context.Background(), []string{"bad\x1b[31m\ncommand"})
	if code == exitcode.Success {
		t.Fatal("hostile command unexpectedly succeeded")
	}
	if strings.ContainsRune(stderr.String(), '\x1b') || strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("diagnostic was not terminal-safe: %q", stderr.String())
	}
}

func TestTrustReviewDisplaysExactDigestsAndPaths(t *testing.T) {
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "secret", Encrypted: "secret.age"}}
	project.RetainedSafety.IgnoredPlaintext = []string{"old-secret"}
	var mappingOutput bytes.Buffer
	printMappingReview(&mappingOutput, project)
	projectSnapshot, err := app.ProjectSnapshotDigest(project)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mappingOutput.String(), project.MappingDigest().Hex()) || !strings.Contains(mappingOutput.String(), project.RetainedSafetyDigest().Hex()) || !strings.Contains(mappingOutput.String(), projectSnapshot.Hex()) || !strings.Contains(mappingOutput.String(), `"secret" -> "secret.age"`) || !strings.Contains(mappingOutput.String(), `RETAINED-PLAINTEXT-SAFETY "old-secret"`) {
		t.Fatalf("mapping review output = %q", mappingOutput.String())
	}
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := projectconfig.Recipients{Version: 1, Members: []projectconfig.Member{{ID: "alice", Name: "Alice", Recipient: identity.CanonicalRecipient()}}}
	var recipientOutput bytes.Buffer
	printRecipientReview(&recipientOutput, recipients)
	if !strings.Contains(recipientOutput.String(), recipients.MembershipDigest().Hex()) || !strings.Contains(recipientOutput.String(), `"alice" name="Alice" fingerprint=`) {
		t.Fatalf("recipient review output = %q", recipientOutput.String())
	}
}

func TestInitTrustUpgradePreviewsExactRetainedDigestWithoutMutation(t *testing.T) {
	clearCLIGitEnvironment(t)
	directory := t.TempDir()
	command := exec.Command("git", "-C", directory, "init", "--quiet")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	legacy := projectconfig.EmptyProject()
	legacy.Version = projectconfig.LegacyProjectVersion
	legacy.RetainedSafety.IgnoredPlaintext = []string{"old-secret"}
	legacy.RetainedSafety.BinaryArtifacts = []string{"old-secret.age"}
	data, err := strictyaml.Encode(legacy.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, ".gitseal", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr, Cwd: directory}).Run(t.Context(), []string{"init", "--upgrade-project-trust"})
	if code != exitcode.TrustRequired || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{legacy.RetainedSafetyDigest().Hex(), `RETAINED-PLAINTEXT-SAFETY "old-secret"`, `RETAINED-ARTIFACT-SAFETY "old-secret.age"`, "nothing was changed"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("migration preview omitted %q: %q", expected, stderr.String())
		}
	}
	after, err := os.ReadFile(name)
	if err != nil || string(after) != string(data) {
		t.Fatalf("preview changed legacy config: %q, %v", after, err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".git", "gitseal")); !os.IsNotExist(err) {
		t.Fatalf("preview created local state: %v", err)
	}
}

func clearCLIGitEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok || !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			continue
		}
		value, present := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(key, value)
			}
		})
	}
}
