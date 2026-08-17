package treeverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestVerifyExactTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.invalid")
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := agefile.NewHybridRecipients([]string{identity.CanonicalRecipient()})
	plan, _ := agefile.NewEncryptionPlan(recipients, identity)
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, strings.NewReader("test secret")); err != nil {
		t.Fatal(err)
	}
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = []projectconfig.ProtectedFile{{Source: ".env", Encrypted: ".env.age"}}
	recipientConfig := projectconfig.Recipients{Version: 1, Members: []projectconfig.Member{{ID: "alice", Name: "Alice", Recipient: identity.CanonicalRecipient()}}}
	h := sha256.Sum256(ciphertext.Bytes())
	book := manifest.Manifest{Version: 1, Artifacts: []manifest.Artifact{{Source: ".env", Encrypted: ".env.age", CiphertextSHA256: hex.EncodeToString(h[:]), RecipientSetSHA256: recipients.Digest().Hex()}}}
	configBytes, _ := project.Marshal()
	recipientBytes, _ := recipientConfig.Marshal()
	manifestBytes, _ := book.Marshal()
	ignoreBytes, _ := gitignore.Render(nil, project)
	attrsBytes, _ := gitattrs.Render(nil, project)
	write := func(name string, data []byte) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(configPath, configBytes)
	write(recipientsPath, recipientBytes)
	write(manifestPath, manifestBytes)
	write(ignorePath, ignoreBytes)
	write(attrsPath, attrsBytes)
	write(".env.age", ciphertext.Bytes())
	runGit(t, dir, "add", "-f", ".")
	runGit(t, dir, "commit", "-qm", "valid")
	clearGitEnvironment(t)
	repo, err := gitrepo.Discover(context.Background(), dir, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), repo, "HEAD", true)
	if err != nil || !report.OK() {
		t.Fatalf("valid report: %#v, %v", report, err)
	}
	write(".env", []byte("tracked plaintext"))
	runGit(t, dir, "add", "-f", ".env")
	runGit(t, dir, "commit", "-qm", "unsafe")
	report, err = Verify(context.Background(), repo, "HEAD", true)
	if err != nil || report.OK() || !hasCode(report, "tracked_plaintext") {
		t.Fatalf("unsafe report: %#v, %v", report, err)
	}
}

func TestVerifyNonProjectStillRejectsPrivateIdentityAndControlCasefold(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.invalid")
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := identity.WritePrivate(&private); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"leaked-one.txt", "leaked-two.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), private.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	casefoldDir := filepath.Join(dir, ".GitSeal")
	if err := os.MkdirAll(casefoldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(casefoldDir, "marker"), []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "-f", ".")
	runGit(t, dir, "commit", "-qm", "non-project invariants")
	clearGitEnvironment(t)
	repo, err := gitrepo.Discover(context.Background(), dir, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), repo, "HEAD", false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Project || report.OK() || !hasCode(report, "private_identity") || !hasCode(report, "control_casefold_collision") {
		t.Fatalf("non-project invariants were not enforced: %#v", report)
	}
	privateFindings := 0
	for _, finding := range report.Findings {
		if finding.Code == "private_identity" {
			privateFindings++
		}
	}
	if privateFindings != 2 {
		t.Fatalf("same private blob should be reported for both paths; findings=%#v", report.Findings)
	}
}

func TestVerifyRetainedArtifactRequiresNonEmptyRecipientSet(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.invalid")
	project := projectconfig.EmptyProject()
	project.RetainedSafety.BinaryArtifacts = []string{"old-secret.age"}
	recipients := projectconfig.EmptyRecipients()
	book := manifest.Empty()
	configBytes, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	recipientBytes, err := recipients.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := book.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ignoreBytes, err := gitignore.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	attrsBytes, err := gitattrs.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(configPath, configBytes)
	write(recipientsPath, recipientBytes)
	write(manifestPath, manifestBytes)
	write(ignorePath, ignoreBytes)
	write(attrsPath, attrsBytes)
	write("old-secret.age", []byte("structurally irrelevant because trust fails first"))
	runGit(t, dir, "add", "-f", ".")
	runGit(t, dir, "commit", "-qm", "retained artifact without recipients")
	clearGitEnvironment(t)
	repo, err := gitrepo.Discover(context.Background(), dir, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), repo, "HEAD", true)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() || !hasCode(report, "empty_recipient_set") {
		t.Fatalf("retained artifact without recipients was not rejected: %#v", report)
	}
}

func TestVerifyRetainedArtifactAllowsHistoricalRecipientCount(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.invalid")
	current, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	historical, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	historicalRecipients, err := agefile.NewHybridRecipients([]string{current.CanonicalRecipient(), historical.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := agefile.NewEncryptionPlan(historicalRecipients, current)
	if err != nil {
		t.Fatal(err)
	}
	var retained bytes.Buffer
	if err := plan.Encrypt(&retained, strings.NewReader("historical retained artifact")); err != nil {
		t.Fatal(err)
	}

	project := projectconfig.EmptyProject()
	project.RetainedSafety.BinaryArtifacts = []string{"old-secret.age"}
	currentRecipients := projectconfig.Recipients{Version: 1, Members: []projectconfig.Member{{ID: "current", Name: "Current", Recipient: current.CanonicalRecipient()}}}
	configBytes, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	recipientBytes, err := currentRecipients.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := manifest.Empty().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ignoreBytes, err := gitignore.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	attrsBytes, err := gitattrs.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		configPath:       configBytes,
		recipientsPath:   recipientBytes,
		manifestPath:     manifestBytes,
		ignorePath:       ignoreBytes,
		attrsPath:        attrsBytes,
		"old-secret.age": retained.Bytes(),
	} {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, dir, "add", "-f", ".")
	runGit(t, dir, "commit", "-qm", "historical retained recipient count")
	clearGitEnvironment(t)
	repo, err := gitrepo.Discover(context.Background(), dir, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), repo, "HEAD", true)
	if err != nil || !report.OK() {
		t.Fatalf("historical retained artifact was rejected: %#v, %v", report, err)
	}
}

func TestVerifyEntryWorkBudgetFailsClosed(t *testing.T) {
	entries := make([]gitrepo.TreeEntry, maxTreeEntries+1)
	report, err := verifyEntries(context.Background(), nil, Report{SchemaVersion: SchemaVersion}, entries, false, nil)
	if err != nil || report.OK() || !hasCode(report, "tree_work_budget") {
		t.Fatalf("entry work budget result = %#v, %v", report, err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func clearGitEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if upper == "GIT_DIR" || upper == "GIT_WORK_TREE" || upper == "GIT_COMMON_DIR" || upper == "GIT_INDEX_FILE" || upper == "GIT_OBJECT_DIRECTORY" || upper == "GIT_ALTERNATE_OBJECT_DIRECTORIES" || upper == "GIT_CONFIG" || upper == "GIT_CONFIG_GLOBAL" || upper == "GIT_CONFIG_SYSTEM" || upper == "GIT_CONFIG_NOSYSTEM" || upper == "GIT_CONFIG_PARAMETERS" || upper == "GIT_CONFIG_COUNT" || upper == "GIT_IMPLICIT_WORK_TREE" || upper == "GIT_GRAFT_FILE" || upper == "GIT_NO_REPLACE_OBJECTS" || upper == "GIT_REPLACE_REF_BASE" || upper == "GIT_PREFIX" || upper == "GIT_SHALLOW_FILE" || upper == "GIT_NAMESPACE" || upper == "GIT_REFERENCE_BACKEND" || upper == "GIT_DEFAULT_HASH" || upper == "GIT_DEFAULT_REF_FORMAT" || upper == "GIT_INDEX_VERSION" || upper == "GIT_LITERAL_PATHSPECS" || upper == "GIT_GLOB_PATHSPECS" || upper == "GIT_NOGLOB_PATHSPECS" || upper == "GIT_ICASE_PATHSPECS" || upper == "GIT_ATTR_SOURCE" || upper == "GIT_ATTR_NOSYSTEM" || upper == "GIT_ATTR_GLOBAL" || upper == "GIT_ATTR_SYSTEM" || upper == "GIT_QUARANTINE_PATH" || upper == "GIT_EXEC_PATH" || upper == "GIT_CEILING_DIRECTORIES" || upper == "GIT_DISCOVERY_ACROSS_FILESYSTEM" || strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			value, present := os.LookupEnv(key)
			_ = os.Unsetenv(key)
			t.Cleanup(func() {
				if present {
					_ = os.Setenv(key, value)
				}
			})
		}
	}
}

func hasCode(report Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
