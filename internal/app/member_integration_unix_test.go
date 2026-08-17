//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package app

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

func TestMemberAddFingerprintMismatchPerformsNoWrite(t *testing.T) {
	w := newMemberTestWorkspace(t)
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	before, err := w.readControl("recipients.yaml")
	if err != nil {
		t.Fatal(err)
	}
	change, err := w.AddMember(t.Context(), projectconfig.Member{ID: "alice", Name: "Alice", Recipient: identity.CanonicalRecipient()}, "wrong")
	if err == nil || change.Fingerprint != digest.RecipientFingerprint(identity.CanonicalRecipient()).Grouped() {
		t.Fatalf("change=%#v err=%v", change, err)
	}
	after, err := w.readControl("recipients.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("recipient policy changed after a fingerprint mismatch")
	}
}

func TestMemberAddRefusesUnmergedIndexBeforeWrite(t *testing.T) {
	t.Skip("POSIX mutating commands fail before index inspection until exact-identity lock release is available")
	w := newMemberTestWorkspace(t)
	makeUnmergedIndex(t, w.Repo.Worktree())
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	before, err := w.readControl("recipients.yaml")
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.CanonicalRecipient()
	accepted := digest.RecipientFingerprint(recipient).Grouped()
	if _, err := w.AddMember(t.Context(), projectconfig.Member{ID: "alice", Name: "Alice", Recipient: recipient}, accepted); err == nil || !strings.Contains(err.Error(), "unmerged") {
		t.Fatalf("unmerged recipient mutation error = %v", err)
	}
	after, err := w.readControl("recipients.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("recipient policy changed despite an unmerged index")
	}
}

func TestInitRerunPreservesNonemptyManagedProtections(t *testing.T) {
	w := newMemberTestWorkspace(t)
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "secret", Encrypted: "secret.age"}}
	config, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), ".gitseal", "config.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	ignore, err := gitignore.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := gitattrs.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), ".gitignore"), ignore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), ".gitattributes"), attrs, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(t.Context(), w.Repo.Worktree()); !errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) {
		t.Fatalf("init POSIX lifecycle refusal = %v", err)
	}
	finalIgnore, err := w.ReadConfigured(".gitignore", 1<<20)
	if err != nil || gitignore.Validate(finalIgnore, project) != nil {
		t.Fatalf("init rerun weakened managed ignore protection: %v", err)
	}
	finalAttrs, err := w.ReadConfigured(".gitattributes", 1<<20)
	if err != nil || gitattrs.Validate(finalAttrs, project) != nil {
		t.Fatalf("init rerun weakened managed attribute protection: %v", err)
	}
}

func TestProtectExistingCiphertextDestinationPerformsZeroWrites(t *testing.T) {
	t.Skip("POSIX protect fails at the pre-mutation lock lifecycle gate before destination planning")
	w := newMemberTestWorkspace(t)
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), "secret"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("user-owned destination")
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), "secret.age"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeConfig, err := w.readControl("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Protect(t.Context(), "secret", ProtectOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("protect existing destination error = %v", err)
	}
	afterConfig, err := w.readControl("config.yaml")
	if err != nil || !bytes.Equal(beforeConfig, afterConfig) {
		t.Fatal("protect mutated config despite an unfamiliar destination")
	}
	afterForeign, err := os.ReadFile(filepath.Join(w.Repo.Worktree(), "secret.age"))
	if err != nil || !bytes.Equal(afterForeign, foreign) {
		t.Fatal("protect overwrote an unfamiliar destination")
	}
}

func newMemberTestWorkspace(t *testing.T) *Workspace {
	t.Helper()
	clearMemberTestGitEnvironment(t)
	directory := t.TempDir()
	runMemberTestGit(t, directory, nil, "init", "--quiet")
	if err := os.Mkdir(filepath.Join(directory, ".gitseal"), 0o700); err != nil {
		t.Fatal(err)
	}
	project := projectconfig.EmptyProject()
	projectData, _ := project.Marshal()
	recipientsData, _ := projectconfig.EmptyRecipients().Marshal()
	bookData, _ := manifest.Empty().Marshal()
	ignoreData, _ := gitignore.Render(nil, project)
	attrsData, _ := gitattrs.Render(nil, project)
	for name, data := range map[string][]byte{
		".gitseal/config.yaml": projectData, ".gitseal/recipients.yaml": recipientsData,
		".gitseal/manifest.yaml": bookData, ".gitignore": ignoreData, ".gitattributes": attrsData,
	} {
		if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(name)), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w, err := Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func clearMemberTestGitEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		switch {
		case key == "GIT_DIR", key == "GIT_WORK_TREE", key == "GIT_INDEX_FILE",
			key == "GIT_OBJECT_DIRECTORY", key == "GIT_COMMON_DIR", key == "GIT_CONFIG",
			key == "GIT_CONFIG_SYSTEM", key == "GIT_CONFIG_GLOBAL", key == "GIT_CONFIG_NOSYSTEM",
			key == "GIT_CONFIG_COUNT", key == "GIT_ALTERNATE_OBJECT_DIRECTORIES",
			strings.HasPrefix(key, "GIT_CONFIG_KEY_"), strings.HasPrefix(key, "GIT_CONFIG_VALUE_"):
			t.Setenv(key, "")
		}
	}
}

func makeUnmergedIndex(t *testing.T, directory string) {
	t.Helper()
	oids := make([]string, 3)
	for i, content := range []string{"base", "ours", "theirs"} {
		oids[i] = strings.TrimSpace(runMemberTestGit(t, directory, []byte(content), "hash-object", "-w", "--stdin"))
	}
	input := ""
	for i, oid := range oids {
		input += "100644 " + oid + " " + string(rune('1'+i)) + "\tconflict.txt\n"
	}
	runMemberTestGit(t, directory, []byte(input), "update-index", "--index-info")
}

func runMemberTestGit(t *testing.T, directory string, input []byte, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", directory}, args...)
	cmd := exec.Command("git", commandArgs...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
