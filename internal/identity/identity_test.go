package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepositoryStorageAncestorRejectsWorktreeAndAdminDirectory(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := repositoryStorageAncestor(filepath.Join(repo, "identity", "nested")); got == "" {
		t.Fatal("identity storage inside a worktree was not detected")
	}
	if got := repositoryStorageAncestor(filepath.Join(repo, ".git", "gitseal-identities")); got == "" {
		t.Fatal("identity storage inside a Git administrative directory was not detected")
	}
	outside := t.TempDir()
	if got := repositoryStorageAncestor(filepath.Join(outside, "identity")); got != "" {
		t.Fatalf("ordinary identity storage misclassified under %q", got)
	}
}

func TestPathNameValidation(t *testing.T) {
	for _, name := range []string{"", "Bad", "../x", "a.txt", strings.Repeat("a", 33)} {
		if _, err := Path(name); err == nil {
			t.Errorf("invalid name accepted: %q", name)
		}
	}
	if value, err := Path("alice"); err != nil || filepath.Base(value) != "alice.txt" {
		t.Fatalf("Path = %q, %v", value, err)
	}
}

func TestKnownCloudStorageAncestorUsesConfiguredProviderRoot(t *testing.T) {
	provider := filepath.Join(t.TempDir(), "provider")
	t.Setenv("OneDrive", provider)
	inside := filepath.Join(provider, "GitSeal", "identities")
	if got := knownCloudStorageAncestor(inside); filepath.Clean(got) != filepath.Clean(provider) {
		t.Fatalf("known cloud ancestor = %q, want %q", got, provider)
	}
}

func TestWindowsIdentityCreateFailsClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only fail-closed boundary")
	}
	if _, err := Create(t.Context(), "gitseal_test_identity"); err == nil {
		t.Fatal("Windows identity creation unexpectedly succeeded without the DACL boundary")
	}
}
