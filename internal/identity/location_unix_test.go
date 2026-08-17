//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreparePlatformDirectoryCreatesPrivateDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "GitSeal", "identities")
	if err := preparePlatformDirectory(directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("identity directory mode = %v", info.Mode())
	}
	parentInfo, err := os.Lstat(filepath.Dir(directory))
	if err != nil {
		t.Fatal(err)
	}
	if parentInfo.Mode().Perm() != 0o700 {
		t.Fatalf("application directory mode = %v", parentInfo.Mode())
	}
}

func TestPreparePlatformDirectoryRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	link := filepath.Join(parent, "identities")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := preparePlatformDirectory(link); err == nil {
		t.Fatal("symlink identity directory accepted")
	}
}

func TestPreparePlatformDirectoryRejectsSymlinkAncestor(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked-config")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := preparePlatformDirectory(filepath.Join(link, "GitSeal", "identities")); err == nil {
		t.Fatal("symlinked identity ancestor accepted")
	}
}

func TestValidatePrivateFileRejectsHardLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".link"); err != nil {
		t.Skipf("hard-link creation unavailable: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateFile(file, info); err == nil {
		t.Fatal("hard-linked identity accepted")
	}
}

func TestDirectoryRejectsConfigurationInsideRepository(t *testing.T) {
	repository := t.TempDir()
	if err := os.Mkdir(filepath.Join(repository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(repository, "configuration"))
	if _, err := Directory(); err == nil {
		t.Fatal("identity configuration inside a repository was accepted")
	}
}

func TestDirectoryRejectsKnownCloudConfiguration(t *testing.T) {
	provider := filepath.Join(t.TempDir(), "OneDrive")
	t.Setenv("OneDrive", provider)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(provider, "configuration"))
	if _, err := Directory(); err == nil {
		t.Fatal("known cloud-synchronized identity configuration was accepted")
	}
}
