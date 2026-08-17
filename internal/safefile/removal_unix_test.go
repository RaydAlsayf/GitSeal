//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/raydalsayf/gitseal/internal/pathpolicy"
)

func TestRemoveOpenedFailsBeforeMutationWhenIdentityBoundUnlinkIsUnavailable(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, "owned")
	want := []byte("preserve this exact object")
	if err := os.WriteFile(name, want, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	configured, err := pathpolicy.Parse("owned")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := root.OpenSensitiveRead(configured)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	before, err := opened.Stat()
	if err != nil {
		t.Fatal(err)
	}

	err = root.RemoveOpened(configured, opened, SensitiveData)
	if !errors.Is(err, ErrIdentityBoundRemovalUnavailable) {
		t.Fatalf("RemoveOpened error = %v", err)
	}
	got, err := os.ReadFile(name)
	if err != nil || string(got) != string(want) {
		t.Fatalf("named object changed: %q, %v", got, err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatalf("named identity or mode changed: %v, %v", after, err)
	}
}
