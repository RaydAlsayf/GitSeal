package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

func TestWriteControlRejectsStaleInputSnapshot(t *testing.T) {
	directory := t.TempDir()
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.EnsureControlDirectory(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, ".gitseal", "manifest.yaml")
	original := []byte("version: 1\nartifacts: []\n")
	concurrent := []byte("version: 1\nartifacts:\n  # concurrent editor change\n  []\n")
	if err := os.WriteFile(name, original, 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Workspace{Root: root, controlSum: map[string]digest.Sum{"manifest.yaml": digest.Bytes(original)}}
	if err := os.WriteFile(name, concurrent, 0o600); err != nil {
		t.Fatal(err)
	}
	err = w.WriteControl(t.Context(), "manifest.yaml", original)
	if err == nil || !strings.Contains(err.Error(), "operation plan") {
		t.Fatalf("stale control publication error = %v", err)
	}
	after, readErr := os.ReadFile(name)
	if readErr != nil || !bytes.Equal(after, concurrent) {
		t.Fatalf("concurrent control edit was overwritten: %q, %v", after, readErr)
	}
}

func TestWriteConfiguredRejectsStaleInputSnapshot(t *testing.T) {
	directory := t.TempDir()
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	name := filepath.Join(directory, ".gitignore")
	original := []byte("# original\n")
	concurrent := []byte("# concurrent editor change\n")
	if err := os.WriteFile(name, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, concurrent, 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Workspace{Root: root}
	err = w.WriteConfigured(t.Context(), ".gitignore", []byte("# replacement\n"), original, true, safefile.PublicData)
	if err == nil || !strings.Contains(err.Error(), "operation plan") {
		t.Fatalf("stale configured publication error = %v", err)
	}
	after, readErr := os.ReadFile(name)
	if readErr != nil || !bytes.Equal(after, concurrent) {
		t.Fatalf("concurrent configured edit was overwritten: %q, %v", after, readErr)
	}
}

func TestWriteConfiguredCanReplaceExistingEmptyFile(t *testing.T) {
	directory := t.TempDir()
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	name := filepath.Join(directory, ".gitignore")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Workspace{Root: root}
	want := []byte("# BEGIN GITSEAL\n.gitseal.tmp.*\n# END GITSEAL\n")
	err = w.WriteConfigured(t.Context(), ".gitignore", want, nil, true, safefile.PublicData)
	if err != nil {
		// Linux and macOS intentionally refuse existing-destination
		// replacement until a reviewed primitive can bind the exact expected
		// destination identity without a destructive pathname-cleanup race.
		// A safe refusal must preserve the original file byte-for-byte.
		after, readErr := os.ReadFile(name)
		if readErr != nil || len(after) != 0 {
			t.Fatalf("failed replacement changed the original file: %q, %v (publication error: %v)", after, readErr, err)
		}
		if !strings.Contains(err.Error(), "replacement is disabled") && !errors.Is(err, safefile.ErrSafePublicationUnavailable) {
			t.Fatalf("unexpected replacement refusal: %v", err)
		}
		return
	}
	after, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(after, want) {
		t.Fatalf("empty-file replacement = %q, %v", after, err)
	}
}
