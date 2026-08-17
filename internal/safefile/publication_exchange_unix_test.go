//go:build linux || darwin

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/pathpolicy"
)

func TestUnixExistingDestinationReplacementFailsBeforeMutation(t *testing.T) {
	directory := t.TempDir()
	destinationName := filepath.Join(directory, "destination")
	if err := os.WriteFile(destinationName, []byte("prior bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("destination")
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write([]byte("replacement bytes")); err != nil {
		t.Fatal(err)
	}
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	err = candidate.Publish(t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "replacement is disabled") {
		t.Fatalf("replacement error = %v", err)
	}
	data, err := os.ReadFile(destinationName)
	if err != nil || string(data) != "prior bytes" {
		t.Fatalf("destination changed to %q: %v", data, err)
	}
}

func TestUnixCreateIfAbsentConsumesCandidateName(t *testing.T) {
	directory := t.TempDir()
	root, err := OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("destination")
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(directory, filepath.FromSlash(candidate.temporary))
	if _, err := candidate.Write([]byte("new bytes")); err != nil {
		t.Fatal(err)
	}
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
		t.Fatalf("temporary name remains after atomic rename: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "destination"))
	if err != nil || string(data) != "new bytes" {
		t.Fatalf("published bytes = %q: %v", data, err)
	}
}
