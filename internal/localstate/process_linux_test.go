//go:build linux

package localstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxStartTicksHandlesParenthesizedCommand(t *testing.T) {
	input := []byte("123 (gitseal ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20")
	got, err := linuxStartTicks(input)
	if err != nil || got != "424242" {
		t.Fatalf("linuxStartTicks = %q, %v", got, err)
	}
}

func TestLinuxStartTicksRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{"", "123 no-parenthesis", "123 (x) S 1"} {
		if _, err := linuxStartTicks([]byte(input)); err == nil {
			t.Fatalf("malformed /proc stat accepted: %q", input)
		}
	}
}

func TestReadProcessIdentityFileIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProcessIdentityFile(path, 4); err == nil {
		t.Fatal("oversized process identity file accepted")
	}
	got, err := readProcessIdentityFile(path, 5)
	if err != nil || string(got) != "12345" {
		t.Fatalf("readProcessIdentityFile = %q, %v", got, err)
	}
}
