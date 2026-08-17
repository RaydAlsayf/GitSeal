//go:build windows

package localstate

import (
	"strings"
	"testing"
)

func TestWindowsProcessIdentityIsStableForCurrentProcess(t *testing.T) {
	first := currentProcessIdentity()
	second := currentProcessIdentity()
	if first == "unknown" || second == "unknown" {
		t.Fatalf("current Windows process identity is unavailable: %q, %q", first, second)
	}
	if first != second {
		t.Fatalf("current Windows process identity changed: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, "windows-session-") || strings.ContainsAny(first, "\r\n\x00") {
		t.Fatalf("invalid Windows process identity: %q", first)
	}
}
