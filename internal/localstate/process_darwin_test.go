//go:build darwin

package localstate

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinProcessIdentityFormatting(t *testing.T) {
	got := darwinProcessIdentity(42, unix.Timeval{Sec: 100, Usec: 7}, unix.Timeval{Sec: 200, Usec: 9})
	if got != "darwin-boot-100.000007-process-42-start-200.000009" {
		t.Fatalf("darwinProcessIdentity = %q", got)
	}
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("Darwin process identity contains an unsafe delimiter: %q", got)
	}
}

func TestDarwinProcessIdentityRejectsInvalidKernelValues(t *testing.T) {
	validBoot := unix.Timeval{Sec: 100}
	validStart := unix.Timeval{Sec: 200}
	for _, test := range []struct {
		pid         int
		boot, start unix.Timeval
	}{
		{pid: 0, boot: validBoot, start: validStart},
		{pid: 1, boot: unix.Timeval{}, start: validStart},
		{pid: 1, boot: validBoot, start: unix.Timeval{}},
		{pid: 1, boot: unix.Timeval{Sec: 100, Usec: -1}, start: validStart},
		{pid: 1, boot: validBoot, start: unix.Timeval{Sec: 200, Usec: 1_000_000}},
	} {
		if got := darwinProcessIdentity(test.pid, test.boot, test.start); got != "unknown" {
			t.Fatalf("invalid Darwin kernel values produced %q", got)
		}
	}
}
