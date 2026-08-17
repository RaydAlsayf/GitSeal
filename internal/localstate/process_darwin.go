//go:build darwin

package localstate

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func platformProcessIdentity() string {
	pid := os.Getpid()
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || process == nil || process.Proc.P_pid != int32(pid) {
		return "unknown"
	}
	boot, err := unix.SysctlTimeval("kern.boottime")
	if err != nil || boot == nil {
		return "unknown"
	}
	return darwinProcessIdentity(pid, *boot, process.Proc.P_starttime)
}

func darwinProcessIdentity(pid int, boot, start unix.Timeval) string {
	if pid <= 0 || boot.Sec <= 0 || start.Sec <= 0 || boot.Usec < 0 || boot.Usec >= 1_000_000 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return "unknown"
	}
	return fmt.Sprintf("darwin-boot-%d.%06d-process-%d-start-%d.%06d", boot.Sec, boot.Usec, pid, start.Sec, start.Usec)
}
