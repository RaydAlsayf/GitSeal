//go:build windows

package localstate

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func currentProcessIdentity() string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		return "unknown"
	}
	var creation, exit, kernel, user windows.Filetime
	timesErr := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user)
	var session uint32
	sessionErr := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session)
	closeErr := windows.CloseHandle(handle)
	if timesErr != nil || sessionErr != nil || closeErr != nil {
		return "unknown"
	}
	return fmt.Sprintf("windows-session-%d-process-start-%08x%08x", session, creation.HighDateTime, creation.LowDateTime)
}
