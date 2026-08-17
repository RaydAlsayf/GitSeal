//go:build linux

package localstate

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func platformProcessIdentity() string {
	data, err := readProcessIdentityFile("/proc/self/stat", 64<<10)
	if err != nil {
		return "unknown"
	}
	start, err := linuxStartTicks(data)
	if err != nil {
		return "unknown"
	}
	boot, err := readProcessIdentityFile("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return "unknown"
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" || strings.ContainsAny(bootID, "\r\n\x00") {
		return "unknown"
	}
	return fmt.Sprintf("linux-boot-%s-start-%s", bootID, start)
}

func readProcessIdentityFile(name string, maximum int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := readBoundedReader(file, maximum)
	return data, errors.Join(readErr, file.Close())
}

func linuxStartTicks(data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	// The comm field is parenthesized and may itself contain spaces or ')'.
	// Fields after its final ") " begin with field 3; starttime is field 22,
	// hence index 19 in this tail.
	end := strings.LastIndex(text, ") ")
	if end < 0 {
		return "", errors.New("malformed /proc stat")
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) <= 19 {
		return "", errors.New("truncated /proc stat")
	}
	value := fields[19]
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return "", errors.New("invalid /proc start time")
	}
	return value, nil
}
