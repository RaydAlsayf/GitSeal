//go:build darwin

package safefile

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func openRelativeNoFollow(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func publishRelativeNoReplace(parent *os.File, temporary, destination string) error {
	err := unix.RenameatxNp(int(parent.Fd()), temporary, int(parent.Fd()), destination, unix.RENAME_EXCL)
	runtime.KeepAlive(parent)
	return err
}
