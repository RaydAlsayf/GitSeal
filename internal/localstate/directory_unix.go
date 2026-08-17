//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/raydalsayf/gitseal/internal/safefile"
)

func requireLocalStateMutationSafety() error {
	return fmt.Errorf("POSIX GitSeal lock and local-state mutation are disabled because exact-identity lock removal cannot be proven: %w", safefile.ErrIdentityBoundRemovalUnavailable)
}

func prepareLocalDirectory(directory string) error {
	parent := filepath.Dir(directory)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("local state parent is not a real directory")
	}
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("local state pathname is not a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := os.Mkdir(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("local state directory is not a non-link directory with mode 0700")
	}
	return nil
}
