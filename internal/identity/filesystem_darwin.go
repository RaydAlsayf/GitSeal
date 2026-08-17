//go:build darwin

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func validateIdentityFilesystem(name string) error {
	existing, err := nearestExistingDirectory(name)
	if err != nil {
		return err
	}
	var information unix.Statfs_t
	if err := unix.Statfs(existing, &information); err != nil {
		return fmt.Errorf("inspect identity filesystem: %w", err)
	}
	if information.Flags&unix.MNT_LOCAL == 0 {
		return errors.New("identity storage is not on a local filesystem; V1 has no persisted location-risk acceptance")
	}
	return nil
}

func nearestExistingDirectory(name string) (string, error) {
	current := filepath.Clean(name)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("identity storage ancestor is linked or not a directory")
			}
			return current, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("identity storage has no existing filesystem ancestor")
		}
		current = parent
	}
}
