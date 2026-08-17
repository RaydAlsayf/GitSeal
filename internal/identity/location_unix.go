//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func platformDirectory() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" || !filepath.IsAbs(base) {
		return "", errors.New("resolve OS user configuration directory")
	}
	return filepath.Join(base, "GitSeal", "identities"), nil
}

func preparePlatformDirectory(directory string) error {
	if directory == "" || !filepath.IsAbs(directory) {
		return errors.New("identity directory must be absolute")
	}
	applicationDirectory := filepath.Dir(directory)
	configurationDirectory := filepath.Dir(applicationDirectory)
	if err := ensureRealDirectoryTree(configurationDirectory); err != nil {
		return err
	}
	for _, privateDirectory := range []string{applicationDirectory, directory} {
		if err := ensurePrivateDirectory(privateDirectory); err != nil {
			return err
		}
	}
	return nil
}

// ensureRealDirectoryTree walks each component without following a final
// symlink and creates missing user-configuration components one at a time. The
// walk deliberately refuses a symlinked ancestor rather than relying on
// MkdirAll's pathname traversal for private-key storage.
func ensureRealDirectoryTree(directory string) error {
	clean := filepath.Clean(directory)
	volume := filepath.VolumeName(clean)
	remainder := strings.TrimPrefix(clean[len(volume):], string(filepath.Separator))
	current := volume + string(filepath.Separator)
	if current == "" {
		return errors.New("identity configuration path has no filesystem root")
	}
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("identity configuration path contains a non-directory or symbolic link")
		}
	}
	return nil
}

func ensurePrivateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("identity directory pathname is not a real directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("identity directory is not a non-link directory with mode 0700")
	}
	return nil
}

func validatePrivateFile(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("identity file permissions are not exactly 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("identity file has multiple hard links")
	}
	return nil
}
