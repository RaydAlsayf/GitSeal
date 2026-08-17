//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package identity

import (
	"errors"
	"os"
)

func platformDirectory() (string, error)              { return "", errors.New("unsupported platform") }
func validateIdentityFilesystem(string) error         { return errors.New("unsupported platform") }
func preparePlatformDirectory(string) error           { return errors.New("unsupported platform") }
func validatePrivateFile(*os.File, os.FileInfo) error { return errors.New("unsupported platform") }
