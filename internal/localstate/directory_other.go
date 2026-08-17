//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package localstate

import "errors"

func requireLocalStateMutationSafety() error { return nil }

func prepareLocalDirectory(string) error { return errors.New("unsupported platform") }
