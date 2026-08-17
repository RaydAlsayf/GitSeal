//go:build aix || dragonfly || freebsd || netbsd || openbsd || solaris

package identity

import "errors"

func validateIdentityFilesystem(string) error {
	return errors.New("identity filesystem locality validation is unavailable on this platform; refusing private-key storage")
}
