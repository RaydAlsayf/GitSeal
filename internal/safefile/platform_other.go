//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package safefile

import (
	"context"
	"errors"
	"os"
)

type rootIdentity struct{}
type fileIdentity struct{}

func captureRootIdentity(string) (rootIdentity, error) {
	return rootIdentity{}, errors.New("unsupported platform")
}
func sameRootIdentity(rootIdentity, rootIdentity) bool { return false }
func captureOpenedRootIdentity(*os.Root) (rootIdentity, error) {
	return rootIdentity{}, errors.New("unsupported platform")
}
func captureFileIdentity(*os.File) (fileIdentity, error) {
	return fileIdentity{}, errors.New("unsupported platform")
}
func sameFileIdentity(fileIdentity, fileIdentity) bool { return false }
func sameFileSystem(rootIdentity, fileIdentity) bool   { return false }
func validatePathObject(*os.Root, string, os.FileInfo) error {
	return errors.New("unsupported platform")
}
func validateOpenFile(*os.File, Sensitivity) error { return errors.New("unsupported platform") }
func establishCandidateSecurity(*os.File, Sensitivity) error {
	return errors.New("unsupported platform")
}
func preflightCandidateSecurity(Sensitivity) error { return errors.New("unsupported platform") }
func removeOwnedTemporary(*Root, string, fileIdentity) error {
	return errors.New("unsupported platform")
}
func publishPlatform(context.Context, *Candidate, bool) error {
	return errors.New("unsupported platform")
}
