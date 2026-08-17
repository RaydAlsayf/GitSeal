//go:build windows

package identity

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func platformDirectory() (directory string, resultErr error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", errors.New("open process token for FOLDERID_LocalAppData")
	}
	defer func() { resultErr = errors.Join(resultErr, token.Close()) }()
	effectiveUser, effectiveErr := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	processUser, processErr := token.GetTokenUser()
	if effectiveErr != nil || processErr != nil || effectiveUser == nil || processUser == nil || effectiveUser.User.Sid == nil || processUser.User.Sid == nil || !effectiveUser.User.Sid.IsValid() || !processUser.User.Sid.IsValid() || !effectiveUser.User.Sid.Equals(processUser.User.Sid) {
		return "", errors.New("effective Windows token does not match the process profile identity")
	}
	base, err := token.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil || base == "" || !filepath.IsAbs(base) {
		return "", errors.New("resolve FOLDERID_LocalAppData")
	}
	return filepath.Join(base, "GitSeal", "identities"), nil
}

func validateIdentityFilesystem(string) error {
	// The Windows sensitive read/create gates perform the stronger fixed-volume,
	// NTFS, DACL, and named-stream checks. They remain fail-closed below until
	// the complete handle-relative boundary is wired and proven on real NTFS.
	return nil
}

func preparePlatformDirectory(string) error {
	return errors.New("Windows protected identity-directory DACL creation is not yet implemented; refusing identity creation")
}

func validatePrivateFile(*os.File, os.FileInfo) error {
	return errors.New("Windows identity DACL/stream validation is not yet implemented; refusing identity use")
}
