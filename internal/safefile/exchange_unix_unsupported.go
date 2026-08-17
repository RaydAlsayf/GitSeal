//go:build aix || dragonfly || freebsd || netbsd || openbsd || solaris

package safefile

import (
	"errors"
	"os"
)

var errConditionalPublicationUnsupported = errors.New("identity-reconcilable handle-relative publication is unsupported on this Unix platform")

func openRelativeNoFollow(*os.File, string) (*os.File, error) {
	return nil, errConditionalPublicationUnsupported
}

func publishRelativeNoReplace(*os.File, string, string) error {
	return errConditionalPublicationUnsupported
}
