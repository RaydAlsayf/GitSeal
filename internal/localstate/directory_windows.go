//go:build windows

package localstate

import "errors"

func requireLocalStateMutationSafety() error { return nil }

func prepareLocalDirectory(string) error {
	return errors.New("Windows protected local-state directory DACL boundary is not yet implemented; refusing local-state creation")
}
