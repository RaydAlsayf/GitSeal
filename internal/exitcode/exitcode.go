// Package exitcode defines GitSeal's stable command failure categories.
package exitcode

import (
	"errors"
	"fmt"
)

// Code is a stable process exit category. It intentionally describes why an
// operation could not complete, not every state that a read-only command can
// report.
type Code int

const (
	Success          Code = 0
	General          Code = 1
	InvalidConfig    Code = 2
	MissingIdentity  Code = 3
	Unauthorized     Code = 4
	GitSafety        Code = 5
	Cryptography     Code = 6
	Conflict         Code = 7
	FilesystemSafety Code = 8
	TrustRequired    Code = 9
	Busy             Code = 10
)

// Error carries a stable category while preserving an internal cause for
// errors.Is/errors.As. Messages must never contain plaintext or private keys.
type Error struct {
	Code Code
	Op   string
	Path string
	Err  error
}

func (e *Error) Error() string {
	switch {
	case e.Path != "" && e.Op != "":
		return fmt.Sprintf("%s %q: %v", e.Op, e.Path, e.Err)
	case e.Op != "":
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	default:
		return e.Err.Error()
	}
}

func (e *Error) Unwrap() error { return e.Err }

// New creates a categorized error.
func New(code Code, op, path string, err error) error {
	if err == nil {
		err = errors.New("operation failed")
	}
	return &Error{Code: code, Op: op, Path: path, Err: err}
}

// Of returns the stable category of err, defaulting to General.
func Of(err error) Code {
	if err == nil {
		return Success
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return General
}
