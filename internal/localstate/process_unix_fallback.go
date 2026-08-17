//go:build (aix || dragonfly || freebsd || netbsd || openbsd || solaris) && !linux

package localstate

// A Go process-local timestamp is not an authoritative OS process creation
// identity and must not be presented as one for stale-lock recovery.
func platformProcessIdentity() string { return "unknown" }
