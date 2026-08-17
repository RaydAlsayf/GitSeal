//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package localstate

func currentProcessIdentity() string { return "unknown" }
