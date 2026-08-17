// Package limits centralizes hard resource ceilings that untrusted repository
// data cannot raise.
package limits

const (
	MaxYAMLBytes       int64 = 1 << 20
	MaxYAMLDepth             = 16
	MaxYAMLScalarBytes       = 64 << 10
	MaxMembers               = 32
	MaxProtectedFiles        = 128
	MaxPathBytes             = 1024
	DefaultFileBytes   int64 = 1 << 30
	MaxGitOutputBytes  int64 = 16 << 20
	MaxDiagnostics           = 1024
	MaxHeaderBytes     int   = 64 << 10
)
