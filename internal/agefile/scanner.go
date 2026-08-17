package agefile

import (
	"errors"
	"io"

	"filippo.io/age"
)

var privatePrefix = []byte("AGE-SECRET-KEY-PQ-1")

const maxIdentityCandidateBytes = 4096

// IdentityScanner detects complete checksum-valid native hybrid identities in
// an arbitrary byte stream without retaining or returning the matched token.
// A mere textual prefix is not a match.
type IdentityScanner struct {
	match     int
	candidate []byte
	found     bool
	overlong  bool
}

func (s *IdentityScanner) Write(p []byte) (int, error) {
	for _, b := range p {
		s.consume(b)
	}
	return len(p), nil
}

func (s *IdentityScanner) Found() bool { return s.found }

func (s *IdentityScanner) Finish() { s.finishCandidate() }

func (s *IdentityScanner) consume(b byte) {
	if s.found {
		return
	}
	if len(s.candidate) > 0 || s.overlong {
		if identityTokenByte(b) {
			if !s.overlong {
				if len(s.candidate) < maxIdentityCandidateBytes {
					s.candidate = append(s.candidate, b)
				} else {
					s.candidate = nil
					s.overlong = true
				}
			}
			return
		}
		s.finishCandidate()
		s.overlong = false
		s.match = 0
	}
	if b == privatePrefix[s.match] {
		s.match++
		if s.match == len(privatePrefix) {
			s.candidate = append(s.candidate[:0], privatePrefix...)
			s.match = 0
		}
		return
	}
	if b == privatePrefix[0] {
		s.match = 1
	} else {
		s.match = 0
	}
}

func (s *IdentityScanner) finishCandidate() {
	if len(s.candidate) == 0 || s.overlong || s.found {
		s.candidate = nil
		return
	}
	value, err := age.ParseHybridIdentity(string(s.candidate))
	if err == nil && value.String() == string(s.candidate) {
		s.found = true
	}
	clear(s.candidate)
	s.candidate = nil
}

func identityTokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-'
}

func ScanHybridIdentity(src io.Reader, max int64) (bool, error) {
	if max < 0 {
		return false, errors.New("negative scan limit")
	}
	scanner := &IdentityScanner{}
	n, err := io.Copy(scanner, io.LimitReader(src, max+1))
	if err != nil {
		return false, err
	}
	if n > max {
		return false, errors.New("identity scan input exceeds limit")
	}
	scanner.Finish()
	return scanner.Found(), nil
}
