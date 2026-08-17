// Package digest implements GitSeal's versioned, length-framed SHA-256
// constructions. These encodings are compatibility surfaces.
package digest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
)

type Sum [sha256.Size]byte

type Member struct {
	ID        string
	Recipient string
}

type Mapping struct {
	Source    string
	Encrypted string
}

func Bytes(b []byte) Sum { return sha256.Sum256(b) }

func Reader(r io.Reader, max int64) (Sum, int64, error) {
	if max < 0 {
		return Sum{}, 0, errors.New("negative byte limit")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, max+1))
	if err != nil {
		return Sum{}, n, err
	}
	if n > max {
		return Sum{}, n, fmt.Errorf("input exceeds %d-byte limit", max)
	}
	var out Sum
	copy(out[:], h.Sum(nil))
	return out, n, nil
}

func (s Sum) Hex() string { return hex.EncodeToString(s[:]) }

func (s Sum) Grouped() string {
	h := s.Hex()
	parts := make([]string, 0, 8)
	for i := 0; i < len(h); i += 8 {
		parts = append(parts, h[i:i+8])
	}
	return strings.Join(parts, " ")
}

func ParseHex(v string) (Sum, error) {
	var out Sum
	if len(v) != sha256.Size*2 || v != strings.ToLower(v) {
		return out, errors.New("SHA-256 must be 64 lowercase hexadecimal characters")
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return out, errors.New("SHA-256 must be 64 lowercase hexadecimal characters")
	}
	copy(out[:], b)
	return out, nil
}

func RecipientFingerprint(recipient string) Sum {
	h := sha256.New()
	writeString(h, "gitseal/recipient-fingerprint/v1\x00")
	writeBytes(h, []byte(recipient))
	return finish(h)
}

func RecipientSet(recipients []string) Sum {
	values := append([]string(nil), recipients...)
	sort.Strings(values)
	return framed("gitseal/recipient-set/v1\x00", values)
}

func MembershipPolicy(members []Member) Sum {
	values := append([]Member(nil), members...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].ID == values[j].ID {
			return values[i].Recipient < values[j].Recipient
		}
		return values[i].ID < values[j].ID
	})
	h := sha256.New()
	writeString(h, "gitseal/membership-policy/v1\x00")
	writeUint64(h, uint64(len(values)))
	for _, member := range values {
		writeBytes(h, []byte(member.ID))
		writeBytes(h, []byte(member.Recipient))
	}
	return finish(h)
}

func Mappings(mappings []Mapping) Sum {
	values := append([]Mapping(nil), mappings...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Source == values[j].Source {
			return values[i].Encrypted < values[j].Encrypted
		}
		return values[i].Source < values[j].Source
	})
	h := sha256.New()
	writeString(h, "gitseal/project-mappings/v1\x00")
	writeUint64(h, uint64(len(values)))
	for _, mapping := range values {
		writeBytes(h, []byte(mapping.Source))
		writeBytes(h, []byte(mapping.Encrypted))
	}
	return finish(h)
}

// RetainedSafety binds the two distinct retained-protection namespaces. The
// existing project-mappings/v1 digest intentionally remains active-only; this
// separate compatibility surface lets local trust detect every addition,
// removal, or category change without silently changing that frozen format.
func RetainedSafety(ignoredPlaintext, binaryArtifacts []string) Sum {
	ignored := append([]string(nil), ignoredPlaintext...)
	artifacts := append([]string(nil), binaryArtifacts...)
	sort.Strings(ignored)
	sort.Strings(artifacts)

	h := sha256.New()
	writeString(h, "gitseal/retained-safety/v1\x00")
	writeUint64(h, uint64(len(ignored)))
	for _, value := range ignored {
		writeBytes(h, []byte(value))
	}
	writeUint64(h, uint64(len(artifacts)))
	for _, value := range artifacts {
		writeBytes(h, []byte(value))
	}
	return finish(h)
}

func framed(domain string, values []string) Sum {
	h := sha256.New()
	writeString(h, domain)
	writeUint64(h, uint64(len(values)))
	for _, value := range values {
		writeBytes(h, []byte(value))
	}
	return finish(h)
}

func writeString(h hash.Hash, value string) { _, _ = io.WriteString(h, value) }

func writeBytes(h hash.Hash, value []byte) {
	writeUint64(h, uint64(len(value)))
	_, _ = h.Write(value)
}

func writeUint64(h hash.Hash, value uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	_, _ = h.Write(b[:])
}

func finish(h hash.Hash) Sum {
	var out Sum
	copy(out[:], h.Sum(nil))
	return out
}

// HashingReader hashes exactly the bytes successfully returned to its caller.
// It is intended to sit directly at the encryption/decryption stream boundary.
type HashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func NewHashingReader(r io.Reader) *HashingReader {
	return &HashingReader{r: r, h: sha256.New()}
}

func (r *HashingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		_, _ = r.h.Write(p[:n])
		r.n += int64(n)
	}
	return n, err
}

func (r *HashingReader) Sum() Sum         { return finishClone(r.h) }
func (r *HashingReader) BytesRead() int64 { return r.n }

// HashingWriter hashes exactly the bytes accepted by its destination.
type HashingWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func NewHashingWriter(w io.Writer) *HashingWriter {
	return &HashingWriter{w: w, h: sha256.New()}
}

func (w *HashingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		_, _ = w.h.Write(p[:n])
		w.n += int64(n)
	}
	return n, err
}

func (w *HashingWriter) Sum() Sum            { return finishClone(w.h) }
func (w *HashingWriter) BytesWritten() int64 { return w.n }

func finishClone(h hash.Hash) Sum {
	var out Sum
	copy(out[:], h.Sum(nil))
	return out
}
