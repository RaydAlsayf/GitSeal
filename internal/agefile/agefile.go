// Package agefile is GitSeal's typed native-hybrid age boundary. It contains no
// filesystem, Git, prompting, or presentation logic.
package agefile

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
)

const (
	stanzaType            = "mlkem768x25519"
	hybridArgumentBytes   = 1120
	hybridBodyBytes       = 32
	hybridArgumentEncoded = 1494
	hybridBodyEncoded     = 43
	hybridStanzaBytes     = 1557
	headerFixedBytes      = 70
	payloadNonceBytes     = 16
	payloadTagBytes       = 16
	payloadChunkBytes     = 64*1024 + payloadTagBytes
)

var (
	versionLine  = []byte("age-encryption.org/v1\n")
	stanzaPrefix = []byte("-> " + stanzaType + " ")
	footerPrefix = []byte("--- ")
)

// HybridRecipients contains only canonical concrete native hybrid recipients.
// Its representation is deliberately unexported so callers cannot inject a
// general age.Recipient wrapper that strips post-quantum labels.
type HybridRecipients struct {
	texts  []string
	values []*age.HybridRecipient
}

// HybridIdentity contains exactly one native hybrid identity. It has no String
// method so generic formatting cannot expose private material.
type HybridIdentity struct {
	value     *age.HybridIdentity
	recipient string
}

type HeaderReport struct {
	StanzaCount int
	HeaderBytes int
	TotalBytes  int64
	Header      []byte
}

type Engine struct {
	expectedStanzas int
}

func NewHybridRecipients(values []string) (HybridRecipients, error) {
	if len(values) > limits.MaxMembers {
		return HybridRecipients{}, fmt.Errorf("recipient count exceeds %d", limits.MaxMembers)
	}
	type parsed struct {
		text  string
		value *age.HybridRecipient
	}
	items := make([]parsed, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, text := range values {
		recipient, err := age.ParseHybridRecipient(text)
		if err != nil || recipient.String() != text {
			return HybridRecipients{}, errors.New("recipient is not a canonical native hybrid age recipient")
		}
		if _, ok := seen[text]; ok {
			return HybridRecipients{}, errors.New("duplicate canonical recipient")
		}
		seen[text] = struct{}{}
		items = append(items, parsed{text: text, value: recipient})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].text < items[j].text })
	out := HybridRecipients{
		texts:  make([]string, len(items)),
		values: make([]*age.HybridRecipient, len(items)),
	}
	for i, item := range items {
		out.texts[i], out.values[i] = item.text, item.value
	}
	return out, nil
}

func (r HybridRecipients) Len() int { return len(r.values) }

func (r HybridRecipients) CanonicalStrings() []string {
	return append([]string(nil), r.texts...)
}

func (r HybridRecipients) Digest() digest.Sum { return digest.RecipientSet(r.texts) }

func (r HybridRecipients) Contains(identity HybridIdentity) bool {
	if identity.value == nil {
		return false
	}
	i := sort.SearchStrings(r.texts, identity.recipient)
	return i < len(r.texts) && r.texts[i] == identity.recipient
}

func GenerateHybridIdentity() (HybridIdentity, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return HybridIdentity{}, fmt.Errorf("generate native hybrid identity: %w", err)
	}
	return HybridIdentity{value: identity, recipient: identity.Recipient().String()}, nil
}

// ParseHybridIdentityFile accepts exactly one canonical token followed by one
// LF. It rejects generic age identity-file syntax, comments, CRLF, and trimming.
func ParseHybridIdentityFile(data []byte) (HybridIdentity, error) {
	if len(data) < 2 || data[len(data)-1] != '\n' || bytes.IndexByte(data[:len(data)-1], '\n') >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return HybridIdentity{}, errors.New("identity file must contain exactly one canonical hybrid identity followed by LF")
	}
	token := string(data[:len(data)-1])
	identity, err := age.ParseHybridIdentity(token)
	if err != nil || identity.String() != token {
		return HybridIdentity{}, errors.New("identity file does not contain a canonical native hybrid age identity")
	}
	return HybridIdentity{value: identity, recipient: identity.Recipient().String()}, nil
}

// WritePrivate writes the canonical private token and LF. Callers must supply a
// destination created with restrictive permissions and must never log it.
func (i HybridIdentity) WritePrivate(dst io.Writer) error {
	if i.value == nil {
		return errors.New("missing hybrid identity")
	}
	if _, err := io.WriteString(dst, i.value.String()); err != nil {
		return err
	}
	_, err := io.WriteString(dst, "\n")
	return err
}

func (i HybridIdentity) CanonicalRecipient() string { return i.recipient }

func (i HybridIdentity) Fingerprint() digest.Sum {
	return digest.RecipientFingerprint(i.recipient)
}

func NewEngine(expectedStanzas int) (*Engine, error) {
	if expectedStanzas < 1 || expectedStanzas > limits.MaxMembers {
		return nil, fmt.Errorf("native hybrid stanza count must be between 1 and %d", limits.MaxMembers)
	}
	return &Engine{expectedStanzas: expectedStanzas}, nil
}

func (e *Engine) Encrypt(dst io.Writer, src io.Reader, recipients HybridRecipients) error {
	if e == nil || recipients.Len() != e.expectedStanzas || recipients.Len() == 0 {
		return errors.New("recipient set does not match the engine plan")
	}
	// This is the only general-interface conversion. All stored values remain
	// concrete *age.HybridRecipient values validated by the constructor above.
	ageRecipients := make([]age.Recipient, len(recipients.values))
	for idx, recipient := range recipients.values {
		ageRecipients[idx] = recipient
	}
	w, err := age.Encrypt(dst, ageRecipients...)
	if err != nil {
		return fmt.Errorf("initialize age encryption: %w", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("stream plaintext into age encryption: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalize age encryption: %w", err)
	}
	return nil
}

func (e *Engine) Decrypt(dst io.Writer, src io.Reader, totalSize int64, identity HybridIdentity) error {
	if identity.value == nil {
		return errors.New("missing hybrid identity")
	}
	_, replay, err := e.Inspect(src, totalSize)
	if err != nil {
		return err
	}
	plaintext, err := age.Decrypt(replay, identity.value)
	if err != nil {
		return errors.New("selected identity did not match or a recipient stanza is invalid")
	}
	if _, err := io.Copy(dst, plaintext); err != nil {
		return errors.New("age payload authentication failed before EOF")
	}
	return nil
}

// Inspect validates exact public native stanza type/count/shape. The returned
// replay reader yields the full original artifact. This metadata is not
// authenticated and cannot prove recipient identity or uniqueness.
func (e *Engine) Inspect(src io.Reader, totalSize int64) (HeaderReport, io.Reader, error) {
	if e == nil {
		return HeaderReport{}, nil, errors.New("missing age engine")
	}
	headerLen := headerFixedBytes + hybridStanzaBytes*e.expectedStanzas
	if headerLen > limits.MaxHeaderBytes {
		return HeaderReport{}, nil, errors.New("age header exceeds GitSeal limit")
	}
	if totalSize >= 0 {
		if totalSize > limits.DefaultFileBytes {
			return HeaderReport{}, nil, fmt.Errorf("artifact exceeds %d-byte local limit", limits.DefaultFileBytes)
		}
		if err := validatePayloadSize(totalSize, int64(headerLen)); err != nil {
			return HeaderReport{}, nil, err
		}
	}
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(src, header); err != nil {
		return HeaderReport{}, nil, errors.New("truncated age header")
	}
	if err := inspectHeader(header, e.expectedStanzas); err != nil {
		return HeaderReport{}, nil, err
	}
	report := HeaderReport{StanzaCount: e.expectedStanzas, HeaderBytes: headerLen, TotalBytes: totalSize, Header: header}
	return report, io.MultiReader(bytes.NewReader(header), src), nil
}

// InspectNativeHybridRange validates a canonical native-hybrid age artifact
// whose historical recipient count is intentionally not asserted. This is for
// retained orphan artifacts that no longer have a manifest entry: it proves a
// bounded public shape, not freshness, unique recipients, or membership in the
// repository's current recipient set.
func InspectNativeHybridRange(src io.Reader, totalSize int64, minimumStanzas, maximumStanzas int) (HeaderReport, io.Reader, error) {
	if minimumStanzas < 1 || maximumStanzas < minimumStanzas || maximumStanzas > limits.MaxMembers {
		return HeaderReport{}, nil, fmt.Errorf("native hybrid stanza range must be within 1..%d", limits.MaxMembers)
	}
	if totalSize < 0 {
		return HeaderReport{}, nil, errors.New("ranged native hybrid inspection requires an exact artifact size")
	}
	if totalSize > limits.DefaultFileBytes {
		return HeaderReport{}, nil, fmt.Errorf("artifact exceeds %d-byte local limit", limits.DefaultFileBytes)
	}
	maximumHeader := headerFixedBytes + hybridStanzaBytes*maximumStanzas
	prefixBytes := int64(maximumHeader)
	if totalSize < prefixBytes {
		prefixBytes = totalSize
	}
	prefix := make([]byte, int(prefixBytes))
	if _, err := io.ReadFull(src, prefix); err != nil {
		return HeaderReport{}, nil, errors.New("truncated age artifact during bounded header inspection")
	}
	for count := minimumStanzas; count <= maximumStanzas; count++ {
		headerLen := headerFixedBytes + hybridStanzaBytes*count
		if headerLen > len(prefix) {
			break
		}
		if err := validatePayloadSize(totalSize, int64(headerLen)); err != nil {
			continue
		}
		if err := inspectHeader(prefix[:headerLen], count); err != nil {
			continue
		}
		report := HeaderReport{StanzaCount: count, HeaderBytes: headerLen, TotalBytes: totalSize, Header: prefix[:headerLen]}
		return report, io.MultiReader(bytes.NewReader(prefix), src), nil
	}
	return HeaderReport{}, nil, errors.New("artifact does not have a canonical native-hybrid header within the allowed stanza range")
}

func (e *Engine) AuthenticateHeader(header []byte, identity HybridIdentity) error {
	if identity.value == nil {
		return errors.New("missing hybrid identity")
	}
	if len(header) != headerFixedBytes+hybridStanzaBytes*e.expectedStanzas {
		return errors.New("unexpected detached header length")
	}
	if err := inspectHeader(header, e.expectedStanzas); err != nil {
		return err
	}
	fileKey, err := age.DecryptHeader(header, identity.value)
	if err != nil {
		return errors.New("candidate header is not decryptable by the acting identity")
	}
	defer clear(fileKey)
	if len(fileKey) != 16 {
		return errors.New("age returned an unexpected file-key length")
	}
	return nil
}

// EncryptionPlan enforces self-membership before a destination can receive a
// byte and authenticates unpublished candidate headers before publication.
type EncryptionPlan struct {
	engine     *Engine
	recipients HybridRecipients
	identity   HybridIdentity
}

func NewEncryptionPlan(recipients HybridRecipients, identity HybridIdentity) (*EncryptionPlan, error) {
	if recipients.Len() == 0 {
		return nil, errors.New("cannot encrypt to an empty recipient set")
	}
	if !recipients.Contains(identity) {
		return nil, errors.New("acting identity is not a member of the effective recipient set")
	}
	engine, err := NewEngine(recipients.Len())
	if err != nil {
		return nil, err
	}
	return &EncryptionPlan{engine: engine, recipients: recipients, identity: identity}, nil
}

func (p *EncryptionPlan) Encrypt(dst io.Writer, src io.Reader) error {
	if p == nil {
		return errors.New("missing encryption plan")
	}
	return p.engine.Encrypt(dst, src, p.recipients)
}

func (p *EncryptionPlan) AuthenticateCandidate(src io.Reader, totalSize int64) error {
	report, _, err := p.engine.Inspect(src, totalSize)
	if err != nil {
		return err
	}
	return p.engine.AuthenticateHeader(report.Header, p.identity)
}

func inspectHeader(header []byte, count int) error {
	wantLen := headerFixedBytes + hybridStanzaBytes*count
	if len(header) != wantLen || !bytes.Equal(header[:len(versionLine)], versionLine) {
		return errors.New("artifact is not a canonical native-hybrid age v1 header")
	}
	offset := len(versionLine)
	seen := make(map[string]struct{}, count)
	for range count {
		start := offset
		if !bytes.Equal(header[offset:offset+len(stanzaPrefix)], stanzaPrefix) {
			return errors.New("artifact contains a non-native-hybrid or malformed stanza")
		}
		offset += len(stanzaPrefix)
		argument := header[offset : offset+hybridArgumentEncoded]
		offset += hybridArgumentEncoded
		if header[offset] != '\n' {
			return errors.New("hybrid stanza argument is not canonically terminated")
		}
		offset++
		body := header[offset : offset+hybridBodyEncoded]
		offset += hybridBodyEncoded
		if header[offset] != '\n' {
			return errors.New("hybrid stanza body is not canonically terminated")
		}
		offset++
		if err := canonicalBase64(argument, hybridArgumentBytes); err != nil {
			return errors.New("hybrid stanza argument has invalid shape")
		}
		if err := canonicalBase64(body, hybridBodyBytes); err != nil {
			return errors.New("hybrid stanza body has invalid shape")
		}
		serialized := string(header[start:offset])
		if _, ok := seen[serialized]; ok {
			return errors.New("artifact contains a byte-identical duplicate hybrid stanza")
		}
		seen[serialized] = struct{}{}
	}
	if !bytes.Equal(header[offset:offset+len(footerPrefix)], footerPrefix) {
		return errors.New("age header footer is malformed or stanza count does not match")
	}
	offset += len(footerPrefix)
	mac := header[offset : offset+hybridBodyEncoded]
	offset += hybridBodyEncoded
	if header[offset] != '\n' || offset+1 != len(header) || canonicalBase64(mac, 32) != nil {
		return errors.New("age header MAC has invalid shape")
	}
	return nil
}

func canonicalBase64(encoded []byte, decodedLen int) error {
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawStdEncoding.Decode(decoded, encoded)
	if err != nil || n != decodedLen {
		return errors.New("invalid base64")
	}
	decoded = decoded[:n]
	if base64.RawStdEncoding.EncodeToString(decoded) != string(encoded) {
		return errors.New("noncanonical base64")
	}
	return nil
}

func validatePayloadSize(total, header int64) error {
	if total < header+payloadNonceBytes+payloadTagBytes {
		return errors.New("age artifact is too short for an authenticated payload")
	}
	afterNonce := total - header - payloadNonceBytes
	remainder := afterNonce % payloadChunkBytes
	// A single 16-byte STREAM tag is the canonical encryption of an empty
	// payload. After any full chunk, however, another tag-only chunk would be
	// an empty final chunk, which the age STREAM format forbids.
	if afterNonce != payloadTagBytes && remainder == payloadTagBytes {
		return errors.New("age payload encodes a forbidden empty final chunk")
	}
	if remainder > 0 && remainder < payloadTagBytes {
		return errors.New("age payload length cannot encode complete authenticated chunks")
	}
	return nil
}
