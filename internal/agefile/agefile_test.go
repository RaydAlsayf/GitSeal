package agefile

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/raydalsayf/gitseal/internal/digest"
)

func mustIdentity(t *testing.T) HybridIdentity {
	t.Helper()
	i, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestHybridRoundTripAndCandidateAuthentication(t *testing.T) {
	first := mustIdentity(t)
	second := mustIdentity(t)
	recipients, err := NewHybridRecipients([]string{second.CanonicalRecipient(), first.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	if got := recipients.CanonicalStrings(); got[0] > got[1] {
		t.Fatal("recipients are not sorted")
	}
	plan, err := NewEncryptionPlan(recipients, first)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, 256*1024+17)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, bytes.NewReader(plaintext)); err != nil {
		t.Fatal(err)
	}
	if err := plan.AuthenticateCandidate(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len())); err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(2)
	for _, identity := range []HybridIdentity{first, second} {
		var recovered bytes.Buffer
		if err := engine.Decrypt(&recovered, bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), identity); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(recovered.Bytes(), plaintext) {
			t.Fatal("plaintext mismatch")
		}
	}
}

func TestAbsentActingIdentityFailsBeforeWrite(t *testing.T) {
	authorized := mustIdentity(t)
	unauthorized := mustIdentity(t)
	recipients, err := NewHybridRecipients([]string{authorized.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptionPlan(recipients, unauthorized); err == nil {
		t.Fatal("unauthorized acting identity was accepted")
	}
}

func TestIdentityFileStrict(t *testing.T) {
	i := mustIdentity(t)
	var encoded bytes.Buffer
	if err := i.WritePrivate(&encoded); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseHybridIdentityFile(encoded.Bytes())
	if err != nil || parsed.CanonicalRecipient() != i.CanonicalRecipient() {
		t.Fatalf("parse round trip: %v", err)
	}
	for _, invalid := range [][]byte{
		bytes.TrimSuffix(encoded.Bytes(), []byte("\n")),
		append(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), '\r', '\n'),
		append(append([]byte(nil), encoded.Bytes()...), '\n'),
		append([]byte("# key\n"), encoded.Bytes()...),
	} {
		if _, err := ParseHybridIdentityFile(invalid); err == nil {
			t.Error("invalid identity file accepted")
		}
	}
}

func TestRecipientTypeAndCanonicalRejection(t *testing.T) {
	i := mustIdentity(t)
	values := []string{"", " " + i.CanonicalRecipient(), strings.ToUpper(i.CanonicalRecipient())}
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	values = append(values, x.Recipient().String())
	for _, value := range values {
		if _, err := NewHybridRecipients([]string{value}); err == nil {
			t.Error("invalid or classical recipient accepted")
		}
	}
	if _, err := NewHybridRecipients([]string{i.CanonicalRecipient(), i.CanonicalRecipient()}); err == nil {
		t.Error("duplicate recipient accepted")
	}
}

func TestCorruptionAndTruncationNeverSucceed(t *testing.T) {
	i := mustIdentity(t)
	recipients, _ := NewHybridRecipients([]string{i.CanonicalRecipient()})
	plan, _ := NewEncryptionPlan(recipients, i)
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, strings.NewReader("secret canary")); err != nil {
		t.Fatal(err)
	}
	original := ciphertext.Bytes()
	engine, _ := NewEngine(1)
	for _, candidate := range [][]byte{
		append([]byte(nil), original[:len(original)-1]...),
		append([]byte(nil), original[:headerFixedBytes+hybridStanzaBytes]...),
	} {
		if err := engine.Decrypt(io.Discard, bytes.NewReader(candidate), int64(len(candidate)), i); err == nil {
			t.Error("truncated ciphertext decrypted")
		}
	}
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 1
	if err := engine.Decrypt(io.Discard, bytes.NewReader(corrupt), int64(len(corrupt)), i); err == nil {
		t.Error("corrupted ciphertext decrypted")
	}
}

func TestHeaderAuthenticationDoesNotSubstituteForPayloadEOFAuthentication(t *testing.T) {
	i := mustIdentity(t)
	recipients, err := NewHybridRecipients([]string{i.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewEncryptionPlan(recipients, i)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, strings.NewReader("payload authentication canary")); err != nil {
		t.Fatal(err)
	}
	corruptPayload := append([]byte(nil), ciphertext.Bytes()...)
	corruptPayload[len(corruptPayload)-1] ^= 1
	if err := plan.AuthenticateCandidate(bytes.NewReader(corruptPayload), int64(len(corruptPayload))); err != nil {
		t.Fatalf("unchanged header did not authenticate: %v", err)
	}
	engine, err := NewEngine(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Decrypt(io.Discard, bytes.NewReader(corruptPayload), int64(len(corruptPayload)), i); err == nil {
		t.Fatal("corrupted payload succeeded after header authentication")
	}
}

func TestInspectorRejectsArmorUnknownAndCountMismatch(t *testing.T) {
	i := mustIdentity(t)
	recipients, _ := NewHybridRecipients([]string{i.CanonicalRecipient()})
	plan, _ := NewEncryptionPlan(recipients, i)
	var ciphertext bytes.Buffer
	_ = plan.Encrypt(&ciphertext, bytes.NewReader(nil))
	engineOne, _ := NewEngine(1)
	engineTwo, _ := NewEngine(2)
	if _, _, err := engineTwo.Inspect(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len())); err == nil {
		t.Error("stanza-count mismatch accepted")
	}
	if _, _, err := engineOne.Inspect(strings.NewReader("-----BEGIN AGE ENCRYPTED FILE-----\n"), -1); err == nil {
		t.Error("armor accepted")
	}
	unknown := append([]byte(nil), ciphertext.Bytes()...)
	copy(unknown[len(versionLine)+3:], []byte("unknownxxxxxxxx"))
	if _, _, err := engineOne.Inspect(bytes.NewReader(unknown), int64(len(unknown))); err == nil {
		t.Error("unknown stanza accepted")
	}
}

func TestRangedInspectorAcceptsHistoricalRecipientCountWithoutClaimingCurrentMembership(t *testing.T) {
	first := mustIdentity(t)
	second := mustIdentity(t)
	recipients, err := NewHybridRecipients([]string{first.CanonicalRecipient(), second.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewEncryptionPlan(recipients, first)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, strings.NewReader("retained artifact")); err != nil {
		t.Fatal(err)
	}
	report, replay, err := InspectNativeHybridRange(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), 1, 32)
	if err != nil || report.StanzaCount != 2 {
		t.Fatalf("ranged inspection = %#v, %v", report, err)
	}
	replayed, err := io.ReadAll(replay)
	if err != nil || !bytes.Equal(replayed, ciphertext.Bytes()) {
		t.Fatalf("ranged replay mismatch: %v", err)
	}
	if _, _, err := InspectNativeHybridRange(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), 1, 1); err == nil {
		t.Fatal("ranged inspector accepted an artifact outside the allowed count")
	}
	if _, _, err := InspectNativeHybridRange(bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()), 0, 32); err == nil {
		t.Fatal("ranged inspector accepted an invalid lower bound")
	}
}

func TestRepeatedEncryptionIsRandomized(t *testing.T) {
	i := mustIdentity(t)
	recipients, _ := NewHybridRecipients([]string{i.CanonicalRecipient()})
	plan, _ := NewEncryptionPlan(recipients, i)
	var first, second bytes.Buffer
	_ = plan.Encrypt(&first, strings.NewReader("same"))
	_ = plan.Encrypt(&second, strings.NewReader("same"))
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("age encryption unexpectedly deterministic")
	}
}

func TestPayloadSizeRejectsEmptyFinalChunkAfterFullChunk(t *testing.T) {
	const header = int64(100)
	valid := []int64{
		header + payloadNonceBytes + payloadTagBytes,
		header + payloadNonceBytes + payloadChunkBytes,
		header + payloadNonceBytes + payloadTagBytes + 1,
	}
	for _, size := range valid {
		if err := validatePayloadSize(size, header); err != nil {
			t.Errorf("valid payload size %d rejected: %v", size, err)
		}
	}
	invalid := []int64{
		header + payloadNonceBytes + payloadTagBytes - 1,
		header + payloadNonceBytes + payloadChunkBytes + payloadTagBytes,
		-1,
	}
	for _, size := range invalid {
		if err := validatePayloadSize(size, header); err == nil {
			t.Errorf("invalid payload size %d accepted", size)
		}
	}
}

func TestCanonicalPublicDigestGoldenVector(t *testing.T) {
	data, err := os.ReadFile("testdata/hybrid-recipient.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 || data[len(data)-1] != '\n' || bytes.Contains(data[:len(data)-1], []byte{'\n'}) {
		t.Fatal("public recipient vector must contain exactly one LF-terminated line")
	}
	recipient := string(data[:len(data)-1])
	typed, err := NewHybridRecipients([]string{recipient})
	if err != nil || typed.CanonicalStrings()[0] != recipient {
		t.Fatalf("committed public vector is not canonical: %v", err)
	}
	vectors := map[string]string{
		"recipient_fingerprint": digest.RecipientFingerprint(recipient).Hex(),
		"recipient_set":         typed.Digest().Hex(),
		"membership_policy":     digest.MembershipPolicy([]digest.Member{{ID: "alice", Recipient: recipient}}).Hex(),
	}
	want := map[string]string{
		"recipient_fingerprint": "f71fff9d43bce744ef910f9edca854185ce5170bea82723da3f666887784a907",
		"recipient_set":         "6b602bac0b7f8408333f7a5f4fe9472299c1c22faa3217eb008d281a1f3a5bf5",
		"membership_policy":     "dde94d71920edc999997db43f13f24cef58c1598d927f4c2d2ad7f4f79f09530",
	}
	for name, expected := range want {
		if vectors[name] != expected {
			t.Errorf("%s golden changed: got %s, want %s", name, vectors[name], expected)
		}
	}
}

func FuzzInspectHeader(f *testing.F) {
	i, err := GenerateHybridIdentity()
	if err != nil {
		f.Fatal(err)
	}
	recipients, _ := NewHybridRecipients([]string{i.CanonicalRecipient()})
	plan, _ := NewEncryptionPlan(recipients, i)
	var valid bytes.Buffer
	_ = plan.Encrypt(&valid, bytes.NewReader(nil))
	f.Add(valid.Bytes())
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		engine, _ := NewEngine(1)
		_, _, _ = engine.Inspect(bytes.NewReader(data), int64(len(data)))
	})
}
