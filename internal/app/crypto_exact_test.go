package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
)

func TestDecryptExactCiphertextAcceptsOnlyPrevalidatedBytes(t *testing.T) {
	identity, engine, ciphertext := exactCiphertextFixture(t, "expected plaintext")
	var plaintext bytes.Buffer
	if err := decryptExactCiphertext(engine, &plaintext, bytes.NewReader(ciphertext), int64(len(ciphertext)), digest.Bytes(ciphertext), identity); err != nil {
		t.Fatal(err)
	}
	if plaintext.String() != "expected plaintext" {
		t.Fatalf("plaintext = %q", plaintext.String())
	}
}

func TestDecryptExactCiphertextRejectsReopenedSubstitution(t *testing.T) {
	identity, engine, expectedCiphertext := exactCiphertextFixture(t, "expected plaintext")
	_, _, substitutedCiphertext := exactCiphertextFixtureForIdentity(t, identity, "substituted plaintext")

	// Model an A -> B -> A pathname race: A supplied the prevalidated digest,
	// while the already-open decryption handle supplies valid ciphertext B. A
	// later pathname re-read could observe A again, so only hashing this consumed
	// stream reliably detects the substitution.
	var unpublishedPlaintext bytes.Buffer
	err := decryptExactCiphertext(engine, &unpublishedPlaintext, bytes.NewReader(substitutedCiphertext), int64(len(substitutedCiphertext)), digest.Bytes(expectedCiphertext), identity)
	if err == nil || !strings.Contains(err.Error(), "ciphertext digest changed") {
		t.Fatalf("substitution error = %v", err)
	}
	if unpublishedPlaintext.String() != "substituted plaintext" {
		t.Fatalf("test did not exercise a valid substituted ciphertext: %q", unpublishedPlaintext.String())
	}
}

func TestDecryptExactCiphertextRejectsStatReadLengthMismatch(t *testing.T) {
	identity, engine, ciphertext := exactCiphertextFixture(t, "plaintext")
	var unpublishedPlaintext bytes.Buffer
	err := decryptExactCiphertext(engine, &unpublishedPlaintext, bytes.NewReader(ciphertext), int64(len(ciphertext)+1), digest.Bytes(ciphertext), identity)
	if err == nil || !strings.Contains(err.Error(), "ciphertext byte count changed") {
		t.Fatalf("length-mismatch error = %v", err)
	}
}

func TestAuthenticateExactCiphertextHeaderRejectsReopenedSubstitution(t *testing.T) {
	identity, engine, expectedCiphertext := exactCiphertextFixture(t, "expected plaintext")
	_, _, substitutedCiphertext := exactCiphertextFixtureForIdentity(t, identity, "substituted plaintext")
	err := authenticateExactCiphertextHeader(engine, bytes.NewReader(substitutedCiphertext), int64(len(substitutedCiphertext)), digest.Bytes(expectedCiphertext), identity)
	if err == nil || !strings.Contains(err.Error(), "ciphertext digest changed") {
		t.Fatalf("header substitution error = %v", err)
	}
}

func TestInspectExactCiphertextRejectsMalformedArtifact(t *testing.T) {
	_, engine, ciphertext := exactCiphertextFixture(t, "plaintext")
	corrupt := append([]byte(nil), ciphertext...)
	corrupt[0] ^= 1
	if err := inspectExactCiphertext(engine, bytes.NewReader(corrupt), int64(len(corrupt)), digest.Bytes(corrupt)); err == nil {
		t.Fatal("malformed artifact passed exact structural inspection")
	}
}

func exactCiphertextFixture(t *testing.T, plaintext string) (agefile.HybridIdentity, *agefile.Engine, []byte) {
	t.Helper()
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return exactCiphertextFixtureForIdentity(t, identity, plaintext)
}

func exactCiphertextFixtureForIdentity(t *testing.T, identity agefile.HybridIdentity, plaintext string) (agefile.HybridIdentity, *agefile.Engine, []byte) {
	t.Helper()
	recipients, err := agefile.NewHybridRecipients([]string{identity.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := agefile.NewEncryptionPlan(recipients, identity)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, strings.NewReader(plaintext)); err != nil {
		t.Fatal(err)
	}
	engine, err := agefile.NewEngine(recipients.Len())
	if err != nil {
		t.Fatal(err)
	}
	return identity, engine, ciphertext.Bytes()
}
