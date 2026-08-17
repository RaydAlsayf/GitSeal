package agefile

import (
	"bytes"
	"os"
	"testing"
)

func TestInteropFixture(t *testing.T) {
	dir := os.Getenv("GITSEAL_INTEROP_DIR")
	if dir == "" {
		t.Skip("GITSEAL_INTEROP_DIR is not set")
	}
	i, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var identityFile []byte
	w := sliceWriter{data: &identityFile}
	if err := i.WritePrivate(w); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/identity.txt", identityFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/recipient.txt", []byte(i.CanonicalRecipient()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := os.ReadFile(dir + "/plain.bin")
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := NewHybridRecipients([]string{i.CanonicalRecipient()})
	plan, _ := NewEncryptionPlan(recipients, i)
	file, err := os.OpenFile(dir+"/gitseal.age", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Encrypt(file, bytes.NewReader(plaintext)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptInteropFixture(t *testing.T) {
	dir := os.Getenv("GITSEAL_INTEROP_DECRYPT_DIR")
	if dir == "" {
		t.Skip("GITSEAL_INTEROP_DECRYPT_DIR is not set")
	}
	identityData, err := os.ReadFile(dir + "/identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ParseHybridIdentityFile(identityData)
	clear(identityData)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.Open(dir + "/official.age")
	if err != nil {
		t.Fatal(err)
	}
	defer ciphertext.Close()
	info, err := ciphertext.Stat()
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(dir+"/gitseal-recovered.bin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(1)
	decryptErr := engine.Decrypt(output, ciphertext, info.Size(), identity)
	closeErr := output.Close()
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

type sliceWriter struct{ data *[]byte }

func (w sliceWriter) Write(p []byte) (int, error) {
	*w.data = append(*w.data, p...)
	return len(p), nil
}
