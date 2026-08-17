package agefile

import (
	"bytes"
	"testing"
)

func TestIdentityScanner(t *testing.T) {
	identity := mustIdentity(t)
	var secret bytes.Buffer
	if err := identity.WritePrivate(&secret); err != nil {
		t.Fatal(err)
	}
	data := append([]byte("prefix("), secret.Bytes()...)
	data = append(data, []byte(")suffix")...)
	found, err := ScanHybridIdentity(bytes.NewReader(data), int64(len(data)))
	if err != nil || !found {
		t.Fatalf("ScanHybridIdentity = %v, %v", found, err)
	}
	for _, harmless := range [][]byte{
		[]byte("documentation mentions AGE-SECRET-KEY-PQ-1 but has no key"),
		[]byte("AGE-SECRET-KEY-PQ-1invalid"),
		secret.Bytes()[:20],
	} {
		found, err := ScanHybridIdentity(bytes.NewReader(harmless), int64(len(harmless)))
		if err != nil || found {
			t.Fatalf("harmless input matched: %v, %v", found, err)
		}
	}
}

func TestIdentityScannerAcrossChunks(t *testing.T) {
	identity := mustIdentity(t)
	var token bytes.Buffer
	_ = identity.WritePrivate(&token)
	scanner := &IdentityScanner{}
	for _, b := range token.Bytes() {
		_, _ = scanner.Write([]byte{b})
	}
	scanner.Finish()
	if !scanner.Found() {
		t.Fatal("chunked identity was not detected")
	}
}
