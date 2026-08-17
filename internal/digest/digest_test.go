package digest

import (
	"bytes"
	"errors"
	"testing"
)

func TestDigestGoldenVectors(t *testing.T) {
	tests := []struct {
		name string
		got  Sum
		want string
	}{
		{"recipient-empty-string", RecipientFingerprint(""), "4fbcaf31477ce7da49d3af03724c00c8b83a308b4c6f924a85de261d7b982e8e"},
		{"recipient-set-zero", RecipientSet(nil), "3824045fe8d91e1c2a8fff28e7b836745e4d2ca51203a109770544d3e313adeb"},
		{"recipient-set-two-sorted", RecipientSet([]string{"b", "a"}), "31b1d30a71b6b5a2559d728ebec7a51ed9baffd94dacbd3adf21fc3b9c60fbd6"},
		{"membership-policy", MembershipPolicy([]Member{{ID: "b", Recipient: "r2"}, {ID: "a", Recipient: "r1"}}), "3854cb870eaae5a3f21952e8ccd7582333261730ab56715950cb4acb5583b8a2"},
		{"mappings", Mappings([]Mapping{{Source: "z", Encrypted: "z.age"}, {Source: "a", Encrypted: "a.age"}}), "9e58146bbbcae0a9d8bf46cc92ca35a99199c46809e38c271dcaef1956b39854"},
		{"retained-safety-zero", RetainedSafety(nil, nil), "6d676e7204192a33265d226acad236c6981012c5886e960bcee2ddd52f8510ff"},
		{"retained-safety-one-each", RetainedSafety([]string{"old/secret"}, []string{"old/secret.age"}), "01da650404b9b20fbf80b39b086bf4c1e8da1c53c7d30154b6824676ec4927fb"},
		{"retained-safety-multiple-sorted", RetainedSafety([]string{"z", "a"}, []string{"z.age", "a.age"}), "6400992866157f10e861bca0d5cd09a610482677968797b285e3d08dd6859efc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.got.Hex(); got != tt.want {
				t.Fatalf("digest changed: got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRetainedSafetyDigestSeparatesCategoriesAndDoesNotMutateInput(t *testing.T) {
	ignored := []string{"z", "a"}
	artifacts := []string{"z.age", "a.age"}
	wantIgnored := append([]string(nil), ignored...)
	wantArtifacts := append([]string(nil), artifacts...)

	first := RetainedSafety(ignored, artifacts)
	if first == RetainedSafety(artifacts, ignored) {
		t.Fatal("retained plaintext and artifact namespaces were not domain separated")
	}
	if first != RetainedSafety([]string{"a", "z"}, []string{"a.age", "z.age"}) {
		t.Fatal("retained safety digest depends on input ordering")
	}
	if !bytes.Equal([]byte(ignored[0]+ignored[1]), []byte(wantIgnored[0]+wantIgnored[1])) ||
		!bytes.Equal([]byte(artifacts[0]+artifacts[1]), []byte(wantArtifacts[0]+wantArtifacts[1])) {
		t.Fatal("retained safety digest mutated caller-owned slices")
	}
}

func TestParseHexStrict(t *testing.T) {
	want := Bytes([]byte("test"))
	got, err := ParseHex(want.Hex())
	if err != nil || got != want {
		t.Fatalf("ParseHex() = %v, %v", got, err)
	}
	for _, invalid := range []string{"", "AA" + want.Hex()[2:], want.Hex() + "00", want.Hex()[:63], "g" + want.Hex()[1:]} {
		if _, err := ParseHex(invalid); err == nil {
			t.Errorf("ParseHex(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestReaderLimit(t *testing.T) {
	_, n, err := Reader(bytes.NewReader([]byte("abcd")), 3)
	if err == nil || n != 4 {
		t.Fatalf("Reader limit = n %d, err %v", n, err)
	}
}

type shortWriter struct{ err error }

func (w shortWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

func TestHashingWriterHashesAcceptedBytes(t *testing.T) {
	w := NewHashingWriter(shortWriter{err: errors.New("disk")})
	n, err := w.Write([]byte("abcdef"))
	if n != 3 || err == nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got, want := w.Sum(), Bytes([]byte("abc")); got != want {
		t.Fatalf("hash = %s, want %s", got.Hex(), want.Hex())
	}
}
