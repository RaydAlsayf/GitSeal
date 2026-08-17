package manifest

import (
	"bytes"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestManifestCanonicalAndProjectBinding(t *testing.T) {
	sum := digest.Bytes([]byte("ciphertext")).Hex()
	set := digest.RecipientSet(nil).Hex()
	m := Manifest{Version: 1, Artifacts: []Artifact{
		{Source: "z", Encrypted: "z.age", CiphertextSHA256: sum, RecipientSetSHA256: set},
		{Source: "a", Encrypted: "a.age", CiphertextSHA256: sum, RecipientSetSHA256: set},
	}}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := parsed.Marshal()
	if !bytes.Equal(data, again) || parsed.Artifacts[0].Encrypted != "a.age" {
		t.Fatal("manifest is not deterministic")
	}
	p := projectconfig.EmptyProject()
	p.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "a", Encrypted: "a.age"}, {Source: "z", Encrypted: "z.age"}}
	if err := parsed.ValidateProject(p); err != nil {
		t.Fatal(err)
	}
	parsed.Artifacts[0].Source = "other"
	if err := parsed.ValidateProject(p); err == nil {
		t.Fatal("source retargeting was accepted")
	}
}

func TestManifestDigestStrict(t *testing.T) {
	m := Empty()
	m.Artifacts = []Artifact{{Source: "a", Encrypted: "a.age", CiphertextSHA256: "AA", RecipientSetSHA256: digest.RecipientSet(nil).Hex()}}
	if err := m.Validate(); err == nil {
		t.Fatal("invalid digest accepted")
	}
}
