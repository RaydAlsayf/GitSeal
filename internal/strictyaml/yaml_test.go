package strictyaml

import (
	"strings"
	"testing"
)

type testDocument struct {
	Version int      `yaml:"version"`
	Values  []string `yaml:"values"`
}

func TestDecodeStrict(t *testing.T) {
	var out testDocument
	if err := Decode([]byte("version: 1\nvalues:\n  - a\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != 1 || len(out.Values) != 1 || out.Values[0] != "a" {
		t.Fatalf("unexpected decode: %#v", out)
	}
	invalid := []string{
		"version: 1\nunknown: true\n",
		"version: 1\nversion: 1\n",
		"version: &v 1\nvalues: [*v]\n",
		"version: !custom 1\n",
		"version: 1\n<<: {values: []}\n",
		"---\nversion: 1\n---\nversion: 1\n",
	}
	for _, input := range invalid {
		out = testDocument{}
		if err := Decode([]byte(input), &out); err == nil {
			t.Errorf("Decode(%q) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeDepthAndSize(t *testing.T) {
	deep := "version: 1\nvalues:\n  - " + strings.Repeat("[", 20) + "x" + strings.Repeat("]", 20) + "\n"
	if err := Decode([]byte(deep), &testDocument{}); err == nil {
		t.Error("deep document unexpectedly succeeded")
	}
	huge := make([]byte, (1<<20)+1)
	if err := Decode(huge, &testDocument{}); err == nil {
		t.Error("oversized document unexpectedly succeeded")
	}
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{"version: 1\nvalues: []\n", "a: &a [*a]\n", "---\na: 1\n---\nb: 2\n", "a: !x b\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = Decode([]byte(value), &testDocument{})
	})
}
