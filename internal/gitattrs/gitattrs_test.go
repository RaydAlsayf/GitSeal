package gitattrs

import (
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestExpected(t *testing.T) {
	p := projectconfig.EmptyProject()
	p.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "a", Encrypted: "a.age"}}
	data, err := Render(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/a.age -text -crlf -eol -ident -diff -merge -filter -working-tree-encoding") {
		t.Fatalf("unexpected block:\n%s", data)
	}
	if err := Validate(data, p); err != nil {
		t.Fatal(err)
	}
}
