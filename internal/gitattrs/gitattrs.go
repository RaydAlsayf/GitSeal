// Package gitattrs generates the deterministic GitSeal-owned binary artifact
// block. Effective attribute evaluation remains a separate Git operation.
package gitattrs

import (
	"sort"

	"github.com/raydalsayf/gitseal/internal/managedblock"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

const (
	Begin  = "# BEGIN GITSEAL"
	End    = "# END GITSEAL"
	suffix = " -text -crlf -eol -ident -diff -merge -filter -working-tree-encoding"
)

var ManagedAttributes = []string{"text", "crlf", "eol", "ident", "diff", "merge", "filter", "working-tree-encoding"}

func Expected(project projectconfig.Project) []string {
	paths := make([]string, 0, len(project.ProtectedFiles)+len(project.RetainedSafety.BinaryArtifacts))
	for _, mapping := range project.ProtectedFiles {
		paths = append(paths, "/"+mapping.Encrypted+suffix)
	}
	for _, path := range project.RetainedSafety.BinaryArtifacts {
		paths = append(paths, "/"+path+suffix)
	}
	sort.Strings(paths)
	return paths
}

func Render(existing []byte, project projectconfig.Project) ([]byte, error) {
	return managedblock.Render(existing, Begin, End, Expected(project))
}

func Validate(data []byte, project projectconfig.Project) error {
	return managedblock.Validate(data, Begin, End, Expected(project))
}
