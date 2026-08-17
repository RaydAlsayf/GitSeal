// Package gitignore generates the deterministic GitSeal-owned ignore block.
package gitignore

import (
	"sort"

	"github.com/raydalsayf/gitseal/internal/managedblock"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

const (
	Begin = "# BEGIN GITSEAL"
	End   = "# END GITSEAL"
)

func Expected(project projectconfig.Project) []string {
	paths := make([]string, 0, len(project.ProtectedFiles)+len(project.RetainedSafety.IgnoredPlaintext))
	for _, mapping := range project.ProtectedFiles {
		paths = append(paths, "/"+mapping.Source)
	}
	for _, path := range project.RetainedSafety.IgnoredPlaintext {
		paths = append(paths, "/"+path)
	}
	sort.Strings(paths)
	return append([]string{".gitseal.tmp.*"}, paths...)
}

func Render(existing []byte, project projectconfig.Project) ([]byte, error) {
	return managedblock.Render(existing, Begin, End, Expected(project))
}

func Validate(data []byte, project projectconfig.Project) error {
	return managedblock.Validate(data, Begin, End, Expected(project))
}
