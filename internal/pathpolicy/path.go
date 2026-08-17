// Package pathpolicy validates the deliberately narrow, portable V1 path
// syntax. Filesystem containment and link checks are separate mandatory layers.
package pathpolicy

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/raydalsayf/gitseal/internal/limits"
)

const ReservedTemporaryPrefix = ".gitseal.tmp."

type Path string

func Parse(value string) (Path, error) {
	if value == "" {
		return "", errors.New("path is empty")
	}
	if len(value) > limits.MaxPathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", limits.MaxPathBytes)
	}
	if value[0] == '/' || value[len(value)-1] == '/' {
		return "", errors.New("path must be repository-relative with no trailing separator")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !isAllowed(c) {
			return "", fmt.Errorf("path contains byte outside portable V1 profile at offset %d", i)
		}
	}
	if path.Clean(value) != value {
		return "", errors.New("path is not normalized repository-relative syntax")
	}
	for _, component := range strings.Split(value, "/") {
		if err := validateComponent(component); err != nil {
			return "", fmt.Errorf("invalid path component %q: %w", component, err)
		}
	}
	return Path(value), nil
}

func (p Path) String() string { return string(p) }

func (p Path) Fold() string { return strings.ToLower(string(p)) }

func isAllowed(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' || c == '.' || c == '_' || c == '/' || c == '-'
}

func validateComponent(component string) error {
	if component == "" || component == "." || component == ".." {
		return errors.New("empty or dot component")
	}
	if strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
		return errors.New("component ends in a dot or space")
	}
	folded := strings.ToLower(component)
	if folded == ".git" || folded == ".gitseal" {
		return errors.New("Git administrative or GitSeal metadata path")
	}
	if strings.HasPrefix(folded, ReservedTemporaryPrefix) {
		return errors.New("reserved GitSeal temporary namespace")
	}
	base := folded
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "con", "prn", "aux", "nul", "clock$":
		return errors.New("Windows device name")
	}
	if len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '1' && base[3] <= '9' {
		return errors.New("Windows device name")
	}
	return nil
}

// CheckMappings rejects source/destination equality and every exact or
// case-fold collision across entries.
func CheckMappings(pairs [][2]string) error {
	seen := make(map[string]string, len(pairs)*2)
	for _, pair := range pairs {
		source, err := Parse(pair[0])
		if err != nil {
			return fmt.Errorf("source %q: %w", pair[0], err)
		}
		encrypted, err := Parse(pair[1])
		if err != nil {
			return fmt.Errorf("encrypted %q: %w", pair[1], err)
		}
		if source.Fold() == encrypted.Fold() {
			return fmt.Errorf("source and encrypted paths collide: %q and %q", source, encrypted)
		}
		for _, current := range []Path{source, encrypted} {
			folded := current.Fold()
			if previous, ok := seen[folded]; ok {
				return fmt.Errorf("portable path collision: %q and %q", previous, current)
			}
			seen[folded] = current.String()
		}
	}
	return nil
}
