// Package manifest implements deterministic committed artifact bookkeeping.
// Its recipient-set field is auditable policy evidence, not cryptographic proof
// of anonymous age stanza recipients.
package manifest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

const Version = 1

type Artifact struct {
	Source             string `yaml:"source" json:"source"`
	Encrypted          string `yaml:"encrypted" json:"encrypted"`
	CiphertextSHA256   string `yaml:"ciphertext_sha256" json:"ciphertext_sha256"`
	RecipientSetSHA256 string `yaml:"recipient_set_sha256" json:"recipient_set_sha256"`
}

type Manifest struct {
	Version   int        `yaml:"version" json:"version"`
	Artifacts []Artifact `yaml:"artifacts" json:"artifacts"`
}

func Empty() Manifest { return Manifest{Version: Version, Artifacts: []Artifact{}} }

func Parse(data []byte) (Manifest, error) {
	var out Manifest
	if err := strictyaml.Decode(data, &out); err != nil {
		return Manifest{}, err
	}
	if err := out.Validate(); err != nil {
		return Manifest{}, err
	}
	return out.Canonical(), nil
}

func (m Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("unsupported manifest version %d; GitSeal supports version %d", m.Version, Version)
	}
	if len(m.Artifacts) > limits.MaxProtectedFiles {
		return fmt.Errorf("artifact count exceeds %d", limits.MaxProtectedFiles)
	}
	seen := make(map[string]struct{}, len(m.Artifacts))
	for _, artifact := range m.Artifacts {
		if _, err := pathpolicy.Parse(artifact.Source); err != nil {
			return fmt.Errorf("manifest source %q: %w", artifact.Source, err)
		}
		if _, err := pathpolicy.Parse(artifact.Encrypted); err != nil {
			return fmt.Errorf("manifest artifact %q: %w", artifact.Encrypted, err)
		}
		if strings.EqualFold(artifact.Source, artifact.Encrypted) {
			return fmt.Errorf("manifest source and artifact collide: %q", artifact.Source)
		}
		folded := strings.ToLower(artifact.Encrypted)
		if _, ok := seen[folded]; ok {
			return fmt.Errorf("duplicate or case-fold-colliding manifest artifact %q", artifact.Encrypted)
		}
		seen[folded] = struct{}{}
		if _, err := digest.ParseHex(artifact.CiphertextSHA256); err != nil {
			return fmt.Errorf("artifact %q ciphertext_sha256: %w", artifact.Encrypted, err)
		}
		if _, err := digest.ParseHex(artifact.RecipientSetSHA256); err != nil {
			return fmt.Errorf("artifact %q recipient_set_sha256: %w", artifact.Encrypted, err)
		}
	}
	return nil
}

func (m Manifest) Canonical() Manifest {
	out := m
	out.Artifacts = append([]Artifact(nil), m.Artifacts...)
	sort.Slice(out.Artifacts, func(i, j int) bool { return out.Artifacts[i].Encrypted < out.Artifacts[j].Encrypted })
	if out.Artifacts == nil {
		out.Artifacts = []Artifact{}
	}
	return out
}

func (m Manifest) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return strictyaml.Encode(m.Canonical())
}

func (m Manifest) ValidateProject(project projectconfig.Project) error {
	want := make(map[string]string, len(project.ProtectedFiles))
	for _, mapping := range project.ProtectedFiles {
		want[mapping.Encrypted] = mapping.Source
	}
	for _, artifact := range m.Artifacts {
		source, ok := want[artifact.Encrypted]
		if !ok || source != artifact.Source {
			return fmt.Errorf("manifest artifact %q does not match the canonical project mapping", artifact.Encrypted)
		}
	}
	return nil
}

func (m Manifest) Find(encrypted string) (Artifact, bool) {
	for _, artifact := range m.Artifacts {
		if artifact.Encrypted == encrypted {
			return artifact, true
		}
	}
	return Artifact{}, false
}

func (m *Manifest) Upsert(artifact Artifact) error {
	if m == nil {
		return fmt.Errorf("nil manifest")
	}
	for idx := range m.Artifacts {
		if m.Artifacts[idx].Encrypted == artifact.Encrypted {
			m.Artifacts[idx] = artifact
			*m = m.Canonical()
			return m.Validate()
		}
	}
	m.Artifacts = append(m.Artifacts, artifact)
	*m = m.Canonical()
	return m.Validate()
}

func (m *Manifest) Remove(encrypted string) bool {
	if m == nil {
		return false
	}
	for idx := range m.Artifacts {
		if m.Artifacts[idx].Encrypted == encrypted {
			m.Artifacts = append(m.Artifacts[:idx:idx], m.Artifacts[idx+1:]...)
			*m = m.Canonical()
			return true
		}
	}
	return false
}
