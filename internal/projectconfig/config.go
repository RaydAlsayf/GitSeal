// Package projectconfig defines and validates GitSeal's tracked V1 schemas.
package projectconfig

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

const (
	ProjectVersion       = 2
	LegacyProjectVersion = 1
	RecipientsVersion    = 1
)

var memberID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type ProtectedFile struct {
	Source    string `yaml:"source" json:"source"`
	Encrypted string `yaml:"encrypted" json:"encrypted"`
}

type RetainedSafety struct {
	IgnoredPlaintext []string `yaml:"ignored_plaintext" json:"ignored_plaintext"`
	BinaryArtifacts  []string `yaml:"binary_artifacts" json:"binary_artifacts"`
}

type Project struct {
	Version        int             `yaml:"version" json:"version"`
	ProtectedFiles []ProtectedFile `yaml:"protected_files" json:"protected_files"`
	RetainedSafety RetainedSafety  `yaml:"retained_safety" json:"retained_safety"`
}

type Member struct {
	ID        string `yaml:"id" json:"id"`
	Name      string `yaml:"name" json:"name"`
	Recipient string `yaml:"recipient" json:"recipient"`
}

type Recipients struct {
	Version int      `yaml:"version" json:"version"`
	Members []Member `yaml:"members" json:"members"`
}

func EmptyProject() Project {
	return Project{
		Version:        ProjectVersion,
		ProtectedFiles: []ProtectedFile{},
		RetainedSafety: RetainedSafety{IgnoredPlaintext: []string{}, BinaryArtifacts: []string{}},
	}
}

func EmptyRecipients() Recipients { return Recipients{Version: RecipientsVersion, Members: []Member{}} }

func ParseProject(data []byte) (Project, error) {
	var out Project
	if err := strictyaml.Decode(data, &out); err != nil {
		return Project{}, err
	}
	if err := out.Validate(); err != nil {
		return Project{}, err
	}
	return out.Canonical(), nil
}

// ParseProjectV1ForMigration is the only parser that accepts the legacy
// project schema. Normal operations must use ParseProject so a pre-trust-model
// repository is never silently reinterpreted as a version 2 repository.
func ParseProjectV1ForMigration(data []byte) (Project, error) {
	var out Project
	if err := strictyaml.Decode(data, &out); err != nil {
		return Project{}, err
	}
	if out.Version != LegacyProjectVersion {
		return Project{}, fmt.Errorf("project configuration version %d is not the legacy version %d eligible for retained-safety trust migration", out.Version, LegacyProjectVersion)
	}
	if err := out.validateFields(); err != nil {
		return Project{}, err
	}
	return out.Canonical(), nil
}

func ParseRecipients(data []byte) (Recipients, agefile.HybridRecipients, error) {
	var out Recipients
	if err := strictyaml.Decode(data, &out); err != nil {
		return Recipients{}, agefile.HybridRecipients{}, err
	}
	typed, err := out.Validate()
	if err != nil {
		return Recipients{}, agefile.HybridRecipients{}, err
	}
	return out.Canonical(), typed, nil
}

func (p Project) Validate() error {
	if p.Version != ProjectVersion {
		if p.Version == LegacyProjectVersion {
			return fmt.Errorf("project configuration version %d requires explicit retained-safety trust migration to version %d", p.Version, ProjectVersion)
		}
		return fmt.Errorf("unsupported project configuration version %d; GitSeal supports version %d", p.Version, ProjectVersion)
	}
	return p.validateFields()
}

func (p Project) validateFields() error {
	if p.ProtectedFiles == nil {
		return errors.New("project protected_files must be an explicit non-null sequence")
	}
	if p.RetainedSafety.IgnoredPlaintext == nil || p.RetainedSafety.BinaryArtifacts == nil {
		return errors.New("project retained_safety and both retained path lists must be explicit and non-null")
	}
	if len(p.ProtectedFiles) > limits.MaxProtectedFiles {
		return fmt.Errorf("protected file count exceeds %d", limits.MaxProtectedFiles)
	}
	pairs := make([][2]string, len(p.ProtectedFiles))
	occupied := map[string]string{
		".gitignore":     ".gitignore",
		".gitattributes": ".gitattributes",
	}
	for idx, mapping := range p.ProtectedFiles {
		pairs[idx] = [2]string{mapping.Source, mapping.Encrypted}
	}
	if err := pathpolicy.CheckMappings(pairs); err != nil {
		return err
	}
	for _, pair := range pairs {
		if err := addOccupiedPath(occupied, pair[0]); err != nil {
			return err
		}
		if err := addOccupiedPath(occupied, pair[1]); err != nil {
			return err
		}
	}
	if err := validateRetained("ignored_plaintext", p.RetainedSafety.IgnoredPlaintext, occupied); err != nil {
		return err
	}
	if err := validateRetained("binary_artifacts", p.RetainedSafety.BinaryArtifacts, occupied); err != nil {
		return err
	}
	return nil
}

func validateRetained(kind string, values []string, occupied map[string]string) error {
	if len(values) > limits.MaxProtectedFiles {
		return fmt.Errorf("retained %s count exceeds %d", kind, limits.MaxProtectedFiles)
	}
	for _, value := range values {
		parsed, err := pathpolicy.Parse(value)
		if err != nil {
			return fmt.Errorf("retained %s %q: %w", kind, value, err)
		}
		if err := addOccupiedPath(occupied, parsed.String()); err != nil {
			return fmt.Errorf("retained safety %s: %w", kind, err)
		}
	}
	return nil
}

func addOccupiedPath(occupied map[string]string, value string) error {
	folded := strings.ToLower(value)
	for previousFolded, previous := range occupied {
		if folded == previousFolded || strings.HasPrefix(folded, previousFolded+"/") || strings.HasPrefix(previousFolded, folded+"/") {
			return fmt.Errorf("portable path collision between %q and %q", previous, value)
		}
	}
	occupied[folded] = value
	return nil
}

func (r Recipients) Validate() (agefile.HybridRecipients, error) {
	if r.Version != RecipientsVersion {
		return agefile.HybridRecipients{}, fmt.Errorf("unsupported recipient configuration version %d; GitSeal supports version %d", r.Version, RecipientsVersion)
	}
	if r.Members == nil {
		return agefile.HybridRecipients{}, errors.New("recipient members must be an explicit non-null sequence")
	}
	if len(r.Members) > limits.MaxMembers {
		return agefile.HybridRecipients{}, fmt.Errorf("member count exceeds %d", limits.MaxMembers)
	}
	ids := make(map[string]struct{}, len(r.Members))
	values := make([]string, 0, len(r.Members))
	for _, member := range r.Members {
		if !memberID.MatchString(member.ID) {
			return agefile.HybridRecipients{}, fmt.Errorf("member ID %q must match %s", member.ID, memberID)
		}
		if _, ok := ids[member.ID]; ok {
			return agefile.HybridRecipients{}, fmt.Errorf("duplicate member ID %q", member.ID)
		}
		ids[member.ID] = struct{}{}
		if err := validateDisplayName(member.Name); err != nil {
			return agefile.HybridRecipients{}, fmt.Errorf("member %q display name: %w", member.ID, err)
		}
		values = append(values, member.Recipient)
	}
	typed, err := agefile.NewHybridRecipients(values)
	if err != nil {
		return agefile.HybridRecipients{}, err
	}
	return typed, nil
}

func validateDisplayName(value string) error {
	if value == "" || len(value) > 100 || !utf8.ValidString(value) {
		return errors.New("must be valid UTF-8 between 1 and 100 bytes")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return errors.New("must not contain control or line-separator characters")
		}
	}
	return nil
}

func (p Project) Canonical() Project {
	out := p
	out.ProtectedFiles = append([]ProtectedFile(nil), p.ProtectedFiles...)
	sort.Slice(out.ProtectedFiles, func(i, j int) bool {
		if out.ProtectedFiles[i].Source == out.ProtectedFiles[j].Source {
			return out.ProtectedFiles[i].Encrypted < out.ProtectedFiles[j].Encrypted
		}
		return out.ProtectedFiles[i].Source < out.ProtectedFiles[j].Source
	})
	out.RetainedSafety.IgnoredPlaintext = append([]string(nil), p.RetainedSafety.IgnoredPlaintext...)
	out.RetainedSafety.BinaryArtifacts = append([]string(nil), p.RetainedSafety.BinaryArtifacts...)
	sort.Strings(out.RetainedSafety.IgnoredPlaintext)
	sort.Strings(out.RetainedSafety.BinaryArtifacts)
	if out.ProtectedFiles == nil {
		out.ProtectedFiles = []ProtectedFile{}
	}
	if out.RetainedSafety.IgnoredPlaintext == nil {
		out.RetainedSafety.IgnoredPlaintext = []string{}
	}
	if out.RetainedSafety.BinaryArtifacts == nil {
		out.RetainedSafety.BinaryArtifacts = []string{}
	}
	return out
}

func (r Recipients) Canonical() Recipients {
	out := r
	out.Members = append([]Member(nil), r.Members...)
	sort.Slice(out.Members, func(i, j int) bool {
		if out.Members[i].ID == out.Members[j].ID {
			return out.Members[i].Recipient < out.Members[j].Recipient
		}
		return out.Members[i].ID < out.Members[j].ID
	})
	if out.Members == nil {
		out.Members = []Member{}
	}
	return out
}

func (p Project) Marshal() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return strictyaml.Encode(p.Canonical())
}

func (r Recipients) Marshal() ([]byte, error) {
	if _, err := r.Validate(); err != nil {
		return nil, err
	}
	return strictyaml.Encode(r.Canonical())
}

func (p Project) MappingDigest() digest.Sum {
	values := make([]digest.Mapping, len(p.ProtectedFiles))
	for i, mapping := range p.ProtectedFiles {
		values[i] = digest.Mapping{Source: mapping.Source, Encrypted: mapping.Encrypted}
	}
	return digest.Mappings(values)
}

func (p Project) RetainedSafetyDigest() digest.Sum {
	return digest.RetainedSafety(p.RetainedSafety.IgnoredPlaintext, p.RetainedSafety.BinaryArtifacts)
}

func (r Recipients) MembershipDigest() digest.Sum {
	values := make([]digest.Member, len(r.Members))
	for i, member := range r.Members {
		values[i] = digest.Member{ID: member.ID, Recipient: member.Recipient}
	}
	return digest.MembershipPolicy(values)
}

func (r Recipients) RecipientStrings() []string {
	values := make([]string, len(r.Members))
	for i, member := range r.Members {
		values[i] = member.Recipient
	}
	return values
}

func (p Project) Find(path string) (ProtectedFile, bool) {
	for _, mapping := range p.ProtectedFiles {
		if mapping.Source == path || mapping.Encrypted == path {
			return mapping, true
		}
	}
	return ProtectedFile{}, false
}
