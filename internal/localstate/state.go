// Package localstate stores conservative Git-local trust and synchronization
// state. Plaintext digests never enter tracked files.
package localstate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

const (
	// Version remains the lock-record format used by lock.go. State and
	// selection versions are deliberately separate compatibility surfaces.
	Version            = 1
	StateVersion       = 2
	LegacyStateVersion = 1
	SelectionVersion   = 1
)

type FileBaseline struct {
	PlaintextSHA256  string `yaml:"plaintext_sha256" json:"plaintext_sha256"`
	CiphertextSHA256 string `yaml:"ciphertext_sha256" json:"ciphertext_sha256"`
}

type State struct {
	Version                       int                     `yaml:"version" json:"version"`
	TrustedRecipientsSHA256       string                  `yaml:"trusted_recipients_sha256,omitempty" json:"trusted_recipients_sha256,omitempty"`
	TrustedMembershipPolicySHA256 string                  `yaml:"trusted_membership_policy_sha256,omitempty" json:"trusted_membership_policy_sha256,omitempty"`
	TrustedMappingsSHA256         string                  `yaml:"trusted_mappings_sha256,omitempty" json:"trusted_mappings_sha256,omitempty"`
	TrustedRetainedSafetySHA256   string                  `yaml:"trusted_retained_safety_sha256,omitempty" json:"trusted_retained_safety_sha256,omitempty"`
	Files                         map[string]FileBaseline `yaml:"files" json:"files"`

	revision stateRevision
}

type stateRevision struct {
	known  bool
	exists bool
	sum    digest.Sum
}

type Selection struct {
	Version  int    `yaml:"version"`
	Identity string `yaml:"identity"`
}

type legacyStateV1 struct {
	Version                       int                     `yaml:"version"`
	TrustedRecipientsSHA256       string                  `yaml:"trusted_recipients_sha256,omitempty"`
	TrustedMembershipPolicySHA256 string                  `yaml:"trusted_membership_policy_sha256,omitempty"`
	TrustedMappingsSHA256         string                  `yaml:"trusted_mappings_sha256,omitempty"`
	Files                         map[string]FileBaseline `yaml:"files"`
}

var identityName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func Empty() State {
	return State{Version: StateVersion, Files: map[string]FileBaseline{}, revision: stateRevision{known: true}}
}

func Parse(data []byte) (State, error) {
	var out State
	if err := strictyaml.Decode(data, &out); err != nil {
		return State{}, err
	}
	if err := out.Validate(); err != nil {
		return State{}, err
	}
	return out, nil
}

// ParseStateV1ForMigration is the only parser that accepts the legacy local
// state schema. It does not manufacture retained-safety trust; callers must
// bind that new field to a separately reviewed exact digest before saving v2.
func ParseStateV1ForMigration(data []byte) (State, error) {
	var legacy legacyStateV1
	if err := strictyaml.Decode(data, &legacy); err != nil {
		return State{}, err
	}
	if legacy.Version != LegacyStateVersion {
		return State{}, fmt.Errorf("local state version %d is not the legacy version %d eligible for retained-safety trust migration", legacy.Version, LegacyStateVersion)
	}
	out := State{
		Version:                       legacy.Version,
		TrustedRecipientsSHA256:       legacy.TrustedRecipientsSHA256,
		TrustedMembershipPolicySHA256: legacy.TrustedMembershipPolicySHA256,
		TrustedMappingsSHA256:         legacy.TrustedMappingsSHA256,
		Files:                         legacy.Files,
	}
	if err := out.validateFields(); err != nil {
		return State{}, err
	}
	return out, nil
}

func (s State) Validate() error {
	if s.Version != StateVersion {
		if s.Version == LegacyStateVersion {
			return fmt.Errorf("local state version %d requires explicit retained-safety trust migration to version %d", s.Version, StateVersion)
		}
		return fmt.Errorf("unsupported local state version %d; GitSeal supports version %d", s.Version, StateVersion)
	}
	return s.validateFields()
}

func (s State) validateFields() error {
	if s.Files == nil {
		return errors.New("local state files mapping must not be null")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"trusted_recipients_sha256", s.TrustedRecipientsSHA256},
		{"trusted_membership_policy_sha256", s.TrustedMembershipPolicySHA256},
		{"trusted_mappings_sha256", s.TrustedMappingsSHA256},
		{"trusted_retained_safety_sha256", s.TrustedRetainedSafetySHA256},
	} {
		name, value := field.name, field.value
		if value != "" {
			if _, err := digest.ParseHex(value); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	for path, baseline := range s.Files {
		if _, err := pathpolicy.Parse(path); err != nil {
			return fmt.Errorf("local baseline path %q: %w", path, err)
		}
		if _, err := digest.ParseHex(baseline.PlaintextSHA256); err != nil {
			return fmt.Errorf("local plaintext digest for %q: %w", path, err)
		}
		if _, err := digest.ParseHex(baseline.CiphertextSHA256); err != nil {
			return fmt.Errorf("local ciphertext digest for %q: %w", path, err)
		}
	}
	return nil
}

func (s State) Marshal() ([]byte, error) {
	if s.Files == nil {
		s.Files = map[string]FileBaseline{}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return strictyaml.Encode(s)
}

func Load(directory string) (State, error) {
	data, err := readBounded(filepath.Join(directory, "state.yaml"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return Empty(), nil
	}
	if err != nil {
		return State{}, err
	}
	state, err := Parse(data)
	if err != nil {
		return State{}, err
	}
	state.revision = stateRevision{known: true, exists: true, sum: digest.Bytes(data)}
	return state, nil
}

// LoadForMigration reads either current state or strict legacy v1 state while
// preserving the exact loaded revision used by Save's compare-before-replace
// boundary. The boolean is true only when the returned state is legacy v1.
func LoadForMigration(directory string) (State, bool, error) {
	data, err := readBounded(filepath.Join(directory, "state.yaml"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return Empty(), false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	revision := stateRevision{known: true, exists: true, sum: digest.Bytes(data)}
	state, currentErr := Parse(data)
	if currentErr == nil {
		state.revision = revision
		return state, false, nil
	}
	legacy, legacyErr := ParseStateV1ForMigration(data)
	if legacyErr == nil {
		legacy.revision = revision
		return legacy, true, nil
	}
	return State{}, false, errors.Join(currentErr, fmt.Errorf("legacy local state is not eligible for migration: %w", legacyErr))
}

func Save(ctx context.Context, directory string, state *State) error {
	if state == nil {
		return errors.New("local state is missing")
	}
	if !state.revision.known {
		return errors.New("local state must be loaded before it can be replaced")
	}
	data, err := state.Marshal()
	if err != nil {
		return err
	}
	if err := writeRooted(ctx, directory, "state.yaml", data, safefile.SensitiveData, state.revision); err != nil {
		return err
	}
	state.revision = stateRevision{known: true, exists: true, sum: digest.Bytes(data)}
	return nil
}

func LoadSelection(directory string) (string, error) {
	data, err := readBounded(filepath.Join(directory, "selection.yaml"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var selection Selection
	if err := strictyaml.Decode(data, &selection); err != nil {
		return "", err
	}
	if selection.Version != SelectionVersion || !identityName.MatchString(selection.Identity) {
		return "", errors.New("invalid local identity selection")
	}
	return selection.Identity, nil
}

func SaveSelection(ctx context.Context, directory, name string) error {
	if !identityName.MatchString(name) {
		return errors.New("invalid local identity name")
	}
	data, err := strictyaml.Encode(Selection{Version: SelectionVersion, Identity: name})
	if err != nil {
		return err
	}
	revision, err := loadRevision(filepath.Join(directory, "selection.yaml"), 4096)
	if err != nil {
		return err
	}
	return writeRooted(ctx, directory, "selection.yaml", data, safefile.SensitiveData, revision)
}

func TrustMatches(state State, recipients, membership, mappings, retainedSafety digest.Sum) (bool, []string) {
	var changes []string
	if state.TrustedRecipientsSHA256 != recipients.Hex() {
		changes = append(changes, "recipient set")
	}
	if state.TrustedMembershipPolicySHA256 != membership.Hex() {
		changes = append(changes, "membership policy")
	}
	if state.TrustedMappingsSHA256 != mappings.Hex() {
		changes = append(changes, "project mappings")
	}
	if state.TrustedRetainedSafetySHA256 != retainedSafety.Hex() {
		changes = append(changes, "retained safety")
	}
	sort.Strings(changes)
	return len(changes) == 0, changes
}

func writeRooted(ctx context.Context, directory, name string, data []byte, sensitivity safefile.Sensitivity, expected stateRevision) (resultErr error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return errors.New("local state directory must be absolute")
	}
	if err := requireLocalStateMutationSafety(); err != nil {
		return err
	}
	if err := prepareDirectory(directory); err != nil {
		return err
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	p, err := pathpolicy.Parse(name)
	if err != nil {
		return err
	}
	if !expected.known {
		return errors.New("local-state write is not bound to a loaded revision")
	}
	candidate, err := root.NewCandidate(p, sensitivity)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			if abortErr := candidate.Abort(); abortErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("local-state write left an owned temporary candidate requiring manual reconciliation: %w", abortErr))
			}
		}
	}()
	if err := candidate.RequireDestination(expected.exists, expected.sum); err != nil {
		return fmt.Errorf("local state changed after it was loaded: %w", err)
	}
	if _, err := candidate.Write(data); err != nil {
		return err
	}
	if err := candidate.FlushClose(); err != nil {
		return err
	}
	if err := candidate.Publish(ctx, expected.exists); err != nil {
		return err
	}
	published = true
	return nil
}

func readBounded(name string, max int64) (data []byte, resultErr error) {
	if max < 0 {
		return nil, errors.New("negative local state byte limit")
	}
	name = filepath.Clean(name)
	directory, base := filepath.Dir(name), filepath.Base(name)
	if !filepath.IsAbs(name) || base == "." || base == string(filepath.Separator) {
		return nil, errors.New("local state path must be an absolute file path")
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	relative, err := pathpolicy.Parse(base)
	if err != nil {
		return nil, err
	}
	file, err := root.OpenSensitiveRead(relative)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("local state file is not a bounded regular file")
	}
	data, err = io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("read bounded local state file")
	}
	return data, nil
}

func loadRevision(name string, max int64) (stateRevision, error) {
	data, err := readBounded(name, max)
	if errors.Is(err, os.ErrNotExist) {
		return stateRevision{known: true}, nil
	}
	if err != nil {
		return stateRevision{}, err
	}
	return stateRevision{known: true, exists: true, sum: digest.Bytes(data)}, nil
}

func prepareDirectory(directory string) error {
	return prepareLocalDirectory(directory)
}

func Paths(directory string) (state, selection, lock string) {
	clean := filepath.Clean(directory)
	return filepath.Join(clean, "state.yaml"), filepath.Join(clean, "selection.yaml"), filepath.Join(clean, "lock.yaml")
}

func IsInsideTrackedMetadata(directory string) bool {
	normalized := filepath.ToSlash(directory)
	return strings.Contains(normalized, "/.gitseal/") || strings.HasSuffix(normalized, "/.gitseal")
}
