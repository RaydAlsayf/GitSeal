// Package treeverify validates an exact Git tree without reading worktree
// plaintext, private identities, local trust, state, or locks.
package treeverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

const SchemaVersion = 1

const (
	configPath     = ".gitseal/config.yaml"
	recipientsPath = ".gitseal/recipients.yaml"
	manifestPath   = ".gitseal/manifest.yaml"
	ignorePath     = ".gitignore"
	attrsPath      = ".gitattributes"

	maxTreeEntries       = 100_000
	maxIdentityScanBytes = int64(8 << 30)
)

var errIdentityScanBudget = fmt.Errorf("private-identity scan work budget exceeded")

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type Report struct {
	SchemaVersion  int                           `json:"schema_version"`
	Source         string                        `json:"source"`
	Tree           string                        `json:"tree,omitempty"`
	Project        bool                          `json:"project"`
	Findings       []Finding                     `json:"findings"`
	Mappings       []projectconfig.ProtectedFile `json:"-"`
	RecipientCount int                           `json:"-"`
}

func (r Report) OK() bool {
	for _, finding := range r.Findings {
		if finding.Severity == "error" {
			return false
		}
	}
	return true
}

func Verify(ctx context.Context, repo *gitrepo.Repository, source string, requireProject bool) (Report, error) {
	report := Report{SchemaVersion: SchemaVersion, Source: source, Findings: []Finding{}}
	tree, err := repo.ResolveTree(ctx, source)
	if err != nil {
		return report, err
	}
	report.Tree = tree
	entries, err := repo.ListTree(ctx, tree)
	if err != nil {
		return report, err
	}
	return verifyEntries(ctx, repo, report, entries, requireProject, nil)
}

// VerifyIndex validates the exact active index inherited by a hook without
// constructing a worktree or running transformations.
func VerifyIndex(ctx context.Context, repo *gitrepo.Repository, requireProject bool) (Report, error) {
	report := Report{SchemaVersion: SchemaVersion, Source: "active-index", Findings: []Finding{}}
	index, err := repo.ListIndex(ctx)
	if err != nil {
		return report, err
	}
	entries := make([]gitrepo.TreeEntry, 0, len(index))
	indexFlags := make(map[string]gitrepo.IndexEntry, len(index))
	for _, entry := range index {
		if entry.Stage != 0 {
			add(&report, "unmerged_index", entry.Path, "active index contains unmerged stages")
			continue
		}
		entries = append(entries, entry.TreeEntry)
		indexFlags[entry.Path] = entry
	}
	if !report.OK() {
		return report, nil
	}
	return verifyEntries(ctx, repo, report, entries, requireProject, indexFlags)
}

func verifyEntries(ctx context.Context, repo *gitrepo.Repository, report Report, entries []gitrepo.TreeEntry, requireProject bool, indexFlags map[string]gitrepo.IndexEntry) (Report, error) {
	if len(entries) > maxTreeEntries {
		add(&report, "tree_work_budget", "", "selected tree exceeds the bounded V1 entry budget")
		return report, nil
	}
	byPath := make(map[string]gitrepo.TreeEntry, len(entries))
	folded := make(map[string]string, len(entries))
	for _, entry := range entries {
		if !utf8.ValidString(entry.Path) || strings.ContainsRune(entry.Path, '\x00') {
			add(&report, "invalid_tree_path", entry.Path, "tree contains a non-UTF-8 or NUL path")
			continue
		}
		if _, ok := byPath[entry.Path]; ok {
			add(&report, "duplicate_tree_path", entry.Path, "tree contains a duplicate path")
		}
		byPath[entry.Path] = entry
		key := strings.ToLower(entry.Path)
		if previous, ok := folded[key]; ok && previous != entry.Path {
			add(&report, "casefold_collision", entry.Path, fmt.Sprintf("tree path case-fold-collides with %q", previous))
		} else {
			folded[key] = entry.Path
		}
		if strings.HasPrefix(strings.ToLower(path.Base(entry.Path)), pathpolicy.ReservedTemporaryPrefix) {
			add(&report, "reserved_temporary", entry.Path, "reserved GitSeal temporary path is present in the tree")
		}
		if canonical, collides := controlCasefoldCollision(entry.Path); collides {
			add(&report, "control_casefold_collision", entry.Path, fmt.Sprintf("tree path case-fold-collides with reserved control path %q", canonical))
		}
	}

	// Private identities and reserved control-name invariants apply to every
	// selected tree, including trees that are not otherwise GitSeal projects.
	// Scan unique blob objects once through one bounded batch process.
	if !scanPrivateIdentities(ctx, repo, &report, entries) {
		return report, nil
	}

	_, hasConfig := byPath[configPath]
	hasPartial := false
	for name := range byPath {
		if name == ".gitseal" || strings.HasPrefix(name, ".gitseal/") {
			hasPartial = true
			break
		}
	}
	if !hasConfig {
		if hasPartial {
			add(&report, "partial_project", ".gitseal", "tree contains partial GitSeal metadata without config.yaml")
		}
		if requireProject {
			add(&report, "project_required", configPath, "selected tree does not contain a complete GitSeal project")
		}
		return report, nil
	}
	report.Project = true

	for _, name := range []string{configPath, recipientsPath, manifestPath, ignorePath, attrsPath} {
		entry, ok := byPath[name]
		if !ok {
			add(&report, "missing_control_file", name, "required GitSeal control file is missing")
			continue
		}
		if entry.Mode != "100644" || entry.Type != "blob" {
			add(&report, "unsafe_control_mode", name, "GitSeal control files must be non-executable regular 100644 blobs")
		}
	}
	addUnsafeIndexFlags(&report, indexFlags, []string{configPath, recipientsPath, manifestPath, ignorePath, attrsPath})
	if !report.OK() {
		return report, nil
	}

	configBytes, err := readSmallBlob(ctx, repo, byPath[configPath].OID)
	if err != nil {
		return report, err
	}
	project, err := projectconfig.ParseProject(configBytes)
	if err != nil {
		add(&report, "invalid_project_config", configPath, "project configuration is invalid or unsupported")
		return report, nil
	}
	canonicalConfig, _ := project.Marshal()
	report.Mappings = append([]projectconfig.ProtectedFile(nil), project.ProtectedFiles...)
	protectedIndexPaths := make([]string, 0, 2*len(project.ProtectedFiles)+len(project.RetainedSafety.IgnoredPlaintext)+len(project.RetainedSafety.BinaryArtifacts))
	for _, mapping := range project.ProtectedFiles {
		protectedIndexPaths = append(protectedIndexPaths, mapping.Source, mapping.Encrypted)
	}
	protectedIndexPaths = append(protectedIndexPaths, project.RetainedSafety.IgnoredPlaintext...)
	protectedIndexPaths = append(protectedIndexPaths, project.RetainedSafety.BinaryArtifacts...)
	addUnsafeIndexFlags(&report, indexFlags, protectedIndexPaths)
	if !bytes.Equal(configBytes, canonicalConfig) {
		add(&report, "noncanonical_project_config", configPath, "project configuration is not canonical V1 YAML")
	}

	recipientBytes, err := readSmallBlob(ctx, repo, byPath[recipientsPath].OID)
	if err != nil {
		return report, err
	}
	recipients, typedRecipients, err := projectconfig.ParseRecipients(recipientBytes)
	if err != nil {
		add(&report, "invalid_recipients", recipientsPath, "recipient configuration is invalid or unsupported")
		return report, nil
	}
	canonicalRecipients, _ := recipients.Marshal()
	report.RecipientCount = typedRecipients.Len()
	if !bytes.Equal(recipientBytes, canonicalRecipients) {
		add(&report, "noncanonical_recipients", recipientsPath, "recipient configuration is not canonical V1 YAML")
	}

	manifestBytes, err := readSmallBlob(ctx, repo, byPath[manifestPath].OID)
	if err != nil {
		return report, err
	}
	book, err := manifest.Parse(manifestBytes)
	if err != nil {
		add(&report, "invalid_manifest", manifestPath, "artifact manifest is invalid or unsupported")
		return report, nil
	}
	canonicalManifest, _ := book.Marshal()
	if !bytes.Equal(manifestBytes, canonicalManifest) {
		add(&report, "noncanonical_manifest", manifestPath, "artifact manifest is not canonical V1 YAML")
	}
	if err := book.ValidateProject(project); err != nil {
		add(&report, "manifest_mapping_mismatch", manifestPath, "manifest source/artifact mappings do not match project configuration")
	}

	ignoreBytes, err := readSmallBlob(ctx, repo, byPath[ignorePath].OID)
	if err != nil {
		return report, err
	}
	if err := gitignore.Validate(ignoreBytes, project); err != nil {
		add(&report, "invalid_managed_ignore", ignorePath, "managed GitSeal ignore block is missing, malformed, or noncanonical")
	}
	attrsBytes, err := readSmallBlob(ctx, repo, byPath[attrsPath].OID)
	if err != nil {
		return report, err
	}
	if err := gitattrs.Validate(attrsBytes, project); err != nil {
		add(&report, "invalid_managed_attributes", attrsPath, "managed GitSeal attribute block is missing, malformed, or noncanonical")
	}

	attributePaths := make([]string, 0, len(project.ProtectedFiles)+len(project.RetainedSafety.BinaryArtifacts))
	shouldIgnore := []string{".gitseal.tmp.probe", ".gitseal/.gitseal.tmp.probe"}
	shouldNotIgnore := []string{configPath, recipientsPath, manifestPath, ignorePath, attrsPath}
	for _, mapping := range project.ProtectedFiles {
		attributePaths = append(attributePaths, mapping.Encrypted)
		shouldIgnore = append(shouldIgnore, mapping.Source, temporaryProbe(mapping.Source), temporaryProbe(mapping.Encrypted))
		shouldNotIgnore = append(shouldNotIgnore, mapping.Encrypted)
	}
	for _, retained := range project.RetainedSafety.IgnoredPlaintext {
		shouldIgnore = append(shouldIgnore, retained, temporaryProbe(retained))
	}
	for _, retained := range project.RetainedSafety.BinaryArtifacts {
		attributePaths = append(attributePaths, retained)
		shouldNotIgnore = append(shouldNotIgnore, retained)
		shouldIgnore = append(shouldIgnore, temporaryProbe(retained))
	}
	if report.Tree != "" {
		if err := repo.CheckTreeAttributes(ctx, report.Tree, attributePaths); err != nil {
			add(&report, "unsafe_tree_attributes", attrsPath, "repository-only exact-tree attribute evaluation failed: "+err.Error())
		}
		if err := repo.CheckTreeIgnorePolicy(ctx, entries, uniqueStrings(shouldIgnore), uniqueStrings(shouldNotIgnore)); err != nil {
			add(&report, "unsafe_tree_ignore", ignorePath, "repository-only exact-tree ignore evaluation failed: "+err.Error())
		}
	} else {
		if err := repo.CheckIndexAttributes(ctx, entries, attributePaths); err != nil {
			add(&report, "unsafe_index_attributes", attrsPath, "isolated exact-index attribute evaluation failed: "+err.Error())
		}
		if err := repo.CheckTreeIgnorePolicy(ctx, entries, uniqueStrings(shouldIgnore), uniqueStrings(shouldNotIgnore)); err != nil {
			add(&report, "unsafe_index_ignore", ignorePath, "isolated exact-index ignore evaluation failed: "+err.Error())
		}
	}

	if (len(project.ProtectedFiles) > 0 || len(project.RetainedSafety.BinaryArtifacts) > 0) && typedRecipients.Len() == 0 {
		add(&report, "empty_recipient_set", recipientsPath, "active or retained artifacts require at least one native hybrid recipient")
		return report, nil
	}
	if len(book.Artifacts) != len(project.ProtectedFiles) {
		add(&report, "manifest_cardinality", manifestPath, "manifest must contain exactly one entry for every active mapping")
	}

	for _, mapping := range project.ProtectedFiles {
		if _, ok := byPath[mapping.Source]; ok {
			add(&report, "tracked_plaintext", mapping.Source, "configured plaintext is present in the selected tree")
		}
		artifact, ok := book.Find(mapping.Encrypted)
		if !ok || artifact.Source != mapping.Source {
			add(&report, "missing_manifest_entry", mapping.Encrypted, "active mapping lacks an exact manifest entry")
			continue
		}
		entry, ok := byPath[mapping.Encrypted]
		if !ok {
			add(&report, "missing_artifact", mapping.Encrypted, "configured ciphertext artifact is missing")
			continue
		}
		if entry.Mode != "100644" || entry.Type != "blob" {
			add(&report, "unsafe_artifact_mode", mapping.Encrypted, "ciphertext artifact must be a non-executable regular 100644 blob")
			continue
		}
		if artifact.RecipientSetSHA256 != typedRecipients.Digest().Hex() {
			add(&report, "stale_recipient_set", mapping.Encrypted, "manifest recipient-set digest is stale")
		}
		if err := verifyArtifact(ctx, repo, entry, artifact, typedRecipients.Len()); err != nil {
			add(&report, "invalid_artifact", mapping.Encrypted, err.Error())
		}
	}
	for _, retained := range project.RetainedSafety.IgnoredPlaintext {
		if _, ok := byPath[retained]; ok {
			add(&report, "tracked_retained_plaintext", retained, "retained plaintext protection path is present in the selected tree")
		}
	}
	for _, retained := range project.RetainedSafety.BinaryArtifacts {
		entry, ok := byPath[retained]
		if !ok {
			continue
		}
		if entry.Mode != "100644" || entry.Type != "blob" {
			add(&report, "unsafe_retained_artifact_mode", retained, "retained artifact must remain a non-executable regular 100644 blob while present")
			continue
		}
		if typedRecipients.Len() > 0 {
			if err := verifyRetainedArtifact(ctx, repo, entry); err != nil {
				add(&report, "invalid_retained_artifact", retained, "retained artifact does not have the bounded native hybrid age shape")
			}
		}
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		if report.Findings[i].Path == report.Findings[j].Path {
			return report.Findings[i].Code < report.Findings[j].Code
		}
		return report.Findings[i].Path < report.Findings[j].Path
	})
	return report, nil
}

func addUnsafeIndexFlags(report *Report, indexFlags map[string]gitrepo.IndexEntry, paths []string) {
	if len(indexFlags) == 0 {
		return
	}
	for _, configured := range uniqueStrings(paths) {
		entry, ok := indexFlags[configured]
		if !ok {
			continue
		}
		if entry.SkipWorktree {
			add(report, "skip_worktree", configured, "GitSeal-owned or protected path is marked skip-worktree in the active index")
		}
		if entry.AssumeUnchanged {
			add(report, "assume_unchanged", configured, "GitSeal-owned or protected path is marked assume-unchanged in the active index")
		}
	}
}

func controlCasefoldCollision(candidate string) (string, bool) {
	for _, canonical := range []string{configPath, recipientsPath, manifestPath, ignorePath, attrsPath} {
		if candidate != canonical && strings.EqualFold(candidate, canonical) {
			return canonical, true
		}
	}
	first, _, _ := strings.Cut(candidate, "/")
	if first != ".gitseal" && strings.EqualFold(first, ".gitseal") {
		return ".gitseal", true
	}
	return "", false
}

func scanPrivateIdentities(ctx context.Context, repo *gitrepo.Repository, report *Report, entries []gitrepo.TreeEntry) bool {
	type target struct {
		request gitrepo.BlobRequest
		paths   []string
	}
	targets := make([]target, 0, len(entries))
	byOID := make(map[string]int, len(entries))
	for _, entry := range entries {
		if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") {
			continue
		}
		if index, ok := byOID[entry.OID]; ok {
			targets[index].paths = append(targets[index].paths, entry.Path)
			continue
		}
		byOID[entry.OID] = len(targets)
		targets = append(targets, target{
			request: gitrepo.BlobRequest{OID: entry.OID, Max: limits.DefaultFileBytes},
			paths:   []string{entry.Path},
		})
	}
	requests := make([]gitrepo.BlobRequest, len(targets))
	for index := range targets {
		requests[index] = targets[index].request
	}
	var consumed int64
	err := repo.ConsumeBlobs(ctx, requests, func(index int, reader io.Reader, size int64) error {
		if size > maxIdentityScanBytes-consumed {
			return errIdentityScanBudget
		}
		consumed += size
		found, err := agefile.ScanHybridIdentity(reader, size)
		if err != nil {
			return err
		}
		if found {
			for _, blobPath := range targets[index].paths {
				add(report, "private_identity", blobPath, "regular blob contains a checksum-valid native hybrid private identity")
			}
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err == errIdentityScanBudget {
		add(report, "identity_scan_budget", "", "regular blobs exceed the bounded V1 private-identity scan budget")
	} else {
		add(report, "identity_scan_failed", "", "regular blobs could not be fully scanned within the bounded V1 work limits")
	}
	return false
}

func readSmallBlob(ctx context.Context, repo *gitrepo.Repository, oid string) ([]byte, error) {
	var data []byte
	err := repo.ConsumeBlob(ctx, oid, limits.MaxYAMLBytes, func(reader io.Reader, size int64) error {
		var err error
		data, err = io.ReadAll(reader)
		if err == nil && int64(len(data)) != size {
			return io.ErrUnexpectedEOF
		}
		return err
	})
	return data, err
}

func verifyArtifact(ctx context.Context, repo *gitrepo.Repository, entry gitrepo.TreeEntry, artifact manifest.Artifact, count int) error {
	engine, err := agefile.NewEngine(count)
	if err != nil {
		return err
	}
	return repo.ConsumeBlob(ctx, entry.OID, limits.DefaultFileBytes, func(reader io.Reader, size int64) error {
		prefix := make([]byte, 43)
		n, readErr := io.ReadFull(reader, prefix)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		if bytes.HasPrefix(prefix[:n], []byte("version https://git-lfs.github.com/spec/v1\n")) {
			return fmt.Errorf("artifact is a Git LFS pointer")
		}
		full := io.MultiReader(bytes.NewReader(prefix[:n]), reader)
		_, replay, err := engine.Inspect(full, size)
		if err != nil {
			return err
		}
		hash := sha256.New()
		written, err := io.Copy(hash, replay)
		if err != nil || written != size {
			return fmt.Errorf("artifact blob could not be streamed exactly")
		}
		if hex.EncodeToString(hash.Sum(nil)) != artifact.CiphertextSHA256 {
			return fmt.Errorf("ciphertext digest does not match the manifest")
		}
		return nil
	})
}

func verifyRetainedArtifact(ctx context.Context, repo *gitrepo.Repository, entry gitrepo.TreeEntry) error {
	return repo.ConsumeBlob(ctx, entry.OID, limits.DefaultFileBytes, func(reader io.Reader, size int64) error {
		// A retained orphan has no active manifest entry that could claim its
		// historical recipient-set digest. Validate only a bounded canonical
		// native-hybrid shape; comparing its stanza count to current membership
		// would make a valid orphan permanently invalid after member rotation.
		_, replay, err := agefile.InspectNativeHybridRange(reader, size, 1, limits.MaxMembers)
		if err != nil {
			return err
		}
		written, err := io.Copy(io.Discard, replay)
		if err != nil || written != size {
			return fmt.Errorf("retained artifact could not be streamed exactly")
		}
		return nil
	})
}

func temporaryProbe(configured string) string {
	directory := path.Dir(configured)
	if directory == "." {
		return ".gitseal.tmp.probe"
	}
	return directory + "/.gitseal.tmp.probe"
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func add(report *Report, code, path, message string) {
	if len(report.Findings) >= limits.MaxDiagnostics {
		return
	}
	report.Findings = append(report.Findings, Finding{Severity: "error", Code: code, Path: path, Message: message})
}
