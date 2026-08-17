package hooks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/identity"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/treeverify"
)

type RunReport struct {
	Hook               string
	Static             treeverify.Report
	Tier2Authenticated []string
}

type VerificationError struct {
	Kind  string
	Count int
}

func (e *VerificationError) Error() string {
	if e.Count > 0 {
		return fmt.Sprintf("%s validation reported %d blocking finding(s)", e.Kind, e.Count)
	}
	return e.Kind + " validation failed"
}

// Run validates the exact inherited active index. It never falls back after an
// inherited index fails validation and never modifies the index, worktree,
// local baseline, or selected identity.
func Run(ctx context.Context, cwd, name string) (RunReport, error) {
	result := RunReport{Hook: name, Tier2Authenticated: []string{}}
	if !validHookName(name) {
		return result, exitcode.New(exitcode.InvalidConfig, "run hook", name, errors.New("unsupported hook name"))
	}
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{AllowActiveIndex: true, AllowGitHookEnvironment: true})
	if err != nil {
		return result, exitcode.New(exitcode.GitSafety, "discover hook repository", "", err)
	}
	before, err := captureIndexSnapshot(ctx, repo)
	if err != nil {
		return result, exitcode.New(exitcode.GitSafety, "capture active index", "", err)
	}
	requireProject, err := headHasProject(ctx, repo)
	if err != nil {
		return result, exitcode.New(exitcode.GitSafety, "inspect HEAD project state", "", err)
	}
	result.Static, err = treeverify.VerifyIndex(ctx, repo, requireProject)
	if err != nil {
		return result, exitcode.New(exitcode.GitSafety, "verify prospective index", "", err)
	}
	if !result.Static.OK() {
		return result, exitcode.New(exitcode.GitSafety, "verify prospective index", "", &VerificationError{Kind: "static prospective-index", Count: blockingFindings(result.Static)})
	}
	if result.Static.Project {
		if err := runTier2(ctx, repo, result.Static, &result); err != nil {
			return result, err
		}
	}
	after, err := captureIndexSnapshot(ctx, repo)
	if err != nil {
		return result, exitcode.New(exitcode.Busy, "recapture active index", "", err)
	}
	if !before.same(after) {
		return result, exitcode.New(exitcode.Busy, "reconcile active index", "", errors.New("active index changed during hook validation"))
	}
	return result, nil
}

func runTier2(ctx context.Context, repo *gitrepo.Repository, static treeverify.Report, result *RunReport) (resultErr error) {
	localBefore, err := captureLocalStateSnapshot(repo.GitSealDir())
	if err != nil {
		return exitcode.New(exitcode.GitSafety, "capture local Tier 2 state", "", err)
	}
	indexEntries, err := repo.ListIndex(ctx)
	if err != nil {
		return exitcode.New(exitcode.GitSafety, "read active index for Tier 2", "", err)
	}
	index := make(map[string]gitrepo.TreeEntry, len(indexEntries))
	for _, entry := range indexEntries {
		if entry.Stage != 0 {
			return exitcode.New(exitcode.GitSafety, "prepare Tier 2", entry.Path, errors.New("unmerged index stage"))
		}
		index[entry.Path] = entry.TreeEntry
	}
	head, err := headEntries(ctx, repo)
	if err != nil {
		return exitcode.New(exitcode.GitSafety, "read HEAD for Tier 2", "", err)
	}
	state, err := localstate.Load(repo.GitSealDir())
	if err != nil {
		return exitcode.New(exitcode.GitSafety, "read local baseline for Tier 2", "", err)
	}
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return exitcode.New(exitcode.FilesystemSafety, "open worktree for Tier 2", "", err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, exitcode.New(exitcode.FilesystemSafety, "close worktree after Tier 2", "", closeErr))
		}
	}()

	type localObservation struct {
		exists bool
		sum    digest.Sum
	}
	observed := make(map[string]localObservation, len(static.Mappings))
	impacted := make([]projectconfig.ProtectedFile, 0, len(static.Mappings))
	for _, mapping := range static.Mappings {
		local, exists, err := hashWorkingPlaintext(root, mapping.Source)
		if err != nil {
			return exitcode.New(exitcode.FilesystemSafety, "hash working plaintext", mapping.Source, err)
		}
		observed[mapping.Source] = localObservation{exists: exists, sum: local}
		if !exists {
			continue
		}
		staged, ok := index[mapping.Encrypted]
		if !ok {
			return exitcode.New(exitcode.GitSafety, "prepare Tier 2", mapping.Encrypted, errors.New("staged ciphertext is absent"))
		}
		previous, hadPrevious := head[mapping.Encrypted]
		artifactChanged := !hadPrevious || staged.Mode != previous.Mode || staged.Type != previous.Type || staged.OID != previous.OID
		baseline, hasBaseline := state.Files[mapping.Source]
		if artifactChanged {
			impacted = append(impacted, mapping)
			continue
		}
		if !hasBaseline {
			return exitcode.New(exitcode.GitSafety, "compare working plaintext", mapping.Source, errors.New("local plaintext exists but no trusted baseline is available and no matching artifact change is staged"))
		}
		stagedDigest, err := hashIndexBlob(ctx, repo, staged)
		if err != nil {
			return exitcode.New(exitcode.GitSafety, "hash staged artifact", mapping.Encrypted, err)
		}
		if stagedDigest != baseline.CiphertextSHA256 {
			// The local baseline advanced beyond the prospective index (for
			// example, encryption updated the worktree but the artifact and
			// manifest were not staged). Decrypt the exact staged blob before a
			// commit may rely on the new plaintext baseline.
			impacted = append(impacted, mapping)
			continue
		}
		if baseline.PlaintextSHA256 != local.Hex() {
			return exitcode.New(exitcode.GitSafety, "compare working plaintext", mapping.Source, errors.New("working plaintext changed but its matching encrypted artifact is not staged"))
		}
	}
	if len(impacted) > 0 {
		selected, err := loadSelectedIdentity(repo.GitSealDir())
		if err != nil {
			return exitcode.New(exitcode.MissingIdentity, "load selected identity for mandatory Tier 2", "", err)
		}
		engine, err := agefile.NewEngine(static.RecipientCount)
		if err != nil {
			return exitcode.New(exitcode.InvalidConfig, "construct Tier 2 age engine", "", err)
		}
		for _, mapping := range impacted {
			entry := index[mapping.Encrypted]
			hash := sha256.New()
			err := repo.ConsumeBlob(ctx, entry.OID, limits.DefaultFileBytes, func(reader io.Reader, size int64) error {
				return engine.Decrypt(hash, reader, size, selected.Identity)
			})
			if err != nil {
				return exitcode.New(exitcode.Unauthorized, "authenticate staged artifact for mandatory Tier 2", mapping.Encrypted, err)
			}
			if !equalSHA256(hash.Sum(nil), observed[mapping.Source].sum) {
				return exitcode.New(exitcode.GitSafety, "compare staged artifact plaintext", mapping.Source, errors.New("staged ciphertext decrypts to bytes different from the current working plaintext"))
			}
			result.Tier2Authenticated = append(result.Tier2Authenticated, mapping.Encrypted)
		}
	}
	for _, mapping := range static.Mappings {
		current, exists, err := hashWorkingPlaintext(root, mapping.Source)
		if err != nil {
			return exitcode.New(exitcode.Busy, "recheck working plaintext", mapping.Source, err)
		}
		first := observed[mapping.Source]
		if exists != first.exists || (exists && current != first.sum) {
			return exitcode.New(exitcode.Busy, "reconcile working plaintext", mapping.Source, errors.New("working plaintext changed during hook validation"))
		}
	}
	localAfter, err := captureLocalStateSnapshot(repo.GitSealDir())
	if err != nil {
		return exitcode.New(exitcode.Busy, "recapture local Tier 2 state", "", err)
	}
	if !localBefore.same(localAfter) {
		return exitcode.New(exitcode.Busy, "reconcile local Tier 2 state", "", errors.New("local baseline or identity selection changed during hook validation"))
	}
	return nil
}

func hashIndexBlob(ctx context.Context, repo *gitrepo.Repository, entry gitrepo.TreeEntry) (string, error) {
	hash := sha256.New()
	if err := repo.ConsumeBlob(ctx, entry.OID, limits.DefaultFileBytes, func(reader io.Reader, size int64) error {
		written, err := io.Copy(hash, reader)
		if err != nil || written != size {
			return errors.New("staged artifact blob could not be streamed exactly")
		}
		return nil
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func loadSelectedIdentity(directory string) (identity.Record, error) {
	name, err := localstate.LoadSelection(directory)
	if err != nil {
		return identity.Record{}, err
	}
	if name == "" {
		return identity.Record{}, errors.New("no local identity is selected")
	}
	return identity.Load(name)
}

func hashWorkingPlaintext(root *safefile.Root, source string) (sum digest.Sum, exists bool, resultErr error) {
	configured, err := pathpolicy.Parse(source)
	if err != nil {
		return digest.Sum{}, false, err
	}
	file, err := root.OpenRead(configured)
	if errors.Is(err, os.ErrNotExist) {
		return digest.Sum{}, false, nil
	}
	if err != nil {
		return digest.Sum{}, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	sum, err = safefile.HashExactFile(file, limits.DefaultFileBytes)
	return sum, err == nil, err
}

func equalSHA256(raw []byte, sum digest.Sum) bool {
	return len(raw) == sha256.Size && string(raw) == string(sum[:])
}

func headHasProject(ctx context.Context, repo *gitrepo.Repository) (bool, error) {
	entries, err := headEntries(ctx, repo)
	if err != nil {
		return false, err
	}
	_, ok := entries[".gitseal/config.yaml"]
	return ok, nil
}

func headEntries(ctx context.Context, repo *gitrepo.Repository) (map[string]gitrepo.TreeEntry, error) {
	tree, unborn, err := repo.ResolveHeadTree(ctx)
	if err != nil {
		return nil, err
	}
	if unborn {
		return map[string]gitrepo.TreeEntry{}, nil
	}
	entries, err := repo.ListTree(ctx, tree)
	if err != nil {
		return nil, err
	}
	out := make(map[string]gitrepo.TreeEntry, len(entries))
	for _, entry := range entries {
		out[entry.Path] = entry
	}
	return out, nil
}

func blockingFindings(report treeverify.Report) int {
	count := 0
	for _, finding := range report.Findings {
		if finding.Severity == "error" {
			count++
		}
	}
	return count
}

type indexSnapshot struct {
	files []indexFileSnapshot
}

type indexFileSnapshot struct {
	path   string
	exists bool
	info   os.FileInfo
	sum    [sha256.Size]byte
}

func captureLocalStateSnapshot(directory string) (indexSnapshot, error) {
	state, selection, _ := localstate.Paths(directory)
	paths := []string{state, selection}
	snapshot := indexSnapshot{files: make([]indexFileSnapshot, 0, len(paths))}
	for _, name := range paths {
		file, err := captureIndexFile(name)
		if err != nil {
			return indexSnapshot{}, err
		}
		snapshot.files = append(snapshot.files, file)
	}
	return snapshot, nil
}

func captureIndexSnapshot(ctx context.Context, repo *gitrepo.Repository) (indexSnapshot, error) {
	primary := repo.ActiveIndex()
	if primary == "" {
		primary = filepath.Join(repo.GitDir(), "index")
	}
	paths := []string{filepath.Clean(primary)}
	sharedOut, err := repo.Run(ctx, "rev-parse", "--shared-index-path")
	if err != nil {
		return indexSnapshot{}, err
	}
	shared := strings.TrimSpace(string(sharedOut))
	if shared != "" {
		if !filepath.IsAbs(shared) {
			shared = filepath.Join(repo.Worktree(), shared)
		}
		shared = filepath.Clean(shared)
		base := filepath.Base(shared)
		parent := filepath.Clean(filepath.Dir(shared))
		if !strings.HasPrefix(base, "sharedindex.") || (parent != filepath.Clean(repo.GitDir()) && parent != filepath.Clean(repo.CommonDir())) {
			return indexSnapshot{}, errors.New("split index points outside the validated Git administrative directory")
		}
		paths = append(paths, shared)
	}
	snapshot := indexSnapshot{files: make([]indexFileSnapshot, 0, len(paths))}
	for _, name := range paths {
		file, err := captureIndexFile(name)
		if err != nil {
			return indexSnapshot{}, err
		}
		snapshot.files = append(snapshot.files, file)
	}
	return snapshot, nil
}

func captureIndexFile(name string) (result indexFileSnapshot, resultErr error) {
	result = indexFileSnapshot{path: name}
	lstat, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || !lstat.Mode().IsRegular() || lstat.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("active index component is missing, linked, or not regular")
	}
	if lstat.Size() > limits.DefaultFileBytes {
		return result, errors.New("active index component exceeds the inspection limit")
	}
	file, err := os.Open(name)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(lstat, opened) {
		return result, errors.New("active index component changed while it was opened")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limits.DefaultFileBytes+1))
	if err != nil || written != opened.Size() {
		return result, errors.New("active index component could not be streamed exactly")
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(opened, final) || final.Size() != opened.Size() || final.ModTime() != opened.ModTime() {
		return result, errors.New("active index component changed while it was streamed")
	}
	copy(result.sum[:], hash.Sum(nil))
	result.exists, result.info = true, final
	return result, nil
}

func (s indexSnapshot) same(other indexSnapshot) bool {
	if len(s.files) != len(other.files) {
		return false
	}
	for idx := range s.files {
		a, b := s.files[idx], other.files[idx]
		if a.path != b.path || a.exists != b.exists || a.sum != b.sum {
			return false
		}
		if a.exists && (!os.SameFile(a.info, b.info) || a.info.Size() != b.info.Size() || a.info.ModTime() != b.info.ModTime()) {
			return false
		}
	}
	return true
}
