package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/localstate"
)

// checkWorktreePolicy validates both the owned canonical blocks and their
// effective Git interpretation. Mutation commands call this before publishing
// any ciphertext or plaintext; .gitignore is never treated as evidence that an
// already tracked plaintext is protected.
func (w *Workspace) checkWorktreePolicy(ctx context.Context) error {
	ignoreData, _, err := readOptionalRoot(w.Root, ".gitignore")
	if err != nil {
		return fmt.Errorf("read .gitignore: %w", err)
	}
	if err := gitignore.Validate(ignoreData, w.Project); err != nil {
		return fmt.Errorf("GitSeal .gitignore block is missing or non-canonical: %w", err)
	}
	attributeData, _, err := readOptionalRoot(w.Root, ".gitattributes")
	if err != nil {
		return fmt.Errorf("read .gitattributes: %w", err)
	}
	if err := gitattrs.Validate(attributeData, w.Project); err != nil {
		return fmt.Errorf("GitSeal .gitattributes block is missing or non-canonical: %w", err)
	}

	shouldIgnore := []string{".gitseal.tmp.probe", ".gitseal/.gitseal.tmp.probe"}
	shouldNotIgnore := []string{
		".gitseal/config.yaml", ".gitseal/recipients.yaml", ".gitseal/manifest.yaml",
		".gitattributes", ".gitignore",
	}
	artifacts := make([]string, 0, len(w.Project.ProtectedFiles)+len(w.Project.RetainedSafety.BinaryArtifacts))
	for _, mapping := range w.Project.ProtectedFiles {
		shouldIgnore = append(shouldIgnore, mapping.Source, directoryProbe(mapping.Source), directoryProbe(mapping.Encrypted))
		shouldNotIgnore = append(shouldNotIgnore, mapping.Encrypted)
		artifacts = append(artifacts, mapping.Encrypted)
	}
	for _, retained := range w.Project.RetainedSafety.IgnoredPlaintext {
		shouldIgnore = append(shouldIgnore, retained, directoryProbe(retained))
	}
	for _, retained := range w.Project.RetainedSafety.BinaryArtifacts {
		shouldNotIgnore = append(shouldNotIgnore, retained)
		artifacts = append(artifacts, retained)
		shouldIgnore = append(shouldIgnore, directoryProbe(retained))
	}
	if err := w.Repo.CheckIgnorePolicy(ctx, shouldIgnore, shouldNotIgnore); err != nil {
		return fmt.Errorf("unsafe effective Git ignore policy: %w", err)
	}
	if err := w.Repo.CheckSafeAttributes(ctx, artifacts); err != nil {
		return fmt.Errorf("unsafe effective Git attributes: %w", err)
	}
	return nil
}

func finishLock(lock *localstate.Lock, operation string, resultErr *error) {
	if lock == nil {
		return
	}
	if err := lock.Release(); err != nil {
		releaseErr := fmt.Errorf("%s completed with a lock-release failure: %w", operation, err)
		*resultErr = errors.Join(*resultErr, releaseErr)
	}
}

func abortCandidate(candidate interface{ Abort() error }, operation string, published *bool, resultErr *error) {
	if candidate == nil || published == nil || *published {
		return
	}
	if err := candidate.Abort(); err != nil {
		*resultErr = errors.Join(*resultErr, fmt.Errorf("%s left an owned temporary candidate requiring manual reconciliation: %w", operation, err))
	}
}

func (w *Workspace) refuseTrackedPlaintext(ctx context.Context) error {
	for _, mapping := range w.Project.ProtectedFiles {
		tracked, err := w.Repo.IsTracked(ctx, mapping.Source)
		if err != nil {
			return err
		}
		if tracked {
			return fmt.Errorf("plaintext %q is present in the active index; ignore rules do not protect tracked files", mapping.Source)
		}
	}
	return nil
}

func (w *Workspace) refuseUnmerged(ctx context.Context, operation string) error {
	unmerged, err := w.Repo.HasUnmerged(ctx)
	if err != nil {
		return err
	}
	if unmerged {
		return fmt.Errorf("unmerged index state refuses %s; GitSeal never selects a merge side", operation)
	}
	return nil
}
