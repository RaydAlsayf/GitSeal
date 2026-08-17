package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

type InitResult struct{ Completed []string }

type ProjectTrustUpgradeResult struct {
	Completed []string
	Project   projectconfig.Project
}

// PreviewProjectTrustUpgrade reads and validates the current or legacy project
// schema without taking a lock or writing. The mutation path re-reads the exact
// bytes under the lock; this preview is presentation only.
func PreviewProjectTrustUpgrade(ctx context.Context, cwd string) (projectconfig.Project, error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return projectconfig.Project{}, err
	}
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return projectconfig.Project{}, err
	}
	project, _, _, readErr := readProjectForTrustUpgrade(root)
	return project, errors.Join(readErr, root.Close())
}

// UpgradeProjectTrust explicitly migrates project schema v1 and local state v1
// to the retained-safety trust model. The tracked schema is published first so
// an older strict tool immediately refuses it. A later local-state failure is
// safe and resumable: current tools continue to refuse until the exact retained
// digest is accepted and state v2 is saved.
func UpgradeProjectTrust(ctx context.Context, cwd, expectedRetainedSafety, expectedProject string) (result ProjectTrustUpgradeResult, resultErr error) {
	preview, err := PreviewProjectTrustUpgrade(ctx, cwd)
	if err != nil {
		return result, err
	}
	if err := requireAcceptedDigest("retained safety", preview.RetainedSafetyDigest(), expectedRetainedSafety); err != nil {
		return ProjectTrustUpgradeResult{Project: preview, Completed: []string{}}, err
	}
	previewSnapshot, err := ProjectSnapshotDigest(preview)
	if err != nil {
		return ProjectTrustUpgradeResult{Project: preview, Completed: []string{}}, err
	}
	if err := requireAcceptedDigest("project configuration snapshot", previewSnapshot, expectedProject); err != nil {
		return ProjectTrustUpgradeResult{Project: preview, Completed: []string{}}, err
	}
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return result, err
	}
	lock, err := localstate.Acquire(repo.GitSealDir(), "upgrade-project-trust")
	if err != nil {
		return ProjectTrustUpgradeResult{Project: preview, Completed: []string{}}, err
	}
	defer finishLock(lock, "project trust upgrade", &resultErr)
	if unmerged, err := repo.HasUnmerged(ctx); err != nil {
		return result, err
	} else if unmerged {
		return result, errors.New("project trust migration refuses an unmerged index and never selects a side")
	}
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	project, raw, legacy, err := readProjectForTrustUpgrade(root)
	if err != nil {
		return result, err
	}
	result = ProjectTrustUpgradeResult{Project: project, Completed: []string{}}
	if err := requireAcceptedDigest("retained safety", project.RetainedSafetyDigest(), expectedRetainedSafety); err != nil {
		return result, err
	}
	currentSnapshot, err := ProjectSnapshotDigest(project)
	if err != nil {
		return result, err
	}
	if currentSnapshot != previewSnapshot {
		return result, errors.New("project configuration changed after the migration review; refusing a different snapshot")
	}
	if legacy {
		upgraded := project.Canonical()
		upgraded.Version = projectconfig.ProjectVersion
		data, err := upgraded.Marshal()
		if err != nil {
			return result, err
		}
		if err := writeExistingControlRoot(ctx, root, "config.yaml", data, raw); err != nil {
			return result, fmt.Errorf("publish tracked project trust schema: %w", err)
		}
		project = upgraded
		result.Project = upgraded
		result.Completed = append(result.Completed, ".gitseal/config.yaml")
	}
	state, needsMigration, err := localstate.LoadForMigration(repo.GitSealDir())
	if err != nil {
		return result, fmt.Errorf("after completing %v, load local trust state for migration: %w", result.Completed, err)
	}
	want := project.RetainedSafetyDigest().Hex()
	if needsMigration || state.TrustedRetainedSafetySHA256 != want {
		state.Version = localstate.StateVersion
		state.TrustedRetainedSafetySHA256 = want
		if err := localstate.Save(ctx, repo.GitSealDir(), &state); err != nil {
			return result, fmt.Errorf("after completing %v, save local retained-safety trust: %w", result.Completed, err)
		}
		result.Completed = append(result.Completed, "local state v2")
	}
	return result, nil
}

func readProjectForTrustUpgrade(root *safefile.Root) (project projectconfig.Project, raw []byte, legacy bool, resultErr error) {
	file, err := root.OpenControlRead("config.yaml")
	if err != nil {
		return projectconfig.Project{}, nil, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	raw, err = readBounded(file, limits.MaxYAMLBytes)
	if err != nil {
		return projectconfig.Project{}, nil, false, err
	}
	if current, currentErr := projectconfig.ParseProject(raw); currentErr == nil {
		return current, raw, false, nil
	}
	legacyProject, legacyErr := projectconfig.ParseProjectV1ForMigration(raw)
	if legacyErr != nil {
		return projectconfig.Project{}, nil, false, fmt.Errorf("project configuration is neither current nor eligible for explicit trust migration: %w", legacyErr)
	}
	return legacyProject, raw, true, nil
}

func Init(ctx context.Context, cwd string) (result InitResult, resultErr error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return InitResult{}, err
	}
	lock, err := localstate.Acquire(repo.GitSealDir(), "init")
	if err != nil {
		return InitResult{}, err
	}
	defer finishLock(lock, "init", &resultErr)
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return InitResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	if err := root.EnsureControlDirectory(); err != nil {
		return InitResult{}, err
	}
	result = InitResult{Completed: []string{}}
	type control struct {
		name  string
		data  []byte
		parse func([]byte) error
	}
	project := projectconfig.EmptyProject()
	projectData, _ := project.Marshal()
	recipientsData, _ := projectconfig.EmptyRecipients().Marshal()
	manifestData, _ := manifest.Empty().Marshal()
	controls := []control{
		{"config.yaml", projectData, func(data []byte) error {
			parsed, err := projectconfig.ParseProject(data)
			if err == nil {
				project = parsed
			}
			return err
		}},
		{"recipients.yaml", recipientsData, func(data []byte) error { _, _, err := projectconfig.ParseRecipients(data); return err }},
		{"manifest.yaml", manifestData, func(data []byte) error { _, err := manifest.Parse(data); return err }},
	}
	for _, item := range controls {
		file, openErr := root.OpenControlRead(item.name)
		if openErr == nil {
			data, readErr := readBounded(file, limits.MaxYAMLBytes)
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || item.parse(data) != nil {
				return result, fmt.Errorf("existing .gitseal/%s is not valid and was preserved", item.name)
			}
			continue
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			return result, openErr
		}
		if err := writeControlRoot(ctx, root, item.name, item.data, false); err != nil {
			return result, fmt.Errorf("after completing %v, create .gitseal/%s: %w", result.Completed, item.name, err)
		}
		result.Completed = append(result.Completed, ".gitseal/"+item.name)
	}
	for _, managed := range []struct {
		name   string
		render func([]byte, projectconfig.Project) ([]byte, error)
	}{
		{".gitignore", gitignore.Render},
		{".gitattributes", gitattrs.Render},
	} {
		existing, existed, err := readOptionalRoot(root, managed.name)
		if err != nil {
			return result, err
		}
		updated, err := managed.render(existing, project)
		if err != nil {
			return result, fmt.Errorf("existing %s managed block is malformed and was preserved: %w", managed.name, err)
		}
		if string(updated) == string(existing) {
			continue
		}
		if err := writeConfiguredRoot(ctx, root, managed.name, updated, existing, existed, safefile.PublicData); err != nil {
			return result, fmt.Errorf("after completing %v, update %s: %w", result.Completed, managed.name, err)
		}
		result.Completed = append(result.Completed, managed.name)
	}
	return result, nil
}

func readOptionalRoot(root *safefile.Root, name string) (data []byte, exists bool, resultErr error) {
	configured, err := pathpolicy.Parse(name)
	if err != nil {
		return nil, false, err
	}
	file, err := root.OpenRead(configured)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	data, err = readBounded(file, limits.MaxYAMLBytes)
	return data, true, err
}

func writeControlRoot(ctx context.Context, root *safefile.Root, name string, data []byte, replace bool) error {
	candidate, err := root.NewControlCandidate(name, safefile.PublicData)
	if err != nil {
		return err
	}
	return finishCandidate(ctx, candidate, data, replace, nil)
}

func writeExistingControlRoot(ctx context.Context, root *safefile.Root, name string, data, expected []byte) (resultErr error) {
	candidate, err := root.NewControlCandidate(name, safefile.PublicData)
	if err != nil {
		return err
	}
	published := false
	defer abortCandidate(candidate, "upgrade project trust schema", &published, &resultErr)
	if err := candidate.RequireDestination(true, digest.Bytes(expected)); err != nil {
		return fmt.Errorf("project configuration changed after review: %w", err)
	}
	if _, err := candidate.Write(data); err != nil {
		return err
	}
	if err := candidate.FlushClose(); err != nil {
		return err
	}
	if err := candidate.Publish(ctx, true); err != nil {
		return err
	}
	published = true
	return nil
}

func writeConfiguredRoot(ctx context.Context, root *safefile.Root, name string, data, expected []byte, existed bool, sensitivity safefile.Sensitivity) error {
	path, err := pathpolicy.Parse(name)
	if err != nil {
		return err
	}
	candidate, err := root.NewCandidate(path, sensitivity)
	if err != nil {
		return err
	}
	var expectedSum *digest.Sum
	if existed {
		sum := digest.Bytes(expected)
		expectedSum = &sum
	}
	return finishCandidate(ctx, candidate, data, existed, expectedSum)
}

func finishCandidate(ctx context.Context, candidate *safefile.Candidate, data []byte, replace bool, expected *digest.Sum) (resultErr error) {
	published := false
	defer abortCandidate(candidate, "publish project metadata", &published, &resultErr)
	if expected != nil {
		if err := candidate.RequireDestination(true, *expected); err != nil {
			return fmt.Errorf("destination changed after the operation plan was created: %w", err)
		}
	} else if err := candidate.RequireDestination(false, digest.Sum{}); err != nil {
		return fmt.Errorf("destination appeared after the operation plan was created: %w", err)
	}
	if _, err := io.Copy(candidate, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := candidate.FlushClose(); err != nil {
		return err
	}
	if err := candidate.Publish(ctx, replace); err != nil {
		return err
	}
	published = true
	return nil
}
