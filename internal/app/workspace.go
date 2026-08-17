// Package app orchestrates GitSeal use cases from concrete security-boundary
// packages. Prompting and presentation remain in internal/cli.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

type Workspace struct {
	Repo       *gitrepo.Repository
	Root       *safefile.Root
	Project    projectconfig.Project
	Recipients projectconfig.Recipients
	Typed      agefile.HybridRecipients
	Manifest   manifest.Manifest
	controlSum map[string]digest.Sum
}

func Open(ctx context.Context, cwd string) (*Workspace, error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return nil, err
	}
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return nil, err
	}
	w := &Workspace{Repo: repo, Root: root}
	if err := w.reload(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return w, nil
}

func (w *Workspace) Close() error {
	if w == nil || w.Root == nil {
		return nil
	}
	return w.Root.Close()
}

func (w *Workspace) reload() error {
	controlSum := make(map[string]digest.Sum, 3)
	config, err := w.readControl("config.yaml")
	if err != nil {
		return fmt.Errorf("read .gitseal/config.yaml: %w", err)
	}
	w.Project, err = projectconfig.ParseProject(config)
	if err != nil {
		return fmt.Errorf("parse .gitseal/config.yaml: %w", err)
	}
	controlSum["config.yaml"] = digest.Bytes(config)
	recipients, err := w.readControl("recipients.yaml")
	if err != nil {
		return fmt.Errorf("read .gitseal/recipients.yaml: %w", err)
	}
	w.Recipients, w.Typed, err = projectconfig.ParseRecipients(recipients)
	if err != nil {
		return fmt.Errorf("parse .gitseal/recipients.yaml: %w", err)
	}
	controlSum["recipients.yaml"] = digest.Bytes(recipients)
	book, err := w.readControl("manifest.yaml")
	if err != nil {
		return fmt.Errorf("read .gitseal/manifest.yaml: %w", err)
	}
	w.Manifest, err = manifest.Parse(book)
	if err != nil {
		return fmt.Errorf("parse .gitseal/manifest.yaml: %w", err)
	}
	controlSum["manifest.yaml"] = digest.Bytes(book)
	if err := w.Manifest.ValidateProject(w.Project); err != nil {
		return err
	}
	w.controlSum = controlSum
	return nil
}

func (w *Workspace) readControl(name string) (data []byte, resultErr error) {
	file, err := w.Root.OpenControlRead(name)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return readBounded(file, limits.MaxYAMLBytes)
}

func (w *Workspace) ReadConfigured(name string, max int64) (data []byte, resultErr error) {
	p, err := pathpolicy.Parse(name)
	if err != nil {
		return nil, err
	}
	file, err := w.Root.OpenRead(p)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return readBounded(file, max)
}

func (w *Workspace) WriteControl(ctx context.Context, name string, data []byte) (resultErr error) {
	candidate, err := w.Root.NewControlCandidate(name, safefile.PublicData)
	if err != nil {
		return err
	}
	published := false
	defer abortCandidate(candidate, "write GitSeal control file", &published, &resultErr)
	expected, ok := w.controlSum[name]
	if !ok {
		return errors.New("control-file publication has no immutable input snapshot")
	}
	if err := candidate.RequireDestination(true, expected); err != nil {
		return fmt.Errorf("control file changed after the operation plan was created: %w", err)
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
	w.controlSum[name] = digest.Bytes(data)
	return nil
}

// revalidateControlSnapshots confirms that immutable operation-plan inputs
// still have the exact bytes captured by reload. It is called immediately
// before publishing a derived plaintext or ciphertext so a concurrent tracked
// policy edit is not silently reinterpreted as authorization for the old plan.
func (w *Workspace) revalidateControlSnapshots(names ...string) error {
	for _, name := range names {
		expected, ok := w.controlSum[name]
		if !ok {
			return fmt.Errorf("control file %q has no immutable input snapshot", name)
		}
		data, err := w.readControl(name)
		if err != nil {
			return fmt.Errorf("revalidate .gitseal/%s: %w", name, err)
		}
		if digest.Bytes(data) != expected {
			return fmt.Errorf(".gitseal/%s changed after the operation plan was created", name)
		}
	}
	return nil
}

// WriteConfigured publishes data only if the destination still matches the
// exact bytes and existence state used to prepare it. This prevents a late
// editor or concurrent-process update from being reinterpreted as permission to
// overwrite the new file merely because Candidate was created afterward.
func (w *Workspace) WriteConfigured(ctx context.Context, name string, data, expected []byte, existed bool, sensitivity safefile.Sensitivity) (resultErr error) {
	p, err := pathpolicy.Parse(name)
	if err != nil {
		return err
	}
	candidate, err := w.Root.NewCandidate(p, sensitivity)
	if err != nil {
		return err
	}
	published := false
	defer abortCandidate(candidate, "write configured file", &published, &resultErr)
	if existed {
		if err := candidate.RequireDestination(true, digest.Bytes(expected)); err != nil {
			return fmt.Errorf("configured file changed after the operation plan was created: %w", err)
		}
	} else if err := candidate.RequireDestination(false, digest.Sum{}); err != nil {
		return fmt.Errorf("configured file appeared after the operation plan was created: %w", err)
	}
	if _, err := candidate.Write(data); err != nil {
		return err
	}
	if err := candidate.FlushClose(); err != nil {
		return err
	}
	if err := candidate.Publish(ctx, existed); err != nil {
		return err
	}
	published = true
	return nil
}

func readBounded(reader io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("file exceeds configured read limit")
	}
	return data, nil
}
