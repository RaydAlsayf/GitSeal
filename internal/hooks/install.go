// Package hooks installs and runs GitSeal's local Git hook guardrails. Hooks
// are defense in depth: Git permits --no-verify and does not clone hooks.
package hooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
)

const (
	PreCommit       = "pre-commit"
	PreMergeCommit  = "pre-merge-commit"
	managedFileSize = 16 << 10
)

var supportedHooks = [...]string{PreCommit, PreMergeCommit}

const managedHeader = "#!/bin/sh\n# GitSeal managed hook v1. Do not edit.\n"

type HookChange struct {
	Name   string
	Path   string
	Action string
}

type ChangeReport struct {
	Hooks []HookChange
}

// Inspect reports whether the exact wrappers for the current executable own
// both supported hook locations. It performs no writes.
func Inspect(ctx context.Context, cwd, executable string) (report ChangeReport, resultErr error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "discover hook repository", "", err)
	}
	executable, err = validateExecutable(executable, repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "validate hook executable", "", err)
	}
	configured, err := repo.HasConfiguredHooksPath(ctx)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "inspect core.hooksPath", "", err)
	}
	if configured {
		return ChangeReport{}, &ConflictError{Reason: "core.hooksPath is configured; exact GitSeal wrapper installation cannot be verified"}
	}
	directory, err := openHookDirectory(repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "open rooted hook directory", repo.CommonDir(), err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, exitcode.New(exitcode.FilesystemSafety, "close rooted hook directory", directory.path, closeErr))
		}
	}()
	report = ChangeReport{Hooks: make([]HookChange, 0, len(supportedHooks))}
	for _, name := range supportedHooks {
		hookPath, pathErr := repo.HookPath(ctx, name)
		if pathErr != nil {
			return report, pathErr
		}
		if pathErr = directory.validateResolvedPath(name, hookPath); pathErr != nil {
			return report, pathErr
		}
		want, _ := managedContent(executable, name)
		current, _, readErr := directory.readHook(name)
		action := "managed"
		switch {
		case errors.Is(readErr, os.ErrNotExist):
			action = "missing"
		case readErr != nil:
			action = "unsafe"
		case !bytes.Equal(current, want):
			action = "conflict"
		}
		report.Hooks = append(report.Hooks, HookChange{Name: name, Path: hookPath, Action: action})
	}
	return report, nil
}

// ConflictError means a hook manager or third-party hook already owns the
// location. IntegrationArgs is an argument vector, not a shell command.
type ConflictError struct {
	Name            string
	Path            string
	Reason          string
	IntegrationArgs []string
}

func (e *ConflictError) Error() string {
	if e.Name == "" {
		return e.Reason
	}
	return fmt.Sprintf("hook %s is not managed by GitSeal: %s", e.Name, e.Reason)
}

// Install installs both supported hooks. It preflights both destinations so a
// pre-existing conflict causes no writes. A filesystem race can still produce
// a partial report, which callers must report rather than roll back by deleting
// a pre-existing path.
func Install(ctx context.Context, cwd, executable string) (report ChangeReport, resultErr error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "discover hook repository", "", err)
	}
	executable, err = validateExecutable(executable, repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "validate hook executable", "", err)
	}
	configured, err := repo.HasConfiguredHooksPath(ctx)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "inspect core.hooksPath", "", err)
	}
	if configured {
		return ChangeReport{}, &ConflictError{
			Reason:          "core.hooksPath is configured; GitSeal will not overwrite a hook framework",
			IntegrationArgs: IntegrationArgs(executable, PreCommit),
		}
	}
	directory, err := openHookDirectory(repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "open rooted hook directory", repo.CommonDir(), err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, exitcode.New(exitcode.FilesystemSafety, "close rooted hook directory", directory.path, closeErr))
		}
	}()
	plans, err := planHooks(ctx, repo, directory, executable)
	if err != nil {
		return ChangeReport{}, err
	}
	report = ChangeReport{Hooks: make([]HookChange, 0, len(plans))}
	for _, plan := range plans {
		if plan.exists {
			if err := directory.makeManagedExecutable(plan); err != nil {
				return report, exitcode.New(exitcode.FilesystemSafety, "make managed hook executable", plan.path, err)
			}
			report.Hooks = append(report.Hooks, HookChange{Name: plan.name, Path: plan.path, Action: "unchanged"})
			continue
		}
		if err := directory.createManagedHook(plan.name, plan.content); err != nil {
			return report, exitcode.New(exitcode.FilesystemSafety, "install managed hook", plan.path, err)
		}
		report.Hooks = append(report.Hooks, HookChange{Name: plan.name, Path: plan.path, Action: "installed"})
	}
	return report, nil
}

// Remove verifies both supported hooks and reports absent locations. A present
// exact wrapper is preserved and removal fails closed until the platform layer
// provides a reviewed atomic delete bound to the authenticated file identity.
func Remove(ctx context.Context, cwd, executable string) (report ChangeReport, resultErr error) {
	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "discover hook repository", "", err)
	}
	executable, err = validateExecutable(executable, repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "validate hook executable", "", err)
	}
	configured, err := repo.HasConfiguredHooksPath(ctx)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.GitSafety, "inspect core.hooksPath", "", err)
	}
	if configured {
		return ChangeReport{}, &ConflictError{
			Reason:          "core.hooksPath is configured; GitSeal cannot prove ownership of the configured hook locations",
			IntegrationArgs: IntegrationArgs(executable, PreCommit),
		}
	}
	directory, err := openHookDirectory(repo)
	if err != nil {
		return ChangeReport{}, exitcode.New(exitcode.FilesystemSafety, "open rooted hook directory", repo.CommonDir(), err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, exitcode.New(exitcode.FilesystemSafety, "close rooted hook directory", directory.path, closeErr))
		}
	}()
	plans, err := planHooks(ctx, repo, directory, executable)
	if err != nil {
		return ChangeReport{}, err
	}
	report = ChangeReport{Hooks: make([]HookChange, 0, len(plans))}
	for _, plan := range plans {
		if !plan.exists {
			report.Hooks = append(report.Hooks, HookChange{Name: plan.name, Path: plan.path, Action: "absent"})
			continue
		}
		if err := directory.revalidatePlan(plan); err != nil {
			return report, exitcode.New(exitcode.Busy, "revalidate managed hook", plan.path, err)
		}
		report.Hooks = append(report.Hooks, HookChange{Name: plan.name, Path: plan.path, Action: "preserved"})
		// os.Root.Remove is handle-rooted to the directory, but its final
		// basename is still resolved independently from the file object we just
		// authenticated. An attacker with write access to the hooks directory can
		// replace that basename between revalidation and unlink. Until a reviewed
		// per-platform primitive can delete by the authenticated object identity,
		// refusing is the only operation that cannot remove a third-party hook.
		return report, exitcode.New(exitcode.FilesystemSafety, "remove managed hook", plan.path, errAtomicHookRemovalUnavailable)
	}
	return report, nil
}

// IntegrationArgs returns a safe argument vector for hook frameworks. It does
// not render a shell command containing repository-controlled text.
func IntegrationArgs(executable, name string) []string {
	if !validHookName(name) {
		return nil
	}
	return []string{executable, "hook", "run", name}
}

type hookPlan struct {
	name    string
	path    string
	content []byte
	exists  bool
	info    os.FileInfo
}

func planHooks(ctx context.Context, repo *gitrepo.Repository, directory *hookDirectory, executable string) ([]hookPlan, error) {
	plans := make([]hookPlan, 0, len(supportedHooks))
	for _, name := range supportedHooks {
		hookPath, err := repo.HookPath(ctx, name)
		if err != nil {
			return nil, exitcode.New(exitcode.GitSafety, "resolve hook path", name, err)
		}
		if err := directory.validateResolvedPath(name, hookPath); err != nil {
			return nil, exitcode.New(exitcode.FilesystemSafety, "validate hook directory", hookPath, err)
		}
		content, err := managedContent(executable, name)
		if err != nil {
			return nil, err
		}
		current, info, err := directory.readHook(name)
		if errors.Is(err, os.ErrNotExist) {
			plans = append(plans, hookPlan{name: name, path: hookPath, content: content})
			continue
		}
		if err != nil {
			return nil, exitcode.New(exitcode.FilesystemSafety, "inspect hook", hookPath, err)
		}
		if !bytes.Equal(current, content) {
			return nil, &ConflictError{
				Name: name, Path: hookPath,
				Reason:          "an existing hook is present; it was preserved",
				IntegrationArgs: IntegrationArgs(executable, name),
			}
		}
		plans = append(plans, hookPlan{name: name, path: hookPath, content: content, exists: true, info: info})
	}
	return plans, nil
}

func managedContent(executable, name string) ([]byte, error) {
	if !validHookName(name) {
		return nil, errors.New("unsupported hook name")
	}
	if executable == "" || strings.ContainsAny(executable, "\x00\r\n") {
		return nil, errors.New("invalid hook executable path")
	}
	executable = filepath.ToSlash(executable)
	return []byte(managedHeader + "exec " + shellQuote(executable) + " hook run " + name + "\n"), nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func validateExecutable(value string, repo *gitrepo.Repository) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("hook executable path is empty or malformed")
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("hook executable is missing, linked, or not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve hook executable links: %w", err)
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil || !resolvedInfo.Mode().IsRegular() || !os.SameFile(info, resolvedInfo) {
		return "", errors.New("resolved hook executable identity is not stable")
	}
	for _, parent := range []string{repo.Worktree(), repo.GitDir(), repo.CommonDir()} {
		if parent != "" && pathWithin(resolved, parent) {
			return "", errors.New("hook executable is inside the repository trust boundary")
		}
	}
	return filepath.Clean(resolved), nil
}

var errAtomicHookRemovalUnavailable = errors.New("no deletion occurred: this platform boundary has no reviewed atomic identity-bound hook removal primitive")
var errAtomicWindowsHookInstallUnavailable = errors.New("no hook was created: Windows requires a reviewed atomic no-replace publication primitive before a complete wrapper can become visible")

// hookDirectory keeps all hook access beneath handles bound to the exact Git
// common directory and hooks directory observed during repository discovery.
// os.OpenRoot alone is not sufficient because it may follow the root pathname;
// the before/opened/after identity checks bind those handles to the objects Git
// named and Revalidate detects later pathname replacement.
type hookDirectory struct {
	commonPath string
	path       string
	commonRoot *os.Root
	root       *os.Root
	commonInfo os.FileInfo
	info       os.FileInfo
	closed     bool
}

type openedHook struct {
	file *os.File
	info os.FileInfo
	data []byte
}

func openHookDirectory(repo *gitrepo.Repository) (_ *hookDirectory, resultErr error) {
	commonPath := filepath.Clean(repo.CommonDir())
	if commonPath == "." || !filepath.IsAbs(commonPath) {
		return nil, errors.New("Git common directory is not absolute")
	}
	if err := validateDirectoryComponents(commonPath); err != nil {
		return nil, err
	}
	commonBefore, err := os.Lstat(commonPath)
	if err != nil {
		return nil, fmt.Errorf("inspect Git common directory: %w", err)
	}
	if err := requireRealDirectory(commonBefore, "Git common directory"); err != nil {
		return nil, err
	}
	commonRoot, err := os.OpenRoot(commonPath)
	if err != nil {
		return nil, fmt.Errorf("open Git common directory root: %w", err)
	}
	defer func() {
		if resultErr != nil && commonRoot != nil {
			resultErr = errors.Join(resultErr, commonRoot.Close())
		}
	}()
	commonOpened, err := openedRootInfo(commonRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect opened Git common directory: %w", err)
	}
	commonAfter, err := os.Lstat(commonPath)
	if err != nil || !sameRealDirectory(commonBefore, commonOpened) || !sameRealDirectory(commonBefore, commonAfter) {
		return nil, errors.New("Git common directory changed while its root was opened")
	}
	if err := validateDirectoryComponents(commonPath); err != nil {
		return nil, err
	}

	hooksBefore, err := commonRoot.Lstat("hooks")
	if err != nil {
		return nil, fmt.Errorf("inspect common hook directory: %w", err)
	}
	if err := requireRealDirectory(hooksBefore, "common hook directory"); err != nil {
		return nil, err
	}
	hookRoot, err := commonRoot.OpenRoot("hooks")
	if err != nil {
		return nil, fmt.Errorf("open common hook directory root: %w", err)
	}
	defer func() {
		if resultErr != nil && hookRoot != nil {
			resultErr = errors.Join(resultErr, hookRoot.Close())
		}
	}()
	hooksOpened, err := openedRootInfo(hookRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect opened common hook directory: %w", err)
	}
	hooksAfter, err := commonRoot.Lstat("hooks")
	if err != nil || !sameRealDirectory(hooksBefore, hooksOpened) || !sameRealDirectory(hooksBefore, hooksAfter) {
		return nil, errors.New("common hook directory changed while its root was opened")
	}

	directory := &hookDirectory{
		commonPath: commonPath,
		path:       filepath.Join(commonPath, "hooks"),
		commonRoot: commonRoot,
		root:       hookRoot,
		commonInfo: commonBefore,
		info:       hooksBefore,
	}
	commonRoot = nil
	hookRoot = nil
	return directory, nil
}

func (d *hookDirectory) Close() error {
	if d == nil || d.closed {
		return nil
	}
	d.closed = true
	var resultErr error
	if d.root != nil {
		resultErr = errors.Join(resultErr, d.root.Close())
		d.root = nil
	}
	if d.commonRoot != nil {
		resultErr = errors.Join(resultErr, d.commonRoot.Close())
		d.commonRoot = nil
	}
	return resultErr
}

func (d *hookDirectory) Revalidate() error {
	if d == nil || d.closed || d.root == nil || d.commonRoot == nil {
		return errors.New("hook directory root is closed")
	}
	if err := validateDirectoryComponents(d.commonPath); err != nil {
		return err
	}
	commonByName, err := os.Lstat(d.commonPath)
	if err != nil || !sameRealDirectory(d.commonInfo, commonByName) {
		return errors.New("Git common directory pathname no longer identifies the opened root")
	}
	commonOpened, err := d.commonRoot.Lstat(".")
	if err != nil || !sameRealDirectory(d.commonInfo, commonOpened) {
		return errors.New("opened Git common directory identity changed")
	}
	hooksFromCommon, err := d.commonRoot.Lstat("hooks")
	if err != nil || !sameRealDirectory(d.info, hooksFromCommon) {
		return errors.New("common hook directory pathname no longer identifies the opened root")
	}
	hooksOpened, err := d.root.Lstat(".")
	if err != nil || !sameRealDirectory(d.info, hooksOpened) {
		return errors.New("opened common hook directory identity changed")
	}
	return nil
}

func (d *hookDirectory) validateResolvedPath(name, hookPath string) error {
	if !validHookName(name) {
		return errors.New("unsupported hook name")
	}
	want := filepath.Join(d.path, name)
	if !sameCleanPath(hookPath, want) {
		return errors.New("Git returned a hook path outside the bound common hook directory")
	}
	return d.Revalidate()
}

func (d *hookDirectory) openHook(name string) (_ *openedHook, resultErr error) {
	return d.openHookWithFlags(name, os.O_RDONLY)
}

func (d *hookDirectory) openHookWithFlags(name string, flags int) (_ *openedHook, resultErr error) {
	if !validHookName(name) {
		return nil, errors.New("unsupported hook name")
	}
	if err := d.Revalidate(); err != nil {
		return nil, err
	}
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := requireRegularHook(before); err != nil {
		return nil, err
	}
	file, err := d.root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil && file != nil {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("hook changed while it was opened")
	}
	if err := requireRegularHook(opened); err != nil || !sameRegularHook(before, opened) {
		return nil, errors.New("hook changed while it was opened")
	}
	data, err := readManagedBytes(file)
	if err != nil {
		return nil, err
	}
	openedAfterRead, err := file.Stat()
	if err != nil {
		return nil, errors.New("opened hook identity changed while it was read")
	}
	if err := requireRegularHook(openedAfterRead); err != nil || !sameRegularHook(opened, openedAfterRead) {
		return nil, errors.New("opened hook identity changed while it was read")
	}
	after, err := d.root.Lstat(name)
	if err != nil {
		return nil, errors.New("hook pathname changed while it was read")
	}
	if err := requireRegularHook(after); err != nil || !sameRegularHook(opened, after) {
		return nil, errors.New("hook pathname changed while it was read")
	}
	if err := d.Revalidate(); err != nil {
		return nil, err
	}
	openedFile := file
	file = nil
	return &openedHook{file: openedFile, info: openedAfterRead, data: data}, nil
}

func (d *hookDirectory) readHook(name string) (data []byte, info os.FileInfo, resultErr error) {
	opened, err := d.openHook(name)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, opened.Close())
	}()
	return opened.data, opened.info, nil
}

func (d *hookDirectory) revalidatePlan(plan hookPlan) (resultErr error) {
	opened, err := d.openHook(plan.name)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, opened.Close())
	}()
	if !os.SameFile(plan.info, opened.info) || !bytes.Equal(plan.content, opened.data) {
		return errors.New("hook changed after preflight; no deletion occurred")
	}
	return nil
}

func (d *hookDirectory) makeManagedExecutable(plan hookPlan) (resultErr error) {
	opened, err := d.openHookWithFlags(plan.name, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, opened.Close())
	}()
	if !os.SameFile(plan.info, opened.info) || !bytes.Equal(plan.content, opened.data) {
		return errors.New("hook changed after preflight")
	}
	// Chmod through the authenticated open object. os.Root.Chmod and os.Chmod
	// both resolve the final pathname again and can therefore affect a raced-in
	// third-party hook on Unix.
	securedInfo, err := establishHookPermissions(opened.file)
	if err != nil {
		return err
	}
	if err := opened.file.Sync(); err != nil {
		return err
	}
	if _, err := opened.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	current, err := readManagedBytes(opened.file)
	if err != nil {
		return err
	}
	if !bytes.Equal(plan.content, current) {
		return errors.New("managed hook contents changed while permissions were applied")
	}
	if err := d.revalidateEntry(plan.name, securedInfo); err != nil {
		return err
	}
	if closeErr := opened.Close(); closeErr != nil {
		return closeErr
	}
	return d.sync()
}

func (d *hookDirectory) createManagedHook(name string, content []byte) (resultErr error) {
	if !validHookName(name) {
		return errors.New("unsupported hook name")
	}
	if len(content) == 0 || len(content) > managedFileSize {
		return errors.New("managed hook content has an invalid size")
	}
	if err := d.Revalidate(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Unlike Unix, Windows has no execute-bit barrier that can keep the final
		// basename inert while its bytes are still being written. Publishing from
		// a completed temporary requires a reviewed atomic no-replace primitive
		// and identity-bound cleanup; pathname rename/delete is not sufficient.
		return errAtomicWindowsHookInstallUnavailable
	}
	// O_EXCL makes absence-to-creation atomic and prevents a racing hook from
	// being overwritten. The initial non-executable mode keeps an incomplete
	// wrapper from running; executable permission is applied through this same
	// authenticated handle only after the complete bytes are durable.
	file, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		// Do not remove by pathname on failure. If an attacker renamed the
		// invocation-owned object and substituted another hook, pathname cleanup
		// could delete the substitute. A failed installation therefore leaves at
		// most the object this invocation created and reports the failure.
	}()
	created, err := file.Stat()
	if err != nil {
		return err
	}
	if err := requireRegularHook(created); err != nil {
		return errors.New("new hook is not an opened regular file")
	}
	written, err := io.Copy(file, bytes.NewReader(content))
	if err != nil {
		return err
	}
	if written != int64(len(content)) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	securedInfo, err := establishHookPermissions(file)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := d.revalidateEntry(name, securedInfo); err != nil {
		return err
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return closeErr
	}
	if err := d.sync(); err != nil {
		return err
	}
	current, info, err := d.readHook(name)
	if err != nil {
		return err
	}
	if !os.SameFile(created, info) || !bytes.Equal(current, content) {
		return errors.New("published hook does not match the invocation-owned object")
	}
	return nil
}

func (d *hookDirectory) revalidateEntry(name string, want os.FileInfo) error {
	if err := d.Revalidate(); err != nil {
		return err
	}
	current, err := d.root.Lstat(name)
	if err != nil {
		return errors.New("hook pathname no longer identifies the authenticated object")
	}
	if err := requireRegularHook(current); err != nil || !sameRegularHook(want, current) {
		return errors.New("hook pathname no longer identifies the authenticated object")
	}
	return nil
}

func (d *hookDirectory) sync() (resultErr error) {
	if err := d.Revalidate(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Windows directory handles do not expose the POSIX directory fsync
		// contract. Hook contents and permissions were flushed through the file
		// handle above; crash-durability still requires real NTFS testing.
		return nil
	}
	directory, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, directory.Close())
	}()
	opened, err := directory.Stat()
	if err != nil || !sameRealDirectory(d.info, opened) {
		return errors.New("opened hook directory identity changed before flush")
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return d.Revalidate()
}

func (o *openedHook) Close() error {
	if o == nil || o.file == nil {
		return nil
	}
	err := o.file.Close()
	o.file = nil
	return err
}

func openedRootInfo(root *os.Root) (info os.FileInfo, resultErr error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, directory.Close())
	}()
	info, err = directory.Stat()
	if err != nil {
		return nil, err
	}
	if err := requireRealDirectory(info, "opened root"); err != nil {
		return nil, err
	}
	return info, nil
}

func readManagedBytes(file *os.File) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, managedFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read hook: %w", err)
	}
	if len(data) > managedFileSize {
		return nil, errors.New("hook exceeds the inspection limit")
	}
	return data, nil
}

func requireRealDirectory(info os.FileInfo, label string) error {
	if info == nil || info.Mode().Type() != os.ModeDir {
		return fmt.Errorf("%s is linked or not a directory", label)
	}
	return nil
}

func sameRealDirectory(want, got os.FileInfo) bool {
	return want != nil && got != nil && want.Mode().Type() == os.ModeDir && got.Mode().Type() == os.ModeDir && os.SameFile(want, got)
}

func requireRegularHook(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("hook is linked or not a regular file")
	}
	if runtime.GOOS != "windows" {
		links, ok := portableLinkCount(info)
		if !ok {
			return errors.New("hook hard-link count is unavailable on this platform")
		}
		if links != 1 {
			return errors.New("hook has multiple hard links")
		}
	}
	return nil
}

func sameRegularHook(want, got os.FileInfo) bool {
	return want != nil && got != nil && want.Mode().IsRegular() && got.Mode().IsRegular() &&
		want.Mode()&os.ModeSymlink == 0 && got.Mode()&os.ModeSymlink == 0 && os.SameFile(want, got)
}

func establishHookPermissions(file *os.File) (os.FileInfo, error) {
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := requireRegularHook(before); err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		// Git for Windows does not use POSIX execute bits. Do not clear a
		// read-only attribute here: that would mutate every hard-link alias, and
		// FileInfo does not expose a link count on Windows.
		if before.Mode().Perm()&0o200 == 0 {
			return nil, errors.New("managed Windows hook is read-only and cannot be changed safely")
		}
		return before, nil
	}
	if before.Mode().Perm() != 0o755 {
		if err := file.Chmod(0o755); err != nil {
			return nil, err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := requireRegularHook(after); err != nil {
		return nil, err
	}
	if after.Mode().Perm() != 0o755 {
		return nil, fmt.Errorf("managed hook mode is %04o after chmod, want 0755", after.Mode().Perm())
	}
	return after, nil
}

func portableLinkCount(info os.FileInfo) (uint64, bool) {
	if info == nil || info.Sys() == nil {
		return 0, false
	}
	value := reflect.ValueOf(info.Sys())
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < 0 {
			return 0, false
		}
		return uint64(field.Int()), true
	default:
		return 0, false
	}
}

func sameCleanPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func validateDirectoryComponents(name string) error {
	name = filepath.Clean(name)
	if !filepath.IsAbs(name) {
		return errors.New("directory path is not absolute")
	}
	volume := filepath.VolumeName(name)
	remainder := strings.TrimPrefix(name, volume)
	components := splitDirectoryComponents(remainder, rune(filepath.Separator))
	current := volume
	if current == "" {
		current = string(filepath.Separator)
	} else if !strings.HasSuffix(current, string(filepath.Separator)) {
		current += string(filepath.Separator)
	}
	if info, err := os.Lstat(current); err != nil || info.Mode().Type() != os.ModeDir {
		return errors.New("directory volume root is linked, unavailable, or not a directory")
	}
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect directory path component: %w", err)
		}
		if info.Mode().Type() != os.ModeDir {
			return fmt.Errorf("directory path component %q is linked or not a directory", current)
		}
	}
	return nil
}

func splitDirectoryComponents(name string, separator rune) []string {
	name = strings.TrimLeftFunc(name, func(value rune) bool { return value == separator })
	return strings.FieldsFunc(name, func(value rune) bool { return value == separator })
}

func validHookName(name string) bool {
	return name == PreCommit || name == PreMergeCommit
}

func pathWithin(candidate, parent string) bool {
	rel, err := filepath.Rel(parent, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	if runtime.GOOS == "windows" {
		return !strings.HasPrefix(strings.ToLower(rel), ".."+string(filepath.Separator))
	}
	return true
}
