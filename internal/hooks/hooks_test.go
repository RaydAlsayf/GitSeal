package hooks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestManagedContentIsDeterministicAndQuoted(t *testing.T) {
	content, err := managedContent(`C:\Program Files\Rayd's\gitseal.exe`, PreCommit)
	if err != nil {
		t.Fatal(err)
	}
	want := "#!/bin/sh\n# GitSeal managed hook v1. Do not edit.\nexec 'C:/Program Files/Rayd'\"'\"'s/gitseal.exe' hook run pre-commit\n"
	if string(content) != want {
		t.Fatalf("wrapper differs\nwant: %q\n got: %q", want, content)
	}
	if _, err := managedContent("gitseal", "post-commit"); err == nil {
		t.Fatal("unsupported hook name accepted")
	}
	if got := IntegrationArgs("gitseal", "post-commit"); got != nil {
		t.Fatalf("unsupported integration args: %q", got)
	}
}

func TestDirectoryComponentsUseOnlyThePlatformSeparator(t *testing.T) {
	got := splitDirectoryComponents(`/one/two\three/four`, '/')
	want := []string{"one", `two\three`, "four"}
	if len(got) != len(want) {
		t.Fatalf("Unix-style components = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("Unix-style components = %#v, want %#v", got, want)
		}
	}
}

func TestInstallAndRemoveManagedHooks(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)

	report, err := Install(context.Background(), repo, executable)
	if runtime.GOOS == "windows" {
		if err == nil || !errors.Is(err, errAtomicWindowsHookInstallUnavailable) || len(report.Hooks) != 0 {
			t.Fatalf("new Windows hook installation did not fail closed: %#v, %T: %v", report, err, err)
		}
		for _, name := range supportedHooks {
			if _, statErr := os.Lstat(filepath.Join(repo, ".git", "hooks", name)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("Windows hook became visible despite fail-closed install: %s: %v", name, statErr)
			}
		}
		seedManagedHookFixtures(t, repo, executable)
	} else {
		if err != nil {
			t.Fatal(err)
		}
		assertActions(t, report, "installed", "installed")
	}
	for _, name := range supportedHooks {
		path := filepath.Join(repo, ".git", "hooks", name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := managedContent(executable, name)
		if !bytes.Equal(got, want) || bytes.Contains(got, []byte("\r\n")) {
			t.Fatalf("managed %s wrapper differs: %q", name, got)
		}
		if runtime.GOOS != "windows" {
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Fatal(statErr)
			}
			links, linksOK := portableLinkCount(info)
			if info.Mode().Perm() != 0o755 || !linksOK || links != 1 {
				t.Fatalf("managed %s mode/link state = %v/%d/%v", name, info.Mode().Perm(), links, linksOK)
			}
		}
	}

	report, err = Install(context.Background(), repo, executable)
	if err != nil {
		t.Fatal(err)
	}
	assertActions(t, report, "unchanged", "unchanged")
	inspected, err := Inspect(context.Background(), repo, executable)
	if err != nil {
		t.Fatal(err)
	}
	assertActions(t, inspected, "managed", "managed")

	report, err = Remove(context.Background(), repo, executable)
	if err == nil || exitcode.Of(err) != exitcode.FilesystemSafety || !errors.Is(err, errAtomicHookRemovalUnavailable) || !strings.Contains(err.Error(), "no deletion occurred") {
		t.Fatalf("present hook removal did not fail closed: %#v, %T: %v", report, err, err)
	}
	assertActions(t, report, "preserved")
	for _, name := range supportedHooks {
		path := filepath.Join(repo, ".git", "hooks", name)
		got, readErr := os.ReadFile(path)
		want, _ := managedContent(executable, name)
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed despite fail-closed removal: %q, %v", name, got, readErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			t.Fatalf("remove test fixture hook %s: %v", name, removeErr)
		}
	}
	report, err = Remove(context.Background(), repo, executable)
	if err != nil {
		t.Fatal(err)
	}
	assertActions(t, report, "absent", "absent")
	inspected, err = Inspect(context.Background(), repo, executable)
	if err != nil {
		t.Fatal(err)
	}
	assertActions(t, inspected, "missing", "missing")
}

func TestInstallPreservesThirdPartyHookWithoutPartialWrite(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	thirdParty := []byte("#!/bin/sh\nexit 42\n")
	preCommit := filepath.Join(repo, ".git", "hooks", PreCommit)
	if err := os.WriteFile(preCommit, thirdParty, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Install(context.Background(), repo, executable)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.Name != PreCommit {
		t.Fatalf("expected pre-commit conflict, got %T: %v", err, err)
	}
	got, readErr := os.ReadFile(preCommit)
	if readErr != nil || !bytes.Equal(got, thirdParty) {
		t.Fatalf("third-party hook changed: %q, %v", got, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(repo, ".git", "hooks", PreMergeCommit)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("preflight created second hook: %v", statErr)
	}
}

func TestInstallRefusesConfiguredHooksPath(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	runGit(t, repo, "config", "core.hooksPath", "managed-hooks")

	_, err := Install(context.Background(), repo, executable)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || !strings.Contains(conflict.Reason, "core.hooksPath") {
		t.Fatalf("expected core.hooksPath conflict, got %T: %v", err, err)
	}
	for _, name := range supportedHooks {
		if _, statErr := os.Lstat(filepath.Join(repo, ".git", "hooks", name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("default hook was written despite core.hooksPath: %s: %v", name, statErr)
		}
	}
}

func TestInstallRefusesSymlinkHook(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	target := filepath.Join(parent, "third-party-hook")
	if err := os.WriteFile(target, []byte("third party\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, ".git", "hooks", PreCommit)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := Install(context.Background(), repo, executable); err == nil {
		t.Fatal("symlink hook was accepted")
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink hook was changed: %v", err)
	}
}

func TestInstallExclusiveCreatePreservesRacedInHook(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repoPath := filepath.Join(parent, "repo")
	initRepository(t, repoPath)
	executable := fakeExecutable(t, parent)
	repo, err := gitrepo.Discover(context.Background(), repoPath, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openHookDirectory(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close hook directory: %v", err)
		}
	})
	plans, err := planHooks(context.Background(), repo, directory, executable)
	if err != nil {
		t.Fatal(err)
	}
	thirdParty := []byte("#!/bin/sh\nexit 73\n")
	path := filepath.Join(repoPath, ".git", "hooks", PreCommit)
	if err := os.WriteFile(path, thirdParty, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := directory.createManagedHook(plans[0].name, plans[0].content); err == nil {
		t.Fatal("exclusive hook creation overwrote a raced-in hook")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, thirdParty) {
		t.Fatalf("raced-in hook changed: %q, %v", got, err)
	}
}

func TestInstallHandleChmodRejectsPreflightReplacement(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repoPath := filepath.Join(parent, "repo")
	initRepository(t, repoPath)
	executable := fakeExecutable(t, parent)
	if runtime.GOOS == "windows" {
		seedManagedHookFixtures(t, repoPath, executable)
	} else if _, err := Install(context.Background(), repoPath, executable); err != nil {
		t.Fatal(err)
	}
	repo, err := gitrepo.Discover(context.Background(), repoPath, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openHookDirectory(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close hook directory: %v", err)
		}
	})
	plans, err := planHooks(context.Background(), repo, directory, executable)
	if err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(repoPath, ".git", "hooks", PreCommit)
	managedBackup := hookPath + ".managed-test-backup"
	if err := os.Rename(hookPath, managedBackup); err != nil {
		t.Fatal(err)
	}
	thirdParty := []byte("#!/bin/sh\nexit 74\n")
	if err := os.WriteFile(hookPath, thirdParty, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(hookPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := directory.makeManagedExecutable(plans[0]); err == nil {
		t.Fatal("preflight replacement was treated as the managed hook")
	}
	got, err := os.ReadFile(hookPath)
	if err != nil || !bytes.Equal(got, thirdParty) {
		t.Fatalf("replacement hook contents changed: %q, %v", got, err)
	}
	after, err := os.Lstat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("replacement hook mode changed: before %o, after %o", before.Mode().Perm(), after.Mode().Perm())
	}
	wantManaged, _ := managedContent(executable, PreCommit)
	managed, err := os.ReadFile(managedBackup)
	if err != nil || !bytes.Equal(managed, wantManaged) {
		t.Fatalf("preflighted managed object changed: %q, %v", managed, err)
	}
}

func TestInstallRefusesHardLinkedManagedHookBeforeChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows FileInfo does not expose a hard-link count; absent-hook installation already fails closed")
	}
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	if _, err := Install(context.Background(), repo, executable); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(repo, ".git", "hooks", PreCommit)
	if err := os.Chmod(hookPath, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "managed-hook-alias")
	if err := os.Link(hookPath, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	if _, err := Install(context.Background(), repo, executable); err == nil || exitcode.Of(err) != exitcode.FilesystemSafety {
		t.Fatalf("hard-linked managed hook was accepted: %T: %v", err, err)
	}
	for _, path := range []string{hookPath, alias} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("hard-linked object was chmodded through %q: mode %04o", path, info.Mode().Perm())
		}
	}
}

func TestRemovePreflightsAllHooksWithoutPartialDeletion(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	if runtime.GOOS == "windows" {
		seedManagedHookFixtures(t, repo, executable)
	} else if _, err := Install(context.Background(), repo, executable); err != nil {
		t.Fatal(err)
	}
	preMerge := filepath.Join(repo, ".git", "hooks", PreMergeCommit)
	thirdParty := []byte("#!/bin/sh\nexit 75\n")
	if err := os.WriteFile(preMerge, thirdParty, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Remove(context.Background(), repo, executable)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.Name != PreMergeCommit {
		t.Fatalf("expected pre-merge-commit conflict, got %T: %v", err, err)
	}
	preCommit := filepath.Join(repo, ".git", "hooks", PreCommit)
	wantManaged, _ := managedContent(executable, PreCommit)
	managed, readErr := os.ReadFile(preCommit)
	if readErr != nil || !bytes.Equal(managed, wantManaged) {
		t.Fatalf("managed hook changed during failed preflight: %q, %v", managed, readErr)
	}
	gotThirdParty, readErr := os.ReadFile(preMerge)
	if readErr != nil || !bytes.Equal(gotThirdParty, thirdParty) {
		t.Fatalf("third-party hook changed during failed preflight: %q, %v", gotThirdParty, readErr)
	}
}

func TestInstallRefusesLinkedHookDirectory(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	initRepository(t, repo)
	executable := fakeExecutable(t, parent)
	hooksPath := filepath.Join(repo, ".git", "hooks")
	originalHooks := filepath.Join(repo, ".git", "hooks-original-test")
	if err := os.Rename(hooksPath, originalHooks); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(parent, "external-hooks")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, hooksPath); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	if _, err := Install(context.Background(), repo, executable); err == nil {
		t.Fatal("linked hook directory was accepted")
	}
	entries, err := os.ReadDir(external)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("linked external hook directory was modified: %v", entries)
	}
}

func TestRunNoProjectPreservesExactIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	writeFile(t, dir, "ordinary.txt", []byte("staged\n"))
	runGit(t, dir, "add", "ordinary.txt")
	index := filepath.Join(dir, ".git", "index")
	before := fileSHA256(t, index)

	report, err := Run(context.Background(), dir, PreCommit)
	if err != nil || !report.Static.OK() || report.Static.Project {
		t.Fatalf("ordinary prospective index rejected: %#v, %v", report, err)
	}
	if after := fileSHA256(t, index); after != before {
		t.Fatal("active index changed during hook validation")
	}
}

func TestRunIgnoresOnlyGitSuppliedHookRedirects(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	writeFile(t, dir, "ordinary.txt", []byte("staged\n"))
	runGit(t, dir, "add", "ordinary.txt")

	// Git itself exports these variables when it invokes a hook (GIT_DIR is
	// especially common in linked worktrees). Run must rediscover from cwd and
	// must not treat either value as repository authority.
	t.Setenv("GIT_DIR", filepath.Join(dir, "not-authority"))
	t.Setenv("GIT_EXEC_PATH", filepath.Join(dir, "not-authority"))
	report, err := Run(context.Background(), dir, PreCommit)
	if err != nil || !report.Static.OK() || report.Static.Project {
		t.Fatalf("documented Git hook environment was not safely ignored: %#v, %v", report, err)
	}
}

func TestRunStillRejectsHookConfigInjection(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	t.Setenv("GIT_EXEC_PATH", filepath.Join(dir, "not-authority"))
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", filepath.Join(dir, "attacker-hooks"))

	if _, err := Run(context.Background(), dir, PreCommit); err == nil || !strings.Contains(err.Error(), "GIT_CONFIG_COUNT") {
		t.Fatalf("Git config injection was not rejected: %v", err)
	}
}

func TestRunStillRejectsHookWorktreeRedirect(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	t.Setenv("GIT_EXEC_PATH", filepath.Join(dir, "not-authority"))
	t.Setenv("GIT_WORK_TREE", filepath.Join(dir, "attacker-worktree"))

	if _, err := Run(context.Background(), dir, PreCommit); err == nil || !strings.Contains(err.Error(), "GIT_WORK_TREE") {
		t.Fatalf("Git worktree redirect was not rejected: %v", err)
	}
}

func TestRunDoesNotFallBackFromUntrustedActiveIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	writeFile(t, dir, "ordinary.txt", []byte("staged\n"))
	runGit(t, dir, "add", "ordinary.txt")
	original := filepath.Join(dir, ".git", "index")
	untrusted := filepath.Join(dir, ".git", "attacker-index")
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(untrusted, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_INDEX_FILE", untrusted)

	_, err = Run(context.Background(), dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety {
		t.Fatalf("untrusted active index did not fail closed: %T: %v", err, err)
	}
	if got := fileSHA256(t, original); got != fileSHA256(t, untrusted) {
		t.Fatal("test index files unexpectedly diverged")
	}
}

func TestRunUsesSupportedInheritedTemporaryIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	defaultIndex := filepath.Join(fixture.dir, ".git", "index")
	temporaryIndex := filepath.Join(fixture.dir, ".git", "next-index-hook-test")
	data, err := os.ReadFile(defaultIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporaryIndex, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fixture.dir, ".env", fixture.plaintext)
	runGitWithIndex(t, fixture.dir, temporaryIndex, "add", "-f", ".env")
	defaultBefore, temporaryBefore := fileSHA256(t, defaultIndex), fileSHA256(t, temporaryIndex)
	t.Setenv("GIT_INDEX_FILE", temporaryIndex)

	report, err := Run(context.Background(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "tracked_plaintext") {
		t.Fatalf("unsafe inherited temporary index was not validated: %#v, %v", report, err)
	}
	if fileSHA256(t, defaultIndex) != defaultBefore || fileSHA256(t, temporaryIndex) != temporaryBefore {
		t.Fatal("default or inherited temporary index changed during validation")
	}
}

func TestLinkedWorktreeUsesCommonHooksAndWorktreeIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	parent := t.TempDir()
	main := filepath.Join(parent, "main")
	linked := filepath.Join(parent, "linked")
	initRepository(t, main)
	writeFile(t, main, "ordinary.txt", []byte("base\n"))
	runGit(t, main, "add", "ordinary.txt")
	runGit(t, main, "commit", "-qm", "base")
	runGit(t, main, "worktree", "add", "-q", "-b", "linked", linked)
	executable := fakeExecutable(t, parent)

	report, err := Install(context.Background(), linked, executable)
	wantActions := []string{"installed", "installed"}
	if runtime.GOOS == "windows" {
		if err == nil || !errors.Is(err, errAtomicWindowsHookInstallUnavailable) {
			t.Fatalf("new linked-worktree Windows hook installation did not fail closed: %#v, %v", report, err)
		}
		seedManagedHookFixtures(t, main, executable)
		report, err = Install(context.Background(), linked, executable)
		wantActions = []string{"unchanged", "unchanged"}
	}
	if err != nil {
		t.Fatal(err)
	}
	assertActions(t, report, wantActions...)
	commonHooks := filepath.Join(main, ".git", "hooks")
	for _, hook := range report.Hooks {
		if filepath.Clean(filepath.Dir(hook.Path)) != filepath.Clean(commonHooks) {
			t.Fatalf("linked-worktree hook path = %q, want common %q", hook.Path, commonHooks)
		}
	}
	writeFile(t, linked, "linked.txt", []byte("staged\n"))
	runGit(t, linked, "add", "linked.txt")
	runReport, err := Run(context.Background(), linked, PreCommit)
	if err != nil || !runReport.Static.OK() {
		t.Fatalf("linked-worktree active index rejected: %#v, %v", runReport, err)
	}
}

func TestRunValidProjectAndTrackedPlaintext(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)

	report, err := Run(context.Background(), fixture.dir, PreCommit)
	if err != nil || !report.Static.OK() || !report.Static.Project {
		t.Fatalf("valid unchanged project rejected: %#v, %v", report, err)
	}
	writeFile(t, fixture.dir, ".env", fixture.plaintext)
	runGit(t, fixture.dir, "add", "-f", ".env")
	report, err = Run(context.Background(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "tracked_plaintext") {
		t.Fatalf("tracked plaintext was not blocked: %#v, %v", report, err)
	}
}

func TestRunRejectsStagedEffectiveAttributeOverride(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	attributes, err := os.ReadFile(filepath.Join(fixture.dir, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	attributes = append(attributes, []byte("/.env.age text\n")...)
	writeFile(t, fixture.dir, ".gitattributes", attributes)
	runGit(t, fixture.dir, "add", ".gitattributes")

	report, err := Run(context.Background(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "unsafe_index_attributes") {
		t.Fatalf("effective staged attribute override was not blocked: %#v, %v", report, err)
	}
}

func TestRunRejectsStagedEffectiveIgnoreOverride(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	ignore, err := os.ReadFile(filepath.Join(fixture.dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	ignore = append(ignore, []byte("!/.env\n")...)
	writeFile(t, fixture.dir, ".gitignore", ignore)
	runGit(t, fixture.dir, "add", ".gitignore")

	report, err := Run(context.Background(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "unsafe_index_ignore") {
		t.Fatalf("effective staged ignore override was not blocked: %#v, %v", report, err)
	}
}

func TestRunRefusesDeletingProjectFromProspectiveIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	runGit(t, fixture.dir, "rm", "-q", "-f", ".gitseal/config.yaml", ".gitseal/recipients.yaml", ".gitseal/manifest.yaml", ".env.age", ".gitignore", ".gitattributes")

	report, err := Run(context.Background(), fixture.dir, PreMergeCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "project_required") {
		t.Fatalf("project deletion was not blocked: %#v, %v", report, err)
	}
}

func TestRunMandatoryTier2FailsWithoutIdentity(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	writeFile(t, fixture.dir, ".env", fixture.plaintext)
	ciphertext := encrypt(t, fixture.identity, fixture.recipients, fixture.plaintext)
	writeFile(t, fixture.dir, ".env.age", ciphertext)
	book := manifestFor(ciphertext, fixture.recipients)
	manifestBytes, err := book.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, fixture.dir, ".gitseal/manifest.yaml", manifestBytes)
	runGit(t, fixture.dir, "add", "-f", ".env.age", ".gitseal/manifest.yaml")

	report, err := Run(context.Background(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.MissingIdentity || !report.Static.OK() {
		t.Fatalf("mandatory Tier 2 did not fail closed without identity: %#v, %v", report, err)
	}
}

func TestRunRefusesUnmergedIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	dir := t.TempDir()
	initRepository(t, dir)
	writeFile(t, dir, "conflict.txt", []byte("base\n"))
	runGit(t, dir, "add", "conflict.txt")
	runGit(t, dir, "commit", "-qm", "base")
	runGit(t, dir, "switch", "-qc", "side")
	writeFile(t, dir, "conflict.txt", []byte("side\n"))
	runGit(t, dir, "commit", "-qam", "side")
	runGit(t, dir, "switch", "-q", "master")
	writeFile(t, dir, "conflict.txt", []byte("main\n"))
	runGit(t, dir, "commit", "-qam", "main")
	runGitFailure(t, dir, "merge", "--no-edit", "side")

	report, err := Run(context.Background(), dir, PreMergeCommit)
	if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, "unmerged_index") {
		t.Fatalf("unmerged index was not blocked: %#v, %v", report, err)
	}
}

func TestRunRejectsHiddenProtectedIndexEntries(t *testing.T) {
	requireGit(t)
	for _, test := range []struct {
		name string
		flag string
		code string
	}{
		{name: "assume-unchanged", flag: "--assume-unchanged", code: "assume_unchanged"},
		{name: "skip-worktree", flag: "--skip-worktree", code: "skip_worktree"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearGitEnvironment(t)
			fixture := newProjectFixture(t)
			runGit(t, fixture.dir, "update-index", test.flag, "--", ".env.age")

			report, err := Run(context.Background(), fixture.dir, PreCommit)
			if err == nil || exitcode.Of(err) != exitcode.GitSafety || !reportHasCode(report, test.code) {
				t.Fatalf("protected index flag %s was not blocked: %#v, %v", test.flag, report, err)
			}
		})
	}
}

func TestGitCommitInvokesHookWithExactCandidateIndex(t *testing.T) {
	requireGit(t)
	for _, test := range []struct {
		name      string
		arguments []string
		wantIndex func(string) bool
	}{
		{
			name:      "commit-all-index-lock",
			arguments: []string{"commit", "-q", "-a", "-m", "unsafe candidate"},
			wantIndex: func(base string) bool { return base == "index.lock" },
		},
		{
			name:      "commit-only-next-index",
			arguments: []string{"commit", "-q", "--only", "-m", "unsafe candidate", "--", "probe.txt"},
			wantIndex: func(base string) bool {
				return strings.HasPrefix(base, "next-index-") && strings.HasSuffix(base, ".lock")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearGitEnvironment(t)
			fixture := newProjectFixture(t)
			writeFile(t, fixture.dir, "probe.txt", []byte("safe base\n"))
			runGit(t, fixture.dir, "add", "probe.txt")
			runGit(t, fixture.dir, "commit", "-qm", "add probe")

			var private bytes.Buffer
			if err := fixture.identity.WritePrivate(&private); err != nil {
				t.Fatal(err)
			}
			writeFile(t, fixture.dir, "probe.txt", private.Bytes())
			installHookTestHelper(t, fixture.dir, PreCommit)
			resultPath := filepath.Join(t.TempDir(), "hook-result.txt")
			beforeHead := runGitOutput(t, fixture.dir, "rev-parse", "HEAD")
			indexPath := filepath.Join(fixture.dir, ".git", "index")
			beforeIndex := fileSHA256(t, indexPath)

			cmd := exec.Command("git", append([]string{"-C", fixture.dir}, test.arguments...)...)
			cmd.Env = append(os.Environ(),
				"GITSEAL_HOOK_TEST_HELPER=1",
				"GITSEAL_HOOK_TEST_RESULT="+resultPath,
			)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("unsafe candidate commit succeeded: %s", output)
			}
			result, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatalf("hook helper did not report the candidate index: %v", err)
			}
			fields := strings.Split(strings.TrimSpace(string(result)), "\n")
			if len(fields) != 4 || fields[0] != "blocked=true" || fields[1] != "finding=private_identity" || !strings.HasPrefix(fields[2], "index=") || fields[3] != "operation=verify prospective index" {
				t.Fatalf("unexpected hook helper result: %q", result)
			}
			if base := strings.TrimPrefix(fields[2], "index="); !test.wantIndex(base) {
				t.Fatalf("hook validated index %q for %s", base, test.name)
			}
			if afterHead := runGitOutput(t, fixture.dir, "rev-parse", "HEAD"); afterHead != beforeHead {
				t.Fatalf("blocked hook changed HEAD: before %s after %s", beforeHead, afterHead)
			}
			if afterIndex := fileSHA256(t, indexPath); afterIndex != beforeIndex {
				t.Fatal("blocked hook changed the default index")
			}
		})
	}
}

func TestGitMergeInvokesPreMergeCommitOnCandidateIndex(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	var private bytes.Buffer
	if err := fixture.identity.WritePrivate(&private); err != nil {
		t.Fatal(err)
	}
	runGit(t, fixture.dir, "switch", "-qc", "unsafe-side")
	writeFile(t, fixture.dir, "merged-private.txt", private.Bytes())
	runGit(t, fixture.dir, "add", "merged-private.txt")
	runGit(t, fixture.dir, "commit", "-qm", "unsafe side")
	runGit(t, fixture.dir, "switch", "-q", "master")
	writeFile(t, fixture.dir, "main-only.txt", []byte("force a merge commit\n"))
	runGit(t, fixture.dir, "add", "main-only.txt")
	runGit(t, fixture.dir, "commit", "-qm", "diverge main")
	installHookTestHelper(t, fixture.dir, PreMergeCommit)
	resultPath := filepath.Join(t.TempDir(), "hook-result.txt")
	beforeHead := runGitOutput(t, fixture.dir, "rev-parse", "HEAD")

	cmd := exec.Command("git", "-C", fixture.dir, "merge", "--no-edit", "unsafe-side")
	cmd.Env = append(os.Environ(),
		"GITSEAL_HOOK_TEST_HELPER=1",
		"GITSEAL_HOOK_TEST_RESULT="+resultPath,
	)
	output, mergeErr := cmd.CombinedOutput()
	if mergeErr == nil {
		t.Fatalf("unsafe automatic merge succeeded: %s", output)
	}
	result, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("pre-merge helper did not report the candidate index: %v", err)
	}
	if got := strings.TrimSpace(string(result)); got != "blocked=true\nfinding=private_identity\nindex=index\noperation=verify prospective index" {
		t.Fatalf("unexpected pre-merge helper result: %q; Git output: %s", result, output)
	}
	if afterHead := runGitOutput(t, fixture.dir, "rev-parse", "HEAD"); afterHead != beforeHead {
		t.Fatalf("blocked pre-merge hook changed HEAD: before %s after %s", beforeHead, afterHead)
	}
}

// TestGitHookRunHelper is re-executed by Git's real hook process. It records
// only the security result and candidate-index basename; no repository content
// or environment value is copied into the parent test output.
func TestGitHookRunHelper(t *testing.T) {
	if os.Getenv("GITSEAL_HOOK_TEST_HELPER") != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		t.Fatal("hook helper name is missing")
	}
	report, runErr := Run(context.Background(), ".", os.Args[separator+1])
	finding := ""
	for _, current := range report.Static.Findings {
		if current.Code == "private_identity" {
			finding = current.Code
			break
		}
	}
	indexBase := filepath.Base(os.Getenv("GIT_INDEX_FILE"))
	operation := ""
	var coded *exitcode.Error
	if errors.As(runErr, &coded) {
		operation = coded.Op
	}
	result := fmt.Sprintf("blocked=%t\nfinding=%s\nindex=%s\noperation=%s\n", runErr != nil, finding, indexBase, operation)
	if err := os.WriteFile(os.Getenv("GITSEAL_HOOK_TEST_RESULT"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Logf("hook helper blocked: %v", runErr)
		t.FailNow()
	}
}

type projectFixture struct {
	dir        string
	identity   agefile.HybridIdentity
	recipients agefile.HybridRecipients
	plaintext  []byte
}

func newProjectFixture(t *testing.T) projectFixture {
	t.Helper()
	dir := t.TempDir()
	initRepository(t, dir)
	identityValue, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := agefile.NewHybridRecipients([]string{identityValue.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("test secret\n")
	ciphertext := encrypt(t, identityValue, recipients, plaintext)
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = []projectconfig.ProtectedFile{{Source: ".env", Encrypted: ".env.age"}}
	recipientConfig := projectconfig.Recipients{Version: 1, Members: []projectconfig.Member{{ID: "alice", Name: "Alice", Recipient: identityValue.CanonicalRecipient()}}}
	book := manifestFor(ciphertext, recipients)
	configBytes, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	recipientBytes, err := recipientConfig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := book.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ignoreBytes, err := gitignore.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	attrsBytes, err := gitattrs.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ".gitseal/config.yaml", configBytes)
	writeFile(t, dir, ".gitseal/recipients.yaml", recipientBytes)
	writeFile(t, dir, ".gitseal/manifest.yaml", manifestBytes)
	writeFile(t, dir, ".gitignore", ignoreBytes)
	writeFile(t, dir, ".gitattributes", attrsBytes)
	writeFile(t, dir, ".env.age", ciphertext)
	runGit(t, dir, "add", "-f", ".")
	runGit(t, dir, "commit", "-qm", "valid project")
	return projectFixture{dir: dir, identity: identityValue, recipients: recipients, plaintext: plaintext}
}

func encrypt(t *testing.T, identityValue agefile.HybridIdentity, recipients agefile.HybridRecipients, plaintext []byte) []byte {
	t.Helper()
	plan, err := agefile.NewEncryptionPlan(recipients, identityValue)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := plan.Encrypt(&ciphertext, bytes.NewReader(plaintext)); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), ciphertext.Bytes()...)
}

func manifestFor(ciphertext []byte, recipients agefile.HybridRecipients) manifest.Manifest {
	sum := sha256.Sum256(ciphertext)
	return manifest.Manifest{Version: 1, Artifacts: []manifest.Artifact{{
		Source: ".env", Encrypted: ".env.age",
		CiphertextSHA256: hex.EncodeToString(sum[:]), RecipientSetSHA256: recipients.Digest().Hex(),
	}}}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
}

func initRepository(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init", "-q", "--initial-branch=master")
	runGit(t, dir, "config", "user.name", "GitSeal Test")
	runGit(t, dir, "config", "user.email", "gitseal@example.invalid")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func installHookTestHelper(t *testing.T, repo, name string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\nexec " + shellQuote(filepath.ToSlash(executable)) + " -test.run '^TestGitHookRunHelper$' -- " + name + "\n")
	path := filepath.Join(repo, ".git", "hooks", name)
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func runGitFailure(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("git %v unexpectedly succeeded: %s", args, out)
	}
}

func runGitWithIndex(t *testing.T, dir, index string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+index)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git with inherited index %v: %v: %s", args, err, out)
	}
}

func clearGitEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if upper == "GIT_DIR" || upper == "GIT_WORK_TREE" || upper == "GIT_COMMON_DIR" || upper == "GIT_INDEX_FILE" || upper == "GIT_OBJECT_DIRECTORY" || upper == "GIT_ALTERNATE_OBJECT_DIRECTORIES" || upper == "GIT_CONFIG_PARAMETERS" || upper == "GIT_CONFIG_COUNT" || upper == "GIT_ATTR_SOURCE" || upper == "GIT_EXEC_PATH" || upper == "GIT_CEILING_DIRECTORIES" || upper == "GIT_DISCOVERY_ACROSS_FILESYSTEM" || strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			value, present := os.LookupEnv(key)
			_ = os.Unsetenv(key)
			t.Cleanup(func() {
				if present {
					_ = os.Setenv(key, value)
				}
			})
		}
	}
}

func fakeExecutable(t *testing.T, _ string) string {
	t.Helper()
	name, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	name, err = filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func seedManagedHookFixtures(t *testing.T, repo, executable string) {
	t.Helper()
	directory := filepath.Join(repo, ".git", "hooks")
	for _, name := range supportedHooks {
		content, err := managedContent(executable, name)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o755); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func writeFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fileSHA256(t *testing.T, name string) [sha256.Size]byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func TestLocalTier2SnapshotDetectsStateAndSelectionChanges(t *testing.T) {
	directory := t.TempDir()
	before, err := captureLocalStateSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	state, selection, _ := localstate.Paths(directory)
	if err := os.WriteFile(state, []byte("version: 1\nfiles: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterState, err := captureLocalStateSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if before.same(afterState) {
		t.Fatal("creation of local baseline state was not detected")
	}
	if err := os.WriteFile(selection, []byte("version: 1\nidentity: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterSelection, err := captureLocalStateSnapshot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if afterState.same(afterSelection) {
		t.Fatal("creation of local identity selection was not detected")
	}
}

func assertActions(t *testing.T, report ChangeReport, want ...string) {
	t.Helper()
	if len(report.Hooks) != len(want) {
		t.Fatalf("hook report length = %d, want %d: %#v", len(report.Hooks), len(want), report)
	}
	for idx, action := range want {
		if report.Hooks[idx].Name != supportedHooks[idx] || report.Hooks[idx].Action != action {
			t.Fatalf("hook report[%d] = %#v, want %s/%s", idx, report.Hooks[idx], supportedHooks[idx], action)
		}
	}
}

func reportHasCode(report RunReport, code string) bool {
	for _, finding := range report.Static.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
