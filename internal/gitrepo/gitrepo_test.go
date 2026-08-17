package gitrepo

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRequireGitVersion(t *testing.T) {
	if err := requireGitVersion("git version 2.43.0\n"); err != nil {
		t.Fatal(err)
	}
	if err := requireGitVersion("git version 2.42.9\n"); err == nil {
		t.Fatal("old Git accepted")
	}
}

func TestSafeGitErrorReplacesASCIIAndUnicodeControls(t *testing.T) {
	got := safeGitError([]byte("fatal:\x1b[31m red\r\n\xc2\x9b32m green\tend"))
	if strings.ContainsAny(got, "\x1b\r\n\t") || strings.ContainsRune(got, '\u009b') {
		t.Fatalf("Git diagnostic retained terminal controls: %q", got)
	}
	if got != "fatal:?[31m red???32m green?end" {
		t.Fatalf("sanitized Git diagnostic = %q", got)
	}
}

func TestDiscoverAndExactTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.invalid")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "a")
	run("commit", "-qm", "test")
	for _, key := range rejectedEnvironment {
		unsetForTest(t, key)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			unsetForTest(t, key)
		}
	}
	repo, err := Discover(context.Background(), dir, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if repo.GitPath() == "git" || repo.Bare() {
		t.Fatal("Git was not resolved or repository was misclassified")
	}
	tree, err := repo.ResolveTree(context.Background(), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := repo.ListTree(context.Background(), tree)
	if err != nil || len(entries) != 1 || entries[0].Path != "a" {
		t.Fatalf("ListTree = %#v, %v", entries, err)
	}
	var got string
	if err := repo.ConsumeBlob(context.Background(), entries[0].OID, 10, func(r io.Reader, size int64) error {
		data, err := io.ReadAll(r)
		got = string(data)
		return err
	}); err != nil || got != "hello" {
		t.Fatalf("ConsumeBlob = %q, %v", got, err)
	}
	var batch []string
	requests := []BlobRequest{{OID: entries[0].OID, Max: 10}, {OID: entries[0].OID, Max: 10}}
	if err := repo.ConsumeBlobs(context.Background(), requests, func(index int, reader io.Reader, size int64) error {
		data, err := io.ReadAll(reader)
		batch = append(batch, string(data))
		return err
	}); err != nil || len(batch) != 2 || batch[0] != "hello" || batch[1] != "hello" {
		t.Fatalf("ConsumeBlobs = %#v, %v", batch, err)
	}
	if err := repo.ConsumeBlobs(context.Background(), requests[:1], func(int, io.Reader, int64) error {
		return nil
	}); err == nil {
		t.Fatal("ConsumeBlobs accepted an incompletely consumed frame")
	}
	reachable, err := repo.ReachableBlobOIDs(context.Background())
	if err != nil || len(reachable) != 1 || reachable[0] != entries[0].OID {
		t.Fatalf("ReachableBlobOIDs = %#v, %v", reachable, err)
	}
}

func TestGitAuthorityEnvironmentIsRejectedAndDropped(t *testing.T) {
	keys := []string{
		"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
		"GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_NO_REPLACE_OBJECTS",
		"GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE", "GIT_NAMESPACE", "GIT_REFERENCE_BACKEND",
		"GIT_DEFAULT_HASH", "GIT_DEFAULT_REF_FORMAT", "GIT_INDEX_VERSION",
		"GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
		"GIT_ICASE_PATHSPECS", "GIT_ATTR_NOSYSTEM", "GIT_ATTR_GLOBAL",
		"GIT_ATTR_SYSTEM", "GIT_QUARANTINE_PATH",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			clearGitEnvironmentForRepositoryTest(t)
			t.Setenv(key, "attacker-controlled")
			if err := rejectPoisonedEnvironment(false, false); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("%s was not rejected: %v", key, err)
			}
			for _, entry := range sanitizedEnvironment() {
				name, _, _ := strings.Cut(entry, "=")
				if strings.EqualFold(name, key) {
					t.Fatalf("%s survived child environment sanitization", key)
				}
			}
		})
	}
}

func TestHookPrefixHasNarrowExceptionButIsNotChildAuthority(t *testing.T) {
	clearGitEnvironmentForRepositoryTest(t)
	t.Setenv("GIT_PREFIX", "nested/")
	if err := rejectPoisonedEnvironment(false, false); err == nil {
		t.Fatal("non-hook invocation accepted GIT_PREFIX")
	}
	if err := rejectPoisonedEnvironment(false, true); err != nil {
		t.Fatalf("hook invocation rejected Git-exported GIT_PREFIX: %v", err)
	}
	for _, entry := range sanitizedEnvironment() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "GIT_PREFIX") {
			t.Fatal("GIT_PREFIX survived child environment sanitization")
		}
	}
}

func TestRequiredPolicyFilesWorkBudget(t *testing.T) {
	paths := make([]string, maxMaterializedPolicyFiles+1)
	for index := range paths {
		paths[index] = fmt.Sprintf("directory-%04d/file", index)
	}
	if _, err := requiredPolicyFiles(paths, ".gitignore"); err == nil {
		t.Fatal("required policy file set exceeded its work budget without failing")
	}
}

func TestDiscoverRejectsPathSelectedGitInsideRepositoryBeforeExecution(t *testing.T) {
	clearGitEnvironmentForRepositoryTest(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "git"
	if runtime.GOOS == "windows" {
		name = "git.exe"
	}
	// This is intentionally not an executable Git program. Discovery must
	// reject its repository location before attempting to execute any byte.
	if err := os.WriteFile(filepath.Join(bin, name), []byte("attacker controlled"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	_, err := Discover(context.Background(), dir, DiscoverOptions{})
	if err == nil || !strings.Contains(err.Error(), "inside the repository trust boundary") {
		t.Fatalf("repository-local PATH executable result = %v", err)
	}
}

func TestResolveHeadTreeOnlyAcceptsGenuineUnbornBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git unavailable")
	}
	dir := t.TempDir()
	run := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("", "init", "-q")
	for _, key := range rejectedEnvironment {
		unsetForTest(t, key)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			unsetForTest(t, key)
		}
	}
	repo, err := Discover(context.Background(), dir, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if tree, unborn, err := repo.ResolveHeadTree(context.Background()); err != nil || !unborn || tree != "" {
		t.Fatalf("unborn ResolveHeadTree = %q, %v, %v", tree, unborn, err)
	}

	// A symbolic HEAD that resolves to a non-tree object is corrupt for these
	// callers. It must not be reclassified as an empty/unborn repository.
	blobOID := run("not a tree", "hash-object", "-w", "--stdin")
	headRef := run("", "symbolic-ref", "HEAD")
	refPath := filepath.Join(dir, ".git", filepath.FromSlash(headRef))
	if err := os.MkdirAll(filepath.Dir(refPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refPath, []byte(blobOID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, unborn, err := repo.ResolveHeadTree(context.Background()); err == nil || unborn {
		t.Fatalf("non-tree HEAD accepted as unborn: unborn=%v err=%v", unborn, err)
	}
}

func unsetForTest(t *testing.T, key string) {
	t.Helper()
	value, present := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(key, value)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func clearGitEnvironmentForRepositoryTest(t *testing.T) {
	t.Helper()
	for _, key := range rejectedEnvironment {
		unsetForTest(t, key)
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			unsetForTest(t, key)
		}
	}
}
