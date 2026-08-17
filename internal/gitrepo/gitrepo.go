// Package gitrepo is the only production boundary for Git subprocesses. It
// resolves Git once, invokes an absolute executable with argument arrays, and
// bounds execution time and output.
package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/raydalsayf/gitseal/internal/limits"
)

const MinimumGitVersion = "2.43.0"

var versionPattern = regexp.MustCompile(`(?m)^git version ([0-9]+)\.([0-9]+)\.([0-9]+)`)

var rejectedEnvironment = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
	"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_IMPLICIT_WORK_TREE",
	"GIT_GRAFT_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE",
	"GIT_PREFIX", "GIT_SHALLOW_FILE", "GIT_NAMESPACE", "GIT_REFERENCE_BACKEND",
	"GIT_DEFAULT_HASH", "GIT_DEFAULT_REF_FORMAT", "GIT_INDEX_VERSION",
	"GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
	"GIT_ICASE_PATHSPECS", "GIT_ATTR_SOURCE", "GIT_ATTR_NOSYSTEM",
	"GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM", "GIT_QUARANTINE_PATH",
	"GIT_EXEC_PATH", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
}

type Repository struct {
	git          string
	worktree     string
	gitDir       string
	commonDir    string
	gitsealDir   string
	objectFormat string
	bare         bool
	env          []string
	timeout      time.Duration
	activeIndex  string
}

type DiscoverOptions struct {
	AllowBare               bool
	AllowActiveIndex        bool
	AllowGitHookEnvironment bool
}

type CommandError struct {
	Code       int
	Diagnostic string
}

func (e *CommandError) Error() string { return "Git command failed: " + e.Diagnostic }

func ErrorExitCode(err error) (int, bool) {
	var command *CommandError
	if errors.As(err, &command) {
		return command.Code, true
	}
	return 0, false
}

func Discover(ctx context.Context, cwd string, options DiscoverOptions) (*Repository, error) {
	if cwd == "" {
		return nil, errors.New("working directory is empty")
	}
	absoluteCWD, err := filepath.Abs(cwd)
	if err != nil {
		return nil, errors.New("resolve working directory")
	}
	cwd = filepath.Clean(absoluteCWD)
	if err := rejectPoisonedEnvironment(options.AllowActiveIndex, options.AllowGitHookEnvironment); err != nil {
		return nil, err
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("Git executable not found")
	}
	gitPath, err = filepath.Abs(gitPath)
	if err != nil {
		return nil, errors.New("resolve Git executable path")
	}
	if resolved, resolveErr := filepath.EvalSymlinks(gitPath); resolveErr == nil {
		gitPath = resolved
	}
	info, err := os.Stat(gitPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("resolved Git executable is not a regular file")
	}
	// Do not execute a PATH-selected program from the repository we are about
	// to inspect. Repository discovery normally requires Git, so first locate
	// the conventional worktree/bare boundary using pathname metadata only.
	// The complete Git-reported worktree/common-dir check is repeated below.
	if boundary := preflightRepositoryBoundary(cwd); boundary != "" && within(gitPath, boundary) {
		return nil, errors.New("resolved Git executable is inside the repository trust boundary")
	}
	inheritedIndex := ""
	if options.AllowActiveIndex {
		inheritedIndex = os.Getenv("GIT_INDEX_FILE")
	}
	r := &Repository{git: gitPath, env: sanitizedEnvironment(), timeout: 15 * time.Second}
	version, err := r.raw(ctx, cwd, nil, "--version")
	if err != nil {
		return nil, fmt.Errorf("run resolved Git executable: %w", err)
	}
	if err := requireGitVersion(string(version)); err != nil {
		return nil, err
	}
	bareText, err := r.raw(ctx, cwd, nil, "-C", cwd, "rev-parse", "--is-bare-repository")
	if err != nil {
		return nil, errors.New("not a Git repository")
	}
	r.bare = strings.TrimSpace(string(bareText)) == "true"
	if r.bare && !options.AllowBare {
		return nil, errors.New("bare repositories are supported only by verify --source")
	}
	if r.bare {
		r.gitDir, err = r.singlePath(ctx, cwd, "--absolute-git-dir")
		r.commonDir = r.gitDir
	} else {
		r.worktree, err = r.singlePath(ctx, cwd, "--path-format=absolute", "--show-toplevel")
		if err == nil {
			r.gitDir, err = r.singlePath(ctx, r.worktree, "--path-format=absolute", "--git-dir")
		}
		if err == nil {
			r.commonDir, err = r.singlePath(ctx, r.worktree, "--path-format=absolute", "--git-common-dir")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("discover repository paths: %w", err)
	}
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	r.objectFormat, err = r.singleValue(ctx, base, "--show-object-format=storage")
	if err != nil || (r.objectFormat != "sha1" && r.objectFormat != "sha256") {
		return nil, errors.New("repository object format is not supported")
	}
	r.gitsealDir, err = r.gitPath(ctx, base, "gitseal")
	if err != nil {
		return nil, fmt.Errorf("resolve Git-local GitSeal directory: %w", err)
	}
	for _, forbidden := range []string{r.worktree, r.gitDir, r.commonDir} {
		if forbidden != "" && within(gitPath, forbidden) {
			return nil, errors.New("resolved Git executable is inside the repository trust boundary")
		}
	}
	if options.AllowActiveIndex && inheritedIndex != "" {
		active, err := validateActiveIndex(inheritedIndex, cwd, r.gitDir)
		if err != nil {
			return nil, err
		}
		r.activeIndex = active
		r.env = append(r.env, "GIT_INDEX_FILE="+active)
	}
	return r, nil
}

func preflightRepositoryBoundary(cwd string) string {
	current, err := filepath.Abs(cwd)
	if err != nil {
		return ""
	}
	if resolved, resolveErr := filepath.EvalSymlinks(current); resolveErr == nil {
		current = resolved
	}
	for {
		marker := filepath.Join(current, ".git")
		if _, err := os.Lstat(marker); err == nil {
			return current
		}
		// Bare repositories have no .git entry. Requiring all three markers
		// avoids treating an arbitrary source directory with a file named HEAD
		// as a repository boundary.
		if head, headErr := os.Lstat(filepath.Join(current, "HEAD")); headErr == nil && head.Mode().IsRegular() {
			if objects, objectsErr := os.Lstat(filepath.Join(current, "objects")); objectsErr == nil && objects.IsDir() {
				if refs, refsErr := os.Lstat(filepath.Join(current, "refs")); refsErr == nil && refs.IsDir() {
					return current
				}
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func (r *Repository) GitPath() string      { return r.git }
func (r *Repository) Worktree() string     { return r.worktree }
func (r *Repository) GitDir() string       { return r.gitDir }
func (r *Repository) CommonDir() string    { return r.commonDir }
func (r *Repository) GitSealDir() string   { return r.gitsealDir }
func (r *Repository) ObjectFormat() string { return r.objectFormat }
func (r *Repository) Bare() bool           { return r.bare }
func (r *Repository) ActiveIndex() string  { return r.activeIndex }

func (r *Repository) Run(ctx context.Context, args ...string) ([]byte, error) {
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	return r.raw(ctx, base, nil, append([]string{"-C", base}, args...)...)
}

func (r *Repository) RunInput(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	return r.raw(ctx, base, bytes.NewReader(input), append([]string{"-C", base}, args...)...)
}

func (r *Repository) raw(ctx context.Context, cwd string, input io.Reader, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	global := []string{"--no-pager", "--no-optional-locks", "--no-replace-objects", "-c", "core.fsmonitor=false"}
	// --version is a special top-level option and does not accept all global
	// options consistently across the minimum-version matrix.
	if len(args) == 1 && args[0] == "--version" {
		global = nil
	}
	cmd := exec.CommandContext(ctx, r.git, append(global, args...)...)
	cmd.Dir = cwd
	cmd.Env = r.env
	cmd.Stdin = input
	stdout := &limitedBuffer{max: limits.MaxGitOutputBytes}
	stderr := &limitedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, errors.New("Git subprocess timed out or was cancelled")
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("Git subprocess output exceeded its limit")
	}
	if err != nil {
		code := 1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		return nil, &CommandError{Code: code, Diagnostic: safeGitError(stderr.Bytes())}
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (r *Repository) singlePath(ctx context.Context, cwd string, args ...string) (string, error) {
	out, err := r.raw(ctx, cwd, nil, append([]string{"-C", cwd, "rev-parse"}, args...)...)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(out), "\n")
	value = strings.TrimSuffix(value, "\r")
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return "", errors.New("Git returned an invalid absolute path")
	}
	return filepath.Clean(value), nil
}

func (r *Repository) singleValue(ctx context.Context, cwd string, args ...string) (string, error) {
	out, err := r.raw(ctx, cwd, nil, append([]string{"-C", cwd, "rev-parse"}, args...)...)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if value == "" || strings.ContainsAny(value, "\x00\r\n\t ") {
		return "", errors.New("Git returned an invalid value")
	}
	return value, nil
}

func (r *Repository) gitPath(ctx context.Context, cwd, name string) (string, error) {
	out, err := r.raw(ctx, cwd, nil, "-C", cwd, "rev-parse", "--path-format=absolute", "--git-path", name)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("Git returned an invalid Git-local path")
	}
	return filepath.Clean(value), nil
}

func rejectPoisonedEnvironment(allowActiveIndex, allowGitHookEnvironment bool) error {
	for _, key := range rejectedEnvironment {
		if allowActiveIndex && key == "GIT_INDEX_FILE" {
			continue
		}
		// Git documents that it exports repository-local environment to hooks.
		// Hook execution re-discovers the repository from the validated working
		// directory and sanitized child processes drop these values, so they
		// are not used as authority. All other redirects remain rejected.
		if allowGitHookEnvironment && (key == "GIT_DIR" || key == "GIT_EXEC_PATH" || key == "GIT_PREFIX") {
			continue
		}
		if value, ok := os.LookupEnv(key); ok && value != "" {
			return fmt.Errorf("refusing ambiguous Git environment variable %s", key)
		}
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") {
			return errors.New("refusing Git config-injection environment variables")
		}
	}
	return nil
}

func sanitizedEnvironment() []string {
	drop := map[string]bool{
		"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_COMMON_DIR": true,
		"GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_CONFIG": true,
		"GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_NOSYSTEM": true,
		"GIT_CONFIG_PARAMETERS": true, "GIT_CONFIG_COUNT": true,
		"GIT_IMPLICIT_WORK_TREE": true, "GIT_GRAFT_FILE": true,
		"GIT_NO_REPLACE_OBJECTS": true, "GIT_REPLACE_REF_BASE": true,
		"GIT_PREFIX": true, "GIT_SHALLOW_FILE": true, "GIT_NAMESPACE": true,
		"GIT_REFERENCE_BACKEND": true, "GIT_DEFAULT_HASH": true,
		"GIT_DEFAULT_REF_FORMAT": true, "GIT_INDEX_VERSION": true,
		"GIT_LITERAL_PATHSPECS": true, "GIT_GLOB_PATHSPECS": true,
		"GIT_NOGLOB_PATHSPECS": true, "GIT_ICASE_PATHSPECS": true,
		"GIT_ATTR_SOURCE": true, "GIT_ATTR_NOSYSTEM": true,
		"GIT_ATTR_GLOBAL": true, "GIT_ATTR_SYSTEM": true, "GIT_QUARANTINE_PATH": true,
		"GIT_NO_LAZY_FETCH": true, "GIT_EXEC_PATH": true,
		"GIT_OPTIONAL_LOCKS": true, "GIT_TERMINAL_PROMPT": true,
		"GIT_PAGER": true, "PAGER": true, "GIT_ASKPASS": true, "SSH_ASKPASS": true,
		"LC_ALL": true, "LANG": true, "LANGUAGE": true,
	}
	var out []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if drop[upper] || strings.HasPrefix(upper, "GIT_CONFIG_KEY_") || strings.HasPrefix(upper, "GIT_CONFIG_VALUE_") || strings.HasPrefix(upper, "GIT_TRACE") {
			continue
		}
		out = append(out, entry)
	}
	out = append(out,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_LAZY_FETCH=1",
		"LC_ALL=C",
	)
	return out
}

func requireGitVersion(output string) error {
	match := versionPattern.FindStringSubmatch(output)
	if match == nil {
		return errors.New("could not parse Git version")
	}
	actual := [3]int{}
	for idx := range actual {
		actual[idx], _ = strconv.Atoi(match[idx+1])
	}
	minimum := [3]int{2, 43, 0}
	for idx := range actual {
		if actual[idx] > minimum[idx] {
			return nil
		}
		if actual[idx] < minimum[idx] {
			return fmt.Errorf("Git %s or later is required", MinimumGitVersion)
		}
	}
	return nil
}

func within(candidate, parent string) bool {
	rel, err := filepath.Rel(parent, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validateActiveIndex(value, cwd, gitDir string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("active Git index path contains invalid bytes")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(cwd, value)
	}
	value = filepath.Clean(value)
	if filepath.Clean(filepath.Dir(value)) != filepath.Clean(gitDir) {
		return "", errors.New("active Git index is not an immediate child of the worktree-specific Git directory")
	}
	base := filepath.Base(value)
	if base != "index" && base != "index.lock" && !strings.HasPrefix(base, "next-index-") {
		return "", errors.New("active Git index basename is not a supported commit-index form")
	}
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("active Git index is missing, linked, or not a regular file")
	}
	return value, nil
}

func safeGitError(value []byte) string {
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return "no diagnostic"
	}
	if len(value) > 1024 {
		value = value[:1024]
	}
	var out strings.Builder
	for _, r := range string(value) {
		// unicode.IsControl covers both ASCII controls and the C1 range,
		// including the single-byte CSI control used to begin ANSI terminal
		// sequences. ESC is covered as an ASCII control.
		if unicode.IsControl(r) {
			out.WriteRune('?')
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

type limitedBuffer struct {
	bytes.Buffer
	max      int64
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	before := int64(b.Len())
	if before < b.max {
		remaining := int(b.max - before)
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.Buffer.Write(p[:remaining])
	}
	if before+int64(len(p)) > b.max {
		b.exceeded = true
	}
	return len(p), nil
}
