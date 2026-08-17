package gitrepo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var managedAttributeNames = []string{"text", "crlf", "eol", "ident", "diff", "merge", "filter", "working-tree-encoding"}

func (r *Repository) IsTracked(ctx context.Context, path string) (bool, error) {
	out, err := r.Run(ctx, "ls-files", "--cached", "--stage", "-z", "--", path)
	if err != nil {
		return false, err
	}
	return len(out) > 0, nil
}

func (r *Repository) HasUnmerged(ctx context.Context) (bool, error) {
	out, err := r.Run(ctx, "ls-files", "--unmerged", "--stage", "-z")
	if err != nil {
		return false, err
	}
	return len(out) > 0, nil
}

func (r *Repository) CheckSafeAttributes(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	var input bytes.Buffer
	for _, path := range paths {
		if path == "" || strings.ContainsRune(path, '\x00') {
			return errors.New("invalid attribute query path")
		}
		input.WriteString(path)
		input.WriteByte(0)
	}
	args := []string{"check-attr", "-z"}
	args = append(args, managedAttributeNames...)
	args = append(args, "--stdin")
	out, err := r.RunInput(ctx, input.Bytes(), args...)
	if err != nil {
		return err
	}
	fields := bytes.Split(out, []byte{0})
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	want := len(paths) * len(managedAttributeNames) * 3
	if len(fields) != want {
		return errors.New("Git returned malformed attribute results")
	}
	for i := 0; i < len(fields); i += 3 {
		if string(fields[i+2]) != "unset" {
			return fmt.Errorf("attribute %q for %q is %q, not unset", fields[i+1], fields[i], fields[i+2])
		}
	}
	return nil
}

func (r *Repository) CheckIgnorePolicy(ctx context.Context, shouldIgnore, shouldNotIgnore []string) error {
	paths := append(append([]string(nil), shouldIgnore...), shouldNotIgnore...)
	if len(paths) == 0 {
		return nil
	}
	var input bytes.Buffer
	for _, path := range paths {
		if path == "" || strings.ContainsRune(path, '\x00') {
			return errors.New("invalid ignore query path")
		}
		input.WriteString(path)
		input.WriteByte(0)
	}
	out, err := r.RunInput(ctx, input.Bytes(), "check-ignore", "--no-index", "-v", "-z", "--non-matching", "--stdin")
	if err != nil {
		return err
	}
	fields := bytes.Split(out, []byte{0})
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	if len(fields) != len(paths)*4 {
		return errors.New("Git returned malformed ignore results")
	}
	for idx, path := range paths {
		source := fields[idx*4]
		pattern := fields[idx*4+2]
		returnedPath := string(fields[idx*4+3])
		if returnedPath != path {
			return errors.New("Git returned ignore results for an unexpected path")
		}
		ignored := (len(source) > 0 || len(pattern) > 0) && !bytes.HasPrefix(pattern, []byte("!"))
		if idx < len(shouldIgnore) && !ignored {
			return fmt.Errorf("%q is not effectively ignored", path)
		}
		if idx >= len(shouldIgnore) && ignored {
			return fmt.Errorf("%q is unexpectedly ignored by repository policy", path)
		}
	}
	return nil
}

func (r *Repository) HookPath(ctx context.Context, name string) (string, error) {
	if name != "pre-commit" && name != "pre-merge-commit" {
		return "", errors.New("unsupported hook name")
	}
	base := r.worktree
	if base == "" {
		return "", errors.New("hooks require a worktree")
	}
	return r.gitPath(ctx, base, "hooks/"+name)
}

func (r *Repository) HasConfiguredHooksPath(ctx context.Context) (bool, error) {
	_, err := r.Run(ctx, "config", "--get-all", "core.hooksPath")
	if err == nil {
		return true, nil
	}
	if code, ok := ErrorExitCode(err); ok && code == 1 {
		return false, nil
	}
	return false, err
}

func (r *Repository) ChangedIndexPaths(ctx context.Context) (map[string]struct{}, error) {
	args := []string{"diff", "--cached", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all"}
	_, unborn, err := r.ResolveHeadTree(ctx)
	if err != nil {
		return nil, err
	}
	if !unborn {
		args = append(args, "HEAD", "--")
	} else {
		args = append(args, "--root", "--")
	}
	out, err := r.Run(ctx, args...)
	if err != nil {
		return nil, err
	}
	result := map[string]struct{}{}
	for _, value := range bytes.Split(out, []byte{0}) {
		if len(value) > 0 {
			result[string(value)] = struct{}{}
		}
	}
	return result, nil
}

// ResolveHeadTree distinguishes a genuinely unborn symbolic branch from every
// other failure to resolve HEAD. Callers must not treat a corrupt ref, missing
// object, or non-tree HEAD as an empty repository.
func (r *Repository) ResolveHeadTree(ctx context.Context) (tree string, unborn bool, err error) {
	tree, resolveErr := r.ResolveTree(ctx, "HEAD")
	if resolveErr == nil {
		return tree, false, nil
	}
	refData, symbolicErr := r.Run(ctx, "symbolic-ref", "--quiet", "HEAD")
	if symbolicErr != nil {
		return "", false, resolveErr
	}
	ref := strings.TrimSpace(string(refData))
	if !strings.HasPrefix(ref, "refs/heads/") || len(ref) == len("refs/heads/") || strings.ContainsAny(ref, " \t\r\n\x00") {
		return "", false, errors.New("Git returned an invalid symbolic HEAD ref")
	}
	_, refErr := r.Run(ctx, "show-ref", "--verify", "--quiet", ref)
	if refErr == nil {
		return "", false, resolveErr
	}
	if code, ok := ErrorExitCode(refErr); ok && code == 1 {
		return "", true, nil
	}
	return "", false, resolveErr
}

func (r *Repository) ResolveTree(ctx context.Context, source string) (string, error) {
	if source == "" || strings.ContainsAny(source, "\x00\r\n") {
		return "", errors.New("invalid tree source")
	}
	out, err := r.Run(ctx, "rev-parse", "--verify", "--end-of-options", source+"^{tree}")
	if err != nil {
		return "", errors.New("tree source does not resolve to an exact Git tree")
	}
	oid := strings.TrimSpace(string(out))
	if oid == "" || strings.ContainsAny(oid, " \t\r\n\x00") {
		return "", errors.New("Git returned an invalid tree object ID")
	}
	return oid, nil
}

type TreeEntry struct {
	Mode string
	Type string
	OID  string
	Path string
}

const maxBatchBlobRequests = 100_000

const (
	maxMaterializedPolicyFiles = 4_096
	maxMaterializedPolicyBytes = int64(32 << 20)
)

// BlobRequest names one exact object and the largest blob the caller is
// prepared to consume.
type BlobRequest struct {
	OID string
	Max int64
}

type IndexEntry struct {
	TreeEntry
	Stage           int
	AssumeUnchanged bool
	SkipWorktree    bool
}

func (r *Repository) ListIndex(ctx context.Context) ([]IndexEntry, error) {
	// -v prefixes every cached record with Git's documented status tag and
	// lower-cases that tag when CE_VALID (assume-unchanged) is set. In
	// particular, H/h are ordinary cached entries and S/s are skip-worktree
	// entries. Keeping these bits attached to the exact inherited index is
	// required because either can hide working-tree divergence.
	out, err := r.Run(ctx, "ls-files", "--cached", "--stage", "--full-name", "-v", "-z")
	if err != nil {
		return nil, err
	}
	records := bytes.Split(out, []byte{0})
	entries := make([]IndexEntry, 0, len(records)-1)
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		if len(record) < 3 || record[1] != ' ' {
			return nil, errors.New("Git returned a malformed tagged index record")
		}
		tag := record[0]
		upperTag := tag
		if upperTag >= 'a' && upperTag <= 'z' {
			upperTag -= 'a' - 'A'
		}
		if upperTag != 'H' && upperTag != 'S' && upperTag != 'M' {
			return nil, errors.New("Git returned an unsupported cached index status tag")
		}
		metadata, pathBytes, ok := bytes.Cut(record[2:], []byte{'\t'})
		fields := bytes.Fields(metadata)
		if !ok || len(fields) != 3 || len(pathBytes) == 0 {
			return nil, errors.New("Git returned a malformed index record")
		}
		stage, err := strconv.Atoi(string(fields[2]))
		if err != nil || stage < 0 || stage > 3 {
			return nil, errors.New("Git returned an invalid index stage")
		}
		mode := string(fields[0])
		typeName := "blob"
		if mode == "160000" {
			typeName = "commit"
		} else if mode == "040000" {
			typeName = "tree"
		}
		entries = append(entries, IndexEntry{
			TreeEntry:       TreeEntry{Mode: mode, Type: typeName, OID: string(fields[1]), Path: string(pathBytes)},
			Stage:           stage,
			AssumeUnchanged: tag >= 'a' && tag <= 'z',
			SkipWorktree:    upperTag == 'S',
		})
	}
	return entries, nil
}

func (r *Repository) ListTree(ctx context.Context, tree string) ([]TreeEntry, error) {
	out, err := r.Run(ctx, "ls-tree", "-r", "-z", "--full-tree", tree)
	if err != nil {
		return nil, err
	}
	records := bytes.Split(out, []byte{0})
	entries := make([]TreeEntry, 0, len(records)-1)
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		metadata, pathBytes, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || bytes.IndexByte(pathBytes, 0) >= 0 {
			return nil, errors.New("Git returned a malformed tree record")
		}
		fields := bytes.Fields(metadata)
		if len(fields) != 3 {
			return nil, errors.New("Git returned malformed tree metadata")
		}
		entry := TreeEntry{Mode: string(fields[0]), Type: string(fields[1]), OID: string(fields[2]), Path: string(pathBytes)}
		if entry.Path == "" || strings.ContainsAny(entry.OID, " \t\r\n\x00") {
			return nil, errors.New("Git returned an invalid tree entry")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ConsumeBlob streams one exact Git blob through consume without filters or
// worktree conversions. The advertised size is checked against max first.
func (r *Repository) ConsumeBlob(ctx context.Context, oid string, max int64, consume func(io.Reader, int64) error) error {
	if consume == nil {
		return errors.New("blob consumer is required")
	}
	return r.ConsumeBlobs(ctx, []BlobRequest{{OID: oid, Max: max}}, func(_ int, reader io.Reader, size int64) error {
		return consume(reader, size)
	})
}

// ConsumeBlobs streams an explicitly bounded request set through one exact
// cat-file --batch process. Reusing the process prevents a hostile tree from
// turning verification into a subprocess-per-blob resource attack.
func (r *Repository) ConsumeBlobs(ctx context.Context, requests []BlobRequest, consume func(int, io.Reader, int64) error) (err error) {
	if len(requests) == 0 {
		return nil
	}
	if len(requests) > maxBatchBlobRequests {
		return errors.New("too many exact blob requests")
	}
	if consume == nil {
		return errors.New("blob consumer is required")
	}
	for _, request := range requests {
		if !r.validOID(request.OID) || request.Max < 0 {
			return errors.New("invalid blob object ID or size limit")
		}
	}

	// Full-tree scans receive a larger, but still finite, wall-clock budget
	// than one ordinary Git query.
	batchContext, cancel := context.WithTimeout(ctx, 4*r.timeout)
	defer cancel()
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	args := []string{"--no-pager", "--no-optional-locks", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", base, "cat-file", "--batch"}
	cmd := exec.CommandContext(batchContext, r.git, args...)
	cmd.Dir, cmd.Env = base, r.env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// This boundary never surfaces Git diagnostics. A real null-device file
	// avoids the unbounded output risk and, on Windows, avoids an os/exec copy
	// goroutine that can remain blocked if a child inherits Git's stderr pipe.
	stderr, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, stderr.Close()) }()
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited && cmd.Process != nil {
			_ = stdin.Close()
			_ = stdout.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	writer := bufio.NewWriterSize(stdin, 4096)
	reader := bufio.NewReaderSize(stdout, 4096)
	for index, request := range requests {
		if n, writeErr := writer.WriteString(request.OID + "\n"); writeErr != nil || n != len(request.OID)+1 {
			return errors.New("write exact Git batch request")
		}
		if err := writer.Flush(); err != nil {
			return errors.New("flush exact Git batch request")
		}

		header, headerErr := reader.ReadSlice('\n')
		if headerErr != nil || len(header) > 256 {
			return errors.New("Git returned a malformed blob frame")
		}
		fields := bytes.Fields(bytes.TrimSuffix(header, []byte{'\n'}))
		if len(fields) != 3 || string(fields[0]) != request.OID || string(fields[1]) != "blob" {
			return errors.New("Git returned an unexpected blob frame")
		}
		size, parseErr := strconv.ParseInt(string(fields[2]), 10, 64)
		if parseErr != nil || size < 0 || size > request.Max {
			return fmt.Errorf("blob size is invalid or exceeds %d bytes", request.Max)
		}

		limited := &io.LimitedReader{R: reader, N: size}
		if consumeErr := consume(index, limited, size); consumeErr != nil {
			return consumeErr
		}
		if limited.N != 0 {
			return io.ErrUnexpectedEOF
		}
		terminator, termErr := reader.ReadByte()
		if termErr != nil || terminator != '\n' {
			return errors.New("Git returned a malformed blob frame terminator")
		}
	}
	if err := stdin.Close(); err != nil {
		return errors.New("close exact Git batch request")
	}
	waitErr := cmd.Wait()
	waited = true
	if batchContext.Err() != nil {
		return errors.New("Git blob subprocess timed out or was cancelled")
	}
	if waitErr != nil {
		return errors.New("Git could not stream the requested blobs")
	}
	return nil
}

func (r *Repository) validOID(oid string) bool {
	want := 40
	if r.objectFormat == "sha256" {
		want = 64
	}
	if len(oid) != want {
		return false
	}
	for _, current := range []byte(oid) {
		if !(current >= '0' && current <= '9' || current >= 'a' && current <= 'f') {
			return false
		}
	}
	return true
}

// ReachableBlobOIDs returns the bounded unique set of blob IDs reachable from
// local refs. Object names are intentionally omitted: history diagnostics need
// exact contents, and hostile historical path bytes are not required to select
// those contents.
func (r *Repository) ReachableBlobOIDs(ctx context.Context) ([]string, error) {
	out, err := r.Run(ctx, "rev-list", "--objects", "--all", "--no-object-names")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if bytes.ContainsAny(line, "\r\x00 ") {
			return nil, errors.New("Git returned a malformed reachable blob object ID")
		}
		oid := string(line)
		if !r.validOID(oid) {
			return nil, errors.New("Git returned an invalid reachable blob object ID")
		}
		seen[oid] = struct{}{}
		if len(seen) > maxBatchBlobRequests {
			return nil, errors.New("reachable blob count exceeds the bounded history-scan budget")
		}
	}
	objects := make([]string, 0, len(seen))
	for oid := range seen {
		objects = append(objects, oid)
	}
	sort.Strings(objects)
	var input bytes.Buffer
	for _, oid := range objects {
		input.WriteString(oid)
		input.WriteByte('\n')
	}
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	typed, err := r.raw(ctx, base, bytes.NewReader(input.Bytes()), "-C", base, "cat-file", "--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSuffix(typed, []byte{'\n'}), []byte{'\n'})
	if len(objects) == 0 && len(typed) == 0 {
		return []string{}, nil
	}
	if len(lines) != len(objects) {
		return nil, errors.New("Git returned an incomplete reachable object type listing")
	}
	blobs := make([]string, 0, len(objects))
	for index, line := range lines {
		fields := bytes.Fields(line)
		if len(fields) != 2 || string(fields[0]) != objects[index] {
			return nil, errors.New("Git returned a malformed reachable object type listing")
		}
		switch string(fields[1]) {
		case "blob":
			blobs = append(blobs, objects[index])
		case "commit", "tree", "tag":
			// Not content-bearing regular blobs.
		default:
			return nil, errors.New("Git returned an unsupported reachable object type")
		}
	}
	return blobs, nil
}

// CheckTreeAttributes evaluates only attributes committed in the selected
// exact tree. The temporary Git directory has empty system/global/local
// attribute sources and sees the original repository only as a read-only object
// alternate.
func (r *Repository) CheckTreeAttributes(ctx context.Context, tree string, paths []string) (resultErr error) {
	if len(paths) == 0 {
		return nil
	}
	isolated, cleanup, err := r.newIsolatedRepository(ctx, true)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	var input bytes.Buffer
	for _, configured := range paths {
		if configured == "" || strings.ContainsRune(configured, '\x00') {
			return errors.New("invalid exact-tree attribute query path")
		}
		input.WriteString(configured)
		input.WriteByte(0)
	}
	args := []string{"-C", isolated.worktree, "-c", "core.attributesFile=" + isolated.empty, "check-attr", "--source=" + tree, "-z"}
	args = append(args, managedAttributeNames...)
	args = append(args, "--stdin")
	out, err := isolated.repo.raw(ctx, isolated.worktree, bytes.NewReader(input.Bytes()), args...)
	if err != nil {
		return err
	}
	return validateAttributeOutput(out, paths)
}

// CheckIndexAttributes evaluates only .gitattributes blobs from the exact
// active index. Relevant ancestor files are materialized by OID into an
// invocation-owned isolated worktree; the original repository, index, object
// database, and worktree remain read-only.
func (r *Repository) CheckIndexAttributes(ctx context.Context, entries []TreeEntry, paths []string) (resultErr error) {
	if len(paths) == 0 {
		return nil
	}
	isolated, cleanup, err := r.newIsolatedRepository(ctx, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	byPath := make(map[string]TreeEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	required, err := requiredPolicyFiles(paths, ".gitattributes")
	if err != nil {
		return err
	}
	if err := r.materializePolicyFiles(ctx, isolated.worktree, byPath, required, "exact-index attribute"); err != nil {
		return err
	}
	var input bytes.Buffer
	for _, configured := range paths {
		parent := filepath.Join(isolated.worktree, filepath.Dir(filepath.FromSlash(configured)))
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		input.WriteString(configured)
		input.WriteByte(0)
	}
	args := []string{"-C", isolated.worktree, "-c", "core.attributesFile=" + isolated.empty, "check-attr", "-z"}
	args = append(args, managedAttributeNames...)
	args = append(args, "--stdin")
	out, err := isolated.repo.raw(ctx, isolated.worktree, bytes.NewReader(input.Bytes()), args...)
	if err != nil {
		return err
	}
	return validateAttributeOutput(out, paths)
}

// CheckTreeIgnorePolicy evaluates committed ignore files in an invocation-owned
// isolated worktree. Only .gitignore files on safe ancestors of queried paths
// are materialized, and global/info excludes are empty.
func (r *Repository) CheckTreeIgnorePolicy(ctx context.Context, entries []TreeEntry, shouldIgnore, shouldNotIgnore []string) (resultErr error) {
	paths := append(append([]string(nil), shouldIgnore...), shouldNotIgnore...)
	if len(paths) == 0 {
		return nil
	}
	isolated, cleanup, err := r.newIsolatedRepository(ctx, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanup()) }()
	byPath := make(map[string]TreeEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	requiredIgnores, err := requiredPolicyFiles(paths, ".gitignore")
	if err != nil {
		return err
	}
	if err := r.materializePolicyFiles(ctx, isolated.worktree, byPath, requiredIgnores, "exact-tree ignore"); err != nil {
		return err
	}
	var input bytes.Buffer
	for _, configured := range paths {
		parent := filepath.Join(isolated.worktree, filepath.Dir(filepath.FromSlash(configured)))
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		input.WriteString(configured)
		input.WriteByte(0)
	}
	args := []string{"-C", isolated.worktree, "-c", "core.excludesFile=" + isolated.empty, "check-ignore", "--no-index", "-v", "-z", "--non-matching", "--stdin"}
	out, err := isolated.repo.raw(ctx, isolated.worktree, bytes.NewReader(input.Bytes()), args...)
	if err != nil {
		return err
	}
	return validateIgnoreOutput(out, shouldIgnore, shouldNotIgnore)
}

func requiredPolicyFiles(paths []string, basename string) (map[string]struct{}, error) {
	required := map[string]struct{}{basename: {}}
	for _, configured := range paths {
		if _, err := validatePortableQuery(configured); err != nil {
			return nil, err
		}
		directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(configured)))
		if directory == "." {
			continue
		}
		current := ""
		for _, component := range strings.Split(directory, "/") {
			if current == "" {
				current = component
			} else {
				current += "/" + component
			}
			required[current+"/"+basename] = struct{}{}
			if len(required) > maxMaterializedPolicyFiles {
				return nil, errors.New("exact policy file count exceeds the bounded work budget")
			}
		}
	}
	return required, nil
}

func (r *Repository) materializePolicyFiles(ctx context.Context, worktree string, entries map[string]TreeEntry, required map[string]struct{}, kind string) error {
	if len(required) > maxMaterializedPolicyFiles {
		return errors.New("exact policy file count exceeds the bounded work budget")
	}
	names := make([]string, 0, len(required))
	for name := range required {
		entry, ok := entries[name]
		if !ok {
			continue
		}
		if entry.Mode != "100644" || entry.Type != "blob" {
			return fmt.Errorf("%s file %q is not a regular 100644 blob", kind, name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	requests := make([]BlobRequest, len(names))
	for index, name := range names {
		requests[index] = BlobRequest{OID: entries[name].OID, Max: 1 << 20}
	}
	var consumed int64
	return r.ConsumeBlobs(ctx, requests, func(index int, reader io.Reader, size int64) error {
		if size > maxMaterializedPolicyBytes-consumed {
			return errors.New("exact policy contents exceed the bounded work budget")
		}
		consumed += size
		name := names[index]
		full := filepath.Join(worktree, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return err
		}
		file, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		written, writeErr := io.Copy(file, reader)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || written != size {
			return fmt.Errorf("materialize %s file", kind)
		}
		return nil
	})
}

type isolatedRepository struct {
	repo     *Repository
	worktree string
	empty    string
}

func (r *Repository) newIsolatedRepository(ctx context.Context, bare bool) (isolatedRepository, func() error, error) {
	temporary, err := os.MkdirTemp("", "gitseal-tree-policy-")
	if err != nil {
		return isolatedRepository{}, func() error { return nil }, err
	}
	cleanup := func() error { return os.RemoveAll(temporary) }
	if err := os.Chmod(temporary, 0o700); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	for _, forbidden := range []string{r.worktree, r.gitDir, r.commonDir} {
		if forbidden != "" && within(temporary, forbidden) {
			return isolatedRepository{}, func() error { return nil }, errors.Join(errors.New("isolated policy directory is inside the repository trust boundary"), cleanup())
		}
	}
	home := filepath.Join(temporary, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	template := filepath.Join(temporary, "template")
	if err := os.Mkdir(template, 0o700); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	empty := filepath.Join(temporary, "empty")
	file, err := os.OpenFile(empty, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	if err := file.Close(); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	location := filepath.Join(temporary, "repo")
	copyRepo := *r
	copyRepo.worktree = location
	copyRepo.bare = bare
	copyRepo.env = isolatedEnvironment(r.env, home)
	initArgs := []string{"init", "--quiet", "--template=" + template, "--object-format=" + r.objectFormat}
	if bare {
		initArgs = append(initArgs, "--bare")
	}
	initArgs = append(initArgs, location)
	if _, err := copyRepo.raw(ctx, temporary, nil, initArgs...); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	base := r.worktree
	if r.bare {
		base = r.gitDir
	}
	objects, err := r.gitPath(ctx, base, "objects")
	if err != nil || strings.ContainsAny(objects, "\r\n\x00") {
		return isolatedRepository{}, func() error { return nil }, errors.Join(errors.New("resolve original object directory for isolated policy evaluation"), cleanup())
	}
	gitDirectory := filepath.Join(location, ".git")
	if bare {
		gitDirectory = location
	}
	infoDirectory := filepath.Join(gitDirectory, "info")
	if err := os.MkdirAll(infoDirectory, 0o700); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	for _, name := range []string{"attributes", "exclude"} {
		file, openErr := os.OpenFile(filepath.Join(infoDirectory, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if openErr != nil {
			return isolatedRepository{}, func() error { return nil }, errors.Join(openErr, cleanup())
		}
		if closeErr := file.Close(); closeErr != nil {
			return isolatedRepository{}, func() error { return nil }, errors.Join(closeErr, cleanup())
		}
	}
	objectInfoDirectory := filepath.Join(gitDirectory, "objects", "info")
	if err := os.MkdirAll(objectInfoDirectory, 0o700); err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	alternates, err := os.OpenFile(filepath.Join(objectInfoDirectory, "alternates"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(err, cleanup())
	}
	_, writeErr := io.WriteString(alternates, filepath.ToSlash(objects)+"\n")
	closeErr := alternates.Close()
	if writeErr != nil || closeErr != nil {
		return isolatedRepository{}, func() error { return nil }, errors.Join(errors.New("configure isolated object alternate"), writeErr, closeErr, cleanup())
	}
	copyRepo.gitDir = gitDirectory
	copyRepo.commonDir = gitDirectory
	return isolatedRepository{repo: &copyRepo, worktree: location, empty: empty}, cleanup, nil
}

func isolatedEnvironment(base []string, home string) []string {
	drop := map[string]bool{
		"HOME": true, "USERPROFILE": true, "XDG_CONFIG_HOME": true,
		"GIT_CONFIG_NOSYSTEM": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_GLOBAL": true,
		"GIT_ATTR_NOSYSTEM": true, "GIT_TEMPLATE_DIR": true,
	}
	out := make([]string, 0, len(base)+4)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !drop[strings.ToUpper(key)] {
			out = append(out, entry)
		}
	}
	return append(out, "HOME="+home, "USERPROFILE="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_ATTR_NOSYSTEM=1")
}

func validatePortableQuery(value string) (string, error) {
	if value == ".gitignore" || value == ".gitattributes" || strings.HasPrefix(value, ".gitseal/") || value == ".gitseal.tmp.probe" {
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", errors.New("invalid exact-tree policy query")
		}
		return value, nil
	}
	// Importing pathpolicy here would form no cycle; keep this helper narrowly
	// syntactic because configured paths were already schema-validated.
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, "\\\r\n\x00") || strings.Contains(value, "../") || strings.HasPrefix(value, "../") {
		return "", errors.New("invalid exact-tree policy query")
	}
	return value, nil
}

func validateAttributeOutput(out []byte, paths []string) error {
	fields := bytes.Split(out, []byte{0})
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	if len(fields) != len(paths)*len(managedAttributeNames)*3 {
		return errors.New("Git returned malformed exact-tree attribute results")
	}
	for pathIndex, configured := range paths {
		for attributeIndex, attribute := range managedAttributeNames {
			i := (pathIndex*len(managedAttributeNames) + attributeIndex) * 3
			if string(fields[i]) != configured || string(fields[i+1]) != attribute {
				return errors.New("Git returned attribute results for an unexpected path or attribute")
			}
			if string(fields[i+2]) != "unset" {
				return fmt.Errorf("exact policy attribute %q for %q is %q, not unset", fields[i+1], fields[i], fields[i+2])
			}
		}
	}
	return nil
}

func validateIgnoreOutput(out []byte, shouldIgnore, shouldNotIgnore []string) error {
	paths := append(append([]string(nil), shouldIgnore...), shouldNotIgnore...)
	fields := bytes.Split(out, []byte{0})
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	if len(fields) != len(paths)*4 {
		return errors.New("Git returned malformed exact-tree ignore results")
	}
	for idx, configured := range paths {
		source, pattern, returned := fields[idx*4], fields[idx*4+2], string(fields[idx*4+3])
		if returned != configured {
			return errors.New("Git returned ignore results for an unexpected exact-tree path")
		}
		ignored := (len(source) > 0 || len(pattern) > 0) && !bytes.HasPrefix(pattern, []byte("!"))
		if idx < len(shouldIgnore) && !ignored {
			return fmt.Errorf("%q is not ignored by the exact selected tree", configured)
		}
		if idx >= len(shouldIgnore) && ignored {
			return fmt.Errorf("%q is unexpectedly ignored by the exact selected tree", configured)
		}
	}
	return nil
}
