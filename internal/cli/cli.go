// Package cli implements GitSeal's stable command-line boundary. It owns
// argument parsing and terminal-safe presentation, but delegates security
// decisions to the typed internal packages.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/raydalsayf/gitseal/internal/app"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/hooks"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/treeverify"
)

const (
	Version          = "0.1.0-pre"
	SchemaRange      = "project:2,recipients:1,manifest:1,state:2"
	JSONSchemaRange  = "1"
	unknownSourceRev = "unknown"
)

// SourceRevision is replaced only by a reproducible release build using
// -trimpath and -ldflags. It intentionally has no timestamp.
var SourceRevision = unknownSourceRev

type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
	Cwd    string
}

type commandFailure struct {
	code exitcode.Code
	err  error
}

func (e *commandFailure) Error() string { return e.err.Error() }
func (e *commandFailure) Unwrap() error { return e.err }

func fail(code exitcode.Code, err error) error {
	if err == nil {
		err = errors.New("operation failed")
	}
	return &commandFailure{code: code, err: err}
}

// Run executes one invocation and converts every failure, including a panic,
// into a stable non-success category. It never prints a stack trace.
func (r Runner) Run(ctx context.Context, args []string) (code exitcode.Code) {
	if r.Stdout == nil {
		r.Stdout = io.Discard
	}
	if r.Stderr == nil {
		r.Stderr = io.Discard
	}
	if r.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			r.diagnostic(errors.New("working directory is unavailable"))
			return exitcode.FilesystemSafety
		}
		r.Cwd = cwd
	}
	defer func() {
		if recover() != nil {
			r.diagnostic(errors.New("internal failure"))
			code = exitcode.General
		}
	}()
	if len(args) == 0 {
		r.usage()
		return exitcode.General
	}
	var err error
	switch args[0] {
	case "help", "--help", "-h":
		r.usage()
		return exitcode.Success
	case "init":
		err = r.runInit(ctx, args[1:])
	case "identity":
		err = r.runIdentity(ctx, args[1:])
	case "member":
		err = r.runMember(ctx, args[1:])
	case "protect":
		err = r.runProtect(ctx, args[1:])
	case "unprotect":
		err = r.runUnprotect(ctx, args[1:])
	case "encrypt":
		err = r.runEncrypt(ctx, args[1:])
	case "decrypt":
		err = r.runDecrypt(ctx, args[1:])
	case "sync":
		err = r.runSync(ctx, args[1:])
	case "status":
		err = r.runStatus(ctx, args[1:])
	case "doctor":
		err = r.runDoctor(ctx, args[1:])
	case "verify":
		err = r.runVerify(ctx, args[1:])
	case "hook":
		err = r.runHook(ctx, args[1:])
	case "version":
		err = r.runVersion(args[1:])
	default:
		err = fail(exitcode.General, fmt.Errorf("unknown command %s", quote(args[0])))
	}
	if err == nil {
		return exitcode.Success
	}
	var command *commandFailure
	if errors.As(err, &command) {
		code = command.code
	} else {
		code = categorize(err, exitcode.General)
	}
	r.diagnostic(err)
	return code
}

func (r Runner) runInit(ctx context.Context, args []string) error {
	fs := newFlagSet("init")
	_ = fs.Bool("non-interactive", false, "refuse prompts (this command does not prompt)")
	upgradeTrust := fs.Bool("upgrade-project-trust", false, "explicitly upgrade a legacy project to retained-safety trust")
	acceptRetained := fs.String("accept-retained-safety", "", "exact reviewed retained-safety SHA-256 for trust migration")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 0); err != nil {
		return err
	}
	if !*upgradeTrust && *acceptRetained != "" {
		return fail(exitcode.InvalidConfig, errors.New("--accept-retained-safety requires --upgrade-project-trust"))
	}
	if *upgradeTrust {
		project, err := app.PreviewProjectTrustUpgrade(ctx, r.Cwd)
		if err != nil {
			return fail(categorize(err, exitcode.InvalidConfig), err)
		}
		printMappingReview(r.Stderr, project)
		if *acceptRetained == "" {
			return fail(exitcode.TrustRequired, errors.New("project trust upgrade requires --accept-retained-safety with the exact displayed digest; nothing was changed"))
		}
		projectSnapshot, err := app.ProjectSnapshotDigest(project)
		if err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		result, err := app.UpgradeProjectTrust(ctx, r.Cwd, *acceptRetained, projectSnapshot.Hex())
		if err != nil {
			return fail(categorize(err, exitcode.TrustRequired), err)
		}
		if len(result.Completed) == 0 {
			fmt.Fprintln(r.Stdout, "Project and local retained-safety trust are already current.")
		} else {
			fmt.Fprintf(r.Stdout, "Upgraded retained-safety trust: %s\n", joinQuoted(result.Completed))
		}
		return nil
	}
	result, err := app.Init(ctx, r.Cwd)
	if err != nil {
		return fail(categorize(err, exitcode.FilesystemSafety), err)
	}
	if len(result.Completed) == 0 {
		fmt.Fprintln(r.Stdout, "GitSeal project metadata is already initialized.")
	} else {
		fmt.Fprintf(r.Stdout, "Initialized GitSeal V1 metadata: %s\n", joinQuoted(result.Completed))
	}
	return nil
}

func (r Runner) runIdentity(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(exitcode.InvalidConfig, errors.New("identity requires create, use, or show"))
	}
	switch args[0] {
	case "create":
		fs := newFlagSet("identity create")
		name := fs.String("name", "default", "local identity name")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 0); err != nil {
			return err
		}
		record, err := app.IdentityCreate(ctx, *name)
		if err != nil {
			return fail(categorize(err, exitcode.FilesystemSafety), err)
		}
		return r.printIdentity(record.Name, record.Path, record.Recipient, record.Fingerprint, *jsonOut, true)
	case "use":
		fs := newFlagSet("identity use")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 1); err != nil {
			return err
		}
		record, err := app.IdentityUse(ctx, r.Cwd, fs.Arg(0))
		if err != nil {
			return fail(categorize(err, exitcode.MissingIdentity), err)
		}
		return r.printIdentity(record.Name, record.Path, record.Recipient, record.Fingerprint, *jsonOut, false)
	case "show":
		fs := newFlagSet("identity show")
		name := fs.String("identity", "", "identity name override")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 0); err != nil {
			return err
		}
		record, err := app.IdentityShow(ctx, r.Cwd, *name)
		if err != nil {
			return fail(categorize(err, exitcode.MissingIdentity), err)
		}
		return r.printIdentity(record.Name, record.Path, record.Recipient, record.Fingerprint, *jsonOut, false)
	default:
		return fail(exitcode.InvalidConfig, fmt.Errorf("unknown identity operation %s", quote(args[0])))
	}
}

func (r Runner) printIdentity(name, path, recipient, fingerprint string, jsonOut, created bool) error {
	value := struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Path          string `json:"path"`
		Recipient     string `json:"recipient"`
		Fingerprint   string `json:"fingerprint"`
	}{1, name, path, recipient, fingerprint}
	if jsonOut {
		return writeJSON(r.Stdout, value)
	}
	fmt.Fprintf(r.Stdout, "Identity: %s\nPath: %s\nRecipient: %s\nFingerprint: %s\n", quote(name), quote(path), quote(recipient), quote(fingerprint))
	if created {
		fmt.Fprintln(r.Stdout, "Create and verify an offline recovery backup before depending on this identity; GitSeal created no backup.")
	}
	return nil
}

func (r Runner) runMember(ctx context.Context, args []string) (resultErr error) {
	if len(args) == 0 {
		return fail(exitcode.InvalidConfig, errors.New("member requires add, remove, or list"))
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	switch args[0] {
	case "list":
		fs := newFlagSet("member list")
		full := fs.Bool("full", false, "include canonical public recipients")
		identityName := fs.String("identity", "", "identity name used for the membership check")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 0); err != nil {
			return err
		}
		list, err := w.ListMembers(*identityName)
		if err != nil {
			return err
		}
		if *jsonOut {
			return writeJSON(r.Stdout, memberListForJSON(list, *full))
		}
		for _, member := range list.Members {
			fmt.Fprintf(r.Stdout, "%s  %s  %s\n", quote(member.ID), quote(member.Name), quote(member.Fingerprint))
			if *full {
				fmt.Fprintf(r.Stdout, "  recipient %s\n", quote(member.Recipient))
			}
		}
		fmt.Fprintf(r.Stdout, "Recipient set: %s\n", quote(list.RecipientSetFingerprint))
		if list.SelectedInSet != nil {
			fmt.Fprintf(r.Stdout, "Selected identity in set: %t\n", *list.SelectedInSet)
		}
		return nil
	case "add":
		fs := newFlagSet("member add")
		id := fs.String("id", "", "stable member ID")
		name := fs.String("name", "", "display name")
		recipient := fs.String("recipient", "", "canonical native hybrid public recipient")
		acceptedFingerprint := fs.String("accept-fingerprint", "", "exact full grouped recipient fingerprint verified through an independent authenticated channel")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 0); err != nil {
			return err
		}
		change, err := w.AddMember(ctx, projectconfig.Member{ID: *id, Name: *name, Recipient: *recipient}, *acceptedFingerprint)
		if err != nil {
			return fail(categorize(err, exitcode.TrustRequired), err)
		}
		fmt.Fprintf(r.Stdout, "Member added. Full fingerprint: %s\n", quote(change.Fingerprint))
		return printStale(r.Stdout, change.Stale)
	case "remove":
		fs := newFlagSet("member remove")
		confirm := fs.Bool("confirm-rotation-warning", false, "confirm old copies remain readable and revocation requires credential rotation")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 1); err != nil {
			return err
		}
		change, err := w.RemoveMember(ctx, fs.Arg(0), *confirm)
		if err != nil {
			return fail(categorize(err, exitcode.TrustRequired), err)
		}
		fmt.Fprintf(r.Stdout, "Member removed. Former fingerprint: %s\nOld commits and copies remain readable; rotate the underlying credential for revocation.\n", quote(change.Fingerprint))
		return printStale(r.Stdout, change.Stale)
	default:
		return fail(exitcode.InvalidConfig, fmt.Errorf("unknown member operation %s", quote(args[0])))
	}
}

func (r Runner) runProtect(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("protect")
	encrypted := fs.String("encrypted", "", "configured ciphertext path")
	identityName := fs.String("identity", "", "identity name override")
	ack := fs.String("acknowledge-exposure", "", "exact previously exposed plaintext path")
	force := fs.Bool("force", false, "choose local plaintext when both sides changed")
	trust := addTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 1); err != nil {
		return err
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	proposed := w.Project
	destination := *encrypted
	if destination == "" {
		destination = fs.Arg(0) + ".age"
	}
	proposed.ProtectedFiles = append(append([]projectconfig.ProtectedFile(nil), proposed.ProtectedFiles...), projectconfig.ProtectedFile{Source: fs.Arg(0), Encrypted: destination})
	if *trust.mappings || *trust.retained {
		if err := proposed.Validate(); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		printMappingReview(r.Stderr, proposed)
	}
	if *trust.initial || *trust.recipients {
		printRecipientReview(r.Stderr, w.Recipients)
	}
	trustOptions, err := trust.value(proposed, w.Recipients)
	if err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	result, err := w.Protect(ctx, fs.Arg(0), app.ProtectOptions{Encrypted: *encrypted, Identity: *identityName, Trust: trustOptions, AcknowledgeExposure: *ack, Force: *force})
	if err != nil {
		return fail(categorize(err, exitcode.General), err)
	}
	printCrypto(r.Stdout, result)
	return nil
}

func (r Runner) runUnprotect(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("unprotect")
	makeTrackable := fs.String("make-trackable", "", "confirm the exact plaintext path whose ignore protection may be removed")
	drop := fs.String("drop-artifact-protection", "", "confirm the exact absent artifact path whose binary protection may be removed")
	accept := fs.Bool("accept-mapping-changes", false, "accept the exact mapping change")
	acceptRetained := fs.Bool("accept-retained-safety-changes", false, "accept the exact retained plaintext/artifact safety change")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 1); err != nil {
		return err
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	expectedMappings := ""
	expectedRetained := ""
	expectedProject := ""
	if *accept || *acceptRetained {
		updated, err := w.PreviewUnprotect(ctx, fs.Arg(0), app.UnprotectOptions{MakeTrackable: *makeTrackable, DropArtifactProtection: *drop})
		if err != nil {
			return fail(categorize(err, exitcode.TrustRequired), err)
		}
		if *accept {
			expectedMappings = updated.MappingDigest().Hex()
		}
		if *acceptRetained {
			expectedRetained = updated.RetainedSafetyDigest().Hex()
		}
		projectSnapshot, err := app.ProjectSnapshotDigest(updated)
		if err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		expectedProject = projectSnapshot.Hex()
		printMappingReview(r.Stderr, updated)
	}
	err = w.Unprotect(ctx, fs.Arg(0), app.UnprotectOptions{
		MakeTrackable: *makeTrackable, DropArtifactProtection: *drop,
		AcceptMappingChanges: *accept, AcceptRetainedSafety: *acceptRetained,
		ExpectedProjectSHA256: expectedProject, ExpectedMappingsSHA256: expectedMappings,
		ExpectedRetainedSafetySHA256: expectedRetained,
	})
	if err != nil {
		return fail(categorize(err, exitcode.TrustRequired), err)
	}
	fmt.Fprintf(r.Stdout, "Updated protection policy for %s; plaintext and ciphertext were not deleted or staged.\n", quote(fs.Arg(0)))
	return nil
}

func (r Runner) runEncrypt(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("encrypt")
	all := fs.Bool("all", false, "encrypt every changed or recipient-stale mapping")
	identityName := fs.String("identity", "", "identity name override")
	force := fs.Bool("force", false, "choose local plaintext when both sides changed")
	trust := addTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if fs.NArg() > 1 {
		return fail(exitcode.InvalidConfig, errors.New("encrypt accepts at most one FILE"))
	}
	requested := ""
	if fs.NArg() == 1 {
		requested = fs.Arg(0)
	}
	if *force && (*all || requested == "") {
		return fail(exitcode.InvalidConfig, errors.New("encrypt --force requires exactly one FILE and cannot be combined with --all"))
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	if *trust.mappings || *trust.retained {
		printMappingReview(r.Stderr, w.Project)
	}
	if *trust.initial || *trust.recipients {
		printRecipientReview(r.Stderr, w.Recipients)
	}
	trustOptions, err := trust.value(w.Project, w.Recipients)
	if err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	results, err := w.Encrypt(ctx, requested, *all, app.EncryptOptions{Identity: *identityName, Trust: trustOptions, Force: *force})
	for _, result := range results {
		printCrypto(r.Stdout, result)
	}
	if err != nil {
		return fail(categorize(err, exitcode.Cryptography), err)
	}
	if len(results) == 0 {
		fmt.Fprintln(r.Stdout, "No artifact required encryption.")
	}
	return nil
}

func (r Runner) runDecrypt(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("decrypt")
	all := fs.Bool("all", false, "decrypt every configured mapping")
	identityName := fs.String("identity", "", "identity name override")
	force := fs.Bool("force", false, "choose ciphertext over changed local plaintext")
	acceptIncoming := fs.String("accept-incoming", "", "exact observed ciphertext SHA-256")
	recoverManifest := fs.Bool("recover-without-manifest", false, "explicitly bypass exact manifest bookkeeping for recovery")
	acceptMappings := fs.Bool("accept-mapping-changes", false, "accept exact configured mappings")
	acceptRetained := fs.Bool("accept-retained-safety-changes", false, "accept exact retained plaintext/artifact safety policy")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if fs.NArg() > 1 {
		return fail(exitcode.InvalidConfig, errors.New("decrypt accepts at most one FILE"))
	}
	requested := ""
	if fs.NArg() == 1 {
		requested = fs.Arg(0)
	}
	if *force && (*all || requested == "") {
		return fail(exitcode.InvalidConfig, errors.New("decrypt --force requires exactly one FILE and cannot be combined with --all"))
	}
	if *acceptIncoming != "" {
		if *all || requested == "" {
			return fail(exitcode.InvalidConfig, errors.New("decrypt --accept-incoming requires exactly one FILE and cannot be combined with --all"))
		}
		if _, err := digest.ParseHex(*acceptIncoming); err != nil {
			return fail(exitcode.InvalidConfig, errors.New("decrypt --accept-incoming requires exactly 64 lowercase hexadecimal characters"))
		}
	}
	if *recoverManifest && (*all || requested == "") {
		return fail(exitcode.InvalidConfig, errors.New("decrypt --recover-without-manifest requires exactly one FILE and cannot be combined with --all"))
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	projectSnapshot, err := app.ProjectSnapshotDigest(w.Project)
	if err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	expectedMappings := ""
	expectedRetained := ""
	if *acceptMappings || *acceptRetained {
		printMappingReview(r.Stderr, w.Project)
	}
	if *acceptMappings {
		expectedMappings = w.Project.MappingDigest().Hex()
	}
	if *acceptRetained {
		expectedRetained = w.Project.RetainedSafetyDigest().Hex()
	}
	if *force {
		fmt.Fprintln(r.Stderr, "WARNING: --force chooses ciphertext over changed local plaintext; unfamiliar ciphertext still requires its exact digest.")
	}
	if *recoverManifest {
		fmt.Fprintln(r.Stderr, "WARNING: --recover-without-manifest bypasses GitSeal manifest bookkeeping for this exact configured file.")
	}
	results, err := w.Decrypt(ctx, requested, *all, app.DecryptOptions{
		Identity: *identityName, Force: *force, AcceptIncoming: *acceptIncoming, RecoverNoManifest: *recoverManifest,
		AcceptMappings: *acceptMappings, AcceptRetainedSafety: *acceptRetained,
		ExpectedProjectSHA256: projectSnapshot.Hex(), ExpectedMappingsSHA256: expectedMappings,
		ExpectedRetainedSafetySHA256: expectedRetained,
	})
	for _, result := range results {
		printCrypto(r.Stdout, result)
	}
	if err != nil {
		return fail(categorize(err, exitcode.Cryptography), err)
	}
	return nil
}

func (r Runner) runSync(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("sync")
	identityName := fs.String("identity", "", "identity name override")
	acceptIncoming := fs.String("accept-incoming", "", "exact observed ciphertext SHA-256")
	acceptMappings := fs.Bool("accept-mapping-changes", false, "accept exact configured mappings")
	acceptRetained := fs.Bool("accept-retained-safety-changes", false, "accept exact retained plaintext/artifact safety policy")
	jsonOut := fs.Bool("json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if fs.NArg() > 1 {
		return fail(exitcode.InvalidConfig, errors.New("sync accepts at most one FILE"))
	}
	requested := ""
	if fs.NArg() == 1 {
		requested = fs.Arg(0)
	}
	if *acceptIncoming != "" {
		if requested == "" {
			return fail(exitcode.InvalidConfig, errors.New("sync --accept-incoming requires one exact FILE destination"))
		}
		if _, err := digest.ParseHex(*acceptIncoming); err != nil {
			return fail(exitcode.InvalidConfig, errors.New("sync --accept-incoming requires exactly 64 lowercase hexadecimal characters"))
		}
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	projectSnapshot, err := app.ProjectSnapshotDigest(w.Project)
	if err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	expectedMappings := ""
	expectedRetained := ""
	if *acceptMappings || *acceptRetained {
		printMappingReview(r.Stderr, w.Project)
	}
	if *acceptMappings {
		expectedMappings = w.Project.MappingDigest().Hex()
	}
	if *acceptRetained {
		expectedRetained = w.Project.RetainedSafetyDigest().Hex()
	}
	report, results, err := w.Sync(ctx, requested, app.SyncOptions{
		Identity: *identityName, AcceptIncoming: *acceptIncoming,
		AcceptMappings: *acceptMappings, AcceptRetainedSafety: *acceptRetained,
		ExpectedProjectSHA256: projectSnapshot.Hex(), ExpectedMappingsSHA256: expectedMappings,
		ExpectedRetainedSafetySHA256: expectedRetained,
	})
	if *jsonOut {
		value := struct {
			SchemaVersion int                `json:"schema_version"`
			Status        app.StatusReport   `json:"status"`
			Completed     []app.CryptoResult `json:"completed"`
		}{1, report, results}
		if jsonErr := writeJSON(r.Stdout, value); jsonErr != nil {
			return jsonErr
		}
	} else {
		printStatus(r.Stdout, report)
		for _, result := range results {
			printCrypto(r.Stdout, result)
		}
	}
	if err != nil {
		return fail(categorize(err, exitcode.Conflict), err)
	}
	return nil
}

func (r Runner) runStatus(ctx context.Context, args []string) (resultErr error) {
	fs := newFlagSet("status")
	jsonOut := fs.Bool("json", false, "write JSON")
	schema := fs.Int("schema-version", 1, "requested JSON schema version")
	identityName := fs.String("identity", "", "identity name override")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 0); err != nil {
		return err
	}
	if *schema != 1 {
		return fail(exitcode.InvalidConfig, fmt.Errorf("unsupported status schema version %d", *schema))
	}
	w, err := app.Open(ctx, r.Cwd)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	report, statusErr := w.Status(ctx, *identityName)
	if *jsonOut {
		if err := writeJSON(r.Stdout, report); err != nil {
			return err
		}
	} else {
		printStatus(r.Stdout, report)
	}
	return statusErr
}

func (r Runner) runDoctor(ctx context.Context, args []string) error {
	fs := newFlagSet("doctor")
	jsonOut := fs.Bool("json", false, "write JSON")
	identityName := fs.String("identity", "", "identity name override")
	full := fs.Bool("full-decrypt", false, "authenticate every artifact payload through EOF into a discard sink")
	history := fs.Bool("history", false, "scan the documented reachable local history scope")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 0); err != nil {
		return err
	}
	report, doctorErr := app.DoctorAt(ctx, r.Cwd, *identityName, *full, *history)
	if *jsonOut {
		if err := writeJSON(r.Stdout, report); err != nil {
			return err
		}
	} else {
		for _, item := range report.Diagnostics {
			fmt.Fprintf(r.Stdout, "%s %s %s %s\n", strings.ToUpper(item.Severity), quote(item.Code), quote(item.Path), quote(item.Message))
		}
		for _, scope := range report.HistoryScope {
			fmt.Fprintf(r.Stdout, "HISTORY-SCOPE %s\n", quote(scope))
		}
	}
	if doctorErr != nil {
		return doctorErr
	}
	if !report.OK() {
		return fail(exitcode.GitSafety, errors.New("doctor completed with blocking findings"))
	}
	return nil
}

func (r Runner) runVerify(ctx context.Context, args []string) error {
	fs := newFlagSet("verify")
	source := fs.String("source", "", "exact commit, tag, or tree to validate")
	requireProject := fs.Bool("require-project", false, "reject a tree with no complete GitSeal project")
	jsonOut := fs.Bool("json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 0); err != nil {
		return err
	}
	if *source == "" {
		return fail(exitcode.InvalidConfig, errors.New("verify requires --source TREE"))
	}
	repo, err := gitrepo.Discover(ctx, r.Cwd, gitrepo.DiscoverOptions{AllowBare: true})
	if err != nil {
		return fail(exitcode.GitSafety, err)
	}
	report, err := treeverify.Verify(ctx, repo, *source, *requireProject)
	if err != nil {
		return fail(exitcode.GitSafety, err)
	}
	if *jsonOut {
		if err := writeJSON(r.Stdout, report); err != nil {
			return err
		}
	} else {
		for _, finding := range report.Findings {
			fmt.Fprintf(r.Stdout, "%s %s %s\n", quote(finding.Code), quote(finding.Path), quote(finding.Message))
		}
		if report.OK() {
			fmt.Fprintf(r.Stdout, "Validated exact tree %s from %s.\n", quote(report.Tree), quote(report.Source))
		}
	}
	if !report.OK() {
		return fail(exitcode.GitSafety, errors.New("exact-tree validation completed with blocking findings"))
	}
	return nil
}

func (r Runner) runVersion(args []string) error {
	fs := newFlagSet("version")
	jsonOut := fs.Bool("json", false, "write JSON")
	if err := fs.Parse(args); err != nil {
		return fail(exitcode.InvalidConfig, err)
	}
	if err := exactArgs(fs, 0); err != nil {
		return err
	}
	value := struct {
		SchemaVersion   int    `json:"schema_version"`
		Version         string `json:"version"`
		SourceRevision  string `json:"source_revision"`
		SchemaRange     string `json:"schema_range"`
		JSONSchemaRange string `json:"json_schema_range"`
		GoVersion       string `json:"go_version"`
	}{1, Version, SourceRevision, SchemaRange, JSONSchemaRange, runtime.Version()}
	if *jsonOut {
		return writeJSON(r.Stdout, value)
	}
	fmt.Fprintf(r.Stdout, "gitseal %s source=%s schemas=%s json=%s go=%s\n", value.Version, quote(value.SourceRevision), value.SchemaRange, value.JSONSchemaRange, value.GoVersion)
	return nil
}

func (r Runner) runHook(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(exitcode.InvalidConfig, errors.New("hook requires install, remove, or run"))
	}
	switch args[0] {
	case "install", "remove":
		fs := newFlagSet("hook " + args[0])
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 0); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return fail(exitcode.FilesystemSafety, errors.New("resolve current GitSeal executable"))
		}
		var report hooks.ChangeReport
		if args[0] == "install" {
			report, err = hooks.Install(ctx, r.Cwd, executable)
		} else {
			report, err = hooks.Remove(ctx, r.Cwd, executable)
		}
		for _, change := range report.Hooks {
			fmt.Fprintf(r.Stdout, "%s %s %s\n", quote(change.Name), quote(change.Action), quote(change.Path))
		}
		if err != nil {
			var conflict *hooks.ConflictError
			if errors.As(err, &conflict) && len(conflict.IntegrationArgs) > 0 {
				fmt.Fprintf(r.Stderr, "Integration argument vector: %s\n", joinQuoted(conflict.IntegrationArgs))
			}
			return fail(categorize(err, exitcode.GitSafety), err)
		}
		if args[0] == "install" {
			fmt.Fprintln(r.Stdout, "Local hooks are not cloned; every contributor must install them. --no-verify can bypass them, so trusted exact-tree CI remains mandatory.")
		}
		return nil
	case "run":
		fs := newFlagSet("hook run")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return fail(exitcode.InvalidConfig, err)
		}
		if err := exactArgs(fs, 1); err != nil {
			return err
		}
		report, err := hooks.Run(ctx, r.Cwd, fs.Arg(0))
		if *jsonOut {
			value := struct {
				SchemaVersion      int               `json:"schema_version"`
				Hook               string            `json:"hook"`
				Static             treeverify.Report `json:"static"`
				Tier2Authenticated []string          `json:"tier2_authenticated"`
			}{1, report.Hook, report.Static, report.Tier2Authenticated}
			if jsonErr := writeJSON(r.Stdout, value); jsonErr != nil {
				return jsonErr
			}
		} else if err == nil {
			fmt.Fprintf(r.Stdout, "Validated exact prospective index for %s; mandatory Tier 2 authenticated %d artifact(s).\n", quote(report.Hook), len(report.Tier2Authenticated))
		}
		if err != nil {
			return fail(categorize(err, exitcode.GitSafety), err)
		}
		return nil
	default:
		return fail(exitcode.InvalidConfig, fmt.Errorf("unknown hook operation %s", quote(args[0])))
	}
}

type trustFlags struct {
	initial    *bool
	recipients *bool
	mappings   *bool
	retained   *bool
}

func addTrustFlags(fs *flag.FlagSet) trustFlags {
	return trustFlags{
		initial:    fs.Bool("accept-recipients", false, "accept initial full recipient fingerprints after independent verification"),
		recipients: fs.Bool("accept-recipient-changes", false, "accept exact recipient-set and membership-policy changes"),
		mappings:   fs.Bool("accept-mapping-changes", false, "accept exact source/artifact mapping changes"),
		retained:   fs.Bool("accept-retained-safety-changes", false, "accept the exact retained plaintext/artifact safety policy"),
	}
}

func (f trustFlags) value(project projectconfig.Project, recipients projectconfig.Recipients) (app.TrustOptions, error) {
	result := app.TrustOptions{
		AcceptInitialRecipients:     *f.initial,
		AcceptRecipientChanges:      *f.recipients,
		AcceptMappingChanges:        *f.mappings,
		AcceptRetainedSafetyChanges: *f.retained,
	}
	projectSnapshot, err := app.ProjectSnapshotDigest(project)
	if err != nil {
		return app.TrustOptions{}, err
	}
	result.ExpectedProjectSHA256 = projectSnapshot.Hex()
	if *f.initial || *f.recipients {
		canonical := recipients.Canonical()
		result.ExpectedRecipientsSHA256 = digest.RecipientSet(canonical.RecipientStrings()).Hex()
		result.ExpectedMembershipPolicySHA256 = canonical.MembershipDigest().Hex()
	}
	if *f.mappings {
		result.ExpectedMappingsSHA256 = project.Canonical().MappingDigest().Hex()
	}
	if *f.retained {
		result.ExpectedRetainedSafetySHA256 = project.Canonical().RetainedSafetyDigest().Hex()
	}
	return result, nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func exactArgs(fs *flag.FlagSet, count int) error {
	if fs.NArg() != count {
		return fail(exitcode.InvalidConfig, fmt.Errorf("%s expects %d positional argument(s), received %d", fs.Name(), count, fs.NArg()))
	}
	return nil
}

func writeJSON(dst io.Writer, value any) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return fail(exitcode.General, errors.New("write JSON output"))
	}
	return nil
}

func quote(value string) string { return strconv.QuoteToASCII(value) }

func joinQuoted(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = quote(value)
	}
	return strings.Join(quoted, ", ")
}

func memberListForJSON(list app.MemberList, full bool) app.MemberList {
	if full {
		return list
	}
	list.Members = append([]app.MemberInfo(nil), list.Members...)
	for i := range list.Members {
		list.Members[i].Recipient = ""
	}
	return list
}

func printMappingReview(dst io.Writer, project projectconfig.Project) {
	canonical := project.Canonical()
	fmt.Fprintf(dst, "ACCEPT-MAPPING-DIGEST %s\n", canonical.MappingDigest().Hex())
	fmt.Fprintf(dst, "ACCEPT-RETAINED-SAFETY-DIGEST %s\n", canonical.RetainedSafetyDigest().Hex())
	if snapshot, err := app.ProjectSnapshotDigest(canonical); err == nil {
		fmt.Fprintf(dst, "REVIEW-PROJECT-SNAPSHOT-SHA256 %s\n", snapshot.Hex())
	}
	for _, mapping := range canonical.ProtectedFiles {
		fmt.Fprintf(dst, "ACCEPT-MAPPING %s -> %s\n", quote(mapping.Source), quote(mapping.Encrypted))
	}
	for _, retained := range canonical.RetainedSafety.IgnoredPlaintext {
		fmt.Fprintf(dst, "RETAINED-PLAINTEXT-SAFETY %s\n", quote(retained))
	}
	for _, retained := range canonical.RetainedSafety.BinaryArtifacts {
		fmt.Fprintf(dst, "RETAINED-ARTIFACT-SAFETY %s\n", quote(retained))
	}
}

func printRecipientReview(dst io.Writer, recipients projectconfig.Recipients) {
	canonical := recipients.Canonical()
	for _, member := range canonical.Members {
		fmt.Fprintf(dst, "ACCEPT-RECIPIENT %s name=%s fingerprint=%s\n", quote(member.ID), quote(member.Name), quote(digest.RecipientFingerprint(member.Recipient).Grouped()))
	}
	set := digest.RecipientSet(canonical.RecipientStrings())
	fmt.Fprintf(dst, "ACCEPT-RECIPIENT-SET %s\nACCEPT-MEMBERSHIP-POLICY %s\n", set.Hex(), canonical.MembershipDigest().Hex())
}

func printStale(dst io.Writer, stale []string) error {
	if len(stale) == 0 {
		return nil
	}
	fmt.Fprintf(dst, "%d artifact(s) are stale for the new recipient set: %s\nRun gitseal encrypt --all after reviewing recipient and mapping trust.\n", len(stale), joinQuoted(stale))
	return nil
}

func printCrypto(dst io.Writer, result app.CryptoResult) {
	fmt.Fprintf(dst, "%s -> %s ciphertext_sha256=%s recipients_sha256=%s baseline_saved=%t\n",
		quote(result.Source), quote(result.Encrypted), result.CiphertextSHA256, result.RecipientSetSHA256, result.StateSaved)
}

func printStatus(dst io.Writer, report app.StatusReport) {
	for _, item := range report.Files {
		fmt.Fprintf(dst, "%s  %s  %s", quote(item.Source), quote(item.Encrypted), quote(item.State))
		if item.Detail != "" {
			fmt.Fprintf(dst, "  %s", quote(item.Detail))
		}
		fmt.Fprintln(dst)
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(dst, "WARNING %s\n", quote(warning))
	}
}

func categorize(err error, fallback exitcode.Code) exitcode.Code {
	if err == nil {
		return exitcode.Success
	}
	if code := exitcode.Of(err); code != exitcode.General {
		return code
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "identity") && (strings.Contains(message, "missing") || strings.Contains(message, "selected") || strings.Contains(message, "does not exist") || strings.Contains(message, "no local")):
		return exitcode.MissingIdentity
	case strings.Contains(message, "identity") && (strings.Contains(message, "recipient set") || strings.Contains(message, "not authorized") || strings.Contains(message, "did not match")):
		return exitcode.Unauthorized
	case strings.Contains(message, "accept") || strings.Contains(message, "trust") || strings.Contains(message, "confirmation") || strings.Contains(message, "verified"):
		return exitcode.TrustRequired
	case strings.Contains(message, "unmerged") || strings.Contains(message, "conflict") || strings.Contains(message, "both changed"):
		return exitcode.Conflict
	case strings.Contains(message, "lock") || strings.Contains(message, "busy") || strings.Contains(message, "indeterminate"):
		return exitcode.Busy
	case strings.Contains(message, "git") || strings.Contains(message, "index") || strings.Contains(message, "tracked") || strings.Contains(message, "attribute") || strings.Contains(message, "ignore"):
		return exitcode.GitSafety
	case strings.Contains(message, "yaml") || strings.Contains(message, "configuration") || strings.Contains(message, "manifest") || strings.Contains(message, "schema"):
		return exitcode.InvalidConfig
	case strings.Contains(message, "decrypt") || strings.Contains(message, "encrypt") || strings.Contains(message, "ciphertext") || strings.Contains(message, "stanza") || strings.Contains(message, "header"):
		return exitcode.Cryptography
	case strings.Contains(message, "filesystem") || strings.Contains(message, "permission") || strings.Contains(message, "acl") || strings.Contains(message, "reparse") || strings.Contains(message, "publish") || strings.Contains(message, "path"):
		return exitcode.FilesystemSafety
	default:
		return fallback
	}
}

func (r Runner) diagnostic(err error) {
	message := "operation failed"
	if err != nil {
		message = err.Error()
	}
	// Quoting prevents ANSI and control characters in hostile paths, Git output,
	// member names, and schema diagnostics from reaching the terminal verbatim.
	fmt.Fprintf(r.Stderr, "gitseal: %s\n", quote(message))
}

func (r Runner) usage() {
	fmt.Fprintln(r.Stdout, `GitSeal V1 pre-alpha

Usage: gitseal COMMAND [OPTIONS]

Commands:
  init
  identity create|use|show
  member add|remove|list
  protect | unprotect
  encrypt | decrypt | sync
  status | doctor
  verify --source TREE
  hook install|remove|run
  version

GitSeal never accepts private identities on the command line and never decrypts plaintext to stdout.`)
}
