package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/hooks"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
)

const DoctorSchemaVersion = 1

const maxHistoryIdentityScanBytes = int64(8 << 30)

var errHistoryIdentityScanBudget = errors.New("history private-identity scan byte budget exceeded")

type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type DoctorReport struct {
	SchemaVersion int          `json:"schema_version"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
	HistoryScope  []string     `json:"history_scope,omitempty"`
}

func (r DoctorReport) OK() bool {
	for _, finding := range r.Diagnostics {
		if finding.Severity == "error" {
			return false
		}
	}
	return true
}

func (w *Workspace) Doctor(ctx context.Context, identityOverride string, fullDecrypt, history bool) (report DoctorReport, resultErr error) {
	report = DoctorReport{SchemaVersion: DoctorSchemaVersion, Diagnostics: []Diagnostic{}}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "doctor")
	if err != nil {
		return report, err
	}
	defer finishLock(lock, "doctor", &resultErr)
	if err := w.reload(); err != nil {
		return report, err
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		addDiagnostic(&report, "error", "invalid_local_state", "", "Git-local state is malformed or cannot be safely read")
	} else {
		if state.TrustedMappingsSHA256 != w.Project.MappingDigest().Hex() {
			addDiagnostic(&report, "error", "untrusted_mappings", ".gitseal/config.yaml", "canonical mapping digest is not locally trusted")
		}
		if state.TrustedRetainedSafetySHA256 != w.Project.RetainedSafetyDigest().Hex() {
			addDiagnostic(&report, "error", "untrusted_retained_safety", ".gitseal/config.yaml", "canonical retained-safety digest is not locally trusted")
		}
		if state.TrustedRecipientsSHA256 != w.Typed.Digest().Hex() || state.TrustedMembershipPolicySHA256 != w.Recipients.MembershipDigest().Hex() {
			addDiagnostic(&report, "error", "untrusted_recipients", ".gitseal/recipients.yaml", "recipient set or ID-to-recipient membership policy is not locally trusted")
		}
	}
	if unmerged, gitErr := w.Repo.HasUnmerged(ctx); gitErr != nil {
		return report, gitErr
	} else if unmerged {
		addDiagnostic(&report, "error", "unmerged", "", "active index contains unmerged entries; GitSeal will not choose a side")
	}
	for _, mapping := range w.Project.ProtectedFiles {
		if tracked, trackErr := w.Repo.IsTracked(ctx, mapping.Source); trackErr != nil {
			return report, trackErr
		} else if tracked {
			addDiagnostic(&report, "error", "tracked_plaintext", mapping.Source, "plaintext is present in the active index; ignore rules do not protect tracked files")
		}
		if inHead, headErr := w.headContains(ctx, mapping.Source); headErr != nil {
			return report, headErr
		} else if inHead {
			addDiagnostic(&report, "error", "plaintext_in_head", mapping.Source, "plaintext is present in HEAD; staging its deletion does not undo exposure and credential rotation must be reviewed")
		}
	}
	for _, retained := range w.Project.RetainedSafety.IgnoredPlaintext {
		if tracked, trackErr := w.Repo.IsTracked(ctx, retained); trackErr != nil {
			return report, trackErr
		} else if tracked {
			addDiagnostic(&report, "error", "tracked_retained_plaintext", retained, "retained plaintext is present in the active index; ignore rules do not protect tracked files")
		}
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		addDiagnostic(&report, "error", "unsafe_worktree_policy", "", err.Error())
	}
	residues, err := w.Root.TemporaryResidues(limits.MaxDiagnostics)
	if err != nil {
		addDiagnostic(&report, "error", "residue_scan_failed", "", "temporary residue scan could not complete safely")
	}
	for _, residue := range residues {
		addDiagnostic(&report, "error", "plaintext_temporary_residue", residue, "reserved GitSeal temporary residue requires manual review; it was not deleted")
	}
	record, identityErr := w.SelectedIdentity(identityOverride)
	if identityErr != nil {
		addDiagnostic(&report, "error", "missing_identity", "", "selected identity could not be safely loaded and validated")
	} else if !w.Typed.Contains(record.Identity) {
		addDiagnostic(&report, "error", "identity_not_in_recipient_set", ".gitseal/recipients.yaml", "selected identity cannot create replacement ciphertext")
	}
	for _, mapping := range w.Project.ProtectedFiles {
		artifact, ok := w.Manifest.Find(mapping.Encrypted)
		if !ok || artifact.Source != mapping.Source {
			addDiagnostic(&report, "error", "manifest_mapping_mismatch", mapping.Encrypted, "manifest does not bind this exact source/artifact mapping")
			continue
		}
		sum, exists, hashErr := w.hashConfigured(mapping.Encrypted)
		if hashErr != nil || !exists {
			addDiagnostic(&report, "error", "missing_artifact", mapping.Encrypted, "ciphertext is missing or unsafe to open")
			continue
		}
		if sum.Hex() != artifact.CiphertextSHA256 {
			addDiagnostic(&report, "error", "manifest_ciphertext_mismatch", mapping.Encrypted, "ciphertext bytes do not match manifest bookkeeping")
			continue
		}
		if artifact.RecipientSetSHA256 != w.Typed.Digest().Hex() {
			addDiagnostic(&report, "error", "stale_recipient_set", mapping.Encrypted, "artifact must be re-encrypted for the current semantic recipient set")
		}
		cipherPath, _ := pathpolicy.Parse(mapping.Encrypted)
		file, openErr := w.Root.OpenRead(cipherPath)
		if openErr != nil {
			addDiagnostic(&report, "error", "artifact_open_failed", mapping.Encrypted, "artifact could not be safely opened")
			continue
		}
		info, statErr := file.Stat()
		engine, engineErr := agefile.NewEngine(w.Typed.Len())
		if statErr == nil && engineErr == nil && identityErr != nil {
			statErr = identityErr
		}
		if statErr == nil && engineErr == nil {
			statErr = authenticateExactCiphertextHeader(engine, file, info.Size(), sum, record.Identity)
		}
		closeErr := file.Close()
		if statErr == nil {
			statErr = closeErr
		}
		if statErr != nil || engineErr != nil {
			addDiagnostic(&report, "error", "header_not_decryptable", mapping.Encrypted, "native stanza shape or selected-identity header authentication failed")
			continue
		}
		addDiagnostic(&report, "info", "header_decryptable", mapping.Encrypted, "selected identity authenticated the age header; this is not full payload authentication")
		if fullDecrypt && identityErr == nil {
			file, openErr = w.Root.OpenRead(cipherPath)
			if openErr == nil {
				openInfo, statOpenErr := file.Stat()
				if statOpenErr != nil {
					openErr = statOpenErr
				} else {
					openErr = decryptExactCiphertext(engine, io.Discard, file, openInfo.Size(), sum, record.Identity)
				}
				closeErr = file.Close()
				if openErr == nil {
					openErr = closeErr
				}
			}
			if openErr != nil {
				addDiagnostic(&report, "error", "payload_authentication_failed", mapping.Encrypted, "full streaming authentication through EOF failed")
			} else {
				addDiagnostic(&report, "info", "payload_authenticated", mapping.Encrypted, "full streaming decryption authenticated through EOF into a discard sink")
			}
		}
	}
	executable, executableErr := os.Executable()
	if executableErr != nil {
		addDiagnostic(&report, "error", "hook_installation_unverified", "", "current executable path is unavailable, so local hook installation could not be verified")
	} else {
		hookReport, hookErr := hooks.Inspect(ctx, w.Repo.Worktree(), executable)
		if hookErr != nil {
			addDiagnostic(&report, "error", "hook_installation_unverified", "", "local GitSeal hook installation could not be safely verified")
		} else {
			for _, hook := range hookReport.Hooks {
				if hook.Action != "managed" {
					addDiagnostic(&report, "error", "hook_not_managed", hook.Path, "required local "+hook.Name+" hook is "+hook.Action+"; exact-tree CI remains mandatory even when hooks are installed")
				}
			}
		}
	}
	if history {
		w.historyScope(ctx, &report)
	}
	sort.SliceStable(report.Diagnostics, func(i, j int) bool {
		if report.Diagnostics[i].Path == report.Diagnostics[j].Path {
			return report.Diagnostics[i].Code < report.Diagnostics[j].Code
		}
		return report.Diagnostics[i].Path < report.Diagnostics[j].Path
	})
	return report, nil
}

func (w *Workspace) historyScope(ctx context.Context, report *DoctorReport) {
	report.HistoryScope = []string{
		"reachable objects named by local --all refs only",
		"replacement objects disabled",
		"does not cover omitted remotes, forks, pull-request refs, server caches, unreachable objects, external clones, backups, or hosting copies",
		"a clean result means no configured plaintext path or checksum-valid native hybrid private identity was found in the completely scanned bounded local scope",
	}
	out, err := w.Repo.Run(ctx, "rev-list", "--objects", "--all")
	if err != nil {
		addDiagnostic(report, "error", "history_scan_failed", "", "reachable local object enumeration failed")
		return
	}
	paths := make(map[string]struct{}, len(w.Project.ProtectedFiles)+len(w.Project.RetainedSafety.IgnoredPlaintext))
	for _, mapping := range w.Project.ProtectedFiles {
		paths[mapping.Source] = struct{}{}
	}
	for _, retained := range w.Project.RetainedSafety.IgnoredPlaintext {
		paths[retained] = struct{}{}
	}
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		_, name, ok := bytes.Cut(line, []byte{' '})
		if ok {
			if _, exposed := paths[string(name)]; exposed {
				addDiagnostic(report, "error", "history_plaintext_path", string(name), "configured plaintext path appears in a reachable local object; rotate exposed credentials and review history-removal limits")
			}
		}
	}
	oids, err := w.Repo.ReachableBlobOIDs(ctx)
	if err != nil {
		addDiagnostic(report, "error", "history_identity_scan_failed", "", "reachable historical blob enumeration failed; no private-identity no-leak claim is made")
		return
	}
	requests := make([]gitrepo.BlobRequest, len(oids))
	for index, oid := range oids {
		requests[index] = gitrepo.BlobRequest{OID: oid, Max: limits.DefaultFileBytes}
	}
	var consumed int64
	err = w.Repo.ConsumeBlobs(ctx, requests, func(index int, reader io.Reader, size int64) error {
		if size > maxHistoryIdentityScanBytes-consumed {
			return errHistoryIdentityScanBudget
		}
		consumed += size
		found, err := agefile.ScanHybridIdentity(reader, size)
		if err != nil {
			return err
		}
		if found {
			addDiagnostic(report, "error", "history_private_identity", oids[index], "reachable historical blob contains a checksum-valid native hybrid private identity; rotate and replace the exposed identity")
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errHistoryIdentityScanBudget) {
			addDiagnostic(report, "error", "history_identity_scan_budget", "", "reachable historical blobs exceed the bounded private-identity scan budget; no no-leak claim is made")
		} else {
			addDiagnostic(report, "error", "history_identity_scan_failed", "", "reachable historical blobs could not be completely scanned; no private-identity no-leak claim is made")
		}
	}
}

func addDiagnostic(report *DoctorReport, severity, code, path, message string) {
	if len(report.Diagnostics) >= limits.MaxDiagnostics {
		return
	}
	report.Diagnostics = append(report.Diagnostics, Diagnostic{Severity: severity, Code: code, Path: path, Message: message})
}
