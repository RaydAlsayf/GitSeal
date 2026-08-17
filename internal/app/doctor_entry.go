package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/hooks"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/treeverify"
)

// DoctorAt is the diagnostic entry point for a repository path. Unlike normal
// commands, it does not require every tracked schema to parse before producing
// useful findings. A malformed control file therefore cannot hide independent
// active-index, HEAD, hook, or temporary-residue observations.
func DoctorAt(ctx context.Context, cwd, identityOverride string, fullDecrypt, history bool) (report DoctorReport, resultErr error) {
	w, openErr := Open(ctx, cwd)
	if openErr == nil {
		report, resultErr = w.Doctor(ctx, identityOverride, fullDecrypt, history)
		closeErr := w.Close()
		if resultErr == nil && closeErr == nil {
			return report, nil
		}
		if len(report.Diagnostics) > 0 {
			return report, errors.Join(resultErr, closeErr)
		}
		openErr = errors.Join(resultErr, closeErr)
	}
	return diagnoseWithoutWorkspace(ctx, cwd, identityOverride, fullDecrypt, history, openErr)
}

func diagnoseWithoutWorkspace(ctx context.Context, cwd, identityOverride string, fullDecrypt, history bool, cause error) (report DoctorReport, resultErr error) {
	report = DoctorReport{SchemaVersion: DoctorSchemaVersion, Diagnostics: []Diagnostic{}}
	addDiagnostic(&report, "error", "workspace_open_failed", "", "GitSeal could not open a complete trusted workspace; independent diagnostics follow")
	if fullDecrypt {
		addDiagnostic(&report, "error", "full_decrypt_unavailable", "", "full payload authentication requires a complete trusted workspace and was not attempted")
	}
	if cause == nil {
		cause = errors.New("workspace is unavailable")
	}

	repo, err := gitrepo.Discover(ctx, cwd, gitrepo.DiscoverOptions{})
	if err != nil {
		return report, errors.Join(cause, err)
	}
	root, err := safefile.OpenRoot(repo.Worktree())
	if err != nil {
		return report, errors.Join(cause, err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()

	lock, lockErr := localstate.Acquire(repo.GitSealDir(), "doctor-malformed")
	if lockErr != nil {
		addDiagnostic(&report, "error", "snapshot_indeterminate", "", "the GitSeal consistency lock is unavailable; observations below are independent and not a coherent multi-file snapshot")
	} else {
		defer finishLock(lock, "malformed-project doctor", &resultErr)
	}

	projectData, projectReadErr := readDoctorControl(root, "config.yaml")
	project, projectErr := projectconfig.ParseProject(projectData)
	if projectReadErr != nil || projectErr != nil {
		addDiagnostic(&report, "error", "invalid_project_config", ".gitseal/config.yaml", "project configuration is missing, unsafe to read, malformed, or unsupported")
	}
	recipientData, recipientReadErr := readDoctorControl(root, "recipients.yaml")
	recipients, typed, recipientErr := projectconfig.ParseRecipients(recipientData)
	if recipientReadErr != nil || recipientErr != nil {
		addDiagnostic(&report, "error", "invalid_recipients", ".gitseal/recipients.yaml", "recipient configuration is missing, unsafe to read, malformed, or unsupported")
	}
	manifestData, manifestReadErr := readDoctorControl(root, "manifest.yaml")
	book, manifestErr := manifest.Parse(manifestData)
	if manifestReadErr != nil || manifestErr != nil {
		addDiagnostic(&report, "error", "invalid_manifest", ".gitseal/manifest.yaml", "artifact manifest is missing, unsafe to read, malformed, or unsupported")
	}

	if unmerged, gitErr := repo.HasUnmerged(ctx); gitErr != nil {
		addDiagnostic(&report, "error", "active_index_unavailable", "", "the active index could not be inspected safely")
	} else if unmerged {
		addDiagnostic(&report, "error", "unmerged", "", "active index contains unmerged entries; GitSeal will not choose a side")
	}
	if indexReport, verifyErr := treeverify.VerifyIndex(ctx, repo, false); verifyErr != nil {
		addDiagnostic(&report, "error", "active_index_verification_failed", "", "the exact active index could not be validated")
	} else {
		for _, finding := range indexReport.Findings {
			severity := finding.Severity
			if severity == "" {
				severity = "error"
			}
			addDiagnostic(&report, severity, "index_"+finding.Code, finding.Path, finding.Message)
		}
	}

	if projectErr == nil && projectReadErr == nil {
		diagnoseProjectPaths(ctx, repo, root, project, &report)
	}
	if history {
		partial := &Workspace{Repo: repo}
		if projectErr == nil && projectReadErr == nil {
			partial.Project = project
		}
		partial.historyScope(ctx, &report)
	}
	if projectErr == nil && projectReadErr == nil && recipientErr == nil && recipientReadErr == nil && manifestErr == nil && manifestReadErr == nil {
		if err := book.ValidateProject(project); err != nil {
			addDiagnostic(&report, "error", "manifest_mapping_mismatch", ".gitseal/manifest.yaml", "manifest mappings do not match project configuration")
		}
		diagnoseArtifactsWithoutWorkspace(root, project, typed, book, &report)
		partial := &Workspace{Repo: repo, Root: root, Project: project, Recipients: recipients, Typed: typed, Manifest: book}
		if record, identityErr := partial.SelectedIdentity(identityOverride); identityErr != nil {
			addDiagnostic(&report, "error", "missing_identity", "", "selected identity could not be safely loaded and validated")
		} else if !typed.Contains(record.Identity) {
			addDiagnostic(&report, "error", "identity_not_in_recipient_set", ".gitseal/recipients.yaml", "selected identity cannot create replacement ciphertext")
		}
	}

	if state, stateErr := localstate.Load(repo.GitSealDir()); stateErr != nil {
		addDiagnostic(&report, "error", "invalid_local_state", "", "Git-local state is unavailable, malformed, or unsafe to read")
	} else if projectErr == nil {
		if state.TrustedMappingsSHA256 != project.MappingDigest().Hex() {
			addDiagnostic(&report, "error", "untrusted_mappings", ".gitseal/config.yaml", "canonical mapping digest is not locally trusted")
		}
		if state.TrustedRetainedSafetySHA256 != project.RetainedSafetyDigest().Hex() {
			addDiagnostic(&report, "error", "untrusted_retained_safety", ".gitseal/config.yaml", "canonical retained-safety digest is not locally trusted")
		}
	}
	residues, residueErr := root.TemporaryResidues(limits.MaxDiagnostics)
	if residueErr != nil {
		addDiagnostic(&report, "error", "residue_scan_failed", "", "temporary residue scan could not complete safely")
	}
	for _, residue := range residues {
		addDiagnostic(&report, "error", "plaintext_temporary_residue", residue, "reserved GitSeal temporary residue requires manual review; it was not deleted")
	}
	diagnoseHookState(ctx, repo, &report)
	sortDoctorDiagnostics(&report)
	return report, nil
}

func readDoctorControl(root *safefile.Root, name string) (data []byte, resultErr error) {
	file, err := root.OpenControlRead(name)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return readBounded(file, limits.MaxYAMLBytes)
}

func diagnoseProjectPaths(ctx context.Context, repo *gitrepo.Repository, root *safefile.Root, project projectconfig.Project, report *DoctorReport) {
	headPaths := map[string]struct{}{}
	if tree, unborn, err := repo.ResolveHeadTree(ctx); err != nil {
		addDiagnostic(report, "error", "head_unavailable", "", "HEAD could not be inspected safely")
	} else if !unborn {
		if entries, listErr := repo.ListTree(ctx, tree); listErr != nil {
			addDiagnostic(report, "error", "head_unavailable", "", "HEAD tree entries could not be inspected safely")
		} else {
			for _, entry := range entries {
				headPaths[entry.Path] = struct{}{}
			}
		}
	}
	for _, mapping := range project.ProtectedFiles {
		if tracked, err := repo.IsTracked(ctx, mapping.Source); err != nil {
			addDiagnostic(report, "error", "active_index_unavailable", mapping.Source, "active-index plaintext exposure could not be determined")
		} else if tracked {
			addDiagnostic(report, "error", "tracked_plaintext", mapping.Source, "plaintext is present in the active index; ignore rules do not protect tracked files")
		}
		if _, ok := headPaths[mapping.Source]; ok {
			addDiagnostic(report, "error", "plaintext_in_head", mapping.Source, "plaintext is present in HEAD; credential rotation and history exposure must be reviewed")
		}
	}
	ignoreData, ignoreExists, ignoreErr := readOptionalRoot(root, ".gitignore")
	if ignoreErr != nil || !ignoreExists || gitignore.Validate(ignoreData, project) != nil {
		addDiagnostic(report, "error", "invalid_managed_ignore", ".gitignore", "managed GitSeal ignore block is missing, unsafe, or noncanonical")
	}
	attrsData, attrsExist, attrsErr := readOptionalRoot(root, ".gitattributes")
	if attrsErr != nil || !attrsExist || gitattrs.Validate(attrsData, project) != nil {
		addDiagnostic(report, "error", "invalid_managed_attributes", ".gitattributes", "managed GitSeal attribute block is missing, unsafe, or noncanonical")
	}
}

func diagnoseArtifactsWithoutWorkspace(root *safefile.Root, project projectconfig.Project, typed agefile.HybridRecipients, book manifest.Manifest, report *DoctorReport) {
	engine, engineErr := agefile.NewEngine(typed.Len())
	for _, mapping := range project.ProtectedFiles {
		artifact, ok := book.Find(mapping.Encrypted)
		if !ok || artifact.Source != mapping.Source {
			addDiagnostic(report, "error", "manifest_mapping_mismatch", mapping.Encrypted, "manifest does not bind this exact source/artifact mapping")
			continue
		}
		configured, parseErr := pathpolicy.Parse(mapping.Encrypted)
		if parseErr != nil {
			addDiagnostic(report, "error", "invalid_artifact_path", mapping.Encrypted, "artifact path is outside the portable V1 policy")
			continue
		}
		file, openErr := root.OpenRead(configured)
		if openErr != nil {
			addDiagnostic(report, "error", "missing_artifact", mapping.Encrypted, "ciphertext is missing or unsafe to open")
			continue
		}
		sum, hashErr := safefile.HashExactFile(file, limits.DefaultFileBytes)
		info, statErr := file.Stat()
		if _, seekErr := file.Seek(0, 0); statErr == nil {
			statErr = seekErr
		}
		inspectErr := engineErr
		if inspectErr == nil && hashErr == nil && statErr == nil {
			inspectErr = inspectExactCiphertext(engine, file, info.Size(), sum)
		}
		closeErr := file.Close()
		if hashErr != nil || statErr != nil || inspectErr != nil || closeErr != nil {
			addDiagnostic(report, "error", "invalid_ciphertext", mapping.Encrypted, "artifact is not an exact bounded native-hybrid age file for the configured recipient count")
			continue
		}
		if sum.Hex() != artifact.CiphertextSHA256 {
			addDiagnostic(report, "error", "manifest_ciphertext_mismatch", mapping.Encrypted, "ciphertext bytes do not match manifest bookkeeping")
		}
		if artifact.RecipientSetSHA256 != typed.Digest().Hex() {
			addDiagnostic(report, "error", "stale_recipient_set", mapping.Encrypted, "artifact must be re-encrypted for the current semantic recipient set")
		}
	}
}

func diagnoseHookState(ctx context.Context, repo *gitrepo.Repository, report *DoctorReport) {
	executable, err := os.Executable()
	if err != nil {
		addDiagnostic(report, "error", "hook_installation_unverified", "", "current executable path is unavailable, so local hook installation could not be verified")
		return
	}
	hookReport, err := hooks.Inspect(ctx, repo.Worktree(), executable)
	if err != nil {
		addDiagnostic(report, "error", "hook_installation_unverified", "", "local GitSeal hook installation could not be safely verified")
		return
	}
	for _, hook := range hookReport.Hooks {
		if hook.Action != "managed" {
			addDiagnostic(report, "error", "hook_not_managed", hook.Path, fmt.Sprintf("required local %s hook is %s; exact-tree CI remains mandatory", hook.Name, hook.Action))
		}
	}
}

func sortDoctorDiagnostics(report *DoctorReport) {
	sort.SliceStable(report.Diagnostics, func(i, j int) bool {
		if report.Diagnostics[i].Path == report.Diagnostics[j].Path {
			return report.Diagnostics[i].Code < report.Diagnostics[j].Code
		}
		return report.Diagnostics[i].Path < report.Diagnostics[j].Path
	})
}
