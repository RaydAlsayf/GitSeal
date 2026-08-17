package app

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	statemachine "github.com/raydalsayf/gitseal/internal/status"
)

const StatusSchemaVersion = 1

type FileStatus struct {
	Source    string `json:"source"`
	Encrypted string `json:"encrypted"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`

	// actionBlocker is deliberately not serialized. Status reports the most
	// useful repository/file state first, while sync still needs to know that a
	// later mutation would be blocked by policy, mapping trust, or identity
	// readiness. Keeping the two concepts separate prevents a missing identity
	// from hiding a missing or malformed artifact.
	actionBlockers []statusActionBlocker
	syncState      string
	// ciphertextSHA256 binds sync's exact incoming acceptance to the bytes
	// observed while computing this locked status snapshot. It is deliberately
	// omitted from both human and JSON status output.
	ciphertextSHA256 string
}

type StatusReport struct {
	SchemaVersion int          `json:"schema_version"`
	Files         []FileStatus `json:"files"`
	Warnings      []string     `json:"warnings,omitempty"`
}

func (w *Workspace) Status(ctx context.Context, identityOverride string) (report StatusReport, resultErr error) {
	report = StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}, Warnings: []string{}}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "status")
	if err != nil {
		return report, err
	}
	defer finishLock(lock, "status", &resultErr)
	if err := w.reload(); err != nil {
		return report, err
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return report, err
	}
	unmerged, err := w.Repo.HasUnmerged(ctx)
	if err != nil {
		return report, err
	}
	policyErr := w.checkWorktreePolicy(ctx)
	mappingTrusted := state.TrustedMappingsSHA256 == w.Project.MappingDigest().Hex()
	retainedSafetyTrusted := state.TrustedRetainedSafetySHA256 == w.Project.RetainedSafetyDigest().Hex()
	selectedAvailable := true
	selectedInSet := true
	record, identityErr := w.SelectedIdentity(identityOverride)
	if identityErr != nil {
		selectedAvailable = false
	} else {
		selectedInSet = w.Typed.Contains(record.Identity)
	}
	var blockers []statusActionBlocker
	if policyErr != nil {
		blockers = append(blockers, statusActionBlocker{state: "unsafe_git_policy", detail: policyErr.Error()})
		report.Warnings = append(report.Warnings, "effective Git ignore or attribute policy is unsafe: "+policyErr.Error())
	}
	if !mappingTrusted {
		blockers = append(blockers, statusActionBlocker{state: "untrusted_mapping", detail: "canonical project mapping digest is not locally trusted"})
		report.Warnings = append(report.Warnings, "canonical project mapping digest is not locally trusted")
	}
	if !retainedSafetyTrusted {
		blockers = append(blockers, statusActionBlocker{state: "untrusted_retained_safety", detail: "canonical retained-safety digest is not locally trusted"})
		report.Warnings = append(report.Warnings, "canonical retained-safety digest is not locally trusted")
	}
	if !selectedAvailable {
		blockers = append(blockers, statusActionBlocker{state: "missing_identity", detail: "no selected identity could be safely loaded"})
		report.Warnings = append(report.Warnings, "no selected identity could be safely loaded; repository-level status remains available")
	} else if !selectedInSet {
		blockers = append(blockers, statusActionBlocker{state: "identity_not_in_recipient_set", detail: "selected identity cannot create replacement ciphertext"})
		report.Warnings = append(report.Warnings, "selected identity is not in the current recipient set; repository-level status remains available")
	}
	var observationErr error
	for _, mapping := range w.Project.ProtectedFiles {
		item := FileStatus{Source: mapping.Source, Encrypted: mapping.Encrypted}
		artifact, artifactOK := w.Manifest.Find(mapping.Encrypted)
		stale := artifactOK && artifact.Source == mapping.Source && artifact.RecipientSetSHA256 != w.Typed.Digest().Hex()
		if stale {
			// Staleness is committed repository evidence and must remain visible
			// even if another structural state or an unmerged index has priority.
			report.Warnings = append(report.Warnings, fmt.Sprintf("artifact %q is stale for the current recipient set", mapping.Encrypted))
		}
		tracked, trackedErr := w.Repo.IsTracked(ctx, mapping.Source)
		if trackedErr != nil {
			item.State, item.Detail = "indeterminate", "active-index plaintext exposure could not be determined"
			observationErr = errors.Join(observationErr, fmt.Errorf("status could not reliably inspect the active index for %q", mapping.Source))
			report.Files = append(report.Files, item)
			continue
		}
		inHead, headErr := w.headContains(ctx, mapping.Source)
		if headErr != nil {
			item.State, item.Detail = "indeterminate", "HEAD plaintext exposure could not be determined"
			observationErr = errors.Join(observationErr, fmt.Errorf("status could not reliably inspect HEAD for %q", mapping.Source))
			report.Files = append(report.Files, item)
			continue
		}
		if applyPrimarySafetyState(&item, unmerged, tracked, inHead) {
			report.Files = append(report.Files, item)
			continue
		}
		{
			if !artifactOK || artifact.Source != mapping.Source {
				item.State, item.Detail = "missing_or_mismatched_manifest", "manifest bookkeeping does not bind this exact mapping"
				report.Files = append(report.Files, item)
				continue
			}
			cipher, cipherExists, hashErr := w.hashConfigured(mapping.Encrypted)
			if hashErr != nil {
				item.State, item.Detail = "unsafe_artifact", "ciphertext could not be opened and streamed through the rooted safety boundary"
				report.Files = append(report.Files, item)
				continue
			}
			if cipherExists {
				item.ciphertextSHA256 = cipher.Hex()
			}
			if cipherExists && artifact.CiphertextSHA256 != cipher.Hex() {
				item.State, item.Detail = "manifest_ciphertext_mismatch", "artifact bytes do not match committed bookkeeping"
				report.Files = append(report.Files, item)
				continue
			}
			if cipherExists {
				cipherPath, _ := pathpolicy.Parse(mapping.Encrypted)
				file, openErr := w.Root.OpenRead(cipherPath)
				if openErr != nil {
					item.State, item.Detail = "unsafe_artifact", "ciphertext changed or became unsafe before structural inspection"
					report.Files = append(report.Files, item)
					continue
				}
				info, inspectErr := file.Stat()
				engine, engineErr := agefile.NewEngine(w.Typed.Len())
				if inspectErr == nil {
					inspectErr = engineErr
				}
				if inspectErr == nil {
					inspectErr = inspectExactCiphertext(engine, file, info.Size(), cipher)
				}
				closeErr := file.Close()
				if inspectErr == nil {
					inspectErr = closeErr
				}
				if inspectErr != nil {
					item.State, item.Detail = "invalid_ciphertext", "artifact is not an exact bounded native-hybrid age file for the current recipient count"
					report.Files = append(report.Files, item)
					continue
				}
			}
			plain, plainExists, hashErr := w.hashConfigured(mapping.Source)
			if hashErr != nil {
				item.State, item.Detail = "unsafe_plaintext", "plaintext could not be opened and streamed through the rooted safety boundary"
				report.Files = append(report.Files, item)
				continue
			}
			baseline, hasBaseline := state.Files[mapping.Source]
			calculated := statemachine.Calculate(statemachine.Input{
				HasBaseline: hasBaseline, PlaintextExists: plainExists, CiphertextExists: cipherExists,
				PlaintextDigest: plain.Hex(), CiphertextDigest: cipher.Hex(),
				BaselinePlain: baseline.PlaintextSHA256, BaselineCipher: baseline.CiphertextSHA256,
			})
			if stale {
				// Structural absence takes priority; the warning above still exposes
				// the independently observed recipient-set staleness.
				if calculated != statemachine.MissingCiphertext && calculated != statemachine.MissingFiles {
					item.State, item.Detail = "stale_recipient_set", "run gitseal encrypt --all after recipient review"
					report.Files = append(report.Files, item)
					continue
				}
			}
			applyCalculatedStatus(&item, calculated, blockers)
		}
		report.Files = append(report.Files, item)
	}
	sort.Slice(report.Files, func(i, j int) bool { return report.Files[i].Encrypted < report.Files[j].Encrypted })
	if len(w.Project.RetainedSafety.IgnoredPlaintext) > 0 || len(w.Project.RetainedSafety.BinaryArtifacts) > 0 {
		report.Warnings = append(report.Warnings, "tracked retained_safety contains orphan paths whose safeguards remain intentionally active")
	}
	return report, observationErr
}

func applyPrimarySafetyState(item *FileStatus, unmerged, tracked, inHead bool) bool {
	// An observed plaintext exposure is more important than the fact that the
	// same index is unmerged. Doctor reports both diagnostics; status has one
	// primary state, so it must not hide the exposure behind workflow state.
	if tracked || inHead {
		item.State, item.Detail = "tracked_plaintext", "plaintext is present in HEAD or the active index; ignore rules do not protect tracked files"
		return true
	}
	if unmerged {
		item.State, item.Detail = "unmerged", "ordinary mutation is refused; GitSeal never selects a merge side"
		return true
	}
	return false
}

type statusActionBlocker struct {
	state  string
	detail string
}

func applyCalculatedStatus(item *FileStatus, calculated statemachine.State, blockers []statusActionBlocker) {
	item.syncState = string(calculated)
	item.actionBlockers = append([]statusActionBlocker(nil), blockers...)
	if calculated != statemachine.Synchronized || len(blockers) == 0 {
		item.State = string(calculated)
		return
	}
	item.State, item.Detail = blockers[0].state, blockers[0].detail
}

type SyncOptions struct {
	Identity                     string
	AcceptIncoming               string
	AcceptMappings               bool
	AcceptRetainedSafety         bool
	ExpectedProjectSHA256        string
	ExpectedMappingsSHA256       string
	ExpectedRetainedSafetySHA256 string
}

func (w *Workspace) Sync(ctx context.Context, requested string, options SyncOptions) (StatusReport, []CryptoResult, error) {
	if options.AcceptIncoming != "" && requested == "" {
		return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, errors.New("--accept-incoming must be bound to one exact configured file")
	}
	if options.AcceptIncoming != "" {
		if _, err := digest.ParseHex(options.AcceptIncoming); err != nil {
			return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, fmt.Errorf("invalid --accept-incoming digest: %w", err)
		}
	}
	if _, err := digest.ParseHex(options.ExpectedProjectSHA256); err != nil {
		return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, fmt.Errorf("synchronization plan is not bound to an exact canonical project snapshot: %w", err)
	}
	if options.AcceptMappings {
		if _, err := digest.ParseHex(options.ExpectedMappingsSHA256); err != nil {
			return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, fmt.Errorf("mapping acceptance is not bound to an exact reviewed mapping digest: %w", err)
		}
	} else if options.ExpectedMappingsSHA256 != "" {
		return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, errors.New("an expected mapping digest is valid only with explicit mapping-change acceptance")
	}
	if options.AcceptRetainedSafety {
		if _, err := digest.ParseHex(options.ExpectedRetainedSafetySHA256); err != nil {
			return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, fmt.Errorf("retained-safety acceptance is not bound to an exact reviewed digest: %w", err)
		}
	} else if options.ExpectedRetainedSafetySHA256 != "" {
		return StatusReport{SchemaVersion: StatusSchemaVersion, Files: []FileStatus{}}, nil, errors.New("an expected retained-safety digest is valid only with explicit retained-safety acceptance")
	}
	report, err := w.Status(ctx, options.Identity)
	if err != nil {
		return report, nil, err
	}
	projectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return report, nil, err
	}
	if projectSnapshot.Hex() != options.ExpectedProjectSHA256 {
		return report, nil, errors.New("project configuration changed after the synchronization plan was created")
	}
	if options.AcceptMappings {
		if err := requireReviewedMappingDigest(w.Project.MappingDigest().Hex(), options.ExpectedMappingsSHA256); err != nil {
			return report, nil, err
		}
	}
	if options.AcceptRetainedSafety {
		if err := requireReviewedRetainedSafetyDigest(w.Project.RetainedSafetyDigest().Hex(), options.ExpectedRetainedSafetySHA256); err != nil {
			return report, nil, err
		}
	}
	selected, err := preflightSync(report, requested, options)
	if err != nil {
		return report, nil, err
	}
	if options.AcceptMappings || options.AcceptRetainedSafety {
		if err := w.acceptCurrentProjectTrust(ctx, requested, options); err != nil {
			return report, nil, err
		}
		// Mapping acceptance is now persisted. Recompute without any acceptance
		// bypass so a policy change between review and action fails closed.
		report, err = w.Status(ctx, options.Identity)
		if err != nil {
			return report, nil, err
		}
		projectSnapshot, err = ProjectSnapshotDigest(w.Project)
		if err != nil || projectSnapshot.Hex() != options.ExpectedProjectSHA256 {
			return report, nil, errors.Join(errors.New("project configuration changed after mapping acceptance"), err)
		}
		selected, err = preflightSync(report, requested, SyncOptions{Identity: options.Identity, AcceptIncoming: options.AcceptIncoming})
		if err != nil {
			return report, nil, err
		}
	}
	var results []CryptoResult
	for _, item := range selected {
		switch item.State {
		case string(statemachine.MissingPlaintext):
			decrypted, err := w.Decrypt(ctx, item.Source, false, DecryptOptions{Identity: options.Identity, ExpectedProjectSHA256: options.ExpectedProjectSHA256})
			if err != nil {
				return report, results, err
			}
			results = append(results, decrypted...)
		case string(statemachine.IncomingConsent):
			decrypted, err := w.Decrypt(ctx, item.Source, false, DecryptOptions{Identity: options.Identity, AcceptIncoming: options.AcceptIncoming, ExpectedProjectSHA256: options.ExpectedProjectSHA256})
			if err != nil {
				return report, results, err
			}
			results = append(results, decrypted...)
		case string(statemachine.FirstRunCompare):
			compared, err := w.establishFirstRunBaseline(ctx, item.Source, options.Identity, options.ExpectedProjectSHA256)
			if err != nil {
				return report, results, err
			}
			results = append(results, compared)
		case string(statemachine.Synchronized):
			// No action required.
		}
	}
	if len(results) > 0 {
		updated, err := w.Status(ctx, options.Identity)
		if err != nil {
			return report, results, fmt.Errorf("synchronization completed but final status could not be recomputed: %w", err)
		}
		report = updated
	}
	return report, results, nil
}

func preflightSync(report StatusReport, requested string, options SyncOptions) ([]FileStatus, error) {
	selected := make([]FileStatus, 0, len(report.Files))
	for _, item := range report.Files {
		if requested == "" || requested == item.Source || requested == item.Encrypted {
			selected = append(selected, item)
		}
	}
	if requested != "" && len(selected) == 0 {
		return nil, fmt.Errorf("%q is not configured", requested)
	}
	if options.AcceptIncoming != "" {
		if len(selected) != 1 || selected[0].State != string(statemachine.IncomingConsent) {
			return nil, errors.New("--accept-incoming applies only to the exact currently observed incoming-ciphertext state")
		}
		if selected[0].ciphertextSHA256 == "" || selected[0].ciphertextSHA256 != options.AcceptIncoming {
			return nil, errors.New("--accept-incoming does not match the exact ciphertext digest in the current status snapshot")
		}
	}
	actionCount := 0
	for _, item := range selected {
		for _, blocker := range item.actionBlockers {
			if options.AcceptMappings && blocker.state == "untrusted_mapping" {
				continue
			}
			if options.AcceptRetainedSafety && blocker.state == "untrusted_retained_safety" {
				continue
			}
			return nil, fmt.Errorf("synchronization is blocked for %q: %s", item.Source, blocker.detail)
		}
		state := item.State
		if item.syncState != "" {
			state = item.syncState
		}
		switch state {
		case string(statemachine.Synchronized):
			// No action is required.
		case string(statemachine.MissingPlaintext), string(statemachine.FirstRunCompare):
			actionCount++
		case string(statemachine.IncomingConsent):
			if options.AcceptIncoming == "" {
				return nil, fmt.Errorf("unfamiliar ciphertext for %q requires acceptance of its exact currently observed digest", item.Source)
			}
			actionCount++
		case string(statemachine.PlaintextChanged):
			return nil, fmt.Errorf("local plaintext changed for %q; run gitseal encrypt for this exact file", item.Source)
		case string(statemachine.MissingCiphertext):
			return nil, fmt.Errorf("ciphertext is missing for %q; run gitseal encrypt for this exact file", item.Source)
		case string(statemachine.MissingFiles):
			return nil, fmt.Errorf("plaintext and ciphertext are both missing for %q; synchronization modified nothing", item.Source)
		case string(statemachine.Conflict), "unmerged", "busy_indeterminate", "indeterminate":
			return nil, fmt.Errorf("synchronization conflict, unmerged state, or indeterminate snapshot for %q; no automatic resolution was attempted", item.Source)
		default:
			return nil, fmt.Errorf("synchronization is blocked by state %q for %q: %s", state, item.Source, item.Detail)
		}
	}
	// Sync actions persist baselines or publish plaintext one mapping at a time.
	// Until a whole-set transaction/reconciliation protocol exists, executing
	// more than one action could leave an earlier mapping changed when a later
	// payload or destination fails. Force an exact-file operation instead.
	if actionCount > 1 {
		return nil, errors.New("synchronization would mutate more than one mapping; name one exact file so a later failure cannot leave a partial multi-file result")
	}
	return selected, nil
}

func (w *Workspace) acceptCurrentProjectTrust(ctx context.Context, requested string, options SyncOptions) (resultErr error) {
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "accept-mappings")
	if err != nil {
		return err
	}
	defer finishLock(lock, "mapping acceptance", &resultErr)
	if err := w.reload(); err != nil {
		return err
	}
	projectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return err
	}
	if projectSnapshot.Hex() != options.ExpectedProjectSHA256 {
		return errors.New("project configuration changed after review; refusing mapping acceptance")
	}
	if err := w.refuseUnmerged(ctx, "mapping acceptance"); err != nil {
		return err
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		return err
	}
	if err := w.refuseTrackedPlaintext(ctx); err != nil {
		return err
	}
	if requested != "" {
		if _, ok := w.Project.Find(requested); !ok {
			return fmt.Errorf("%q is not configured", requested)
		}
	}
	if options.AcceptIncoming != "" {
		mapping, ok := w.Project.Find(requested)
		if !ok {
			return fmt.Errorf("%q is not configured", requested)
		}
		artifact, ok := w.Manifest.Find(mapping.Encrypted)
		cipher, exists, err := w.hashConfigured(mapping.Encrypted)
		if err != nil || !exists {
			return errors.Join(errors.New("accepted incoming ciphertext is missing or unsafe to read"), err)
		}
		if !ok || artifact.Source != mapping.Source || artifact.CiphertextSHA256 != cipher.Hex() || artifact.RecipientSetSHA256 != w.Typed.Digest().Hex() {
			return errors.New("accepted incoming ciphertext no longer matches exact manifest and recipient bookkeeping")
		}
		if cipher.Hex() != options.AcceptIncoming {
			return errors.New("incoming ciphertext changed before project trust could be persisted")
		}
	}
	currentDigest := w.Project.MappingDigest().Hex()
	currentRetained := w.Project.RetainedSafetyDigest().Hex()
	if options.AcceptMappings {
		if err := requireReviewedMappingDigest(currentDigest, options.ExpectedMappingsSHA256); err != nil {
			return err
		}
	}
	if options.AcceptRetainedSafety {
		if err := requireReviewedRetainedSafetyDigest(currentRetained, options.ExpectedRetainedSafetySHA256); err != nil {
			return err
		}
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return err
	}
	if options.AcceptMappings {
		state.TrustedMappingsSHA256 = currentDigest
	}
	if options.AcceptRetainedSafety {
		state.TrustedRetainedSafetySHA256 = currentRetained
	}
	return localstate.Save(ctx, w.Repo.GitSealDir(), &state)
}

func requireReviewedMappingDigest(current, expected string) error {
	if current != expected {
		return errors.New("project mappings changed after review; refusing to accept a different mapping digest")
	}
	return nil
}

func requireReviewedRetainedSafetyDigest(current, expected string) error {
	if current != expected {
		return errors.New("retained safety changed after review; refusing to accept a different digest")
	}
	return nil
}
