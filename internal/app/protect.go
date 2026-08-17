package app

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

type ProtectOptions struct {
	Encrypted           string
	Identity            string
	Trust               TrustOptions
	AcknowledgeExposure string
	Force               bool
}

type UnprotectOptions struct {
	MakeTrackable                string
	DropArtifactProtection       string
	AcceptMappingChanges         bool
	AcceptRetainedSafety         bool
	ExpectedProjectSHA256        string
	ExpectedMappingsSHA256       string
	ExpectedRetainedSafetySHA256 string
}

type unprotectPlan struct {
	mapping        projectconfig.ProtectedFile
	baselineSource string
	mappingChanged bool
	project        projectconfig.Project
	manifest       manifest.Manifest
}

func (w *Workspace) Protect(ctx context.Context, source string, options ProtectOptions) (out CryptoResult, resultErr error) {
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "protect")
	if err != nil {
		return CryptoResult{}, err
	}
	defer finishLock(lock, "protect", &resultErr)
	if err := w.reload(); err != nil {
		return CryptoResult{}, err
	}
	if err := w.refuseUnmerged(ctx, "protect"); err != nil {
		return CryptoResult{}, err
	}
	if _, err := pathpolicy.Parse(source); err != nil {
		return CryptoResult{}, err
	}
	encrypted := options.Encrypted
	if encrypted == "" {
		encrypted = source + ".age"
	}
	if _, err := pathpolicy.Parse(encrypted); err != nil {
		return CryptoResult{}, err
	}
	if _, exists := w.Project.Find(source); exists {
		return CryptoResult{}, fmt.Errorf("%q is already part of a protected mapping", source)
	}
	if _, exists, err := w.hashConfigured(encrypted); err != nil {
		return CryptoResult{}, err
	} else if exists {
		return CryptoResult{}, fmt.Errorf("ciphertext destination %q already exists; protect never overwrites an unfamiliar user file", encrypted)
	}
	if tracked, err := w.Repo.IsTracked(ctx, encrypted); err != nil {
		return CryptoResult{}, err
	} else if tracked {
		return CryptoResult{}, fmt.Errorf("ciphertext destination %q is already present in the active index and was not created by this mapping", encrypted)
	}
	if inHead, err := w.headContains(ctx, encrypted); err != nil {
		return CryptoResult{}, err
	} else if inHead {
		return CryptoResult{}, fmt.Errorf("ciphertext destination %q already exists in HEAD and will not be overwritten", encrypted)
	}
	proposed := w.Project
	proposed.ProtectedFiles = append(append([]projectconfig.ProtectedFile(nil), w.Project.ProtectedFiles...), projectconfig.ProtectedFile{Source: source, Encrypted: encrypted})
	if err := proposed.Validate(); err != nil {
		return CryptoResult{}, err
	}
	if tracked, err := w.Repo.IsTracked(ctx, source); err != nil || tracked {
		if err != nil {
			return CryptoResult{}, err
		}
		return CryptoResult{}, errors.New("plaintext is present in the active index; protect performed zero writes because ignore rules do not affect tracked files")
	}
	if inHead, err := w.headContains(ctx, source); err != nil {
		return CryptoResult{}, err
	} else if inHead && options.AcknowledgeExposure != source {
		return CryptoResult{}, fmt.Errorf("%q exists in HEAD and requires exact --acknowledge-exposure %s after credential rotation review", source, source)
	}
	if _, exists, err := w.hashConfigured(source); err != nil || !exists {
		if err == nil {
			err = errors.New("source plaintext is missing")
		}
		return CryptoResult{}, err
	}
	record, err := w.SelectedIdentity(options.Identity)
	if err != nil {
		return CryptoResult{}, err
	}
	oldProject := w.Project
	w.Project = proposed.Canonical()
	state, trust, err := w.RequireEncryptionTrust(options.Trust)
	if err != nil {
		w.Project = oldProject
		return CryptoResult{}, err
	}
	plan, err := agefile.NewEncryptionPlan(w.Typed, record.Identity)
	if err != nil {
		w.Project = oldProject
		return CryptoResult{}, err
	}
	if err := w.refuseTrackedPlaintext(ctx); err != nil {
		w.Project = oldProject
		return CryptoResult{}, err
	}
	ignoreExisting, ignoreExisted, err := readOptionalRoot(w.Root, ".gitignore")
	if err != nil {
		return CryptoResult{}, err
	}
	ignoreData, err := gitignore.Render(ignoreExisting, w.Project)
	if err != nil {
		return CryptoResult{}, err
	}
	attrsExisting, attrsExisted, err := readOptionalRoot(w.Root, ".gitattributes")
	if err != nil {
		return CryptoResult{}, err
	}
	attrsData, err := gitattrs.Render(attrsExisting, w.Project)
	if err != nil {
		return CryptoResult{}, err
	}
	projectData, _ := w.Project.Marshal()
	completed := []string{}
	if err := w.WriteControl(ctx, "config.yaml", projectData); err != nil {
		return CryptoResult{}, err
	}
	completed = append(completed, ".gitseal/config.yaml")
	if err := w.WriteConfigured(ctx, ".gitignore", ignoreData, ignoreExisting, ignoreExisted, safefile.PublicData); err != nil {
		return CryptoResult{}, fmt.Errorf("after updating %v: %w", completed, err)
	}
	completed = append(completed, ".gitignore")
	if err := w.WriteConfigured(ctx, ".gitattributes", attrsData, attrsExisting, attrsExisted, safefile.PublicData); err != nil {
		return CryptoResult{}, fmt.Errorf("after updating %v: %w", completed, err)
	}
	completed = append(completed, ".gitattributes")
	if err := w.Repo.CheckIgnorePolicy(ctx,
		[]string{source, ".gitseal.tmp.probe", directoryProbe(source)},
		[]string{encrypted, ".gitseal/config.yaml", ".gitseal/recipients.yaml", ".gitseal/manifest.yaml", ".gitattributes", ".gitignore"}); err != nil {
		return CryptoResult{}, fmt.Errorf("managed files were updated but effective ignore policy is unsafe: %w", err)
	}
	if err := w.Repo.CheckSafeAttributes(ctx, []string{encrypted}); err != nil {
		return CryptoResult{}, fmt.Errorf("managed files were updated but effective attributes are unsafe: %w", err)
	}
	result, err := w.encryptMapping(ctx, plan, state, trust, projectconfig.ProtectedFile{Source: source, Encrypted: encrypted}, options.Force)
	if err != nil {
		return result, fmt.Errorf("managed project files were updated but encryption failed; run status or doctor: %w", err)
	}
	state.Files[source] = localstate.FileBaseline{PlaintextSHA256: result.PlaintextSHA256, CiphertextSHA256: result.CiphertextSHA256}
	ApplyTrust(&state, trust)
	if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
		return result, fmt.Errorf("protected artifact and manifest were published but baseline save failed: %w", err)
	}
	result.StateSaved = true
	return result, nil
}

func directoryProbe(configured string) string {
	directory := path.Dir(configured)
	if directory == "." {
		return ".gitseal.tmp.probe"
	}
	return directory + "/.gitseal.tmp.probe"
}

// PreviewUnprotect computes the exact post-operation mapping set under the
// same repository checks used by Unprotect, but performs no writes. The CLI
// displays this snapshot and binds the subsequent acceptance to its digest.
func (w *Workspace) PreviewUnprotect(ctx context.Context, source string, options UnprotectOptions) (updated projectconfig.Project, resultErr error) {
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "unprotect-preview")
	if err != nil {
		return projectconfig.Project{}, err
	}
	defer finishLock(lock, "unprotect preview", &resultErr)
	if err := w.reload(); err != nil {
		return projectconfig.Project{}, err
	}
	if err := w.refuseUnmerged(ctx, "unprotect preview"); err != nil {
		return projectconfig.Project{}, err
	}
	plan, err := w.planUnprotect(ctx, source, options)
	if err != nil {
		return projectconfig.Project{}, err
	}
	return plan.project, nil
}

func (w *Workspace) Unprotect(ctx context.Context, source string, options UnprotectOptions) (resultErr error) {
	if err := validateUnprotectAcceptanceOptions(options); err != nil {
		return err
	}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "unprotect")
	if err != nil {
		return err
	}
	defer finishLock(lock, "unprotect", &resultErr)
	if err := w.reload(); err != nil {
		return err
	}
	if err := w.refuseUnmerged(ctx, "unprotect"); err != nil {
		return err
	}
	plan, err := w.planUnprotect(ctx, source, options)
	if err != nil {
		return err
	}
	if plan.mappingChanged && !options.AcceptMappingChanges {
		return errors.New("unprotect changes trusted mappings and requires explicit mapping-change acceptance")
	}
	if !options.AcceptRetainedSafety {
		return errors.New("unprotect changes retained safety and requires explicit retained-safety acceptance")
	}
	if options.AcceptMappingChanges {
		if err := requireAcceptedDigest("project mappings", plan.project.MappingDigest(), options.ExpectedMappingsSHA256); err != nil {
			return err
		}
	}
	if err := requireAcceptedDigest("retained safety", plan.project.RetainedSafetyDigest(), options.ExpectedRetainedSafetySHA256); err != nil {
		return err
	}
	projectSnapshot, err := ProjectSnapshotDigest(plan.project)
	if err != nil {
		return err
	}
	if err := requireAcceptedDigest("post-unprotect project configuration", projectSnapshot, options.ExpectedProjectSHA256); err != nil {
		return err
	}
	updated := plan.project
	updatedManifest := plan.manifest
	projectData, _ := updated.Marshal()
	manifestData, _ := updatedManifest.Marshal()
	ignoreExisting, ignoreExisted, err := readOptionalRoot(w.Root, ".gitignore")
	if err != nil {
		return err
	}
	ignoreData, err := gitignore.Render(ignoreExisting, updated)
	if err != nil {
		return err
	}
	attrsExisting, attrsExisted, err := readOptionalRoot(w.Root, ".gitattributes")
	if err != nil {
		return err
	}
	attrsData, err := gitattrs.Render(attrsExisting, updated)
	if err != nil {
		return err
	}
	completed := []string{}
	for _, write := range []struct {
		name     string
		data     []byte
		expected []byte
		existed  bool
		control  bool
	}{
		{name: "config.yaml", data: projectData, control: true},
		{name: "manifest.yaml", data: manifestData, control: true},
		{name: ".gitignore", data: ignoreData, expected: ignoreExisting, existed: ignoreExisted},
		{name: ".gitattributes", data: attrsData, expected: attrsExisting, existed: attrsExisted},
	} {
		if write.control {
			err = w.WriteControl(ctx, write.name, write.data)
		} else {
			err = w.WriteConfigured(ctx, write.name, write.data, write.expected, write.existed, safefile.PublicData)
		}
		if err != nil {
			return fmt.Errorf("after updating %v, write %s: %w", completed, write.name, err)
		}
		completed = append(completed, write.name)
	}
	if err := w.reload(); err != nil {
		return fmt.Errorf("after updating %v, final tracked policy could not be reloaded: %w", completed, err)
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		return fmt.Errorf("after updating %v, final effective Git policy is unsafe: %w", completed, err)
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return fmt.Errorf("tracked config, manifest, ignore, and attribute safety files were updated but local state could not be loaded: %w", err)
	}
	if plan.baselineSource != "" {
		delete(state.Files, plan.baselineSource)
	}
	if options.AcceptMappingChanges {
		state.TrustedMappingsSHA256 = updated.MappingDigest().Hex()
	}
	state.TrustedRetainedSafetySHA256 = updated.RetainedSafetyDigest().Hex()
	if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
		return fmt.Errorf("tracked safety files were updated but local state save failed: %w", err)
	}
	return nil
}

func validateUnprotectAcceptanceOptions(options UnprotectOptions) error {
	if !options.AcceptMappingChanges && !options.AcceptRetainedSafety && options.ExpectedProjectSHA256 != "" {
		return errors.New("an expected project snapshot requires explicit project-trust acceptance")
	}
	if !options.AcceptMappingChanges && options.ExpectedMappingsSHA256 != "" {
		return errors.New("an expected mapping digest requires explicit mapping-change acceptance")
	}
	if !options.AcceptRetainedSafety && options.ExpectedRetainedSafetySHA256 != "" {
		return errors.New("an expected retained-safety digest requires explicit retained-safety acceptance")
	}
	if options.AcceptMappingChanges || options.AcceptRetainedSafety {
		if _, err := digest.ParseHex(options.ExpectedProjectSHA256); err != nil {
			return fmt.Errorf("project acceptance is not bound to an exact canonical snapshot: %w", err)
		}
	}
	if options.AcceptMappingChanges {
		if _, err := digest.ParseHex(options.ExpectedMappingsSHA256); err != nil {
			return fmt.Errorf("mapping acceptance is not bound to an exact reviewed digest: %w", err)
		}
	}
	if options.AcceptRetainedSafety {
		if _, err := digest.ParseHex(options.ExpectedRetainedSafetySHA256); err != nil {
			return fmt.Errorf("retained-safety acceptance is not bound to an exact reviewed digest: %w", err)
		}
	}
	return nil
}

func (w *Workspace) planUnprotect(ctx context.Context, source string, options UnprotectOptions) (unprotectPlan, error) {
	mapping, ok := w.Project.Find(source)
	if !ok || mapping.Source != source {
		return w.planRetainedSafetyRelease(ctx, source, options)
	}
	plainExists := false
	if _, exists, err := w.hashConfigured(mapping.Source); err != nil {
		return unprotectPlan{}, err
	} else {
		plainExists = exists
	}
	cipherExists := false
	if _, exists, err := w.hashConfigured(mapping.Encrypted); err != nil {
		return unprotectPlan{}, err
	} else {
		cipherExists = exists
	}
	cipherTracked, err := w.Repo.IsTracked(ctx, mapping.Encrypted)
	if err != nil {
		return unprotectPlan{}, err
	}
	if options.MakeTrackable != "" && options.MakeTrackable != mapping.Source {
		return unprotectPlan{}, fmt.Errorf("--make-trackable must confirm the exact plaintext path %q", mapping.Source)
	}
	if options.DropArtifactProtection != "" && options.DropArtifactProtection != mapping.Encrypted {
		return unprotectPlan{}, fmt.Errorf("--drop-artifact-protection must confirm the exact artifact path %q", mapping.Encrypted)
	}
	if options.DropArtifactProtection != "" && (cipherExists || cipherTracked) {
		return unprotectPlan{}, errors.New("artifact protection cannot be dropped while ciphertext exists in the worktree or prospective index")
	}
	updated := w.Project.Canonical()
	updated.ProtectedFiles = nil
	for _, current := range w.Project.ProtectedFiles {
		if current.Source != mapping.Source {
			updated.ProtectedFiles = append(updated.ProtectedFiles, current)
		}
	}
	if plainExists && options.MakeTrackable == "" {
		updated.RetainedSafety.IgnoredPlaintext = append(updated.RetainedSafety.IgnoredPlaintext, mapping.Source)
	}
	if options.DropArtifactProtection == "" {
		updated.RetainedSafety.BinaryArtifacts = append(updated.RetainedSafety.BinaryArtifacts, mapping.Encrypted)
	}
	updated = updated.Canonical()
	if err := updated.Validate(); err != nil {
		return unprotectPlan{}, err
	}
	updatedManifest := w.Manifest.Canonical()
	updatedManifest.Remove(mapping.Encrypted)
	if err := updatedManifest.ValidateProject(updated); err != nil {
		return unprotectPlan{}, err
	}
	return unprotectPlan{
		mapping: mapping, baselineSource: mapping.Source, mappingChanged: true,
		project: updated, manifest: updatedManifest,
	}, nil
}

func (w *Workspace) planRetainedSafetyRelease(ctx context.Context, retainedPath string, options UnprotectOptions) (unprotectPlan, error) {
	updated := w.Project.Canonical()
	removed := false
	for _, current := range w.Project.RetainedSafety.IgnoredPlaintext {
		if current == retainedPath {
			if options.MakeTrackable != retainedPath {
				return unprotectPlan{}, fmt.Errorf("retained plaintext safety for %q requires --make-trackable with that exact path", retainedPath)
			}
			if options.DropArtifactProtection != "" {
				return unprotectPlan{}, errors.New("a retained plaintext release cannot also drop artifact protection")
			}
			updated.RetainedSafety.IgnoredPlaintext = removeExactPath(updated.RetainedSafety.IgnoredPlaintext, retainedPath)
			removed = true
			break
		}
	}
	if !removed {
		for _, current := range w.Project.RetainedSafety.BinaryArtifacts {
			if current != retainedPath {
				continue
			}
			if options.DropArtifactProtection != retainedPath {
				return unprotectPlan{}, fmt.Errorf("retained artifact safety for %q requires --drop-artifact-protection with that exact path", retainedPath)
			}
			if options.MakeTrackable != "" {
				return unprotectPlan{}, errors.New("a retained artifact release cannot also make plaintext trackable")
			}
			if _, exists, err := w.hashConfigured(retainedPath); err != nil {
				return unprotectPlan{}, err
			} else if exists {
				return unprotectPlan{}, errors.New("retained artifact protection cannot be dropped while ciphertext exists in the worktree")
			}
			tracked, err := w.Repo.IsTracked(ctx, retainedPath)
			if err != nil {
				return unprotectPlan{}, err
			}
			if tracked {
				return unprotectPlan{}, errors.New("retained artifact protection cannot be dropped while ciphertext exists in the prospective index")
			}
			updated.RetainedSafety.BinaryArtifacts = removeExactPath(updated.RetainedSafety.BinaryArtifacts, retainedPath)
			removed = true
			break
		}
	}
	if !removed {
		return unprotectPlan{}, fmt.Errorf("%q is neither an active plaintext mapping nor an exact retained-safety path", retainedPath)
	}
	updated = updated.Canonical()
	if err := updated.Validate(); err != nil {
		return unprotectPlan{}, err
	}
	currentManifest := w.Manifest.Canonical()
	if err := currentManifest.ValidateProject(updated); err != nil {
		return unprotectPlan{}, err
	}
	return unprotectPlan{project: updated, manifest: currentManifest}, nil
}

func removeExactPath(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}
