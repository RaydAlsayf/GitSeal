package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/limits"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

type EncryptOptions struct {
	Identity string
	Trust    TrustOptions
	Force    bool
}

type DecryptOptions struct {
	Identity                     string
	Force                        bool
	AcceptIncoming               string
	RecoverNoManifest            bool
	AcceptMappings               bool
	AcceptRetainedSafety         bool
	ExpectedProjectSHA256        string
	ExpectedMappingsSHA256       string
	ExpectedRetainedSafetySHA256 string
}

type CryptoResult struct {
	Source    string `json:"source"`
	Encrypted string `json:"encrypted"`
	// PlaintextSHA256 is required for local baseline persistence, but must never
	// be serialized: low-entropy plaintext digests are guessable and remain in
	// Git-local state only.
	PlaintextSHA256    string `json:"-"`
	CiphertextSHA256   string `json:"ciphertext_sha256"`
	RecipientSetSHA256 string `json:"recipient_set_sha256"`
	StateSaved         bool   `json:"state_saved"`
}

func (w *Workspace) Encrypt(ctx context.Context, requested string, all bool, options EncryptOptions) (results []CryptoResult, resultErr error) {
	if all && options.Force {
		return nil, errors.New("--force must name one exact file and cannot be combined with --all")
	}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "encrypt")
	if err != nil {
		return nil, err
	}
	defer finishLock(lock, "encrypt", &resultErr)
	if err := w.reload(); err != nil {
		return nil, err
	}
	if err := w.refuseUnmerged(ctx, "encryption"); err != nil {
		return nil, err
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		return nil, err
	}
	if err := w.refuseTrackedPlaintext(ctx); err != nil {
		return nil, err
	}
	record, err := w.SelectedIdentity(options.Identity)
	if err != nil {
		return nil, err
	}
	state, trust, err := w.RequireEncryptionTrust(options.Trust)
	if err != nil {
		return nil, err
	}
	plan, err := agefile.NewEncryptionPlan(w.Typed, record.Identity)
	if err != nil {
		return nil, err
	}
	mappings, err := selectMappings(w, state, requested, all)
	if err != nil {
		return nil, err
	}
	if len(mappings) == 0 {
		return []CryptoResult{}, nil
	}
	artifacts := make([]string, len(mappings))
	for i, mapping := range mappings {
		artifacts[i] = mapping.Encrypted
	}
	if err := w.Repo.CheckSafeAttributes(ctx, artifacts); err != nil {
		return nil, fmt.Errorf("unsafe effective Git attributes: %w", err)
	}
	// Complete every deterministic source/destination/conflict check for the
	// selected set before the first artifact is published. Each mapping is
	// checked again at its mutation boundary, because external editors do not
	// participate in the GitSeal lock.
	if len(mappings) > 1 {
		if err := w.preflightEncryptMappings(state, mappings, options.Force); err != nil {
			return nil, err
		}
	}
	results = make([]CryptoResult, 0, len(mappings))
	for _, mapping := range mappings {
		result, err := w.encryptMapping(ctx, plan, state, trust, mapping, options.Force)
		if err != nil {
			return results, fmt.Errorf("after completing %d artifact(s), encrypt %q: %w", len(results), mapping.Source, err)
		}
		state.Files[mapping.Source] = localstate.FileBaseline{PlaintextSHA256: result.PlaintextSHA256, CiphertextSHA256: result.CiphertextSHA256}
		ApplyTrust(&state, trust)
		if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
			return append(results, result), fmt.Errorf("ciphertext and manifest were published but local baseline was not saved: %w", err)
		}
		result.StateSaved = true
		results = append(results, result)
	}
	return results, nil
}

func selectMappings(w *Workspace, state localstate.State, requested string, all bool) ([]projectconfig.ProtectedFile, error) {
	if all && requested != "" {
		return nil, errors.New("encrypt accepts either one FILE or --all, not both")
	}
	if !all {
		if requested == "" {
			return nil, errors.New("encrypt requires FILE or --all")
		}
		mapping, ok := w.Project.Find(requested)
		if !ok {
			return nil, fmt.Errorf("%q is not a configured protected file or artifact", requested)
		}
		return []projectconfig.ProtectedFile{mapping}, nil
	}
	selected := make([]projectconfig.ProtectedFile, 0, len(w.Project.ProtectedFiles))
	for _, mapping := range w.Project.ProtectedFiles {
		artifact, ok := w.Manifest.Find(mapping.Encrypted)
		cipher, cipherExists, err := w.hashConfigured(mapping.Encrypted)
		if err != nil {
			return nil, err
		}
		baseline, hasBaseline := state.Files[mapping.Source]
		stale := !ok || artifact.Source != mapping.Source || artifact.RecipientSetSHA256 != w.Typed.Digest().Hex() ||
			!cipherExists || artifact.CiphertextSHA256 != cipher.Hex()
		changed := !hasBaseline
		if hasBaseline {
			if sum, exists, err := w.hashConfigured(mapping.Source); err != nil {
				return nil, err
			} else {
				changed = !exists || sum.Hex() != baseline.PlaintextSHA256
			}
		}
		if stale || changed {
			selected = append(selected, mapping)
		}
	}
	return selected, nil
}

func (w *Workspace) preflightEncryptMappings(state localstate.State, mappings []projectconfig.ProtectedFile, force bool) error {
	for _, mapping := range mappings {
		plain, plainExists, err := w.hashConfigured(mapping.Source)
		if err != nil {
			return fmt.Errorf("preflight plaintext %q: %w", mapping.Source, err)
		}
		if !plainExists {
			return fmt.Errorf("preflight plaintext %q: plaintext source is missing", mapping.Source)
		}
		cipher, cipherExists, err := w.hashConfigured(mapping.Encrypted)
		if err != nil {
			return fmt.Errorf("preflight ciphertext %q: %w", mapping.Encrypted, err)
		}
		if baseline, ok := state.Files[mapping.Source]; ok && cipherExists &&
			plain.Hex() != baseline.PlaintextSHA256 && cipher.Hex() != baseline.CiphertextSHA256 && !force {
			return fmt.Errorf("preflight %q: plaintext and ciphertext both changed; --force is required to choose local plaintext", mapping.Source)
		}
	}
	return nil
}

func (w *Workspace) encryptMapping(ctx context.Context, plan *agefile.EncryptionPlan, state localstate.State, trust TrustSnapshot, mapping projectconfig.ProtectedFile, force bool) (result CryptoResult, resultErr error) {
	baseline, hasBaseline := state.Files[mapping.Source]
	plainBefore, plainExists, err := w.hashConfigured(mapping.Source)
	if err != nil || !plainExists {
		if err == nil {
			err = errors.New("plaintext source is missing")
		}
		return CryptoResult{}, err
	}
	cipherBefore, cipherExists, err := w.hashConfigured(mapping.Encrypted)
	if err != nil {
		return CryptoResult{}, err
	}
	if hasBaseline && cipherExists && plainBefore.Hex() != baseline.PlaintextSHA256 && cipherBefore.Hex() != baseline.CiphertextSHA256 && !force {
		return CryptoResult{}, errors.New("plaintext and ciphertext both changed; --force is required to choose local plaintext")
	}
	sourcePath, _ := pathpolicy.Parse(mapping.Source)
	source, err := w.Root.OpenRead(sourcePath)
	if err != nil {
		return CryptoResult{}, err
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			resultErr = errors.Join(resultErr, source.Close())
		}
	}()
	before, err := source.Stat()
	if err != nil {
		return CryptoResult{}, err
	}
	destination, _ := pathpolicy.Parse(mapping.Encrypted)
	candidate, err := w.Root.NewCandidate(destination, safefile.PublicData)
	if err != nil {
		return CryptoResult{}, err
	}
	published := false
	defer abortCandidate(candidate, "encrypt artifact", &published, &resultErr)
	if err := candidate.RequireDestination(cipherExists, cipherBefore); err != nil {
		return CryptoResult{}, fmt.Errorf("ciphertext destination changed after conflict validation: %w", err)
	}
	hashingSource := digest.NewHashingReader(io.LimitReader(source, limits.DefaultFileBytes+1))
	if err := plan.Encrypt(candidate, hashingSource); err != nil {
		return CryptoResult{}, err
	}
	if hashingSource.BytesRead() > limits.DefaultFileBytes {
		return CryptoResult{}, errors.New("plaintext exceeds the local size limit")
	}
	if hashingSource.Sum() != plainBefore {
		return CryptoResult{}, errors.New("plaintext bytes changed after conflict validation")
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hashingSource.BytesRead() != after.Size() {
		return CryptoResult{}, errors.New("plaintext changed while it was being encrypted")
	}
	if err := source.Close(); err != nil {
		return CryptoResult{}, fmt.Errorf("close plaintext after exact encryption stream: %w", err)
	}
	sourceOpen = false
	if err := candidate.FlushClose(); err != nil {
		return CryptoResult{}, err
	}
	unpublished, err := candidate.OpenUnpublished()
	if err != nil {
		return CryptoResult{}, err
	}
	info, statErr := unpublished.Stat()
	if statErr == nil {
		statErr = plan.AuthenticateCandidate(unpublished, info.Size())
	}
	closeErr := unpublished.Close()
	if statErr != nil {
		return CryptoResult{}, statErr
	}
	if closeErr != nil {
		return CryptoResult{}, closeErr
	}
	if err := w.revalidateControlSnapshots("config.yaml", "recipients.yaml", "manifest.yaml"); err != nil {
		return CryptoResult{}, err
	}
	if err := candidate.Publish(ctx, cipherExists); err != nil {
		return CryptoResult{}, err
	}
	published = true
	result = CryptoResult{Source: mapping.Source, Encrypted: mapping.Encrypted, PlaintextSHA256: hashingSource.Sum().Hex(), CiphertextSHA256: candidate.Sum().Hex(), RecipientSetSHA256: trust.RecipientSet.Hex()}
	entry := manifest.Artifact{Source: mapping.Source, Encrypted: mapping.Encrypted, CiphertextSHA256: result.CiphertextSHA256, RecipientSetSHA256: result.RecipientSetSHA256}
	if err := w.Manifest.Upsert(entry); err != nil {
		return result, fmt.Errorf("ciphertext was published but manifest update could not be prepared: %w", err)
	}
	manifestData, _ := w.Manifest.Marshal()
	if err := w.WriteControl(ctx, "manifest.yaml", manifestData); err != nil {
		return result, fmt.Errorf("ciphertext was published but manifest replacement failed: %w", err)
	}
	return result, nil
}

func (w *Workspace) Decrypt(ctx context.Context, requested string, all bool, options DecryptOptions) (results []CryptoResult, resultErr error) {
	if all && options.Force {
		return nil, errors.New("--force must name one exact file and cannot be combined with --all")
	}
	if options.AcceptIncoming != "" && (all || requested == "") {
		return nil, errors.New("--accept-incoming must be bound to one exact configured file")
	}
	if options.RecoverNoManifest && (all || requested == "") {
		return nil, errors.New("--recover-without-manifest must be bound to one exact configured file")
	}
	if options.AcceptIncoming != "" {
		if _, err := digest.ParseHex(options.AcceptIncoming); err != nil {
			return nil, fmt.Errorf("invalid --accept-incoming digest: %w", err)
		}
	}
	if _, err := digest.ParseHex(options.ExpectedProjectSHA256); err != nil {
		return nil, fmt.Errorf("project operation plan is not bound to an exact canonical snapshot: %w", err)
	}
	if options.AcceptMappings {
		if _, err := digest.ParseHex(options.ExpectedMappingsSHA256); err != nil {
			return nil, fmt.Errorf("mapping acceptance is not bound to an exact reviewed digest: %w", err)
		}
	} else if options.ExpectedMappingsSHA256 != "" {
		return nil, errors.New("an expected mapping digest requires explicit mapping-change acceptance")
	}
	if options.AcceptRetainedSafety {
		if _, err := digest.ParseHex(options.ExpectedRetainedSafetySHA256); err != nil {
			return nil, fmt.Errorf("retained-safety acceptance is not bound to an exact reviewed digest: %w", err)
		}
	} else if options.ExpectedRetainedSafetySHA256 != "" {
		return nil, errors.New("an expected retained-safety digest requires explicit retained-safety acceptance")
	}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "decrypt")
	if err != nil {
		return nil, err
	}
	defer finishLock(lock, "decrypt", &resultErr)
	if err := w.reload(); err != nil {
		return nil, err
	}
	projectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return nil, err
	}
	if projectSnapshot.Hex() != options.ExpectedProjectSHA256 {
		return nil, errors.New("project configuration changed after the operation plan was created")
	}
	if err := w.refuseUnmerged(ctx, "decryption"); err != nil {
		return nil, err
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		return nil, err
	}
	if err := w.refuseTrackedPlaintext(ctx); err != nil {
		return nil, err
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return nil, err
	}
	if options.AcceptMappings && options.ExpectedMappingsSHA256 != w.Project.MappingDigest().Hex() {
		return nil, errors.New("project mappings changed after review; refusing to accept a different mapping digest")
	}
	if state.TrustedMappingsSHA256 != w.Project.MappingDigest().Hex() && !options.AcceptMappings {
		return nil, errors.New("project mappings are not locally trusted; exact mapping-change acceptance is required")
	}
	if options.AcceptRetainedSafety && options.ExpectedRetainedSafetySHA256 != w.Project.RetainedSafetyDigest().Hex() {
		return nil, errors.New("retained safety changed after review; refusing to accept a different digest")
	}
	if state.TrustedRetainedSafetySHA256 != w.Project.RetainedSafetyDigest().Hex() && !options.AcceptRetainedSafety {
		return nil, errors.New("retained safety is not locally trusted; exact retained-safety acceptance is required")
	}
	record, err := w.SelectedIdentity(options.Identity)
	if err != nil {
		return nil, err
	}
	mappings, err := decryptMappings(w, requested, all)
	if err != nil {
		return nil, err
	}
	if len(mappings) == 0 {
		return []CryptoResult{}, nil
	}
	artifacts := make([]string, len(mappings))
	for i, mapping := range mappings {
		artifacts[i] = mapping.Encrypted
	}
	if err := w.Repo.CheckSafeAttributes(ctx, artifacts); err != nil {
		return nil, err
	}
	// Authenticate and validate the complete selected set into a discard sink
	// before publishing the first plaintext. Per-mapping validation is repeated
	// below to bind each publication to its then-current exact bytes.
	if len(mappings) > 1 {
		if err := w.preflightDecryptMappings(ctx, state, record.Identity, mappings, options); err != nil {
			return nil, err
		}
	}
	results = make([]CryptoResult, 0, len(mappings))
	for _, mapping := range mappings {
		result, err := w.decryptMapping(ctx, state, record.Identity, mapping, options)
		if err != nil {
			return results, fmt.Errorf("after completing %d artifact(s), decrypt %q: %w", len(results), mapping.Encrypted, err)
		}
		state.Files[mapping.Source] = localstate.FileBaseline{PlaintextSHA256: result.PlaintextSHA256, CiphertextSHA256: result.CiphertextSHA256}
		state.TrustedMappingsSHA256 = w.Project.MappingDigest().Hex()
		state.TrustedRetainedSafetySHA256 = w.Project.RetainedSafetyDigest().Hex()
		if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
			return append(results, result), fmt.Errorf("plaintext was published but local baseline was not saved: %w", err)
		}
		result.StateSaved = true
		results = append(results, result)
	}
	return results, nil
}

func decryptMappings(w *Workspace, requested string, all bool) ([]projectconfig.ProtectedFile, error) {
	if all && requested != "" {
		return nil, errors.New("decrypt accepts either one FILE or --all, not both")
	}
	if all {
		return append([]projectconfig.ProtectedFile(nil), w.Project.ProtectedFiles...), nil
	}
	if requested == "" {
		return nil, errors.New("decrypt requires FILE or --all")
	}
	mapping, ok := w.Project.Find(requested)
	if !ok {
		return nil, fmt.Errorf("%q is not configured", requested)
	}
	return []projectconfig.ProtectedFile{mapping}, nil
}

func (w *Workspace) decryptMapping(ctx context.Context, state localstate.State, identity agefile.HybridIdentity, mapping projectconfig.ProtectedFile, options DecryptOptions) (result CryptoResult, resultErr error) {
	observation, err := w.inspectDecryptMapping(ctx, state, mapping, options)
	if err != nil {
		return CryptoResult{}, err
	}
	cipherSum := observation.ciphertext
	plainSum := observation.plaintext
	plainExists := observation.plaintextExists

	cipherPath, _ := pathpolicy.Parse(mapping.Encrypted)
	ciphertext, err := w.Root.OpenRead(cipherPath)
	if err != nil {
		return CryptoResult{}, err
	}
	ciphertextOpen := true
	defer func() {
		if ciphertextOpen {
			resultErr = errors.Join(resultErr, ciphertext.Close())
		}
	}()
	info, err := ciphertext.Stat()
	if err != nil {
		return CryptoResult{}, err
	}
	plainPath, _ := pathpolicy.Parse(mapping.Source)
	candidate, err := w.Root.NewCandidate(plainPath, safefile.SensitiveData)
	if err != nil {
		return CryptoResult{}, err
	}
	published := false
	defer abortCandidate(candidate, "decrypt plaintext", &published, &resultErr)
	if err := candidate.RequireDestination(plainExists, plainSum); err != nil {
		return CryptoResult{}, fmt.Errorf("plaintext destination changed after conflict validation: %w", err)
	}
	engine, err := agefile.NewEngine(w.Typed.Len())
	if err != nil {
		return CryptoResult{}, err
	}
	if err := decryptExactCiphertext(engine, candidate, ciphertext, info.Size(), cipherSum, identity); err != nil {
		return CryptoResult{}, err
	}
	if err := ciphertext.Close(); err != nil {
		return CryptoResult{}, fmt.Errorf("close ciphertext after exact authenticated stream: %w", err)
	}
	ciphertextOpen = false
	if err := candidate.FlushClose(); err != nil {
		return CryptoResult{}, err
	}
	if err := w.revalidateControlSnapshots("config.yaml", "recipients.yaml", "manifest.yaml"); err != nil {
		return CryptoResult{}, err
	}
	if err := candidate.Publish(ctx, plainExists); err != nil {
		return CryptoResult{}, err
	}
	published = true
	return CryptoResult{Source: mapping.Source, Encrypted: mapping.Encrypted, PlaintextSHA256: candidate.Sum().Hex(), CiphertextSHA256: cipherSum.Hex(), RecipientSetSHA256: w.Typed.Digest().Hex()}, nil
}

type decryptMappingObservation struct {
	plaintext       digest.Sum
	plaintextExists bool
	ciphertext      digest.Sum
}

func (w *Workspace) inspectDecryptMapping(ctx context.Context, state localstate.State, mapping projectconfig.ProtectedFile, options DecryptOptions) (decryptMappingObservation, error) {
	if tracked, err := w.Repo.IsTracked(ctx, mapping.Source); err != nil || tracked {
		if err != nil {
			return decryptMappingObservation{}, err
		}
		return decryptMappingObservation{}, errors.New("plaintext destination is present in the active index; ignore rules do not protect tracked files")
	}
	if present, err := w.headContains(ctx, mapping.Source); err != nil || present {
		if err != nil {
			return decryptMappingObservation{}, err
		}
		return decryptMappingObservation{}, errors.New("plaintext destination is tracked in HEAD; V1 has no overwrite-tracked escape hatch")
	}
	artifact, hasManifest := w.Manifest.Find(mapping.Encrypted)
	cipherSum, cipherExists, err := w.hashConfigured(mapping.Encrypted)
	if err != nil || !cipherExists {
		if err == nil {
			err = errors.New("ciphertext artifact is missing")
		}
		return decryptMappingObservation{}, err
	}
	if (!hasManifest || artifact.Source != mapping.Source || artifact.CiphertextSHA256 != cipherSum.Hex()) && !options.RecoverNoManifest {
		return decryptMappingObservation{}, errors.New("ciphertext does not match exact manifest bookkeeping; explicit recovery bypass is required")
	}
	if hasManifest && artifact.RecipientSetSHA256 != w.Typed.Digest().Hex() && !options.RecoverNoManifest {
		return decryptMappingObservation{}, errors.New("artifact recipient-set bookkeeping is stale")
	}
	plainSum, plainExists, err := w.hashConfigured(mapping.Source)
	if err != nil {
		return decryptMappingObservation{}, err
	}
	baseline, hasBaseline := state.Files[mapping.Source]
	unfamiliar := plainExists && (!hasBaseline || baseline.CiphertextSHA256 != cipherSum.Hex())
	if unfamiliar && options.AcceptIncoming != cipherSum.Hex() {
		return decryptMappingObservation{}, fmt.Errorf("unfamiliar ciphertext requires --accept-incoming %s for this exact artifact", cipherSum.Hex())
	}
	if plainExists && !hasBaseline && !options.Force {
		return decryptMappingObservation{}, errors.New("existing plaintext has no trusted baseline; compare with sync first or use --force with exact incoming-ciphertext acceptance")
	}
	if plainExists && hasBaseline && plainSum.Hex() != baseline.PlaintextSHA256 && !options.Force {
		return decryptMappingObservation{}, errors.New("local plaintext changed; --force is required to choose ciphertext")
	}
	return decryptMappingObservation{plaintext: plainSum, plaintextExists: plainExists, ciphertext: cipherSum}, nil
}

func (w *Workspace) preflightDecryptMappings(ctx context.Context, state localstate.State, identity agefile.HybridIdentity, mappings []projectconfig.ProtectedFile, options DecryptOptions) error {
	engine, err := agefile.NewEngine(w.Typed.Len())
	if err != nil {
		return err
	}
	for _, mapping := range mappings {
		observation, err := w.inspectDecryptMapping(ctx, state, mapping, options)
		if err != nil {
			return fmt.Errorf("preflight decrypt %q: %w", mapping.Encrypted, err)
		}
		cipherPath, _ := pathpolicy.Parse(mapping.Encrypted)
		ciphertext, err := w.Root.OpenRead(cipherPath)
		if err != nil {
			return fmt.Errorf("preflight decrypt %q: %w", mapping.Encrypted, err)
		}
		info, statErr := ciphertext.Stat()
		authErr := statErr
		if authErr == nil {
			authErr = decryptExactCiphertext(engine, io.Discard, ciphertext, info.Size(), observation.ciphertext, identity)
		}
		closeErr := ciphertext.Close()
		if authErr != nil || closeErr != nil {
			return fmt.Errorf("preflight decrypt %q: %w", mapping.Encrypted, errors.Join(authErr, closeErr))
		}
	}
	return nil
}

// establishFirstRunBaseline authenticates the complete ciphertext into a hash
// sink and records a baseline only when it exactly matches the independently
// hashed existing plaintext. It never creates or replaces plaintext.
func (w *Workspace) establishFirstRunBaseline(ctx context.Context, requested, identityName, expectedProject string) (out CryptoResult, resultErr error) {
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "sync-compare")
	if err != nil {
		return CryptoResult{}, err
	}
	defer finishLock(lock, "first-run comparison", &resultErr)
	if err := w.reload(); err != nil {
		return CryptoResult{}, err
	}
	projectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return CryptoResult{}, err
	}
	if projectSnapshot.Hex() != expectedProject {
		return CryptoResult{}, errors.New("project configuration changed after the synchronization plan was created")
	}
	if err := w.refuseUnmerged(ctx, "first-run comparison"); err != nil {
		return CryptoResult{}, err
	}
	if err := w.checkWorktreePolicy(ctx); err != nil {
		return CryptoResult{}, err
	}
	if err := w.refuseTrackedPlaintext(ctx); err != nil {
		return CryptoResult{}, err
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return CryptoResult{}, err
	}
	mappingDigest := w.Project.MappingDigest()
	if state.TrustedMappingsSHA256 != mappingDigest.Hex() {
		return CryptoResult{}, errors.New("project mappings are not locally trusted; exact mapping-change acceptance is required")
	}
	retainedSafetyDigest := w.Project.RetainedSafetyDigest()
	if state.TrustedRetainedSafetySHA256 != retainedSafetyDigest.Hex() {
		return CryptoResult{}, errors.New("retained safety is not locally trusted; exact retained-safety acceptance is required")
	}
	mapping, ok := w.Project.Find(requested)
	if !ok {
		return CryptoResult{}, fmt.Errorf("%q is not configured", requested)
	}
	if _, already := state.Files[mapping.Source]; already {
		return CryptoResult{}, errors.New("first-run comparison is no longer applicable because a baseline now exists")
	}
	artifact, ok := w.Manifest.Find(mapping.Encrypted)
	if !ok || artifact.Source != mapping.Source {
		return CryptoResult{}, errors.New("manifest does not bind the exact first-run mapping")
	}
	recipientDigest := w.Typed.Digest()
	if artifact.RecipientSetSHA256 != recipientDigest.Hex() {
		return CryptoResult{}, errors.New("artifact recipient-set bookkeeping is stale")
	}
	cipherSum, cipherExists, err := w.hashConfigured(mapping.Encrypted)
	if err != nil || !cipherExists {
		if err == nil {
			err = errors.New("ciphertext artifact is missing")
		}
		return CryptoResult{}, err
	}
	if artifact.CiphertextSHA256 != cipherSum.Hex() {
		return CryptoResult{}, errors.New("ciphertext does not match exact manifest bookkeeping")
	}
	plainSum, plainExists, err := w.hashConfigured(mapping.Source)
	if err != nil || !plainExists {
		if err == nil {
			err = errors.New("plaintext disappeared before first-run comparison")
		}
		return CryptoResult{}, err
	}
	record, err := w.SelectedIdentity(identityName)
	if err != nil {
		return CryptoResult{}, err
	}
	if !w.Typed.Contains(record.Identity) {
		return CryptoResult{}, errors.New("selected identity is not in the current recipient set")
	}
	cipherPath, _ := pathpolicy.Parse(mapping.Encrypted)
	ciphertext, err := w.Root.OpenRead(cipherPath)
	if err != nil {
		return CryptoResult{}, err
	}
	info, err := ciphertext.Stat()
	if err != nil {
		return CryptoResult{}, errors.Join(err, ciphertext.Close())
	}
	engine, err := agefile.NewEngine(w.Typed.Len())
	if err != nil {
		return CryptoResult{}, errors.Join(err, ciphertext.Close())
	}
	plainHash := digest.NewHashingWriter(io.Discard)
	decryptErr := decryptExactCiphertext(engine, plainHash, ciphertext, info.Size(), cipherSum, record.Identity)
	closeErr := ciphertext.Close()
	if decryptErr != nil {
		return CryptoResult{}, decryptErr
	}
	if closeErr != nil {
		return CryptoResult{}, closeErr
	}
	if plainHash.BytesWritten() > limits.DefaultFileBytes {
		return CryptoResult{}, errors.New("decrypted plaintext exceeds the local size limit")
	}
	if plainHash.Sum() != plainSum {
		return CryptoResult{}, errors.New("first-run plaintext and authenticated ciphertext differ; synchronization conflict modified neither file")
	}
	plainAfter, plainStillExists, err := w.hashConfigured(mapping.Source)
	if err != nil || !plainStillExists || plainAfter != plainSum {
		return CryptoResult{}, errors.New("plaintext changed during first-run comparison")
	}
	cipherAfter, cipherStillExists, err := w.hashConfigured(mapping.Encrypted)
	if err != nil || !cipherStillExists || cipherAfter != cipherSum {
		return CryptoResult{}, errors.New("ciphertext changed during first-run comparison")
	}
	if err := w.reload(); err != nil {
		return CryptoResult{}, err
	}
	currentProjectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return CryptoResult{}, err
	}
	currentMapping, currentOK := w.Project.Find(mapping.Source)
	currentArtifact, artifactOK := w.Manifest.Find(mapping.Encrypted)
	if !currentOK || currentMapping != mapping || currentProjectSnapshot != projectSnapshot || w.Project.MappingDigest() != mappingDigest || w.Project.RetainedSafetyDigest() != retainedSafetyDigest || w.Typed.Digest() != recipientDigest || !artifactOK || currentArtifact != artifact {
		return CryptoResult{}, errors.New("tracked GitSeal policy changed during first-run comparison")
	}
	state, err = localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return CryptoResult{}, err
	}
	if _, already := state.Files[mapping.Source]; already {
		return CryptoResult{}, errors.New("local baseline changed during first-run comparison")
	}
	state.Files[mapping.Source] = localstate.FileBaseline{PlaintextSHA256: plainSum.Hex(), CiphertextSHA256: cipherSum.Hex()}
	state.TrustedMappingsSHA256 = mappingDigest.Hex()
	state.TrustedRetainedSafetySHA256 = retainedSafetyDigest.Hex()
	if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
		return CryptoResult{}, err
	}
	return CryptoResult{
		Source: mapping.Source, Encrypted: mapping.Encrypted,
		PlaintextSHA256: plainSum.Hex(), CiphertextSHA256: cipherSum.Hex(),
		RecipientSetSHA256: recipientDigest.Hex(), StateSaved: true,
	}, nil
}

// decryptExactCiphertext binds the bytes consumed by age decryption to the
// digest established before opening the decryption stream. This closes the
// validation/open race: a valid substitute ciphertext may authenticate, but it
// cannot authorize plaintext publication or a baseline for different bytes.
// The size check also rejects truncation, growth, or a decoder that returns
// before consuming the exact file observed through the opened handle.
func decryptExactCiphertext(engine *agefile.Engine, dst io.Writer, src io.Reader, totalSize int64, expected digest.Sum, identity agefile.HybridIdentity) error {
	consumed, err := newExactCiphertextReader(src, totalSize)
	if err != nil {
		return err
	}
	if err := engine.Decrypt(dst, consumed, totalSize, identity); err != nil {
		return err
	}
	return validateExactCiphertext(consumed, totalSize, expected)
}

// authenticateExactCiphertextHeader authenticates only the age header, then
// hashes the remainder without decrypting it. A successful result therefore
// means header_decryptable for the exact manifest-bound artifact, not payload
// authentication.
func authenticateExactCiphertextHeader(engine *agefile.Engine, src io.Reader, totalSize int64, expected digest.Sum, identity agefile.HybridIdentity) error {
	consumed, err := newExactCiphertextReader(src, totalSize)
	if err != nil {
		return err
	}
	report, _, err := engine.Inspect(consumed, totalSize)
	if err != nil {
		return err
	}
	if err := engine.AuthenticateHeader(report.Header, identity); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, consumed); err != nil {
		return errors.New("ciphertext could not be read exactly after header authentication")
	}
	return validateExactCiphertext(consumed, totalSize, expected)
}

func inspectExactCiphertext(engine *agefile.Engine, src io.Reader, totalSize int64, expected digest.Sum) error {
	consumed, err := newExactCiphertextReader(src, totalSize)
	if err != nil {
		return err
	}
	_, replay, err := engine.Inspect(consumed, totalSize)
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, replay); err != nil {
		return errors.New("ciphertext could not be streamed exactly after shape inspection")
	}
	return validateExactCiphertext(consumed, totalSize, expected)
}

func newExactCiphertextReader(src io.Reader, totalSize int64) (*digest.HashingReader, error) {
	if totalSize < 0 || totalSize > limits.DefaultFileBytes {
		return nil, errors.New("ciphertext size is outside the local limit")
	}
	return digest.NewHashingReader(io.LimitReader(src, totalSize+1)), nil
}

func validateExactCiphertext(consumed *digest.HashingReader, totalSize int64, expected digest.Sum) error {
	if consumed.BytesRead() != totalSize {
		return errors.New("ciphertext byte count changed while it was being authenticated")
	}
	if consumed.Sum() != expected {
		return errors.New("ciphertext digest changed while it was being authenticated")
	}
	return nil
}

func (w *Workspace) hashConfigured(name string) (sum digest.Sum, exists bool, resultErr error) {
	p, err := pathpolicy.Parse(name)
	if err != nil {
		return digest.Sum{}, false, err
	}
	file, err := w.Root.OpenRead(p)
	if errors.Is(err, os.ErrNotExist) {
		return digest.Sum{}, false, nil
	}
	if err != nil {
		return digest.Sum{}, false, err
	}
	sum, err = safefile.HashExactFile(file, limits.DefaultFileBytes)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return digest.Sum{}, false, errors.Join(err, closeErr)
	}
	return sum, true, nil
}

func (w *Workspace) headContains(ctx context.Context, configured string) (bool, error) {
	tree, unborn, err := w.Repo.ResolveHeadTree(ctx)
	if err != nil {
		return false, err
	}
	if unborn {
		return false, nil
	}
	entries, err := w.Repo.ListTree(ctx, tree)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Path == configured {
			return true, nil
		}
	}
	return false, nil
}
