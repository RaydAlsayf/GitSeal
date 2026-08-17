package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

type MemberInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Recipient   string `json:"recipient,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

type MemberList struct {
	SchemaVersion           int          `json:"schema_version"`
	Members                 []MemberInfo `json:"members"`
	RecipientSetFingerprint string       `json:"recipient_set_fingerprint"`
	SelectedInSet           *bool        `json:"selected_identity_in_set,omitempty"`
}

func (w *Workspace) ListMembers(identityOverride string) (MemberList, error) {
	result := MemberList{SchemaVersion: 1, Members: make([]MemberInfo, 0, len(w.Recipients.Members)), RecipientSetFingerprint: w.Typed.Digest().Grouped()}
	for _, member := range w.Recipients.Members {
		result.Members = append(result.Members, MemberInfo{ID: member.ID, Name: member.Name, Recipient: member.Recipient, Fingerprint: digest.RecipientFingerprint(member.Recipient).Grouped()})
	}
	selected := identityOverride
	if selected == "" {
		var err error
		selected, err = localstate.LoadSelection(w.Repo.GitSealDir())
		if err != nil {
			return result, err
		}
	}
	if selected != "" {
		record, err := w.SelectedIdentity(selected)
		if err != nil {
			return result, err
		}
		contained := w.Typed.Contains(record.Identity)
		result.SelectedInSet = &contained
	}
	return result, nil
}

type MemberChange struct {
	Fingerprint string
	Stale       []string
}

func (w *Workspace) AddMember(ctx context.Context, member projectconfig.Member, acceptedFingerprint string) (change MemberChange, resultErr error) {
	parsed, err := agefile.NewHybridRecipients([]string{member.Recipient})
	if err != nil {
		return MemberChange{}, err
	}
	fingerprint := digest.RecipientFingerprint(parsed.CanonicalStrings()[0]).Grouped()
	if acceptedFingerprint != fingerprint {
		return MemberChange{Fingerprint: fingerprint}, fmt.Errorf("member add requires --accept-fingerprint %s after verifying that full fingerprint over an independent authenticated channel", fingerprint)
	}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "member-add")
	if err != nil {
		return MemberChange{}, err
	}
	defer finishLock(lock, "member add", &resultErr)
	if err := w.reload(); err != nil {
		return MemberChange{}, err
	}
	if err := w.refuseUnmerged(ctx, "recipient mutation"); err != nil {
		return MemberChange{}, err
	}
	updated := w.Recipients
	updated.Members = append([]projectconfig.Member(nil), w.Recipients.Members...)
	updated.Members = append(updated.Members, member)
	expectedTyped, err := updated.Validate()
	if err != nil {
		return MemberChange{}, err
	}
	updated = updated.Canonical()
	data, err := updated.Marshal()
	if err != nil {
		return MemberChange{}, err
	}
	if err := w.WriteControl(ctx, "recipients.yaml", data); err != nil {
		return MemberChange{}, err
	}
	if err := w.reconcileRecipientsWrite(data, updated, expectedTyped); err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but final-path validation failed: %w", err)
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but local trust state could not be loaded: %w", err)
	}
	state.TrustedRecipientsSHA256 = w.Typed.Digest().Hex()
	state.TrustedMembershipPolicySHA256 = w.Recipients.MembershipDigest().Hex()
	if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but local trust state could not be saved: %w", err)
	}
	return MemberChange{Fingerprint: fingerprint, Stale: activeArtifacts(w.Project)}, nil
}

func (w *Workspace) RemoveMember(ctx context.Context, id string, confirmed bool) (change MemberChange, resultErr error) {
	if !confirmed {
		return MemberChange{}, errors.New("member removal requires explicit confirmation that old commits remain readable and credentials must be rotated for revocation")
	}
	lock, err := localstate.Acquire(w.Repo.GitSealDir(), "member-remove")
	if err != nil {
		return MemberChange{}, err
	}
	defer finishLock(lock, "member remove", &resultErr)
	if err := w.reload(); err != nil {
		return MemberChange{}, err
	}
	if err := w.refuseUnmerged(ctx, "recipient mutation"); err != nil {
		return MemberChange{}, err
	}
	updated := w.Recipients
	updated.Members = append([]projectconfig.Member(nil), w.Recipients.Members...)
	index := -1
	for i, member := range updated.Members {
		if member.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return MemberChange{}, fmt.Errorf("member %q does not exist", id)
	}
	if len(updated.Members) == 1 && (len(w.Project.ProtectedFiles) > 0 || len(w.Manifest.Artifacts) > 0 || len(w.Project.RetainedSafety.BinaryArtifacts) > 0) {
		return MemberChange{}, errors.New("cannot remove the final member while active, manifested, or retained artifacts exist")
	}
	removed := updated.Members[index]
	updated.Members = append(updated.Members[:index:index], updated.Members[index+1:]...)
	expectedTyped, err := updated.Validate()
	if err != nil {
		return MemberChange{}, err
	}
	updated = updated.Canonical()
	data, err := updated.Marshal()
	if err != nil {
		return MemberChange{}, err
	}
	if err := w.WriteControl(ctx, "recipients.yaml", data); err != nil {
		return MemberChange{}, err
	}
	if err := w.reconcileRecipientsWrite(data, updated, expectedTyped); err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but final-path validation failed: %w", err)
	}
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but local trust state could not be loaded: %w", err)
	}
	state.TrustedRecipientsSHA256 = w.Typed.Digest().Hex()
	state.TrustedMembershipPolicySHA256 = w.Recipients.MembershipDigest().Hex()
	if err := localstate.Save(ctx, w.Repo.GitSealDir(), &state); err != nil {
		return MemberChange{}, fmt.Errorf("recipients.yaml was updated but local trust state could not be saved: %w", err)
	}
	return MemberChange{Fingerprint: digest.RecipientFingerprint(removed.Recipient).Grouped(), Stale: activeArtifacts(w.Project)}, nil
}

func (w *Workspace) reconcileRecipientsWrite(expectedBytes []byte, expected projectconfig.Recipients, expectedTyped agefile.HybridRecipients) error {
	actual, err := w.readControl("recipients.yaml")
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expectedBytes) {
		return errors.New("recipient file bytes changed after publication")
	}
	recipients, typed, err := projectconfig.ParseRecipients(actual)
	if err != nil {
		return err
	}
	if recipients.MembershipDigest() != expected.MembershipDigest() || typed.Digest() != expectedTyped.Digest() {
		return errors.New("recipient policy changed after publication")
	}
	w.Recipients, w.Typed = recipients, typed
	return nil
}

func activeArtifacts(project projectconfig.Project) []string {
	values := make([]string, len(project.ProtectedFiles))
	for i, mapping := range project.ProtectedFiles {
		values[i] = mapping.Encrypted
	}
	return values
}
