package app

import (
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestMemberAddFingerprintMismatchRefusesBeforeWorkspaceAccess(t *testing.T) {
	// An incorrect acceptance fingerprint must be rejected before AddMember
	// accesses repository or local-state data. A zero Workspace makes that
	// ordering an explicit, platform-independent invariant.
	w := &Workspace{}
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	change, err := w.AddMember(t.Context(), projectconfig.Member{ID: "alice", Name: "Alice", Recipient: identity.CanonicalRecipient()}, "wrong")
	if err == nil || change.Fingerprint != digest.RecipientFingerprint(identity.CanonicalRecipient()).Grouped() {
		t.Fatalf("change=%#v err=%v", change, err)
	}
}
