package app

import (
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestProjectSnapshotDigestIncludesRetainedSafety(t *testing.T) {
	t.Parallel()
	first := projectconfig.EmptyProject()
	first.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "secret", Encrypted: "secret.age"}}
	second := first.Canonical()
	second.RetainedSafety.IgnoredPlaintext = []string{"old-secret"}
	if first.MappingDigest() != second.MappingDigest() {
		t.Fatal("normative active-mapping digest unexpectedly includes retained safety")
	}
	firstSnapshot, err := ProjectSnapshotDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := ProjectSnapshotDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstSnapshot == secondSnapshot {
		t.Fatal("operation-plan snapshot did not bind retained safety")
	}
}

func TestBindTrustAcceptanceRequiresExactReviewedDigests(t *testing.T) {
	t.Parallel()
	snapshot := TrustSnapshot{
		Project:          digest.Bytes([]byte("canonical project")),
		RecipientSet:     digest.Bytes([]byte("recipient set")),
		MembershipPolicy: digest.Bytes([]byte("membership policy")),
		Mappings:         digest.Bytes([]byte("mappings")),
		RetainedSafety:   digest.Bytes([]byte("retained safety")),
	}
	tests := []struct {
		name    string
		options TrustOptions
		wantErr bool
	}{
		{name: "missing project plan", options: TrustOptions{}, wantErr: true},
		{name: "exact project plan without acceptance", options: TrustOptions{ExpectedProjectSHA256: snapshot.Project.Hex()}},
		{name: "changed project plan", options: TrustOptions{ExpectedProjectSHA256: digest.Bytes([]byte("different")).Hex()}, wantErr: true},
		{name: "recipient flag without digests", options: TrustOptions{AcceptInitialRecipients: true, ExpectedProjectSHA256: snapshot.Project.Hex()}, wantErr: true},
		{
			name: "recipient digest changed after review",
			options: TrustOptions{
				AcceptRecipientChanges:         true,
				ExpectedProjectSHA256:          snapshot.Project.Hex(),
				ExpectedRecipientsSHA256:       digest.Bytes([]byte("different")).Hex(),
				ExpectedMembershipPolicySHA256: snapshot.MembershipPolicy.Hex(),
			},
			wantErr: true,
		},
		{
			name: "exact recipient review",
			options: TrustOptions{
				AcceptRecipientChanges:         true,
				ExpectedProjectSHA256:          snapshot.Project.Hex(),
				ExpectedRecipientsSHA256:       snapshot.RecipientSet.Hex(),
				ExpectedMembershipPolicySHA256: snapshot.MembershipPolicy.Hex(),
			},
		},
		{name: "mapping flag without digest", options: TrustOptions{AcceptMappingChanges: true, ExpectedProjectSHA256: snapshot.Project.Hex()}, wantErr: true},
		{
			name: "mapping digest changed after review",
			options: TrustOptions{
				AcceptMappingChanges:   true,
				ExpectedProjectSHA256:  snapshot.Project.Hex(),
				ExpectedMappingsSHA256: digest.Bytes([]byte("different")).Hex(),
			},
			wantErr: true,
		},
		{
			name: "exact combined review",
			options: TrustOptions{
				AcceptInitialRecipients:        true,
				AcceptMappingChanges:           true,
				AcceptRetainedSafetyChanges:    true,
				ExpectedProjectSHA256:          snapshot.Project.Hex(),
				ExpectedRecipientsSHA256:       snapshot.RecipientSet.Hex(),
				ExpectedMembershipPolicySHA256: snapshot.MembershipPolicy.Hex(),
				ExpectedMappingsSHA256:         snapshot.Mappings.Hex(),
				ExpectedRetainedSafetySHA256:   snapshot.RetainedSafety.Hex(),
			},
		},
		{
			name: "retained safety digest changed after review",
			options: TrustOptions{
				AcceptRetainedSafetyChanges:  true,
				ExpectedProjectSHA256:        snapshot.Project.Hex(),
				ExpectedRetainedSafetySHA256: digest.Bytes([]byte("different")).Hex(),
			},
			wantErr: true,
		},
		{
			name:    "retained safety digest without acceptance flag",
			options: TrustOptions{ExpectedProjectSHA256: snapshot.Project.Hex(), ExpectedRetainedSafetySHA256: snapshot.RetainedSafety.Hex()},
			wantErr: true,
		},
		{
			name:    "digest without acceptance flag",
			options: TrustOptions{ExpectedProjectSHA256: snapshot.Project.Hex(), ExpectedMappingsSHA256: snapshot.Mappings.Hex()},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := bindTrustAcceptance(test.options, snapshot)
			if test.wantErr && err == nil {
				t.Fatal("expected trust binding to fail")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("bindTrustAcceptance: %v", err)
			}
		})
	}
}
