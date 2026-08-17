package app

import (
	"errors"
	"fmt"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

type TrustOptions struct {
	AcceptInitialRecipients        bool
	AcceptRecipientChanges         bool
	AcceptMappingChanges           bool
	AcceptRetainedSafetyChanges    bool
	ExpectedProjectSHA256          string
	ExpectedRecipientsSHA256       string
	ExpectedMembershipPolicySHA256 string
	ExpectedMappingsSHA256         string
	ExpectedRetainedSafetySHA256   string
}

type TrustSnapshot struct {
	Project          digest.Sum
	RecipientSet     digest.Sum
	MembershipPolicy digest.Sum
	Mappings         digest.Sum
	RetainedSafety   digest.Sum
	FirstUse         bool
	Changes          []string
}

func (w *Workspace) RequireEncryptionTrust(options TrustOptions) (localstate.State, TrustSnapshot, error) {
	state, err := localstate.Load(w.Repo.GitSealDir())
	if err != nil {
		return localstate.State{}, TrustSnapshot{}, err
	}
	projectSnapshot, err := ProjectSnapshotDigest(w.Project)
	if err != nil {
		return state, TrustSnapshot{}, err
	}
	snapshot := TrustSnapshot{
		Project:      projectSnapshot,
		RecipientSet: w.Typed.Digest(), MembershipPolicy: w.Recipients.MembershipDigest(),
		Mappings:       w.Project.MappingDigest(),
		RetainedSafety: w.Project.RetainedSafetyDigest(),
	}
	if err := bindTrustAcceptance(options, snapshot); err != nil {
		return state, snapshot, err
	}
	snapshot.FirstUse = state.TrustedRecipientsSHA256 == "" || state.TrustedMembershipPolicySHA256 == "" || state.TrustedMappingsSHA256 == "" || state.TrustedRetainedSafetySHA256 == ""
	_, snapshot.Changes = localstate.TrustMatches(state, snapshot.RecipientSet, snapshot.MembershipPolicy, snapshot.Mappings, snapshot.RetainedSafety)
	if snapshot.FirstUse {
		if !options.AcceptInitialRecipients {
			return state, snapshot, errors.New("first encryption requires explicit recipient acceptance after independently verifying every full fingerprint")
		}
		if !options.AcceptMappingChanges {
			return state, snapshot, errors.New("first encryption requires explicit mapping acceptance after reviewing every exact path")
		}
		if !options.AcceptRetainedSafetyChanges {
			return state, snapshot, errors.New("first encryption requires explicit retained-safety acceptance after reviewing every protected orphan path")
		}
	} else {
		for _, change := range snapshot.Changes {
			switch change {
			case "recipient set", "membership policy":
				if !options.AcceptRecipientChanges {
					return state, snapshot, fmt.Errorf("%s changed and requires explicit recipient-change acceptance", change)
				}
			case "project mappings":
				if !options.AcceptMappingChanges {
					return state, snapshot, errors.New("project mappings changed and require explicit mapping-change acceptance")
				}
			case "retained safety":
				if !options.AcceptRetainedSafetyChanges {
					return state, snapshot, errors.New("retained safety changed and requires explicit retained-safety acceptance")
				}
			}
		}
	}
	return state, snapshot, nil
}

func bindTrustAcceptance(options TrustOptions, snapshot TrustSnapshot) error {
	if err := requireAcceptedDigest("project configuration snapshot", snapshot.Project, options.ExpectedProjectSHA256); err != nil {
		return err
	}
	recipientsAccepted := options.AcceptInitialRecipients || options.AcceptRecipientChanges
	if recipientsAccepted {
		if err := requireAcceptedDigest("recipient set", snapshot.RecipientSet, options.ExpectedRecipientsSHA256); err != nil {
			return err
		}
		if err := requireAcceptedDigest("membership policy", snapshot.MembershipPolicy, options.ExpectedMembershipPolicySHA256); err != nil {
			return err
		}
	} else if options.ExpectedRecipientsSHA256 != "" || options.ExpectedMembershipPolicySHA256 != "" {
		return errors.New("recipient trust expectations require an explicit recipient acceptance flag")
	}
	if options.AcceptMappingChanges {
		if err := requireAcceptedDigest("project mappings", snapshot.Mappings, options.ExpectedMappingsSHA256); err != nil {
			return err
		}
	} else if options.ExpectedMappingsSHA256 != "" {
		return errors.New("mapping trust expectation requires explicit mapping-change acceptance")
	}
	if options.AcceptRetainedSafetyChanges {
		if err := requireAcceptedDigest("retained safety", snapshot.RetainedSafety, options.ExpectedRetainedSafetySHA256); err != nil {
			return err
		}
	} else if options.ExpectedRetainedSafetySHA256 != "" {
		return errors.New("retained-safety trust expectation requires explicit retained-safety acceptance")
	}
	return nil
}

// ProjectSnapshotDigest is an ephemeral operation-plan token over the exact
// canonical project, including retained_safety. It accepts migration-eligible
// project schema v1 only so the explicit upgrade preview can bind what it
// displayed; ordinary command loading still rejects v1. It is not persisted,
// is not a repository trust anchor, and does not replace the specification's
// normative active-mapping digest.
func ProjectSnapshotDigest(project projectconfig.Project) (digest.Sum, error) {
	canonical := project.Canonical()
	if canonical.Version == projectconfig.LegacyProjectVersion {
		data, err := strictyaml.Encode(canonical)
		if err != nil {
			return digest.Sum{}, err
		}
		validated, err := projectconfig.ParseProjectV1ForMigration(data)
		if err != nil {
			return digest.Sum{}, err
		}
		data, err = strictyaml.Encode(validated.Canonical())
		if err != nil {
			return digest.Sum{}, err
		}
		return digest.Bytes(data), nil
	}
	data, err := canonical.Marshal()
	if err != nil {
		return digest.Sum{}, err
	}
	return digest.Bytes(data), nil
}

func requireAcceptedDigest(label string, current digest.Sum, expected string) error {
	parsed, err := digest.ParseHex(expected)
	if err != nil {
		return fmt.Errorf("%s acceptance is not bound to an exact reviewed digest: %w", label, err)
	}
	if parsed != current {
		return fmt.Errorf("%s changed after review; refusing to accept a different digest", label)
	}
	return nil
}

func ApplyTrust(state *localstate.State, snapshot TrustSnapshot) {
	state.TrustedRecipientsSHA256 = snapshot.RecipientSet.Hex()
	state.TrustedMembershipPolicySHA256 = snapshot.MembershipPolicy.Hex()
	state.TrustedMappingsSHA256 = snapshot.Mappings.Hex()
	state.TrustedRetainedSafetySHA256 = snapshot.RetainedSafety.Hex()
}
