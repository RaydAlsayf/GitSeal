//go:build windows

package safefile

import (
	"errors"
	"fmt"

	"github.com/raydalsayf/gitseal/internal/digest"
)

// windowsObjectFingerprint binds reconciliation to both the NTFS file identity
// and the exact streamed bytes. DACL and stream validation is represented by
// windowsObservedObject.SecurityValid and must have been performed by handle.
type windowsObjectFingerprint struct {
	Identity fileIdentity
	Sum      digest.Sum
}

type windowsObservedObject struct {
	Exists        bool
	Fingerprint   windowsObjectFingerprint
	SecurityValid bool
}

type windowsPublicationExpectation struct {
	Candidate windowsObjectFingerprint
	Original  *windowsObjectFingerprint
}

type windowsReconciliationState uint8

const (
	windowsReconciliationPublished windowsReconciliationState = iota + 1
	windowsReconciliationOriginalRetained
	windowsReconciliationOriginalNeedsRestore
	windowsReconciliationUnpublishedNewFile
)

type windowsReconciliationAction uint8

const (
	windowsRestoreOriginalFromBackup windowsReconciliationAction = iota + 1
	windowsRemoveCandidateTemporary
	windowsRemoveOriginalBackup
)

type windowsReconciliationPlan struct {
	State   windowsReconciliationState
	Actions []windowsReconciliationAction
}

type windowsObjectRole uint8

const (
	windowsRoleAbsent windowsObjectRole = iota
	windowsRoleCandidate
	windowsRoleOriginal
)

// reconcileWindowsPublication is pure and intentionally conservative. It
// classifies the only states GitSeal can prove from already-open handles after
// a publication failure. Every returned action still has to be carried out by
// identity-bound handle operations; an unknown object produces no plan.
func reconcileWindowsPublication(
	expected windowsPublicationExpectation,
	temporary windowsObservedObject,
	destination windowsObservedObject,
	backup windowsObservedObject,
) (windowsReconciliationPlan, error) {
	if expected.Candidate.Identity == (fileIdentity{}) {
		return windowsReconciliationPlan{}, errors.New("missing candidate identity")
	}
	if expected.Original != nil {
		if expected.Original.Identity == (fileIdentity{}) {
			return windowsReconciliationPlan{}, errors.New("missing original identity")
		}
		if expected.Original.Identity == expected.Candidate.Identity {
			return windowsReconciliationPlan{}, errors.New("candidate and original identities are not distinct")
		}
		if expected.Original.Identity.volume != expected.Candidate.Identity.volume {
			return windowsReconciliationPlan{}, errors.New("candidate and original are not on the same volume")
		}
	}
	if err := rejectDuplicateObservedIdentities(temporary, destination, backup); err != nil {
		return windowsReconciliationPlan{}, err
	}
	temporaryRole, err := classifyWindowsObservedObject(expected, temporary)
	if err != nil {
		return windowsReconciliationPlan{}, fmt.Errorf("temporary: %w", err)
	}
	destinationRole, err := classifyWindowsObservedObject(expected, destination)
	if err != nil {
		return windowsReconciliationPlan{}, fmt.Errorf("destination: %w", err)
	}
	backupRole, err := classifyWindowsObservedObject(expected, backup)
	if err != nil {
		return windowsReconciliationPlan{}, fmt.Errorf("backup: %w", err)
	}
	if temporaryRole != windowsRoleAbsent && temporaryRole != windowsRoleCandidate {
		return windowsReconciliationPlan{}, errors.New("the reserved candidate pathname names the original object")
	}
	if backupRole != windowsRoleAbsent && backupRole != windowsRoleOriginal {
		return windowsReconciliationPlan{}, errors.New("the reserved backup pathname names the candidate object")
	}

	switch destinationRole {
	case windowsRoleCandidate:
		actions := []windowsReconciliationAction(nil)
		if backupRole == windowsRoleOriginal {
			actions = append(actions, windowsRemoveOriginalBackup)
		}
		return windowsReconciliationPlan{State: windowsReconciliationPublished, Actions: actions}, nil
	case windowsRoleOriginal:
		if backupRole != windowsRoleAbsent {
			return windowsReconciliationPlan{}, errors.New("original object appears at both destination and backup")
		}
		actions := []windowsReconciliationAction(nil)
		if temporaryRole == windowsRoleCandidate {
			actions = append(actions, windowsRemoveCandidateTemporary)
		}
		return windowsReconciliationPlan{State: windowsReconciliationOriginalRetained, Actions: actions}, nil
	case windowsRoleAbsent:
		if expected.Original == nil {
			if backupRole != windowsRoleAbsent {
				return windowsReconciliationPlan{}, errors.New("unexpected backup exists for create-if-absent publication")
			}
			if temporaryRole != windowsRoleCandidate {
				return windowsReconciliationPlan{}, errors.New("new-file candidate disappeared without being published")
			}
			return windowsReconciliationPlan{
				State:   windowsReconciliationUnpublishedNewFile,
				Actions: []windowsReconciliationAction{windowsRemoveCandidateTemporary},
			}, nil
		}
		if backupRole != windowsRoleOriginal {
			// This includes ReplaceFileW's documented 1176 state when no
			// backup was requested. GitSeal cannot infer or recreate the
			// missing original and must require manual reconciliation.
			return windowsReconciliationPlan{}, errors.New("original destination is missing and no identity-bound backup can restore it")
		}
		actions := []windowsReconciliationAction{windowsRestoreOriginalFromBackup}
		if temporaryRole == windowsRoleCandidate {
			actions = append(actions, windowsRemoveCandidateTemporary)
		}
		return windowsReconciliationPlan{State: windowsReconciliationOriginalNeedsRestore, Actions: actions}, nil
	default:
		return windowsReconciliationPlan{}, errors.New("invalid reconciliation state")
	}
}

func classifyWindowsObservedObject(expected windowsPublicationExpectation, observed windowsObservedObject) (windowsObjectRole, error) {
	if !observed.Exists {
		return windowsRoleAbsent, nil
	}
	if !observed.SecurityValid {
		return windowsRoleAbsent, errors.New("object ACL or stream state was not validated")
	}
	if observed.Fingerprint.Identity == expected.Candidate.Identity {
		if observed.Fingerprint.Sum != expected.Candidate.Sum {
			return windowsRoleAbsent, errors.New("candidate identity has unexpected bytes")
		}
		return windowsRoleCandidate, nil
	}
	if expected.Original != nil && observed.Fingerprint.Identity == expected.Original.Identity {
		if observed.Fingerprint.Sum != expected.Original.Sum {
			return windowsRoleAbsent, errors.New("original identity has unexpected bytes")
		}
		return windowsRoleOriginal, nil
	}
	return windowsRoleAbsent, errors.New("pathname names an unfamiliar object")
}

func rejectDuplicateObservedIdentities(objects ...windowsObservedObject) error {
	for left := range objects {
		if !objects[left].Exists {
			continue
		}
		for right := left + 1; right < len(objects); right++ {
			if objects[right].Exists && objects[left].Fingerprint.Identity == objects[right].Fingerprint.Identity {
				return errors.New("one file identity appears at multiple publication pathnames")
			}
		}
	}
	return nil
}
