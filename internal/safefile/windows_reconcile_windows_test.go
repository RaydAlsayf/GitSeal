//go:build windows

package safefile

import (
	"reflect"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
)

func TestReconcileWindowsPublicationKnownStates(t *testing.T) {
	candidate := windowsTestFingerprint(1, "candidate")
	original := windowsTestFingerprint(2, "original")
	known := func(fingerprint windowsObjectFingerprint) windowsObservedObject {
		return windowsObservedObject{Exists: true, Fingerprint: fingerprint, SecurityValid: true}
	}
	tests := []struct {
		name        string
		expectation windowsPublicationExpectation
		temporary   windowsObservedObject
		destination windowsObservedObject
		backup      windowsObservedObject
		want        windowsReconciliationPlan
	}{
		{
			name:        "replacement published with backup",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			destination: known(candidate),
			backup:      known(original),
			want: windowsReconciliationPlan{
				State:   windowsReconciliationPublished,
				Actions: []windowsReconciliationAction{windowsRemoveOriginalBackup},
			},
		},
		{
			name:        "replacement published without backup",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			destination: known(candidate),
			want:        windowsReconciliationPlan{State: windowsReconciliationPublished},
		},
		{
			name:        "original retained and candidate remains",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(candidate),
			destination: known(original),
			want: windowsReconciliationPlan{
				State:   windowsReconciliationOriginalRetained,
				Actions: []windowsReconciliationAction{windowsRemoveCandidateTemporary},
			},
		},
		{
			name:        "original needs identity-bound restore",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(candidate),
			backup:      known(original),
			want: windowsReconciliationPlan{
				State: windowsReconciliationOriginalNeedsRestore,
				Actions: []windowsReconciliationAction{
					windowsRestoreOriginalFromBackup,
					windowsRemoveCandidateTemporary,
				},
			},
		},
		{
			name:        "create-if-absent published",
			expectation: windowsPublicationExpectation{Candidate: candidate},
			destination: known(candidate),
			want:        windowsReconciliationPlan{State: windowsReconciliationPublished},
		},
		{
			name:        "create-if-absent candidate retained",
			expectation: windowsPublicationExpectation{Candidate: candidate},
			temporary:   known(candidate),
			want: windowsReconciliationPlan{
				State:   windowsReconciliationUnpublishedNewFile,
				Actions: []windowsReconciliationAction{windowsRemoveCandidateTemporary},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := reconcileWindowsPublication(test.expectation, test.temporary, test.destination, test.backup)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("plan = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestReconcileWindowsPublicationRefusesAmbiguity(t *testing.T) {
	candidate := windowsTestFingerprint(1, "candidate")
	original := windowsTestFingerprint(2, "original")
	unknown := windowsTestFingerprint(3, "unknown")
	known := func(fingerprint windowsObjectFingerprint) windowsObservedObject {
		return windowsObservedObject{Exists: true, Fingerprint: fingerprint, SecurityValid: true}
	}
	mutatedCandidate := candidate
	mutatedCandidate.Sum = digest.Bytes([]byte("mutated"))
	unsafeCandidate := known(candidate)
	unsafeCandidate.SecurityValid = false

	tests := []struct {
		name        string
		expectation windowsPublicationExpectation
		temporary   windowsObservedObject
		destination windowsObservedObject
		backup      windowsObservedObject
	}{
		{
			name:        "unfamiliar destination",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(candidate),
			destination: known(unknown),
		},
		{
			name:        "candidate bytes changed",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(mutatedCandidate),
			destination: known(original),
		},
		{
			name:        "security state not validated",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   unsafeCandidate,
			destination: known(original),
		},
		{
			name:        "same identity at two names",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(candidate),
			destination: known(candidate),
		},
		{
			name:        "candidate appears at backup",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			backup:      known(candidate),
		},
		{
			name:        "original missing without backup",
			expectation: windowsPublicationExpectation{Candidate: candidate, Original: &original},
			temporary:   known(candidate),
		},
		{
			name:        "create candidate disappeared",
			expectation: windowsPublicationExpectation{Candidate: candidate},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if plan, err := reconcileWindowsPublication(test.expectation, test.temporary, test.destination, test.backup); err == nil {
				t.Fatalf("ambiguous state produced deletion/restoration plan %#v", plan)
			}
		})
	}
}

func windowsTestFingerprint(identityByte byte, contents string) windowsObjectFingerprint {
	identity := fileIdentity{volume: 1}
	identity.fileID[0] = identityByte
	return windowsObjectFingerprint{Identity: identity, Sum: digest.Bytes([]byte(contents))}
}
