package app

import (
	"strings"
	"testing"

	statemachine "github.com/raydalsayf/gitseal/internal/status"
)

func TestCalculatedRepositoryStatePrecedesActionBlocker(t *testing.T) {
	for _, state := range []statemachine.State{
		statemachine.MissingCiphertext,
		statemachine.IncomingConsent,
		statemachine.Conflict,
	} {
		item := FileStatus{}
		applyCalculatedStatus(&item, state, []statusActionBlocker{{state: "missing_identity", detail: "identity unavailable"}})
		if item.State != string(state) {
			t.Errorf("calculated state %q was masked by %q", state, item.State)
		}
		if len(item.actionBlockers) == 0 {
			t.Errorf("calculated state %q lost its mutation blocker", state)
		}
	}

	item := FileStatus{}
	applyCalculatedStatus(&item, statemachine.Synchronized, []statusActionBlocker{{state: "missing_identity", detail: "identity unavailable"}})
	if item.State != "missing_identity" {
		t.Fatalf("synchronized item did not report its action blocker: %#v", item)
	}
}

func TestPreflightSyncRejectsLaterIncomingBeforePlanningAnyAction(t *testing.T) {
	report := StatusReport{Files: []FileStatus{
		{Source: "a", Encrypted: "a.age", State: string(statemachine.MissingPlaintext)},
		{Source: "b", Encrypted: "b.age", State: string(statemachine.IncomingConsent)},
	}}
	selected, err := preflightSync(report, "", SyncOptions{})
	if err == nil || !strings.Contains(err.Error(), "exact currently observed digest") {
		t.Fatalf("preflight error = %v", err)
	}
	if selected != nil {
		t.Fatalf("rejected multi-file sync returned an executable plan: %#v", selected)
	}
}

func TestPreflightSyncRejectsMultipleMutationsAsOnePlan(t *testing.T) {
	report := StatusReport{Files: []FileStatus{
		{Source: "a", Encrypted: "a.age", State: string(statemachine.MissingPlaintext)},
		{Source: "b", Encrypted: "b.age", State: string(statemachine.FirstRunCompare)},
	}}
	selected, err := preflightSync(report, "", SyncOptions{})
	if err == nil || !strings.Contains(err.Error(), "more than one mapping") {
		t.Fatalf("multi-mutation preflight error = %v", err)
	}
	if selected != nil {
		t.Fatalf("rejected multi-mutation sync returned a plan: %#v", selected)
	}
}

func TestPreflightSyncRejectsEveryUnsafeNoOpState(t *testing.T) {
	states := []string{
		string(statemachine.PlaintextChanged),
		string(statemachine.MissingCiphertext),
		string(statemachine.MissingFiles),
		string(statemachine.Conflict),
		"unmerged",
		"busy_indeterminate",
		"indeterminate",
		"invalid_ciphertext",
		"stale_recipient_set",
	}
	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			report := StatusReport{Files: []FileStatus{{Source: "secret", Encrypted: "secret.age", State: state}}}
			selected, err := preflightSync(report, "", SyncOptions{})
			if err == nil {
				t.Fatalf("unsafe state %q returned success", state)
			}
			if selected != nil {
				t.Fatalf("unsafe state %q returned an executable plan", state)
			}
		})
	}
}

func TestPreflightSyncRequiresActionReadinessBeforeRestore(t *testing.T) {
	report := StatusReport{Files: []FileStatus{{
		Source: "secret", Encrypted: "secret.age", State: string(statemachine.MissingPlaintext),
		actionBlockers: []statusActionBlocker{{state: "missing_identity", detail: "no selected identity could be safely loaded"}},
	}}}
	if selected, err := preflightSync(report, "secret", SyncOptions{}); err == nil || selected != nil {
		t.Fatalf("blocked restore plan = %#v, %v", selected, err)
	}
}

func TestPreflightSyncAllowsOnlyTheReviewedMappingBlocker(t *testing.T) {
	report := StatusReport{Files: []FileStatus{{
		Source: "secret", Encrypted: "secret.age", State: "untrusted_mapping",
		syncState:      string(statemachine.Synchronized),
		actionBlockers: []statusActionBlocker{{state: "untrusted_mapping", detail: "mapping review required"}},
	}}}
	if selected, err := preflightSync(report, "secret", SyncOptions{}); err == nil || selected != nil {
		t.Fatalf("unaccepted mapping plan = %#v, %v", selected, err)
	}
	selected, err := preflightSync(report, "secret", SyncOptions{AcceptMappings: true})
	if err != nil || len(selected) != 1 {
		t.Fatalf("reviewed mapping plan = %#v, %v", selected, err)
	}

	report.Files[0].actionBlockers = append(report.Files[0].actionBlockers,
		statusActionBlocker{state: "missing_identity", detail: "identity unavailable"})
	if selected, err := preflightSync(report, "secret", SyncOptions{AcceptMappings: true}); err == nil || selected != nil {
		t.Fatalf("mapping flag bypassed a different action blocker: %#v, %v", selected, err)
	}
}

func TestPreflightSyncAllowsOnlyTheReviewedRetainedSafetyBlocker(t *testing.T) {
	report := StatusReport{Files: []FileStatus{{
		Source: "secret", Encrypted: "secret.age", State: "untrusted_retained_safety",
		syncState:      string(statemachine.Synchronized),
		actionBlockers: []statusActionBlocker{{state: "untrusted_retained_safety", detail: "retained-safety review required"}},
	}}}
	if selected, err := preflightSync(report, "secret", SyncOptions{}); err == nil || selected != nil {
		t.Fatalf("unaccepted retained-safety plan = %#v, %v", selected, err)
	}
	selected, err := preflightSync(report, "secret", SyncOptions{AcceptRetainedSafety: true})
	if err != nil || len(selected) != 1 {
		t.Fatalf("reviewed retained-safety plan = %#v, %v", selected, err)
	}
	report.Files[0].actionBlockers = append(report.Files[0].actionBlockers,
		statusActionBlocker{state: "missing_identity", detail: "identity unavailable"})
	if selected, err := preflightSync(report, "secret", SyncOptions{AcceptRetainedSafety: true}); err == nil || selected != nil {
		t.Fatalf("retained-safety flag bypassed a different blocker: %#v, %v", selected, err)
	}
}

func TestPreflightSyncAcceptIncomingIsExactStateScoped(t *testing.T) {
	report := StatusReport{Files: []FileStatus{{
		Source: "secret", Encrypted: "secret.age", State: string(statemachine.IncomingConsent),
		ciphertextSHA256: strings.Repeat("0", 64),
	}}}
	options := SyncOptions{AcceptIncoming: strings.Repeat("0", 64)}
	selected, err := preflightSync(report, "secret", options)
	if err != nil || len(selected) != 1 {
		t.Fatalf("exact incoming plan = %#v, %v", selected, err)
	}

	report.Files[0].State = string(statemachine.Synchronized)
	if selected, err := preflightSync(report, "secret", options); err == nil || selected != nil {
		t.Fatalf("stale incoming acceptance plan = %#v, %v", selected, err)
	}
	report.Files[0].State = string(statemachine.IncomingConsent)
	report.Files[0].ciphertextSHA256 = strings.Repeat("1", 64)
	if selected, err := preflightSync(report, "secret", options); err == nil || selected != nil {
		t.Fatalf("wrong-digest incoming acceptance plan = %#v, %v", selected, err)
	}
}

func TestPrimaryStatusDoesNotHideTrackedPlaintextBehindUnmergedState(t *testing.T) {
	item := FileStatus{}
	if !applyPrimarySafetyState(&item, true, true, false) {
		t.Fatal("tracked plaintext did not produce a primary safety state")
	}
	if item.State != "tracked_plaintext" {
		t.Fatalf("primary state = %q, want tracked_plaintext", item.State)
	}
}

func TestReviewedMappingDigestCannotAuthorizeChangedSnapshot(t *testing.T) {
	reviewed := strings.Repeat("1", 64)
	changed := strings.Repeat("2", 64)
	if err := requireReviewedMappingDigest(reviewed, reviewed); err != nil {
		t.Fatal(err)
	}
	if err := requireReviewedMappingDigest(changed, reviewed); err == nil {
		t.Fatal("mapping acceptance authorized a digest different from the reviewed snapshot")
	}
}

func TestReviewedRetainedSafetyDigestCannotAuthorizeChangedSnapshot(t *testing.T) {
	reviewed := strings.Repeat("3", 64)
	changed := strings.Repeat("4", 64)
	if err := requireReviewedRetainedSafetyDigest(reviewed, reviewed); err != nil {
		t.Fatal(err)
	}
	if err := requireReviewedRetainedSafetyDigest(changed, reviewed); err == nil {
		t.Fatal("retained-safety acceptance authorized a digest different from the reviewed snapshot")
	}
}

func TestSyncMappingAcceptanceRequiresExpectedDigest(t *testing.T) {
	w := &Workspace{}
	if _, _, err := w.Sync(t.Context(), "", SyncOptions{AcceptMappings: true}); err == nil {
		t.Fatal("mapping acceptance without an exact reviewed digest reached workspace mutation")
	}
}
