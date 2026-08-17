package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestPlanRetainedPlaintextReleaseRequiresExactPathAndDoesNotMutateWorkspace(t *testing.T) {
	project := projectconfig.EmptyProject()
	project.RetainedSafety.IgnoredPlaintext = []string{"old-secret"}
	w := &Workspace{Project: project.Canonical(), Manifest: manifest.Empty()}
	original := w.Project.Canonical()

	if _, err := w.planUnprotect(t.Context(), "old-secret", UnprotectOptions{}); err == nil {
		t.Fatal("retained plaintext safety was released without exact confirmation")
	}
	if !reflect.DeepEqual(w.Project, original) {
		t.Fatal("rejected retained release mutated the workspace project")
	}
	plan, err := w.planUnprotect(t.Context(), "old-secret", UnprotectOptions{MakeTrackable: "old-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.mappingChanged || plan.baselineSource != "" || len(plan.project.RetainedSafety.IgnoredPlaintext) != 0 {
		t.Fatalf("retained release plan = %#v", plan)
	}
	if plan.project.MappingDigest() != original.MappingDigest() || plan.project.RetainedSafetyDigest() == original.RetainedSafetyDigest() {
		t.Fatal("retained release changed the active digest or failed to change the retained digest")
	}
	if !reflect.DeepEqual(w.Project, original) {
		t.Fatal("accepted planning mutated the workspace before publication")
	}
}

func TestRetainedOnlyUnprotectAcceptanceUsesExactProjectAndRetainedDigests(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	options := UnprotectOptions{
		AcceptRetainedSafety:         true,
		ExpectedProjectSHA256:        digestA,
		ExpectedRetainedSafetySHA256: digestB,
	}
	if err := validateUnprotectAcceptanceOptions(options); err != nil {
		t.Fatalf("retained-only exact acceptance was rejected: %v", err)
	}
	options.ExpectedRetainedSafetySHA256 = ""
	if err := validateUnprotectAcceptanceOptions(options); err == nil {
		t.Fatal("retained-only acceptance without its exact retained digest passed validation")
	}
}

func TestUnprotectExpectedDigestsCannotBeDetachedFromAcceptance(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	for name, options := range map[string]UnprotectOptions{
		"project":  {ExpectedProjectSHA256: digestA},
		"mapping":  {ExpectedMappingsSHA256: digestA},
		"retained": {ExpectedRetainedSafetySHA256: digestA},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateUnprotectAcceptanceOptions(options); err == nil {
				t.Fatal("detached expected digest passed validation")
			}
		})
	}
}
