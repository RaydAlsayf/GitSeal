package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
	"github.com/raydalsayf/gitseal/internal/strictyaml"
)

func TestProjectTrustUpgradeRequiresExactDigestBeforeAnyWrite(t *testing.T) {
	clearDoctorGitEnvironment(t)
	directory := t.TempDir()
	runDoctorGit(t, directory, "init", "--quiet")
	legacy := projectconfig.EmptyProject()
	legacy.Version = projectconfig.LegacyProjectVersion
	legacy.RetainedSafety.IgnoredPlaintext = []string{"old-secret"}
	legacy.RetainedSafety.BinaryArtifacts = []string{"old-secret.age"}
	data, err := strictyaml.Encode(legacy.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/config.yaml", data)

	preview, err := PreviewProjectTrustUpgrade(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Version != projectconfig.LegacyProjectVersion || preview.RetainedSafetyDigest() != legacy.RetainedSafetyDigest() {
		t.Fatalf("preview = %#v", preview)
	}
	before, err := os.ReadFile(filepath.Join(directory, ".gitseal", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := digest.Bytes([]byte("not the reviewed policy")).Hex()
	snapshot, err := ProjectSnapshotDigest(preview)
	if err != nil {
		t.Fatal(err)
	}
	result, err := UpgradeProjectTrust(t.Context(), directory, wrong, snapshot.Hex())
	if err == nil || len(result.Completed) != 0 {
		t.Fatalf("stale acceptance = %#v, %v", result, err)
	}
	after, readErr := os.ReadFile(filepath.Join(directory, ".gitseal", "config.yaml"))
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("legacy config changed despite rejected acceptance: %q, %v", after, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(directory, ".git", "gitseal")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected acceptance created Git-local state: %v", statErr)
	}
	wrongProject := digest.Bytes([]byte("not the displayed project snapshot")).Hex()
	result, err = UpgradeProjectTrust(t.Context(), directory, legacy.RetainedSafetyDigest().Hex(), wrongProject)
	if err == nil || len(result.Completed) != 0 {
		t.Fatalf("detached project acceptance = %#v, %v", result, err)
	}
	after, readErr = os.ReadFile(filepath.Join(directory, ".gitseal", "config.yaml"))
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("legacy config changed after detached snapshot: %q, %v", after, readErr)
	}
}

func TestProjectTrustUpgradePlatformRefusalPreservesLegacyConfig(t *testing.T) {
	clearDoctorGitEnvironment(t)
	directory := t.TempDir()
	runDoctorGit(t, directory, "init", "--quiet")
	legacy := projectconfig.EmptyProject()
	legacy.Version = projectconfig.LegacyProjectVersion
	data, err := strictyaml.Encode(legacy.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/config.yaml", data)

	snapshot, err := ProjectSnapshotDigest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	result, err := UpgradeProjectTrust(t.Context(), directory, legacy.RetainedSafetyDigest().Hex(), snapshot.Hex())
	if err == nil || len(result.Completed) != 0 {
		t.Fatalf("unqualified platform crossed trust migration boundary: %#v, %v", result, err)
	}
	if !errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) && !containsWindowsLocalStateRefusal(err) {
		t.Fatalf("unexpected platform refusal: %v", err)
	}
	after, readErr := os.ReadFile(filepath.Join(directory, ".gitseal", "config.yaml"))
	if readErr != nil || string(after) != string(data) {
		t.Fatalf("platform refusal changed legacy config: %q, %v", after, readErr)
	}
}

func containsWindowsLocalStateRefusal(err error) bool {
	return err != nil && (errors.Is(err, safefile.ErrIdentityBoundRemovalUnavailable) ||
		strings.Contains(err.Error(), "Windows protected local-state directory DACL boundary"))
}
