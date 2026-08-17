package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
)

func TestEncryptAllSelectsMissingAndManifestMismatchedArtifacts(t *testing.T) {
	directory := t.TempDir()
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	typed, err := agefile.NewHybridRecipients([]string{identity.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	mapping := projectconfig.ProtectedFile{Source: "secret", Encrypted: "secret.age"}
	plaintext := []byte("synthetic plaintext")
	if err := os.WriteFile(filepath.Join(directory, mapping.Source), plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	expectedCiphertext := []byte("bookkept ciphertext")
	w := &Workspace{
		Root:    root,
		Project: projectconfig.Project{Version: projectconfig.ProjectVersion, ProtectedFiles: []projectconfig.ProtectedFile{mapping}, RetainedSafety: projectconfig.RetainedSafety{IgnoredPlaintext: []string{}, BinaryArtifacts: []string{}}},
		Typed:   typed,
		Manifest: manifest.Manifest{Version: manifest.Version, Artifacts: []manifest.Artifact{{
			Source: mapping.Source, Encrypted: mapping.Encrypted,
			CiphertextSHA256: digest.Bytes(expectedCiphertext).Hex(), RecipientSetSHA256: typed.Digest().Hex(),
		}}},
	}
	state := localstate.Empty()
	state.Files[mapping.Source] = localstate.FileBaseline{PlaintextSHA256: digest.Bytes(plaintext).Hex(), CiphertextSHA256: digest.Bytes(expectedCiphertext).Hex()}

	selected, err := selectMappings(w, state, "", true)
	if err != nil || len(selected) != 1 {
		t.Fatalf("missing artifact selection = %#v, %v", selected, err)
	}
	if err := os.WriteFile(filepath.Join(directory, mapping.Encrypted), expectedCiphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err = selectMappings(w, state, "", true)
	if err != nil || len(selected) != 0 {
		t.Fatalf("exact artifact selection = %#v, %v", selected, err)
	}
	if err := os.WriteFile(filepath.Join(directory, mapping.Encrypted), []byte("unfamiliar ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err = selectMappings(w, state, "", true)
	if err != nil || len(selected) != 1 {
		t.Fatalf("mismatched artifact selection = %#v, %v", selected, err)
	}
}

func TestEncryptSetPreflightRejectsLaterConflictWithoutMutation(t *testing.T) {
	directory := t.TempDir()
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	mappings := []projectconfig.ProtectedFile{{Source: "a", Encrypted: "a.age"}, {Source: "b", Encrypted: "b.age"}}
	before := map[string][]byte{"a": []byte("a plain"), "a.age": []byte("a cipher"), "b": []byte("b changed plain"), "b.age": []byte("b changed cipher")}
	for name, data := range before {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := localstate.Empty()
	state.Files["a"] = localstate.FileBaseline{PlaintextSHA256: digest.Bytes(before["a"]).Hex(), CiphertextSHA256: digest.Bytes(before["a.age"]).Hex()}
	state.Files["b"] = localstate.FileBaseline{PlaintextSHA256: digest.Bytes([]byte("old b plain")).Hex(), CiphertextSHA256: digest.Bytes([]byte("old b cipher")).Hex()}
	w := &Workspace{Root: root}
	if err := w.preflightEncryptMappings(state, mappings, false); err == nil || !strings.Contains(err.Error(), "both changed") {
		t.Fatalf("later conflict preflight error = %v", err)
	}
	assertFilesUnchanged(t, directory, before)
}

func TestDecryptSetPreflightRejectsLaterOverwriteWithoutPublishingEarlierPlaintext(t *testing.T) {
	directory := t.TempDir()
	clearSyncTestGitEnvironment(t)
	cmd := exec.Command("git", "-C", directory, "init", "--quiet")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	repo, err := gitrepo.Discover(t.Context(), directory, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	root, err := safefile.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	identity, _, cipherA := exactCiphertextFixture(t, "a plaintext")
	_, _, cipherB := exactCiphertextFixtureForIdentity(t, identity, "b plaintext")
	typed, err := agefile.NewHybridRecipients([]string{identity.CanonicalRecipient()})
	if err != nil {
		t.Fatal(err)
	}
	mappings := []projectconfig.ProtectedFile{{Source: "a", Encrypted: "a.age"}, {Source: "b", Encrypted: "b.age"}}
	for name, data := range map[string][]byte{"a.age": cipherA, "b.age": cipherB, "b": []byte("unfamiliar existing plaintext")} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := &Workspace{Repo: repo, Root: root, Typed: typed, Manifest: manifest.Manifest{Version: manifest.Version, Artifacts: []manifest.Artifact{
		{Source: "a", Encrypted: "a.age", CiphertextSHA256: digest.Bytes(cipherA).Hex(), RecipientSetSHA256: typed.Digest().Hex()},
		{Source: "b", Encrypted: "b.age", CiphertextSHA256: digest.Bytes(cipherB).Hex(), RecipientSetSHA256: typed.Digest().Hex()},
	}}}
	beforeB := []byte("unfamiliar existing plaintext")
	if err := w.preflightDecryptMappings(t.Context(), localstate.Empty(), identity, mappings, DecryptOptions{}); err == nil || !strings.Contains(err.Error(), "unfamiliar ciphertext") {
		t.Fatalf("later overwrite preflight error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "a")); !os.IsNotExist(err) {
		t.Fatalf("earlier plaintext was published during preflight: %v", err)
	}
	afterB, err := os.ReadFile(filepath.Join(directory, "b"))
	if err != nil || !bytes.Equal(afterB, beforeB) {
		t.Fatalf("later plaintext changed during rejected preflight: %q, %v", afterB, err)
	}
}

func assertFilesUnchanged(t *testing.T, directory string, before map[string][]byte) {
	t.Helper()
	for name, expected := range before {
		actual, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("%s changed: %q, %v", name, actual, err)
		}
	}
}

func clearSyncTestGitEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_") {
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Setenv(key, value) })
		}
	}
}
