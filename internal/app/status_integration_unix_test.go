//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/localstate"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
	"github.com/raydalsayf/gitseal/internal/safefile"
	statemachine "github.com/raydalsayf/gitseal/internal/status"
)

func TestStatusMissingIdentityDoesNotMaskMissingCiphertext(t *testing.T) {
	t.Skip("POSIX status requires the unavailable exact-identity lock lifecycle")
	w := newMemberTestWorkspace(t)
	project, recipientSet := configureStatusProject(t, w, []projectconfig.ProtectedFile{{Source: "secret", Encrypted: "secret.age"}}, nil)
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), "secret"), []byte("synthetic plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	book := manifest.Manifest{Version: manifest.Version, Artifacts: []manifest.Artifact{{
		Source: "secret", Encrypted: "secret.age",
		CiphertextSHA256: digest.Bytes(nil).Hex(), RecipientSetSHA256: recipientSet,
	}}}
	writeStatusManifest(t, w, book)
	trustStatusMappings(t, w, project)

	report, err := w.Status(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Files) != 1 || report.Files[0].State != string(statemachine.MissingCiphertext) {
		t.Fatalf("status = %#v", report)
	}
}

func TestStatusEnumeratesInvalidAndMissingArtifactsWithoutIdentity(t *testing.T) {
	t.Skip("POSIX status requires the unavailable exact-identity lock lifecycle")
	w := newMemberTestWorkspace(t)
	mappings := []projectconfig.ProtectedFile{
		{Source: "a", Encrypted: "a.age"},
		{Source: "b", Encrypted: "b.age"},
	}
	project, recipientSet := configureStatusProject(t, w, mappings, nil)
	malformed := []byte("not an age file")
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), "a.age"), malformed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Repo.Worktree(), "b"), []byte("synthetic plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	book := manifest.Manifest{Version: manifest.Version, Artifacts: []manifest.Artifact{
		{Source: "a", Encrypted: "a.age", CiphertextSHA256: digest.Bytes(malformed).Hex(), RecipientSetSHA256: recipientSet},
		{Source: "b", Encrypted: "b.age", CiphertextSHA256: digest.Bytes(nil).Hex(), RecipientSetSHA256: recipientSet},
	}}
	writeStatusManifest(t, w, book)
	trustStatusMappings(t, w, project)

	report, err := w.Status(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, item := range report.Files {
		states[item.Source] = item.State
	}
	if states["a"] != "invalid_ciphertext" || states["b"] != string(statemachine.MissingCiphertext) {
		t.Fatalf("artifact states = %#v; report = %#v", states, report)
	}
}

func configureStatusProject(t *testing.T, w *Workspace, mappings []projectconfig.ProtectedFile, book *manifest.Manifest) (projectconfig.Project, string) {
	t.Helper()
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := projectconfig.Recipients{Version: projectconfig.RecipientsVersion, Members: []projectconfig.Member{{
		ID: "alice", Name: "Alice", Recipient: identity.CanonicalRecipient(),
	}}}
	typed, err := recipients.Validate()
	if err != nil {
		t.Fatal(err)
	}
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = append([]projectconfig.ProtectedFile(nil), mappings...)
	project = project.Canonical()
	projectData, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	recipientData, err := recipients.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteControl(t.Context(), "config.yaml", projectData); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteControl(t.Context(), "recipients.yaml", recipientData); err != nil {
		t.Fatal(err)
	}
	if book != nil {
		writeStatusManifest(t, w, *book)
	}
	ignoreExisting, ignoreExists, err := readOptionalRoot(w.Root, ".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	ignoreData, err := gitignore.Render(ignoreExisting, project)
	if err != nil {
		t.Fatal(err)
	}
	attributeExisting, attributeExists, err := readOptionalRoot(w.Root, ".gitattributes")
	if err != nil {
		t.Fatal(err)
	}
	attributeData, err := gitattrs.Render(attributeExisting, project)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteConfigured(t.Context(), ".gitignore", ignoreData, ignoreExisting, ignoreExists, safefile.PublicData); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteConfigured(t.Context(), ".gitattributes", attributeData, attributeExisting, attributeExists, safefile.PublicData); err != nil {
		t.Fatal(err)
	}
	return project, typed.Digest().Hex()
}

func writeStatusManifest(t *testing.T, w *Workspace, book manifest.Manifest) {
	t.Helper()
	data, err := book.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteControl(t.Context(), "manifest.yaml", data); err != nil {
		t.Fatal(err)
	}
}

func trustStatusMappings(t *testing.T, w *Workspace, project projectconfig.Project) {
	t.Helper()
	state := localstate.Empty()
	state.TrustedMappingsSHA256 = project.MappingDigest().Hex()
	state.TrustedRetainedSafetySHA256 = project.RetainedSafetyDigest().Hex()
	if err := localstate.Save(t.Context(), w.Repo.GitSealDir(), &state); err != nil {
		t.Fatal(err)
	}
}
