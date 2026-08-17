//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/raydalsayf/gitseal/internal/exitcode"
	"github.com/raydalsayf/gitseal/internal/gitrepo"
	"github.com/raydalsayf/gitseal/internal/localstate"
)

func TestRunRejectsBaselineAdvancedBeyondUnstagedArtifact(t *testing.T) {
	requireGit(t)
	clearGitEnvironment(t)
	fixture := newProjectFixture(t)
	newPlaintext := []byte("new secret not represented by the index artifact\n")
	newCiphertext := encrypt(t, fixture.identity, fixture.recipients, newPlaintext)
	writeFile(t, fixture.dir, ".env", newPlaintext)
	writeFile(t, fixture.dir, ".env.age", newCiphertext) // deliberately unstaged
	plainSum, cipherSum := sha256.Sum256(newPlaintext), sha256.Sum256(newCiphertext)
	repo, err := gitrepo.Discover(t.Context(), fixture.dir, gitrepo.DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state := localstate.Empty()
	state.Files[".env"] = localstate.FileBaseline{PlaintextSHA256: hex.EncodeToString(plainSum[:]), CiphertextSHA256: hex.EncodeToString(cipherSum[:])}
	if err := localstate.Save(t.Context(), repo.GitSealDir(), &state); err != nil {
		t.Fatal(err)
	}
	report, err := Run(t.Context(), fixture.dir, PreCommit)
	if err == nil || exitcode.Of(err) != exitcode.MissingIdentity || !report.Static.OK() {
		t.Fatalf("advanced baseline with unstaged artifact was not forced through Tier 2: %#v, %v", report, err)
	}
}
