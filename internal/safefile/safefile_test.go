package safefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/raydalsayf/gitseal/internal/digest"
	"github.com/raydalsayf/gitseal/internal/pathpolicy"
)

func TestRootReadAndHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := pathpolicy.Parse("a")
	file, err := root.OpenRead(p)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := HashExactFile(file, 10)
	if err != nil || got != digest.Bytes([]byte("hello")) {
		t.Fatalf("HashExactFile = %s, %v", got.Hex(), err)
	}
}

func TestPublicCandidatePublication(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := pathpolicy.Parse("out.age")
	candidate, err := root.NewCandidate(p, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	if _, err := candidate.Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if candidate.Sum() != digest.Bytes([]byte("ciphertext")) {
		t.Fatal("candidate hash mismatch")
	}
	if err := candidate.Publish(t.Context(), false); runtime.GOOS == "windows" {
		if !errors.Is(err, ErrSafePublicationUnavailable) {
			t.Fatalf("Windows publication error = %v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(dir, "out.age")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed publication made destination visible: %v", statErr)
		}
		if abortErr := candidate.Abort(); !errors.Is(abortErr, ErrIdentityBoundRemovalUnavailable) {
			t.Fatalf("Windows residue cleanup error = %v", abortErr)
		}
		secret, err := root.NewCandidate(p, SensitiveData)
		if err == nil {
			_ = secret.Abort()
			t.Fatal("sensitive Windows candidate unexpectedly succeeded")
		}
		residues, residueErr := root.TemporaryResidues(2)
		if residueErr != nil || len(residues) != 1 {
			t.Fatalf("Windows residue result = %v, %v", residues, residueErr)
		}
		return
	} else if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.age"))
	if err != nil || string(data) != "ciphertext" {
		t.Fatalf("published data = %q, %v", data, err)
	}
}

func TestHashExactLimit(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, _ = file.Write(bytes.Repeat([]byte{'x'}, 4))
	if _, err := HashExactFile(file, 3); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestOpenRootRequiresAbsolutePath(t *testing.T) {
	if _, err := OpenRoot("relative"); err == nil {
		t.Fatal("relative root path accepted")
	}
}

func TestPublishCreateIfAbsentPreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	if err := os.WriteFile(filepath.Join(dir, destination.String()), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	_, _ = candidate.Write([]byte("replacement"))
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), false); err == nil {
		t.Fatal("create-if-absent publication overwrote an existing destination")
	}
	data, err := os.ReadFile(filepath.Join(dir, destination.String()))
	if err != nil || string(data) != "existing" {
		t.Fatalf("destination changed to %q: %v", data, err)
	}
}

func TestPublishRefusesDestinationCreatedAfterCandidate(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	_, _ = candidate.Write([]byte("candidate"))
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, destination.String()), []byte("racing creator"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), true); err == nil {
		t.Fatal("replacement overwrote a destination created after candidate setup")
	}
	data, err := os.ReadFile(filepath.Join(dir, destination.String()))
	if err != nil || string(data) != "racing creator" {
		t.Fatalf("racing destination changed to %q: %v", data, err)
	}
}

func TestPublishRefusesDestinationIdentitySwap(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	destinationName := filepath.Join(dir, destination.String())
	if err := os.WriteFile(destinationName, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	_, _ = candidate.Write([]byte("candidate"))
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(dir, "displaced")
	if err := os.Rename(destinationName, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinationName, []byte("replacement object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), true); err == nil {
		t.Fatal("replacement accepted a swapped destination identity")
	}
	data, err := os.ReadFile(destinationName)
	if err != nil || string(data) != "replacement object" {
		t.Fatalf("replacement object changed to %q: %v", data, err)
	}
}

func TestPublishRefusesDestinationBytesChangedInPlace(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	destinationName := filepath.Join(dir, destination.String())
	if err := os.WriteFile(destinationName, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	_, _ = candidate.Write([]byte("candidate"))
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinationName, []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), true); err == nil {
		t.Fatal("replacement accepted in-place destination mutation")
	}
	data, err := os.ReadFile(destinationName)
	if err != nil || string(data) != "mutated" {
		t.Fatalf("mutated destination changed to %q: %v", data, err)
	}
}

func TestPublishReplacementReconcilesPriorDestination(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	if err := os.WriteFile(filepath.Join(dir, destination.String()), []byte("prior"), 0o644); err != nil {
		t.Fatal(err)
	}
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Abort()
	if _, err := candidate.Write([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), true); err != nil {
		data, readErr := os.ReadFile(filepath.Join(dir, destination.String()))
		if readErr != nil || string(data) != "prior" {
			t.Fatalf("failed replacement changed prior data to %q: %v (publish: %v)", data, readErr, err)
		}
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, destination.String()))
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement data = %q, %v", data, err)
	}
	residues, err := root.TemporaryResidues(2)
	if err != nil || len(residues) != 0 {
		t.Fatalf("replacement residues = %v, %v", residues, err)
	}
}

func TestCandidatePathSwapFailsClosed(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination, _ := pathpolicy.Parse("out.age")
	candidate, err := root.NewCandidate(destination, PublicData)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = candidate.Write([]byte("candidate"))
	if err := candidate.FlushClose(); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(dir, filepath.FromSlash(candidate.temporary))
	displaced := temporary + ".displaced"
	if err := os.Rename(temporary, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, []byte("attacker"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Publish(t.Context(), false); err == nil {
		t.Fatal("candidate publication accepted a replaced temporary pathname")
	}
	if err := candidate.Abort(); err == nil {
		t.Fatal("candidate cleanup removed a replaced temporary pathname")
	}
	data, err := os.ReadFile(temporary)
	if err != nil || string(data) != "attacker" {
		t.Fatalf("replacement temporary changed to %q: %v", data, err)
	}
}

func TestOpenReadRejectsFinalLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := pathpolicy.Parse("link")
	if _, err := root.OpenRead(p); err == nil {
		t.Fatal("final-path link accepted")
	}
}

func TestOpenReadRejectsHardLinkedFile(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	if err := os.WriteFile(first, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(dir, "second")); err != nil {
		t.Skipf("hard-link creation unavailable: %v", err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := pathpolicy.Parse("first")
	if _, err := root.OpenRead(p); err == nil {
		t.Fatal("multiply-linked file accepted")
	}
}

func TestTemporaryResidueLimitCountsOnlyResidues(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, pathpolicy.ReservedTemporaryPrefix+"owned"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := root.TemporaryResidues(1)
	if err != nil || len(got) != 1 {
		t.Fatalf("TemporaryResidues = %v, %v", got, err)
	}
}

func TestInvalidSensitivityRejected(t *testing.T) {
	root, err := OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p, _ := pathpolicy.Parse("out")
	if _, err := root.NewCandidate(p, Sensitivity(255)); err == nil || errors.Is(err, os.ErrExist) {
		t.Fatalf("invalid sensitivity result = %v", err)
	}
}
