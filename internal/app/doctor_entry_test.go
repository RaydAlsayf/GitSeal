package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raydalsayf/gitseal/internal/agefile"
	"github.com/raydalsayf/gitseal/internal/gitattrs"
	"github.com/raydalsayf/gitseal/internal/gitignore"
	"github.com/raydalsayf/gitseal/internal/manifest"
	"github.com/raydalsayf/gitseal/internal/projectconfig"
)

func TestDoctorHistoryScansReachablePrivateIdentityBlobs(t *testing.T) {
	clearDoctorGitEnvironment(t)
	directory := t.TempDir()
	runDoctorGit(t, directory, "init", "--quiet")
	if err := os.Mkdir(filepath.Join(directory, ".gitseal"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A malformed project exercises the diagnostic-open path and proves the
	// history scan does not depend on a usable identity or local state.
	writeDoctorFile(t, directory, ".gitseal/config.yaml", []byte("version: [\n"))
	recipients, err := projectconfig.EmptyRecipients().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/recipients.yaml", recipients)
	book, err := manifest.Empty().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/manifest.yaml", book)
	identity, err := agefile.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := identity.WritePrivate(&private); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, "historical-private.txt", private.Bytes())
	runDoctorGit(t, directory, "add", "--", ".gitseal/config.yaml", ".gitseal/recipients.yaml", ".gitseal/manifest.yaml", "historical-private.txt")
	runDoctorGit(t, directory, "-c", "user.name=GitSeal Test", "-c", "user.email=gitseal@example.invalid", "commit", "--quiet", "-m", "synthetic historical identity")
	if err := os.Remove(filepath.Join(directory, "historical-private.txt")); err != nil {
		t.Fatal(err)
	}
	runDoctorGit(t, directory, "add", "-u", "--", "historical-private.txt")
	runDoctorGit(t, directory, "-c", "user.name=GitSeal Test", "-c", "user.email=gitseal@example.invalid", "commit", "--quiet", "-m", "remove synthetic identity from current tree")

	report, err := DoctorAt(t.Context(), directory, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(report, "history_private_identity") || hasDiagnostic(report, "history_identity_scan_failed") || hasDiagnostic(report, "index_private_identity") {
		t.Fatalf("history diagnostics = %#v", report.Diagnostics)
	}
}

func TestDoctorAtReportsMalformedProjectInsteadOfFailingBeforeOutput(t *testing.T) {
	clearDoctorGitEnvironment(t)
	directory := t.TempDir()
	runDoctorGit(t, directory, "init", "--quiet")
	if err := os.Mkdir(filepath.Join(directory, ".gitseal"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/config.yaml", []byte("version: [\n"))
	recipients, err := projectconfig.EmptyRecipients().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/recipients.yaml", recipients)
	book, err := manifest.Empty().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/manifest.yaml", book)

	report, err := DoctorAt(t.Context(), directory, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(report, "workspace_open_failed") || !hasDiagnostic(report, "invalid_project_config") {
		t.Fatalf("malformed-project diagnostics = %#v", report.Diagnostics)
	}
}

func TestDoctorAtMalformedRecipientsStillReportsHeadPlaintext(t *testing.T) {
	clearDoctorGitEnvironment(t)
	directory := t.TempDir()
	runDoctorGit(t, directory, "init", "--quiet")
	if err := os.Mkdir(filepath.Join(directory, ".gitseal"), 0o700); err != nil {
		t.Fatal(err)
	}
	project := projectconfig.EmptyProject()
	project.ProtectedFiles = []projectconfig.ProtectedFile{{Source: "synthetic-secret", Encrypted: "synthetic-secret.age"}}
	config, err := project.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/config.yaml", config)
	writeDoctorFile(t, directory, ".gitseal/recipients.yaml", []byte("version: [\n"))
	book, err := manifest.Empty().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitseal/manifest.yaml", book)
	ignore, err := gitignore.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := gitattrs.Render(nil, project)
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorFile(t, directory, ".gitignore", ignore)
	writeDoctorFile(t, directory, ".gitattributes", attrs)
	writeDoctorFile(t, directory, "synthetic-secret", []byte("not a real credential\n"))
	runDoctorGit(t, directory, "add", "--", ".gitseal/config.yaml", ".gitseal/recipients.yaml", ".gitseal/manifest.yaml", ".gitignore", ".gitattributes")
	runDoctorGit(t, directory, "add", "-f", "--", "synthetic-secret")
	runDoctorGit(t, directory, "-c", "user.name=GitSeal Test", "-c", "user.email=gitseal@example.invalid", "commit", "--quiet", "-m", "synthetic fixture")

	report, err := DoctorAt(t.Context(), directory, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(report, "invalid_recipients") || !hasDiagnostic(report, "plaintext_in_head") {
		t.Fatalf("malformed-recipient diagnostics = %#v", report.Diagnostics)
	}
}

func hasDiagnostic(report DoctorReport, code string) bool {
	for _, finding := range report.Diagnostics {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func writeDoctorFile(t *testing.T, directory, relative string, data []byte) {
	t.Helper()
	name := filepath.Join(directory, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func runDoctorGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func clearDoctorGitEnvironment(t *testing.T) {
	t.Helper()
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_") {
			value, present := os.LookupEnv(key)
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if present {
					_ = os.Setenv(key, value)
				}
			})
		}
	}
}
