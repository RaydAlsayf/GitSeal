# GitSeal

**Git-native encrypted file sharing for development teams.**

GitSeal is an open-source command-line tool that helps a team keep sensitive
project files available to authorized developers without committing the
plaintext to Git. Developers work with normal local files, while Git stores an
encrypted `age` artifact and a small set of public policy files.

> [!WARNING]
> GitSeal V1 is a security-gated **pre-alpha**. Use it only in a disposable
> repository with synthetic data. It is not production-ready and must not be
> trusted with real secrets. An independent review found that replacing an
> existing file safely is not yet proven on Unix, so those replacements fail
> closed; POSIX local state and locking also refuse before mutation because an
> exact acquired inode cannot be removed atomically with the current protocol.
> On Windows, all publication plus sensitive identity/local-state operations
> fail closed pending the required NTFS/DACL/ADS implementation and real
> unsandboxed testing. The complete protect/update/restore workflow is therefore
> not currently available on any platform.

## Why GitSeal?

Teams often need to share files such as local development configuration,
certificates, or test fixtures whose plaintext does not belong in source
control. GitSeal is designed to make that workflow explicit and reviewable:

- **Git stays the transport.** Encrypted artifacts travel through the same
  branch, review, and pull workflow as the rest of the project.
- **Plaintext stays local.** GitSeal never decrypts a protected file to standard
  output and manages ignore rules to reduce accidental staging risk.
- **Access is team-oriented.** A project records an auditable public recipient
  set, while every private identity remains outside the repository.
- **Changes are conservative.** Unfamiliar incoming ciphertext, mapping changes,
  stale recipients, tracked plaintext, and merge conflicts require an explicit
  decision or are refused.
- **Validation is built in.** Status, diagnostics, hooks, and exact-tree
  verification expose problems before a change is shared.

GitSeal V1 uses the standard `age` file format through the official Go library.
Its only supported recipient type is the native ML-KEM-768/X25519 hybrid. V1
does not support classical, SSH, passphrase, plugin, KMS, SaaS, GUI, or telemetry
integrations.

## Why the pre-alpha warning exists

Encryption is only one part of safely managing a secret file. GitSeal must also
prove that it is reading the intended Git state, publishing to the intended
filesystem object, preserving an editor's concurrent changes, protecting local
identities, and validating the exact tree that will be merged. A failure in any
one of those boundaries can expose or destroy data even when the cryptography
itself is correct.

This warning remains because several mandatory gates do not yet have objective
evidence:

- Existing-destination publication on Linux and macOS is disabled after review
  found a final pathname cleanup race. Create-if-absent uses atomic no-replace
  rename, but native ext4/APFS testing has not run.
- POSIX lock release cannot atomically remove a name only if it still identifies
  the acquired inode. Lock and local-state mutation therefore fail before any
  write; conservative stale-lock recovery remains unimplemented.
- The complete Windows handle-rooted NTFS writer, protected DACL-at-creation,
  alternate-stream validation, contention handling, and reconciliation path is
  not implemented or proven under a normal unsandboxed user profile. Public
  publication also refuses because its prior replacement/cleanup proof was
  raceable.
- Local hook deletion is unavailable without an identity-bound removal
  primitive; new hook installation also fails closed on Windows. Hooks remain
  bypassable in every case.
- Trusted exact-tree CI still needs a separately reviewed immutable validator.
  The supplied workflow deliberately fails instead of trusting pull-request
  code to validate itself.
- Native Linux, macOS, and unsandboxed Windows fault/race testing, independent
  human review, recovery drills, and the full release supply-chain gate remain
  incomplete.

Failing closed is intentional: an unavailable command is safer than a command
that reports success without enforcing its security promise.

## How it works

```text
Edit a local plaintext file
          |
          v
    gitseal encrypt
          |
          v
Commit ciphertext + public policy -----> Teammate pulls
                                               |
                                               v
                                         gitseal sync
                                               |
                                               v
                                  Plaintext restored locally
```

For example, protecting `demo-secret.bin` creates
`demo-secret.bin.age`. The plaintext remains a local working file; the
ciphertext, recipient policy, mapping, manifest, and managed Git rules are the
reviewable repository state. GitSeal does not run `git add`, commit, push, or
rewrite history for you.

## Quick start: safe developer preview

The build and read-only checks below are safe for a developer preview. The
later command sequence explains GitSeal's intended workflow, but this snapshot
will stop when it reaches an unavailable publication or platform boundary. Do
not bypass that refusal. Use **synthetic test data only**.

### 1. Install the prerequisites and build

You need Go 1.26.6 or a later project-reviewed security patch, plus Git 2.43 or
later.

```text
git clone https://github.com/RaydAlsayf/GitSeal.git
cd GitSeal
go mod verify
go test ./...
go build -trimpath -o gitseal ./cmd/gitseal
./gitseal version
```

On Windows, build the executable with:

```text
go build -trimpath -o gitseal.exe ./cmd/gitseal
gitseal.exe version
```

A local build is not an authenticated release and passing tests does not remove
the pre-alpha security limitations. Place the resulting executable on your
`PATH`, or substitute its absolute path in the commands below.

### 2. Run read-only checks

From the GitSeal source clone:

```text
gitseal version --json
gitseal verify --source HEAD
```

`verify` checks the selected immutable tree and can also run against a bare
repository. A clean local result is diagnostic evidence, not a trusted CI or
release decision.

### 3. Understand the intended project workflow

From a directory outside the GitSeal source tree, run GitSeal inside a new
repository that contains no real credentials:

```text
git init gitseal-demo
cd gitseal-demo
gitseal init
```

`gitseal init` creates the project policy and managed Git protection files. It
does not create a commit. In the current security-gated snapshot it may refuse
when an existing managed file would need replacement.

### 4. Create and select a test identity

```text
gitseal identity create --name alice
gitseal identity use alice
gitseal identity show
```

`identity show` prints the public recipient, its full fingerprint, and the
private identity file's location. It never prints the private identity itself.
Back up a real identity through a separately tested offline process before
depending on it; GitSeal does not create a backup.

### 5. Add the public recipient

Compare the complete fingerprint through an authenticated channel that is
independent of the repository, then provide the exact displayed values:

```text
gitseal member add --id alice --name "Alice" --recipient "<PUBLIC_RECIPIENT>" --accept-fingerprint "<FULL_FINGERPRINT>"
gitseal member list --full --identity alice
```

The fingerprint check records your explicit trust decision. It does not prove
who owns the recipient if both values came from the same untrusted source.

### 6. Protect a synthetic file

Create `demo-secret.bin` with non-sensitive test content, then run:

```text
gitseal protect demo-secret.bin --accept-recipients --accept-mapping-changes --accept-retained-safety-changes
gitseal status
gitseal doctor --full-decrypt
```

These mutating commands describe the V1 interface but are not expected to
complete end to end while the publication gates above remain closed.

Review exactly what Git will store:

```text
git status --short
git check-ignore -v -- demo-secret.bin
git diff -- .gitseal/config.yaml .gitseal/recipients.yaml .gitseal/manifest.yaml .gitignore .gitattributes
git add .gitseal/config.yaml .gitseal/recipients.yaml .gitseal/manifest.yaml .gitignore .gitattributes demo-secret.bin.age
git commit -m "Protect synthetic demo file"
gitseal verify --source HEAD --require-project
```

Never stage `demo-secret.bin`, a `.gitseal.tmp.*` file, or an identity file.

If a repository was created with legacy project schema 1, first review the
displayed active mappings and both retained-safety lists:

```text
gitseal init --upgrade-project-trust
gitseal init --upgrade-project-trust --accept-retained-safety <EXACT_DISPLAYED_RETAINED_SAFETY_SHA256>
```

The preview exits without writing. The second form is the only migration path
to project schema 2/local-state schema 2, and it still fails closed while the
platform lock/publication boundary is unavailable.

### 7. Continue working

After editing the local plaintext, refresh its encrypted artifact:

```text
gitseal encrypt demo-secret.bin
```

After a reviewed recipient change, re-encrypt every stale artifact:

```text
gitseal encrypt --all --accept-recipient-changes
```

Encryption is randomized, so different ciphertext is expected even when the
plaintext did not change.

### 8. Restore files after pulling

An authorized teammate selects a local identity, reviews the repository change,
and synchronizes the working copy:

```text
gitseal identity use bob
gitseal status
gitseal sync --accept-mapping-changes --accept-retained-safety-changes demo-secret.bin
```

If GitSeal reports unfamiliar incoming ciphertext, compare the exact SHA-256
with the reviewed Git artifact before accepting it:

```text
gitseal sync --accept-incoming <EXACT_CIPHERTEXT_SHA256> demo-secret.bin
```

If both plaintext and ciphertext changed, GitSeal will not merge them or choose
a side automatically. Preserve both versions, review the conflict, and make an
explicit decision.

One `sync` invocation will not mutate more than one mapping. Name one exact file
for a restore or baseline action; an unscoped status may still classify the
whole project. This avoids reporting success after a later mapping leaves a
partial multi-file result.

## Command overview

| Command | Purpose |
| --- | --- |
| `gitseal init` | Create GitSeal project metadata and managed Git rules. |
| `gitseal identity create/use/show` | Create, select, and inspect a local hybrid identity. |
| `gitseal member add/remove/list` | Manage the project's public recipient set. |
| `gitseal protect` / `unprotect` | Add or remove a protected-file mapping without staging or committing. |
| `gitseal encrypt` | Refresh one artifact or all changed and recipient-stale artifacts. |
| `gitseal decrypt` | Restore an authorized plaintext file without writing it to stdout. |
| `gitseal sync` | Classify local/incoming state and perform only an accepted safe action. |
| `gitseal status` | Report mapping, trust, identity, policy, and synchronization state. |
| `gitseal doctor` | Run deeper repository, identity, cryptographic, and history diagnostics. |
| `gitseal verify --source TREE` | Validate an exact Git tree, including a bare repository. |
| `gitseal hook install/remove` | Manage local pre-commit and pre-merge-commit guards. |
| `gitseal version` | Print build and version information. |

Run `gitseal` to see the top-level command list. JSON output is available for
selected commands, including `status`, `sync`, `doctor`, `identity`, and
`version`.

## Local hooks and CI

Install local defense-in-depth hooks with:

```text
gitseal hook install
```

Hooks are not cloned with a repository and can be bypassed with `--no-verify`.
They are not a trusted CI boundary. New installation currently fails closed on
Windows, and removing a present managed hook fails closed on every platform
until identity-bound deletion is available. A separately reviewed validator
must inspect the exact candidate tree with `gitseal verify --source`; the
supplied pre-alpha exact-tree workflow deliberately fails closed until such a
validator is pinned. The required ruleset, expected check sources, merge-queue
behavior, release environment, and read-only audit procedure are defined in
[Repository Security Settings](docs/repository-security-settings.md); those
external controls have not been configured or verified by this worktree.

## Security boundaries and limitations

GitSeal is intentionally narrow. Understanding what it does **not** guarantee is
part of using it correctly:

- It encrypts whole opaque files; it does not partially encrypt or merge
  structured documents.
- It provides recipient confidentiality, not sender authentication or proof of
  recipient ownership.
- Removing a member does not revoke old commits, backups, or copied ciphertext.
  Rotate the underlying credential when revocation matters.
- Git metadata can still reveal protected paths, approximate sizes, change
  timing, and history.
- It cannot protect a compromised workstation, an authorized malicious
  recipient, editor backup files, or a lost and unbacked identity.
- Private identities are plaintext files protected by filesystem controls.
  Full-disk encryption and a tested offline recovery plan remain necessary.
- GitSeal does not provide secure deletion, complete memory erasure,
  full-disk-encryption detection, secret delivery to CI/production, or a
  replacement for a dedicated runtime secret manager.
- Randomized ciphertext can produce ordinary binary Git conflicts. GitSeal
  never resolves a secret merge conflict automatically.

See [Limitations](docs/limitations.md), the
[Threat Model](docs/threat-model.md), and [Security Policy](SECURITY.md) for the
complete boundary.

## Platform status

| Platform | Current pre-alpha status |
| --- | --- |
| Linux | Atomic create-if-absent is implemented; replacement, local state, and locks are disabled, and native filesystem/race testing is still required. |
| macOS | Atomic create-if-absent is implemented; replacement, local state, and locks are disabled, and native APFS/race testing is still required. |
| Windows | CLI builds and security primitives have unit coverage, but all publication, identities, local state, locks, and new hook installation fail closed pending the real-NTFS boundary. |

Cross-compilation is not equivalent to native testing. Exact evidence and
remaining release blockers are tracked in
[IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md).

## What production-ready would require

GitSeal can be considered for a production release only after all of the
following are complete and independently reviewed:

1. Safe existing-file publication and failure reconciliation on supported
   Linux filesystems and APFS, plus the complete handle-rooted NTFS boundary on
   Windows.
2. A reviewed exact-identity POSIX lock protocol with conservative stale-lock
   recovery and no check-to-unlink race.
3. Native adversarial tests on all three operating systems, including links,
   hard links, concurrent editors, antivirus/sharing contention, crashes,
   permission failures, and destination/directory replacement races.
4. A separately maintained and immutably pinned exact-tree validator enforced
   for pull-request merge commits, merge queues, and protected branches.
5. A release pipeline built from a verified signed tag in isolated
   environments, with normalized archives, reproducibility from two independent
   builders, checksums, SBOM, provenance/attestations, dependency review, and
   protected publication controls.
6. Independent cryptography, filesystem, Git, synchronization, Windows, and
   supply-chain approvals, plus tested identity backup/restoration, rotation,
   exposure, corruption, and interrupted-publication drills.
7. Resolution of every open blocker in
   [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md), with no security-
   critical success stub or undocumented fallback.

Until then, “tests pass” means only that the tested behavior matched the code;
it does not mean GitSeal is safe for real credentials.

## Documentation

- [Getting Started](docs/getting-started.md) — detailed pre-alpha evaluation
- [Architecture](docs/architecture.md) — package and trust-boundary design
- [Threat Model](docs/threat-model.md) — assets, adversaries, and guarantees
- [Identity Backup and Recovery](docs/identity-backup-recovery.md)
- [Credential Rotation and Incident Response](docs/incident-response.md)
- [Compatibility Policy](docs/compatibility.md)
- [Release Verification](docs/release-verification.md)
- [Repository Security Settings](docs/repository-security-settings.md)
- [Specification](SPECIFICATION.md) — normative V1 requirements
- [Security Review](SECURITY-REVIEW.md) and
  [Audit Disposition](AUDIT-DISPOSITION.md) — review findings and required gates

## Project status and contributing

GitSeal is under active pre-alpha development. A successful build or test run is
not evidence that its filesystem, Git, hook, CI, or cross-platform security
boundaries are complete. Before evaluating the project, read the current
[implementation status](IMPLEMENTATION-STATUS.md).

Security reports are welcome through the process in [SECURITY.md](SECURITY.md).
For development guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). GitSeal is licensed under the terms in
[LICENSE](LICENSE).
