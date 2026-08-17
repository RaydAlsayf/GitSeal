# GitSeal V1 implementation status

Snapshot: 2026-08-17

Status: functional, security-gated pre-alpha; **not a release candidate, not
production-ready, and not approved for real secrets**.

GitSeal is no longer scaffolding. The worktree contains a cross-platform Go CLI,
strict schemas, native-hybrid age integration, synchronization logic, Git and
exact-tree validation, tests, documentation, and review-only CI configuration.
It also contains deliberate refusals where the required filesystem or trust
boundary cannot yet be enforced safely.

There is currently **no supported operating system on which the complete
protect, update, synchronize, and restore workflow is available end to end**.
On Linux and macOS, replacing an existing destination is disabled and the
current lock/local-state protocol refuses before mutation. On Windows, all
publication plus sensitive identity, local-state, and lock operations are
disabled. These refusals are release blockers, not optional compatibility
limitations.

## Release classification

| Classification | Current result |
| --- | --- |
| Design and implementation review | Substantial implementation exists; independent implementation-focused approval is incomplete |
| Developer preview with synthetic data | Available for read-only checks and selected fail-closed experiments |
| Public pre-release binary | Not supported by the current publication pipeline |
| Release candidate | No |
| Production use or real credentials | No |

Passing a unit test or completing an age round trip does not establish the
filesystem, GitHub, identity-recovery, or release-supply-chain guarantees needed
for production use.

## Command inventory

| Command | Implemented behavior | Current boundary |
| --- | --- | --- |
| `init` | Discovers a non-bare worktree, creates or preserves strict metadata, manages deterministic ignore/attribute blocks, and previews an exact legacy project-trust migration | POSIX and Windows lock/publication gates block the mutating workflow; migration preview remains zero-write |
| `identity create/use/show` | Generates a runtime native hybrid identity, validates its final path and permissions, derives only public output, and performs a production-engine self-test | Windows identity storage fails closed; Unix still needs native filesystem and recovery-drill evidence |
| `member add/remove/list` | Uses canonical recipients and full fingerprints, deterministic membership, locked updates, and stale-artifact reporting | Human identity-to-recipient verification remains an external ceremony; mutation inherits platform publication/lock blockers |
| `protect` | Checks mapping and recipient trust, acting-identity membership, tracked/HEAD exposure, paths, effective ignore/attributes, then plans mapping/artifact publication | Cannot complete the documented workflow on any supported OS under the current publication gates |
| `unprotect` | Previews and revalidates the exact post-operation project, preserves plaintext/ciphertext, pins retained safety separately, and supports exact later release of a retained orphan | Publication/lock blockers prevent end-to-end mutation; compatibility and native review remain open |
| `encrypt [FILE] [--all]` | Streams exact hashes; includes changed, missing, manifest-mismatched, and recipient-stale artifacts; preflights the full set; validates native stanza shape/count; and authenticates the candidate header | Replacing an existing artifact is disabled on Unix; Windows and platform lock/state gates block the normal operation |
| `decrypt [FILE] [--all]` | Requires manifest consistency or explicit recovery, exact unfamiliar-ciphertext consent, and whole-set payload authentication through EOF before first publication; there is no plaintext-to-stdout path | Existing plaintext replacement is disabled on Unix; all sensitive publication fails closed on Windows |
| `sync` | Classifies and preflights the selected set, rebinds consent to exact ciphertext under lock, and applies the baseline state machine | Any unsafe item fails; mutation of more than one mapping is deliberately refused, so an exact file is required until a transaction protocol exists |
| `status [--json]` | Produces deterministic artifact states and versioned schema-1 JSON; successfully reported conflict/stale/incoming states are not command failures | A consistent multi-file snapshot requires the conservative local lock, which currently refuses before mutation on POSIX and Windows |
| `doctor [--full-decrypt] [--history]` | Checks schemas, policy, identity, manifests, headers, payloads, residues, hooks, and a bounded local history scope | A clean result is not a no-leak claim; native filesystem and remote-host scope remain outside the result |
| `verify --source TREE` | Performs identity-free exact-tree validation in worktree or bare repositories with isolated committed ignore/attribute evaluation | Candidate implementation exists, but no trusted external validator is provisioned or pinned in required CI |
| `hook install/remove/run` | Runs exact-active-index Tier 1 and mandatory impacted Tier 2 validation for pre-commit and pre-merge-commit | New installation fails closed on Windows; removal of a present managed hook fails closed on every platform; hooks remain local, bypassable, and uncloned |
| `version` | Reports version, source, compatibility ranges, and Go metadata, including JSON | Development builds legitimately report an unknown source revision; that is unacceptable for a release artifact |

There is no classical, SSH, passphrase, plugin, general-recipient, KMS, SaaS,
GUI, telemetry, plaintext-to-standard-output, automatic Git mutation, or
automatic secret-conflict resolution path.

## Implemented security foundations

- Bounded YAML parsing uses the maintained `go.yaml.in/yaml/v3` module behind
  byte, document, depth, alias, anchor, tag, merge-key, duplicate-key, scalar,
  unknown-field, count, and semantic validation.
- Recipient, recipient-set, membership-policy, active-mapping, and retained-
  safety digests are domain-separated, length framed, deterministic, and
  covered by committed golden vectors. Project/state schemas 2 separate active
  and retained trust; version 1 is migration-only.
- The V1 path profile rejects traversal, volume syntax, Git administration,
  `.gitseal` internals, device names, reserved `.gitseal.tmp.*` components,
  nonportable characters, case-fold collisions, links/reparse points, hard-link
  aliases, and observed filesystem crossings.
- File access is rooted and identity checked. Candidates use exclusive random
  reserved names, exact streaming hashes, restrictive Unix permissions, flush
  checks, and post-publication reconciliation. No truncation or cross-volume
  copy/delete fallback is used.
- The age boundary accepts only concrete canonical native
  ML-KEM-768/X25519 hybrid recipients from official `filippo.io/age` APIs.
  It bounds native stanza type/count/shape, enforces acting-identity membership,
  authenticates candidate headers, and consumes decryption through EOF.
- Repository recipient, membership, active-mapping, and retained-safety changes
  require separately scoped exact local trust. Each mutating CLI plan also
  binds an ephemeral SHA-256 snapshot of the complete canonical project and
  revalidates raw project/recipient/manifest bytes before publication.
- The synchronization implementation uses exact plaintext and ciphertext
  digests rather than timestamps, performs whole-selection preflight, refuses
  unmerged/conflicting states, and separates exact incoming-ciphertext consent
  from generic force or trust flags.
- Git is resolved once outside repository-controlled paths, invoked without a
  shell using bounded arguments/output/time, and runs with prompts, pagers,
  replacement objects, and repository-selection/config-injection variables
  disabled. Active-index and exact-tree code treats object IDs as opaque,
  canonicalizes hook cwd, validates inherited index locations, and preserves
  skip-worktree/assume-unchanged flags.
- Exact index/tree validation checks modes, schemas, managed blocks, effective
  ignore/attributes, tracked plaintext, reserved temporaries, LFS pointers,
  manifests, digests, recipient staleness, native header structure, and complete
  checksum-valid native hybrid private-identity tokens. Relevant index entries
  carrying skip-worktree or assume-unchanged bits are rejected. Retained orphan
  ciphertext permits only a bounded 1..32 historical native stanza count and
  does not claim current recipient freshness.
- Terminal output quotes hostile text; JSON uses real encoders and versioned
  schemas. Git diagnostics sanitize ASCII and C1 Unicode controls. Plaintext
  hashes, private identities, plaintext, and age file keys are not normal
  diagnostic output.

## Deliberate fail-closed platform boundaries

### Linux

Create-if-absent publication uses handle-bound same-directory
`renameat2(RENAME_NOREPLACE)`. Existing-destination replacement returns an
error before mutation because the independently reviewed exchange/cleanup
design could delete or lose a raced editor object. No native ext4/XFS/Btrfs
race, crash, or durability matrix has been completed for this worktree.
Exact-inode removal cannot be expressed by the current portable protocol, so
local-state writes and lock acquisition fail before filesystem mutation.

### macOS

Create-if-absent publication uses handle-bound same-directory
`renameatx_np(RENAME_EXCL)`. Existing-destination replacement has the same
deliberate refusal. Darwin process-start and boot identity acquisition is
implemented, but only cross-compiled; it has not been run on macOS. No native
APFS race, crash, permission, or durability evidence exists.
Local-state writes and lock acquisition have the same pre-mutation refusal as
Linux.

### Windows

The code contains fixed-volume NTFS, DACL, alternate-data-stream, token/profile,
file-identity, and partial-replacement reconciliation primitives and tests.
They are not a complete publication implementation. All public publication now
refuses before making a destination visible because conditional identity-bound
replacement and temporary cleanup are unavailable. Sensitive candidate
creation refuses before allocation; plaintext, private identities, local state,
and locks also fail closed. New managed-hook installation fails closed. Real
unsandboxed NTFS testing must establish containing-directory and
destination identity, restrictive DACL-at-creation, stream policy,
handle-relative same-volume publication, contention behavior, every documented
`ReplaceFileW` partial-failure state, reconciliation, final permissions, and
unsupported-filesystem refusal.

The Windows token/profile helper and identity location now resolve known folders
using an explicit process token and reject an effective-token mismatch. That
read-only hardening does not qualify the write boundary. A Windows build or unit
test pass is not a substitute for real NTFS tests.

## Retained trust resolution and open lock contradiction

### Retained-safety persistence

The source design now resolves the active-only mapping-digest conflict without
changing that digest's v1 framing. Project schema 2 and local state schema 2 add
a separate canonical retained-safety digest and trust pin. Exact confirmation is
scoped independently from mapping trust, and `unprotect` binds the post-operation
project/retained digests. Legacy project/state schema 1 is accepted only by the
explicit `init --upgrade-project-trust` flow; configuration is published before
local state so old strict tools fail safely, and a state-write failure is
repairable by rerunning the same exact acceptance.

Golden, strict-parser, downgrade, migration-preservation, exact-acceptance, and
retained-orphan planning tests exist. End-to-end successful migration cannot be
run while every supported platform's lock/publication boundary is deliberately
closed, and the schema transition still requires independent compatibility and
security review.

### POSIX lock release and stale recovery

Locks bind a random token, PID, OS process-start identity, and boot/session
identity; acquisition is exclusive and release reopens and rechecks the exact
record and file identity. On POSIX pathname APIs, however, a hostile local
process can substitute the final basename between the last identity check and
`unlink`. The portable API cannot atomically express “unlink this exact open
file identity.” `RemoveOpened`, lock acquisition, and local-state writes now
refuse before that mutation rather than executing a check-then-unlink sequence.
This containment blocks normal commands and is not a completed lock design.

Automatic stale-lock recovery is not implemented. Unknown, permission-denied,
or otherwise ambiguous locks remain in place and require manual review; a live
record cannot be overridden. Conservative refusal avoids deleting another
process's lock but can leave a repository blocked.

## History diagnostic scope and bounds

`doctor --history` performs two local checks with Git replacement objects
disabled:

1. It reports configured plaintext path names found in objects reachable from
   local `--all` refs.
2. It enumerates at most 100,000 unique reachable object IDs, filters exact blob
   objects in one bounded batch, and streams every selected blob through the
   native hybrid private-identity scanner. Each blob is limited to 1 GiB, the
   aggregate content budget is 8 GiB, ordinary Git commands use a 15-second
   timeout, and the batch consumer uses a 60-second timeout.

Exceeding a count, byte, parser, subprocess, or time budget is a diagnostic
failure, not a clean result. Even a complete clean scan covers only reachable
objects selected by local `--all` refs. It does not cover omitted remote or
pull-request refs, reflog-only or unreachable objects, forks, server caches,
external clones, backups, snapshots, or copies.

## GitHub and release-supply-chain status

- Candidate validation, CodeQL, exact-tree, and review-build workflows are
  present with least-privilege permissions and third-party Actions pinned to
  full commit SHAs.
- The exact-tree workflow deliberately exits nonzero. No independently reviewed
  immutable validator artifact or trusted validator GitHub App is provisioned;
  pull-request code must never validate itself as the security boundary.
- The ordinary candidate and CodeQL workflows include `merge_group` triggers,
  but GitHub has not executed or evidenced them on an actual merge-group SHA.
  They must not become merge-queue requirements until their exact emitted check
  names, source Apps, and `head_sha` values are observed and verified.
- The release workflow creates short-lived review artifacts only and then
  deliberately fails. It cannot create a tag, GitHub release, SBOM, provenance,
  attestation, signature, or published binary and has no write permission.
- Repository rulesets, required-check source binding, protected release
  environment, private vulnerability reporting, and security-feature settings
  have not been changed or verified during this implementation pass. The exact
  required target state and read-only verification steps are documented in
  [Repository Security Settings](docs/repository-security-settings.md).
- The local Git repository has no commits on its unborn `master` branch and no
  configured remote; all project files are untracked. It is not evidence of the
  live GitHub repository's `main` branch or settings.
- No authenticated signed release, normalized archive set, independently
  reproduced artifact set, SBOM, or verifiable provenance exists.
- The official Go 1.26.6 Windows archive matched the SHA-256 published by
  `go.dev`, and the module, workflow, and reproducible-build pins were raised
  from Go 1.26.5. Fresh `govulncheck` reports zero symbol or imported-package
  vulnerabilities. Its one module-only result is the unimported
  `golang.org/x/crypto/openpgp` package; GitSeal has no OpenPGP feature path.

## Validation evidence and its limits

The final proposed source snapshot was exercised on Windows NT 10.0.26200.0
with portable Go 1.26.6, Git 2.54.0.windows.1, offline production modules, and
invocation-owned caches:

- `gofmt -l cmd internal` returned no files; `go test -count=1 -timeout=5m
  ./...`, `go vet ./...`, and `go mod verify` all passed.
- Focused native-hybrid round-trip, randomized-encryption,
  corruption/truncation, Windows security/reconciliation/ADS/DACL, and process
  identity tests passed in the sandboxed Windows environment.
- All five fuzz targets completed for five seconds: header inspection had only
  3 executions; path parsing 7,070; strict YAML 23,462; project parsing 19,522;
  and Windows stream metadata 171,891.
- The CLI and all 18 test-bearing package binaries compiled for Windows, Linux,
  and macOS on amd64 and arm64: 6 CLI builds and 108 test binaries. Only the
  Windows/amd64 test binaries were executed.
- `gitseal version --json` and `gitseal --help` passed. Two consecutive
  Windows/amd64 review builds were byte-identical with SHA-256
  `c69c9577e044828fc7933417a0d64a5351137733c960227b3cfe1539d32d9da9`.
- Pinned actionlint 1.7.12 passed after the final workflow edits. Markdown
  fences and internal links passed for all 18 Markdown files. An isolated
  alternate Git index checked all 129 proposed untracked files with `git diff
  --cached --check`; the final result passed. A conservative static
  secret/private-key pattern scan found no complete credential.

Eleven tests were explicitly skipped on Windows: two optional external-age
fixtures, five deliberate Windows sensitive-state/lock refusals, three hook
link tests requiring unavailable privilege or link-count evidence, and one
safefile symlink test requiring unavailable privilege. The official `age` CLI
was unavailable, so interoperability with that external executable was not
rerun. A previous intermediate snapshot completed both interoperability
directions and a broad Windows Git command matrix, but those results are not
fresh execution evidence for every final file. The fresh network-backed
`govulncheck` result above applies to the final Go 1.26.6-pinned tree.

Use these evidence categories literally:

| Category | Meaning |
| --- | --- |
| Locally verified | Executed on this Windows host against the stated source snapshot |
| Compile-only verified | Cross-compiled successfully; no target-OS behavior was exercised |
| CI-configured | Workflow text exists; GitHub did not execute it in this local run |
| Requires another OS | Needs a native Linux or macOS runner/filesystem |
| Requires human review | Tests alone cannot approve the trust boundary |

`go test -race ./...` is unavailable in the portable Windows environment because
`CGO_ENABLED=0` and the probe failed with `-race requires cgo`. Linux race CI is
configured but was not executed here. Linux and macOS build/test-binary checks
are compile-only. No cross-compilation result is described as a native platform
test, and sandboxed Windows metadata tests are not unsandboxed NTFS
qualification.

## Major specification and accepted-finding mapping

| Specification / accepted findings | Implementation and tests | Remaining qualification |
| --- | --- | --- |
| Sections 4–5; GS-A-05, A-06, A-10–A-12, A-15–A-17, C-04, C-05, C-10 | `strictyaml`, `digest`, `pathpolicy`, `projectconfig`, `manifest`, `gitignore`, `gitattrs`, `gitrepo`; schema-2 migration, retained-digest golden, parser, path, rooted, Git-policy tests | Native filesystem race/crash matrix, successful gated migration, and independent schema review remain open |
| Sections 6–8; GS-A-06, A-09, A-12, A-13, B-03–B-05, C-01–C-03, C-09 | `agefile`, `identity`, `app/trust.go`, member/crypto/scanner/interoperability tests | Windows identity boundary, independent crypto review, and recovery drill remain open |
| Sections 9–10; GS-A-01, A-03–A-05, A-14, A-16–A-18, B-01, B-02, C-06, C-07 | `safefile`, `localstate`, `status`, app crypto/sync/protect orchestration and failure tests | Unix replacement, Windows Phase 0, POSIX lock unlink, stale recovery, and native fault injection remain open |
| Sections 11–13; GS-A-02, A-07, A-08, A-10, A-11, A-15, A-18 | CLI dispatch, `treeverify`, hooks, exact-index/tree and Git-matrix tests | Hook install/removal limits and trusted merge/merge-group validator remain open |
| Sections 14–17; GS-D-01–D-09, GS-F-01–F-12 | Bounded subprocess/output, safe terminal formatting, doctor/history, docs and adversarial tests | Complete three-OS, race, canary, benchmark, recovery, and human-review evidence remains open |
| Sections 18–20; GS-E-01–E-06 | Lowercase module, prescribed packages, pinned review workflows, deterministic build scripts, notices and release docs | Repository controls, trusted publisher, normalized artifacts, SBOM, provenance, signing, and independent reproduction remain open |

## Release blockers

1. A reviewed existing-destination replacement primitive and native
   race/crash/durability tests are missing on Linux and macOS.
2. The complete handle-rooted Windows NTFS sensitive-publication, identity,
   public control/ciphertext publication, local-state, lock, DACL, stream,
   contention, and partial-failure boundary is unavailable and unproven.
3. POSIX exact-identity lock unlink and conservative stale-lock recovery do not
   meet the complete hostile-filesystem requirement; commands now refuse before
   mutation, so the ordinary workflow is unavailable.
4. Retained-safety schema/trust migration is implemented and specified, but a
   successful end-to-end migration cannot run behind the platform gates and the
   compatibility/security transition lacks independent human approval.
5. Hook installation/removal is incomplete, and hooks remain bypassable and
   non-distributed by design.
6. No trusted external exact-tree validator checks actual pull-request merge
   and merge-group trees, and current repository rules/settings are not
   evidenced.
7. Native Linux, APFS, and unsandboxed NTFS adversarial testing, supported Git
   floor/latest testing, race coverage, stable resource benchmarks, and
   implementation-focused cryptography/Git/filesystem/Windows review remain.
8. No protected release publisher, signed source tag, normalized artifacts,
   checksums, SBOM, provenance attestations, independently reproducible build
   evidence, or authenticated release exists.
9. Private vulnerability reporting and the second-person identity
   backup/restoration and incident-response drills are not evidenced.

## Safest next action

Keep every refusal in place. First obtain focused human review of the project/
state schema-2 retained-safety migration and a new POSIX lock protocol, then run
native create-only publication and race tests on Linux/APFS. In parallel,
implement and fault-test the Windows handle-rooted writer in a normal
unsandboxed NTFS user profile. Only after those foundations pass native tests
should the project provision an immutable external exact-tree validator,
activate the documented repository rules, and build a non-publishing release
candidate for independent reproduction and review.
