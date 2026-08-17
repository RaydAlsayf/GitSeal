# GitSeal Pre-Implementation Security Review

**Review date:** 2026-08-13

**Scope:** Product model and normative V1 specification

**Implementation reviewed:** None; the repository does not yet contain product
code

## Assurance statement

No responsible review can guarantee that a security product has no security or
reliability issues. At this stage, the design has been strengthened against the
failure classes identified in this review and the independently verified
[audit disposition](AUDIT-DISPOSITION.md), but none of those controls is verified
until code, adversarial tests, supported-platform tests, release checks, and an
independent review pass.

Publishing this design for review is appropriate. Advertising GitSeal as safe
for production secrets is not appropriate yet.

The GitHub repository is public, but at the review time its `main` branch
contains only `LICENSE`. The README, specification, security review, and audit
disposition are untracked local files and are not yet published on GitHub. No
commit or push occurred during this review. The current MIT license should remain
the documented license unless the maintainer deliberately performs a reviewed
license change. The repository description is empty and should be filled before
announcing the project broadly.

## Expert review perspectives

The review applied these perspectives together:

- cryptographic protocol integration and key lifecycle;
- Git object, index, ignore, attribute, hook, and history behavior;
- Unix, macOS, and Windows filesystem safety;
- concurrent and crash-safe state machines;
- secure CLI and untrusted-input handling;
- Go dependency and toolchain security;
- open-source build and release supply-chain security;
- product scope, usability, recovery, and honest security claims.

## Material findings and design changes

| Finding | Risk | Normative response | Verification status |
|---|---|---|---|
| A local timestamp cannot resolve sync direction | Silent loss of a developer's local plaintext | Whole-file baseline state machine with an explicit conflict state | Specified, not implemented |
| Native age stanzas do not expose stable recipient identities | A fresh clone cannot infer whether every file was re-encrypted after membership changes | Deterministic committed manifest binding ciphertext digest to a claimed semantic recipient-set digest | Specified; claim cannot be cryptographically proven from age ciphertext |
| Repository recipients are untrusted policy input | A malicious recipient could be added before re-encryption | Canonical full SHA-256 fingerprints, local trust pin, authenticated out-of-band verification, explicit non-interactive approval | Specified, not implemented |
| Classical-only encryption leaves long-lived Git history exposed to future quantum attacks | Harvest-now/decrypt-later confidentiality loss | V1 accepts only native hybrid ML-KEM-768/X25519 age recipients and forbids mixed suites | Specified, not implemented |
| Git may transform binary ciphertext | Corrupted or non-identical artifacts through EOL conversion, filters, encodings, or LFS | Managed `.gitattributes`, effective-attribute checks, staged-blob/manifest hashing | Specified, not implemented |
| Lexical path checks have symlink and TOCTOU gaps | Read or overwrite outside the repository | Patched handle-relative `os.Root`, no-follow/file-identity checks, portable paths, hard-link and mount rejection | Specified, not implemented |
| Go's rooted path API has had recent security fixes | A vulnerable toolchain can invalidate the filesystem boundary | Exact Go 1.26.6 release pin or later project-reviewed supported security patch plus advisory regression tests | Implemented and locally validated at 1.26.6; independent release evidence remains open |
| Windows replacement and ACL behavior differs from POSIX | Partial writes, lost ACLs, or inaccessible plaintext | Dedicated Windows replacement and ACL implementation with real NTFS tests | Specified, not implemented |
| `%AppData%` is roaming storage | Private identities may roam or synchronize unexpectedly | Use Windows `FOLDERID_LocalAppData`, restricted ACLs, and storage-location checks | Specified, not implemented |
| Working-tree hook checks miss partial staging | An unsafe prospective commit can differ from local files | Parse and validate config, recipients, manifest, attributes, and ciphertext from index blobs | Specified, not implemented |
| Git index entries can be symlinks, executable blobs, or submodules | Content parsing alone can validate the wrong object type or permit path indirection | Require mode `100644` for GitSeal metadata and ciphertext; reject every plaintext path regardless of index mode | Specified, not implemented |
| A repository-local executable or changing `PATH` can redirect Git subprocesses | Attacker-controlled code execution under the developer account | Resolve Git once, reject repository-contained candidates, invoke its absolute path, and avoid Git operations that execute user-configured transforms | Specified, not implemented |
| Pre-commit hooks are optional and bypassable | `--no-verify` or a fresh clone can omit the guardrail | Required tree-level CI validation and protected branches; hook described only as defense in depth | Specified, repository controls not configured |
| A prefix-only private-key scan creates false positives | Documentation or tests containing the prefix are blocked | Parse complete checksum-valid native hybrid private identity tokens; generate test keys at runtime | Specified, not implemented |
| Tracked settings could disable safety | Repository changes weaken local safeguards | No tracked option may raise size limits or disable ignore, attribute, path, or overwrite controls | Specified, not implemented |
| Config, Git output, and filenames are untrusted text | Resource exhaustion, terminal injection, or pathspec injection | Strict schema/size/depth limits, terminal escaping, literal pathspecs, bounded subprocesses | Specified, not implemented |
| Checksums alone do not authenticate public releases | A substituted binary can retain an attacker-controlled checksum | SBOM, reproducible-build goal, pinned CI actions, least privilege, and GitHub build provenance attestations | Specified, not configured |
| Losing the only identity can permanently lose data | Availability failure | Recovery documentation and an independently tested backup/recovery drill before production status | Specified, workflow not implemented |
| Unprotecting a file can expose plaintext to a later commit | Confidentiality loss after a seemingly administrative action | Keep existing plaintext ignored unless the exact `--make-trackable` action is confirmed | Specified, not implemented |
| `sync` could treat unfamiliar valid ciphertext as authority to overwrite existing plaintext | Silent malicious substitution or rollback | Distinct incoming state and exact-digest consent before replacement | Corrected in specification, not implemented |
| Repository mappings were not locally trusted | A hostile config could retarget decryption | Separate canonical mapping trust digest, source in manifest, tracked-destination refusal | Corrected in specification, not implemented |
| The unordered recipient set did not bind member IDs to recipients | A hostile association swap could misdirect a later member removal without changing the set | Separate trusted canonical membership-policy digest over ID/recipient pairs | Newly identified; corrected in specification, not implemented |
| Acting identity was not required in the recipient set | Self-lockout after encryption | Pre-mutation self-membership plus candidate-header unwrap | Corrected in specification, not implemented |
| Same-directory plaintext temporaries were neither ignored nor tree-blocked | Crash residue could be committed by `git add -A` or `-f` | Reserved random temporary namespace, permanent ignore, hook/tree rejection, conservative diagnostics | Corrected in specification, not implemented |
| Hook semantics did not cover Git's active temporary indexes or merge commits | Validator can inspect bytes other than the prospective commit | Inherited-index validation, `pre-merge-commit`, documented hook gaps, required exact-tree CI | Corrected in specification; Git behavior tested, implementation absent |
| The required tree-only CI control had no command | Hook bypass had no implementable compensating control | `verify --source`, bare-repository support, isolated Git semantics, trusted pinned merge-tree CI | Corrected in specification, not implemented |
| Initial hybrid recipient/file ceilings implied excessive Git growth | Hundreds of MiB per full re-encryption generation | V1 caps reduced to 32 members and 128 files; benchmarks remain required | Corrected in specification, not implemented |
| Windows replacement preserves an old DACL and named streams and can partially fail | Broad plaintext access, surviving hidden data, or unsafe cleanup | Pre/post ACL and stream validation plus file-identity/digest reconciliation and real NTFS fault injection | Newly identified release blocker; specified, not implemented |

## Independent audit verification

The supplied audit was treated as leads, not authority. The complete
[64-finding disposition](AUDIT-DISPOSITION.md) records 23 Confirmed, 19 Partially
correct, 3 Already addressed, 3 Incorrect, 1 Duplicate, 3 Deferred by scope, and
12 Cannot be evaluated until implementation. Accepted portions are mapped to the
corrected specification; rejected recommendations include raw decoded-key
hashing, a predicted overlength private identity, optional hook safety checks,
tracked-plaintext overwrite escapes, mixed-recipient behavior attributed to the
official age CLI, automatic identity trial, and unbounded V1 feature additions.

## Cryptographic integration decision

GitSeal does not create a file format or cryptographic primitive. V1 uses only
the official `filippo.io/age` native hybrid API. The current age specification
defines hybrid ML-KEM-768/X25519 recipients and warns against mixing a hybrid
recipient with a non-quantum-resistant recipient for the same file. The project
therefore chooses one suite for the entire V1 team rather than offering a menu
of cryptographic options.

An authorized recipient can unwrap the file key and verify the age header MAC;
the payload is authenticated only as decryption is consumed through EOF. Public
header type/count/shape inspection is
useful rejection evidence but remains attacker-controlled until header-MAC
verification. It does not prove unique recipient identities or authenticate the
human sender. Git review, protected branches, signed commits or tags, and
release governance retain that responsibility.

Native hybrid public recipients are currently 1,959 characters while private
identities are 77. The practical trust ceremony therefore uses the complete
domain-separated SHA-256 fingerprint of strict parse-to-`String()` canonical
recipient text over an independently authenticated channel. Decoded key bytes
are unexported and unnecessary; adding another Bech32 decoder would increase the
security surface. A set fingerprint copied from the same repository is not an
independent trust anchor.

The artifact manifest deliberately stays outside the ciphertext format so a
normal compatible age client can still recover the data. It detects bookkeeping
inconsistency and recipient-set staleness, but because native recipient stanzas
are anonymous, it cannot prove the actual recipient set. The product must state
that limitation plainly.

## Filesystem decision

The repository is an attacker-controlled directory tree in the threat model.
Checking `filepath.Clean`, checking a prefix, or resolving symlinks and later
opening by name is insufficient. File access must stay rooted through operating
system handles, use exclusive temporary creation, compare file identities, and
publish with same-directory replacement.

Go's `os.Root` is the foundation, not the entire solution: its documentation
notes platform limitations, mount-boundary behavior, and operation-specific
races. GitSeal additionally rejects observed links, reparse points, hard-link
aliases, non-regular files, mount crossings, and non-portable paths. Releases
must use a patched toolchain because a July 2026 `os.Root` path-escape advisory
affected earlier Go versions.

The opened root handle must be identity-bound to Git's discovered worktree
because `os.OpenRoot` can follow links in the root path. Windows publication must
also account for `ReplaceFileW` preserving the destination DACL and named streams
and for Microsoft-documented partial failure states; a false return does not
authorize blind cleanup. These properties require real NTFS tests.

Crash durability is filesystem-dependent. NTFS, APFS, and a mainstream Linux
filesystem require real tests. Network, removable, virtual, copy-on-write,
journaling, backup, and synchronized filesystems weaken or change guarantees.
GitSeal must never promise secure deletion.

## Git decision

The Git index is the prospective commit. The pre-commit check must therefore
read staged GitSeal metadata and blobs, not assume that working-tree files are
what Git will commit. All machine-readable Git traffic uses NUL delimiters and
literal pathspec behavior. It also validates index modes: ciphertext and
GitSeal-owned metadata must be non-executable regular blobs, while a protected
plaintext path is forbidden in every mode.

Ciphertext is explicitly protected from text/EOL conversion, ident expansion,
diff/merge drivers, clean/smudge filters, and working-tree re-encoding; effective
values must each be exactly `unset`; `unspecified`, set, and valued results fail.
Nearer or Git-local rules can override the managed block, and global/local rules
remain visible to some cached/source queries. Exact-tree CI therefore needs a
sanitized isolated Git context rather than treating `check-attr --source` as
pure repository truth. A staged ciphertext digest
must equal its staged manifest digest. This catches clean/smudge transformation
and line-ending corruption before commit.

Hooks remain optional and locally bypassable. The same tree-only checks belong
in required CI through `verify --source`. Hooks must honor Git's inherited active
index, including temporary commit indexes, and install a non-destructive
`pre-merge-commit` integration. Rebase, cherry-pick, revert, and `am` gaps further
require CI. CI cannot compare a ciphertext with an absent local plaintext,
but it can reject tracked plaintext, malformed metadata, valid private
native hybrid private identities, unsafe attributes, invalid age artifacts, stale recipient manifests,
and internal hash mismatches.

## Supply-chain decision

The runtime dependency set should remain small: the standard library, the
official age module, the maintained pinned `go.yaml.in/yaml/v3` module behind a
strict wrapper (not archived `gopkg.in/yaml.v3`), and narrowly
scoped platform packages where the standard library is insufficient.

Pull requests and releases require:

- the latest supported patched Go toolchain;
- a documented, feature-tested Git floor and vendor-supported patched Git build;
- pinned module versions and `go mod verify`;
- `govulncheck`, race tests, fuzz tests, vet, formatting, static analysis, and
  CodeQL;
- dependency review and automated security updates;
- Actions pinned to full commit SHAs with least-privilege permissions;
- separation between untrusted pull-request jobs and privileged release jobs;
- SHA-256 checksums, an SBOM, and verifiable build provenance for every binary;
- reproducible builds where practical and documented nondeterminism otherwise.

Release builds additionally select an exact verified patched Go distribution,
set `GOTOOLCHAIN=local`, verify modules, build offline/read-only with deterministic
flags and no wall-clock build time, normalize archives, and compare two clean
independent artifact builds before attestation.

## GitHub repository settings observed

Point-in-time read-only checks were performed against `RaydAlsayf/GitSeal` on
2026-08-13. At 13:11:05 +03:00, an authenticated maintainer-context GitHub REST
query recorded repository, branch protection, ruleset, Actions permission,
vulnerability-alert, code-scanning, and private-reporting endpoints. At 13:50
+03:00, the installed GitHub App independently confirmed public visibility,
default branch `main`, administrative access for the connected account, and the
published file results. No credential or token is recorded here. HTTP 404 was
interpreted per the endpoint: absent branch protection/analysis, disabled alert
endpoint, or absent content as noted. These values can change immediately and
are observations, not design requirements or continuous monitoring.

| Control | Observed state | Assessment |
|---|---|---|
| Repository visibility | Public | Appropriate for design-stage review |
| Secret scanning | Enabled | Good baseline |
| Secret-scanning push protection | Enabled | Good baseline |
| Default workflow token permissions | Read-only | Good baseline |
| Default branch protection | Not configured | Must be configured before accepting production changes |
| Repository rulesets | None | Add a default-branch ruleset before production development |
| Allowed Actions policy | All actions allowed; SHA pinning not required | Restrict and require immutable full-SHA pins before adding workflows |
| Dependabot vulnerability alerts | Disabled | Enable when dependencies are introduced |
| Dependabot security updates | Disabled | Enable when the Go module is created |
| Code scanning | No analysis present | Add CodeQL with the first implementation |
| Private vulnerability reporting | Disabled | Enable before distributing binaries |
| Repository description | Empty | Add a clear design-stage description before broad announcement |
| Published `README.md`, `SPECIFICATION.md`, and `SECURITY-REVIEW.md` | Each returned content API 404; `main` contains only `LICENSE` | The design is local/untracked and not yet public; commit/push only with explicit maintainer authorization |

These controls do not replace code review or tests. In particular, branch rules
must require the tree-only GitSeal safety job once that validator exists. No
hosting setting was changed as part of this review.

Endpoints queried were `GET /repos/RaydAlsayf/GitSeal`,
`/branches/main/protection`, `/rulesets`, `/actions/permissions`,
`/actions/permissions/workflow`, `/vulnerability-alerts`,
`/code-scanning/analyses`, `/private-vulnerability-reporting`, and the contents
API for the four named files. This provenance makes the table reproducible but
does not make private/admin-only settings publicly verifiable without equivalent
authorization.

## Residual risks that remain by design

- A compromised machine or the same OS account can read plaintext and private
  identities.
- An authorized user can copy every secret they can decrypt.
- Removing a recipient cannot revoke old commits or copies; credentials must be
  rotated separately.
- A malicious repository author can substitute valid attacker-chosen
  ciphertext. GitSeal does not supply sender signatures.
- The committed manifest is reviewable evidence, not proof of anonymous age
  recipients.
- Public header shape/type/count remains unauthenticated until header-MAC
  verification and never identifies unique recipients.
- Git metadata leaks paths, sizes, change frequency, and history.
- Randomized opaque ciphertext has binary merge conflicts; GitSeal never chooses
  a side or makes encryption deterministic.
- Plaintext can leak through editors, backups, sync agents, build outputs,
  containers, swap, crash dumps, indexing, or malware.
- A local hook can be bypassed and is not distributed by clone.
- Filesystem flush and replacement semantics vary by platform and filesystem.
- Go cannot guarantee erasure of all secret copies from memory.
- Post-quantum designs and implementations can receive future cryptanalytic or
  implementation findings; dependency maintenance remains continuous work.
- GitSeal cannot attest full-disk encryption or backup exclusion, and V1 stores a
  plaintext private identity with restrictive filesystem permissions.
- V1 does not deliver private identities or plaintext to CI or production.
- No code exists yet, so implementation defects are currently unmeasurable.

## Public-release recommendation

The local design documents may be committed and pushed as a design-stage project
to gain review once the maintainer explicitly authorizes publication. Use an
explicit `pre-alpha` label and the warning in the README. Do not
recommend real-secret use until the public-release gate in the specification is
complete. A v0.x binary can be shared for testing only with test credentials and
clear pre-release language. A v1.0 security claim should follow independent
review of the implemented filesystem, identity, manifest, Git, and release
paths.

## Current release blockers

- There is no implementation, dependency graph, executable, or test result to
  review.
- The framed digest golden vectors and version-1 schemas are not implemented or
  frozen by tests.
- Rooted safe-file publication, exact stream hashing, identity ACLs, and the
  Windows DACL/named-stream/partial-failure boundary lack real filesystem tests.
- The typed hybrid engine, exact header inspector, identity self-test,
  self-membership rule, and EOF authentication paths do not exist.
- The state machine, explicit incoming-ciphertext consent, mapping trust,
  unmerged workflow, and lock-consistent reads do not exist.
- `verify --source`, exact-active-index hooks, isolated attribute/ignore
  evaluation, trusted merge-tree CI, and required branch controls do not exist.
- Required security, recovery, rotation/incident, compatibility, limitations,
  contribution, and release-verification documents are incomplete.
- No reproducible release, SBOM, provenance attestation, cross-platform matrix,
  recovery drill, implementation-focused human security review, or production
  readiness evidence exists.
- The corrected documents remain local and untracked; the GitHub repository
  still publishes only `LICENSE` until the maintainer explicitly commits/pushes.

## Primary research sources

- [Current C2SP age format specification](https://c2sp.org/age)
- [Official age v1.3.1 Go API](https://pkg.go.dev/filippo.io/age@v1.3.1)
- [Official age v1.3.1 hybrid implementation](https://github.com/FiloSottile/age/blob/v1.3.1/pq.go)
- [Official age v1.3.1 parsing implementation](https://github.com/FiloSottile/age/blob/v1.3.1/parse.go)
- [BIP-173 checksum design and length bound](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#checksum-design)
- [Go `os.Root` documentation](https://pkg.go.dev/os#Root)
- [Go `os.OpenRoot` documentation](https://pkg.go.dev/os#OpenRoot)
- [Go `os.Root` path-escape advisory GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970)
- [Go security best practices](https://go.dev/doc/security/best-practices)
- [Go toolchain selection](https://go.dev/doc/toolchain)
- [Go command/build flags](https://pkg.go.dev/cmd/go)
- [Maintained Go YAML module](https://github.com/yaml/go-yaml)
- [Git attributes documentation](https://git-scm.com/docs/gitattributes)
- [Git `check-attr` documentation](https://git-scm.com/docs/git-check-attr)
- [Git ignore semantics](https://git-scm.com/docs/gitignore)
- [Git `check-ignore` documentation](https://git-scm.com/docs/git-check-ignore)
- [Git hooks documentation](https://git-scm.com/docs/githooks)
- [Git environment and active index](https://git-scm.com/docs/git)
- [Git staged/index comparison documentation](https://git-scm.com/docs/git-diff-index)
- [Microsoft `ReplaceFileW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
- [Microsoft `MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
- [Microsoft known-folder identifiers](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)
- [POSIX `rename`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html)
- [CWE-59 link-following weakness](https://cwe.mitre.org/data/definitions/59.html)
- [GitHub sensitive-data removal limits](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [GitHub merge queues and `merge_group`](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
- [GitHub Actions security settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub supply-chain security](https://docs.github.com/en/code-security/concepts/supply-chain-security/supply-chain-security)
- [SOPS official repository](https://github.com/getsops/sops)
- [git-crypt documented limitations](https://github.com/AGWA/git-crypt#limitations)

## Next review point

Repeat this review after the Phase 1 vertical slice exists. At that point the
review must inspect code and tests rather than requirements, run dependency and
static scans, exercise real platform filesystems, and attempt adversarial
repository, configuration, manifest, index, and recipient inputs.
