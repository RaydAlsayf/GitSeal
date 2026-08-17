# GitSeal V1 Specification

**Status:** Normative pre-implementation specification

**Target:** Open-source Go CLI

**License:** MIT (the repository's current license)

**Ciphertext format:** `age` v1, native hybrid recipients

This document supersedes earlier GitSeal design notes where they conflict with
it. The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe normative
requirements.

## 1. Product boundary

GitSeal helps small development teams store encrypted versions of sensitive
files in Git while keeping plaintext local and ignored.

GitSeal provides:

- project and recipient configuration;
- local identity discovery and creation;
- safe file encryption and decryption;
- synchronization and conflict detection;
- Git ignore, hook, and exact-tree safeguards;
- diagnostics and automation-friendly output.

GitSeal does not provide:

- custom cryptography;
- a SaaS backend, accounts, RBAC, SSO, KMS, HSM, or a database;
- retroactive revocation of Git history;
- third-party credential rotation;
- protection after plaintext or a private identity is compromised;
- authenticity of the person who produced a ciphertext;
- automatic Git pull, commit, push, staging, or history rewriting.

V1 is a workstation workflow. CI MAY perform the tree-only verification defined
in Section 11 without a private identity, but GitSeal does not provision secrets
to CI or production. Those environments require a dedicated secret manager.

V1 supports the native hybrid `age` recipient and identity types introduced in
`filippo.io/age` v1.3.0. These combine ML-KEM-768 with X25519 and are the only
recipient suite accepted by a V1 project. A file MUST NOT mix hybrid and
classical recipients because confidentiality against a future quantum attacker
would then be limited by the classical encapsulation. The official age library's
recipient labels are defense in depth, not GitSeal's only enforcement boundary.
Classical X25519, SSH,
plugins, passphrase identities, SOPS, keychains, and hardware keys are future
migration capabilities and MUST NOT complicate the first implementation.

## 2. Security claims

GitSeal may claim that protected file contents remain confidential when an
attacker obtains only the repository and no authorized private identity.

GitSeal MUST NOT claim that:

- filenames, sizes, change timing, or repository metadata are hidden;
- ciphertext proves who created it;
- removing a recipient revokes old Git history;
- `.gitignore` prevents cloud backup or filesystem synchronization;
- encrypted files are fresh or cannot be rolled back to an old valid revision;
- a manifest proves the actual private identities capable of decryption;
- a compromised or malicious authorized developer cannot copy secrets.

`age` provides authenticated encryption, but public recipients are sufficient
to create new ciphertext. An attacker who can modify the repository can replace
a protected file with attacker-chosen content encrypted to the legitimate team.
Git review, branch protection, and optional signed commits remain the source of
repository authorship and change authorization.

Native `age` recipient stanzas intentionally avoid embedding a stable recipient
identifier. GitSeal can record which recipient set it instructed the library to
use, but another clone cannot cryptographically prove that claim from the
ciphertext alone. Section 4.3 defines auditable bookkeeping, not a new
cryptographic guarantee.

The hybrid KEM protects asymmetric encapsulation of age's 16-byte random file
key. The age payload construction derives a separate 32-byte
ChaCha20-Poly1305 key with HKDF. GitSeal claims neither a new payload cipher nor
that hybrid encapsulation changes age's symmetric construction.

## 3. Data locations and trust boundaries

| Data | Location | Commit to Git |
|---|---|---:|
| Project configuration | `.gitseal/config.yaml` | Yes |
| Public recipients | `.gitseal/recipients.yaml` | Yes |
| Artifact manifest | `.gitseal/manifest.yaml` | Yes |
| Ciphertext | Configured `*.age` paths | Yes |
| Binary attribute rules | `.gitattributes` | Yes |
| Plaintext | Working tree | No; MUST be ignored |
| Sync baseline | Git-local GitSeal directory | No |
| Lock files | Git-local GitSeal directory | No |
| Identity selection | Git-local or user configuration | No |
| Private identities | OS user configuration directory | Never |

Repository configuration is untrusted input until validated. Public recipient
keys are not secret, but adding a recipient changes who can decrypt future
ciphertext and is therefore a security-sensitive action.

The Git-local directory MUST be resolved using Git, equivalent to:

```text
git rev-parse --git-path gitseal
```

This supports normal repositories and linked worktrees without assuming that
`.git` is a directory. State and locks MUST NOT be stored in `.gitseal/`.

On Linux and macOS, the private identity directory MUST be derived with the OS
user configuration API and namespaced under `GitSeal/identities`. On Windows it
MUST use the `FOLDERID_LocalAppData` known-folder API rather than roaming
`%AppData%`, then append `GitSeal\identities`. Every platform implementation
MUST resolve the result, verify it is outside every discovered Git worktree and
Git administrative directory, and reject a directory that is a link, reparse
point, network location, or known cloud-synchronization location unless the user
explicitly accepts the documented risk. Synchronized-location detection is
best-effort and non-exhaustive; a clean result is not evidence that backup,
snapshot, redirection, or enterprise software excludes the directory.

## 4. Tracked configuration

### 4.1 Project configuration

```yaml
version: 2

protected_files:
  - source: .env
    encrypted: .env.age

retained_safety:
  ignored_plaintext: []
  binary_artifacts: []
```

Tracked configuration MUST NOT contain a local identity name or path. Identity
selection differs by user and machine. V1 has no tracked option that can weaken
ignore, attribute, path, size, or overwrite protections.

`retained_safety` explicitly models paths that are no longer active mappings but
must remain protected after `unprotect`. Its entries use the same path validator,
are deterministically sorted, and cannot overlap or conflict with active
mappings. Managed ignore and attribute blocks are derived from active mappings
plus these retained entries; they are never inferred from untracked local state.
Removing a retained entry requires the exact safe conditions in Sections 11 and
12. This state resolves the otherwise contradictory requirements to retain
orphan safeguards and to derive managed blocks deterministically.

Project schema version 2 is the first schema that makes retained-safety trust a
separate, persistent authorization boundary. Legacy project schema version 1 is
accepted only by the explicit migration reader described in Section 15.2; all
ordinary commands reject it with an upgrade-required error. Older strict tools
therefore reject version 2 instead of silently accepting retained-safety changes
that they did not pin. `protected_files`, `retained_safety`,
`ignored_plaintext`, and `binary_artifacts` MUST be present sequences, including
when empty; omitted or YAML `null` values are invalid.

A retained binary artifact has no active manifest entry and no supported
re-encryption command. Static validation therefore requires canonical native-
hybrid age shape with a historical stanza count from 1 through the V1 member
ceiling, independent of the current recipient count. It MUST NOT report that as
freshness, recipient uniqueness, or proof of current-member access. The project
still requires a nonempty current recipient set while any retained artifact is
present, so future protection cannot silently begin from an empty policy.

### 4.2 Recipient configuration

```yaml
version: 1

members:
  - id: rayd
    name: Rayd
    recipient: "age1pq1..."
```

Configuration parsing MUST:

- use a strict schema and reject unknown fields;
- reject unsupported versions rather than reinterpret them;
- reject YAML aliases and excessive nesting or input sizes;
- reject duplicate member IDs and duplicate canonical recipients;
- validate IDs, display-name lengths, and recipient syntax;
- produce deterministic output and ordering;
- never place private key material in a generic config model.

Each YAML file MUST contain exactly one document. The parser MUST first enforce
a 1 MiB byte limit, then reject aliases, anchors, custom tags, duplicate mapping
keys, merge keys, excessive scalar lengths, and nesting deeper than 16 before
decoding into typed structures with unknown-field rejection. Phase 0 MUST use a
pinned, reviewed release of the maintained `go.yaml.in/yaml/v3` module, not the
archived `gopkg.in/yaml.v3` module, behind this strict wrapper.

V1 has hard ceilings of 32 members and 128 protected files. With the current
native hybrid stanza size, the recipient header is `70 + 1,557 * members` bytes:
49,894 bytes at 32 members and 6,386,432 bytes across 128 artifacts, before
payloads, per complete re-encryption generation. Benchmarks and repository-size
tests MUST confirm these ceilings before V1.0; raising them requires a later
reviewed schema/tool release, never a tracked-project override.

An empty recipient set is permitted only while the project has no active or
retained artifacts. `protect` and every encryption refuse an empty set, and
`member remove` refuses to remove the final member while any active mapping,
manifest entry, ciphertext, or retained binary artifact exists.

The V1 protected-file model is:

```go
type ProtectedFile struct {
    Source    string
    Encrypted string
}
```

No configurable engine field is needed until a second engine is designed and
implemented.

### 4.3 Artifact manifest

GitSeal maintains a deterministic committed manifest:

```yaml
version: 1

artifacts:
  - source: .env
    encrypted: .env.age
    ciphertext_sha256: "..."
    recipient_set_sha256: "..."
```

The manifest MUST NOT contain plaintext digests, timestamps, usernames, machine
paths, or private material. Entries are sorted by encrypted path. A ciphertext
digest binds bookkeeping to exact artifact bytes. A recipient-set digest records
the semantic recipient set used by GitSeal during encryption so that a fresh
clone can detect artifacts that require re-encryption after membership changes.

Every field named `*_sha256` serializes exactly the 32 raw digest bytes as 64
lowercase hexadecimal characters; schemas reject every other length, case, or
encoding. Ciphertext and plaintext digests hash exact raw file/stream bytes.

Every recipient MUST be parsed with `age.ParseHybridRecipient`. The input is
canonical only when it is byte-identical to the parsed recipient's `String()`;
GitSeal MUST NOT trim or case-fold it. Canonical UTF-8 recipient strings are
sorted by bytewise lexicographic order. The recipient-set digest is:

```text
SHA-256(
  "gitseal/recipient-set/v1\x00" ||
  uint64_be(count) ||
  for each recipient: uint64_be(byte_length) || recipient_bytes
)
```

It MUST NOT hash raw YAML or display names. Canonical text is the official
library's injective representation; requiring unexported decoded key bytes would
add an unnecessary second Bech32 implementation. Golden vectors for zero, one,
and multiple recipients are normative before the schema is released.

The manifest is auditable bookkeeping protected by Git review; it is not
cryptographic proof of the anonymous recipient stanzas inside an age file. A
consistent malicious replacement of both ciphertext and manifest defeats this
check. “Integrity” in manifest diagnostics means bookkeeping consistency and
transformation detection, not sender authenticity or change authorization.

The global manifest remains a deliberate V1 simplicity decision. Its digest is
not redundant in the working tree or prospective index: it detects
transformation and binds a reviewed source path and semantic recipient-set claim
to exact staged artifact bytes. Per-artifact manifests are deferred until merge
experience justifies another schema.

Encryption updates ciphertext and manifest as a repairable multi-file operation.
Because the filesystem cannot atomically replace both files, `status`, `doctor`,
and validation MUST reject any mismatch. A commit is GitSeal's consistency
boundary only after that exact prospective tree passes hook or tree-only
validation. Git itself does not enforce the invariant, and every merge, rebase,
cherry-pick, revert, or partial-stage result is a new tree requiring validation.

## 5. Repository and path policy

Normal GitSeal commands MUST discover the repository root through `git rev-parse
--show-toplevel` and MUST refuse bare repositories. The sole exception is
`verify --source`, which operates on an exact tree and MUST support a bare
repository without inventing a worktree.

Every configured path MUST:

- use the portable V1 allowlist `[A-Za-z0-9._/-]` with `/` separators; spaces,
  non-ASCII text, glob/ignore metacharacters, control characters, and every
  other byte are rejected rather than escaped by handwritten grammars;
- be normalized repository-relative syntax with no empty or trailing component;
- resolve inside the current worktree;
- reject absolute paths, empty paths, `..`, NUL, and platform volume prefixes;
- reject `.git`, Git administrative paths, and `.gitseal` internal files;
- reject components ending in a dot or space and case-insensitive Windows device
  names such as `CON`, `NUL`, `COM1`, and `LPT1`, including names with suffixes;
- have a distinct source and encrypted path;
- avoid case-insensitive collisions with every other configured source and
  destination, even on a case-sensitive filesystem;
- reject symlinks, junctions, and reparse points in the target or its parents;
- reject files with multiple hard links and different paths resolving to the
  same filesystem identity;
- reject mount-point or volume-boundary crossings below the repository root;
- reject any component whose basename begins with the reserved
  `.gitseal.tmp.` temporary-file namespace;
- refer to a regular source file for encryption;
- use a regular destination file when the destination already exists.

Lexical validation is necessary but not sufficient. Repository file operations
MUST be scoped through a handle-relative root facility such as patched Go
`os.Root`, plus platform-specific no-follow and file-identity checks. The
implementation MUST NOT authorize an operation by calling `EvalSymlinks`,
comparing path prefixes, or checking a path and later reopening it by name.
The opened root handle's filesystem identity MUST be bound to the worktree
identity discovered through Git; `os.OpenRoot` following a link in the root path
is not by itself authorization. Root rename/replacement and the
GO-2026-4970 final-symlink-with-trailing-slash case require named regression
tests.

Git commands MUST be executed directly with argument arrays. User-controlled
values MUST NOT be interpolated into a shell command. Literal pathspec mode,
`--`, or NUL-delimited `--pathspec-from-file` MUST be used as appropriate.
GitSeal MUST set bounded execution time and output size, disable pagers and
terminal prompts, and refuse ambiguous repository-selection variables such as
`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, and Git config-parameter injection
variables during normal CLI invocation. The hook entry point MUST honor the
active index exported by Git only after confirming it describes the same
repository/worktree. It MUST NOT silently fall back to the default index when
`GIT_INDEX_FILE` names an index lock, `next-index-*`, linked-worktree index, or
other active commit index. An unsupported or unverifiable inherited index fails
closed.

GitSeal MUST resolve the Git executable once per process, reject a candidate
inside the repository or its Git administrative directories, and invoke the
validated absolute path thereafter. It MUST NOT perform a fresh `PATH` search
for each Git command. Repository inspection MUST use plumbing commands that do
not apply clean/smudge filters, text conversions, external diffs, credential
helpers, or user-defined programs. Staged bytes are read from index objects, not
re-created from working-tree files.

Git object IDs are opaque values returned to Git; code MUST NOT assume SHA-1
length or parse them as fixed 40-character strings. V1 supports Git repositories
whose reported object format is SHA-1 or SHA-256. Replacement objects are
disabled for security validation/history scans. GitSeal MUST detect and reject
`skip-worktree` or `assume-unchanged` on owned/protected paths when it would hide
divergence, report sparse-checkout limitations, and reject exact-case or
case-fold collisions with `.gitseal`, `.gitignore`, and `.gitattributes` in the
prospective tree.

The implementation MUST publish a minimum Git version derived from the exact
commands and options it uses, reject older versions, and test both that minimum
and the latest stable Git release. A release also requires a Git build that still
receives vendor security fixes; a feature-compatible but unsupported build is
not considered safe.

## 6. Identities

`gitseal identity create [--name NAME]` MUST:

1. Resolve and validate the OS-specific identity directory.
2. Create missing directories with restrictive permissions where supported.
3. Refuse to overwrite an existing identity.
4. Generate a hybrid identity through the official `age` Go library.
5. Write it through the safe-file writer.
6. Reopen the final path, recheck type and permissions/ACL, parse it with
   `age.ParseHybridIdentity`, derive and compare its public recipient, and run a
   small in-memory encrypt/decrypt round trip through the production engine.
7. Print only its public recipient and storage path after every check succeeds.

Failure cleanup may remove only a path created exclusively by this invocation;
it MUST report a cleanup failure and MUST NOT delete or replace a pre-existing
path.

The private identity filename SHOULD end in `.txt`, not `.age`, because its
contents are a plaintext private identity rather than an encrypted age file.

On Unix, private identity files MUST be created as mode `0600` and directories
as `0700`, independently of umask. On Windows, GitSeal MUST create and verify an
ACL restricted to the current user and required system principals; inheritance
MUST NOT silently broaden access. `doctor` MUST fail when identity storage is
materially broader than expected.

`identity create` MUST never rotate or replace an identity implicitly.
`identity show` MUST never print private material. Export/import are outside V1.
Creation output and documentation MUST direct the user to a reviewed offline
backup-and-recovery procedure. GitSeal does not create an automatic private-key
backup, and users MUST verify recovery before deleting or replacing a machine.
Recovery and secure backup instructions are required before public release.
GitSeal MUST explain that administrators, the same OS account, malware, crash
dumps, and process inspection remain capable of accessing key material. It MUST
not claim that Go can reliably erase every private-key copy from process memory.
The documentation MUST recommend full-disk encryption and an offline recovery
backup, while stating that GitSeal cannot portably prove that a filesystem is
encrypted, backed up, or excluded from enterprise backup and snapshots.

Every encryption, decryption, sync, and identity-aware diagnostic MUST use one
explicitly selected local GitSeal hybrid identity, supplied by local selection
or an identity name flag; private material itself is never a flag or environment
value. V1 MUST NOT try other registered identities, search arbitrary home
directories, or silently use SSH keys. Missing and unauthorized results are
therefore deterministic and independent of unrelated local keys.

## 7. Recipient trust

For a canonical recipient string `r`, the recipient fingerprint is:

```text
SHA-256("gitseal/recipient-fingerprint/v1\x00" ||
        uint64_be(byte_length(r)) || r)
```

Human output renders all 32 digest bytes as 64 lowercase hexadecimal digits in
eight groups of eight. The full canonical recipient remains available on demand.
Fingerprint comparison MUST use an authenticated channel independent of the Git
repository; a fingerprint, set digest, or commit obtained from the same
repository is not a trust anchor. The 1,959-character hybrid recipient and its
short Bech32 checksum are not a practical human-comparison ceremony.

The recipient-set fingerprint is the Section 4.3 recipient-set digest rendered
with the same complete grouped lowercase-hex format.

Before encrypting, GitSeal MUST compare the current canonical mapping,
recipient-set, and membership-policy digests with their last locally trusted
values. Membership pairs are sorted by member-ID bytes then recipient bytes, and
the membership-policy digest is:

```text
SHA-256(
  "gitseal/membership-policy/v1\x00" ||
  uint64_be(count) ||
  for each pair:
    uint64_be(member_id_byte_length) || member_id_bytes ||
    uint64_be(recipient_byte_length) || recipient_bytes
)
```

Display names are untrusted presentation and are excluded. Any ID-to-recipient
association or ID change requires the recipient-change confirmation even when
the unordered recipient-set digest is unchanged.

Mapping pairs
are sorted by source bytes then encrypted-path bytes, and the mapping digest is:

```text
SHA-256(
  "gitseal/project-mappings/v1\x00" ||
  uint64_be(count) ||
  for each pair:
    uint64_be(source_byte_length) || source_bytes ||
    uint64_be(encrypted_byte_length) || encrypted_bytes
)
```

The mapping digest remains active-only so its released v1 domain and golden
vectors do not change. Every retained-safety change is instead bound by a
second canonical digest. Ignored plaintext paths and binary artifact paths are
sorted independently by their canonical UTF-8 bytes, and the retained-safety
digest is:

```text
SHA-256(
  "gitseal/retained-safety/v1\x00" ||
  uint64_be(ignored_plaintext_count) ||
  for each ignored plaintext path:
    uint64_be(path_byte_length) || path_bytes ||
  uint64_be(binary_artifact_count) ||
  for each binary artifact path:
    uint64_be(path_byte_length) || path_bytes
)
```

The two category counts prevent a path from moving between safety meanings
without changing the digest. Golden vectors for empty, one-per-category, and
multiple unsorted inputs are normative. Local trust is the tuple of recipient
set, membership policy, active mapping, and retained-safety digests; no member of
that tuple substitutes for another.

| Ignored plaintext input | Binary artifact input | Retained-safety SHA-256 |
|---|---|---|
| `[]` | `[]` | `6d676e7204192a33265d226acad236c6981012c5886e960bcee2ddd52f8510ff` |
| `["old/secret"]` | `["old/secret.age"]` | `01da650404b9b20fbf80b39b086bf4c1e8da1c53c7d30154b6824676ec4927fb` |
| `["z", "a"]` | `["z.age", "a.age"]` | `6400992866157f10e861bca0d5cd09a610482677968797b285e3d08dd6859efc` |

First use and any mapping received through Git require exact path/digest display
and confirmation; non-interactive use needs
`--accept-mapping-changes`. First use and any retained-safety change require the
independently displayed exact retained paths and digest plus
`--accept-retained-safety-changes`. A generic `--yes` cannot approve either
trust change.

- `member add` and `member remove` are explicit local actions and MAY update the
  trusted recipient-set and membership-policy digests after successfully writing
  and rereading the recipient file.
- A recipient change received through Git MUST be displayed before encryption.
- Added recipients require interactive confirmation.
- Non-interactive use requires an explicit `--accept-recipient-changes` flag.
- A generic `--yes` MUST NOT approve recipient changes implicitly.
- Removed recipients require the historical-access and credential-rotation
  warning from the product specification.

The first encryption in a cloned repository has no local trust baseline. GitSeal
MUST display each member ID, name, full fingerprint, and the recipient-set
fingerprint and require confirmation, or require `--accept-recipients` in
non-interactive use.

`member add` MUST show and require verification of the full recipient fingerprint
through that independent channel. Names, email addresses, GitHub accounts, and
repository authorship do not bind a person to an age recipient. Shortened
fingerprints are presentation only and can never approve or compare a key.

Before any encrypt, `protect`, or re-encryption mutation, GitSeal MUST derive the
recipient of the explicitly selected acting identity and require exact membership
in the effective recipient set. There is no V1 bypass. `status` and `doctor`
report missing self-membership. After candidate encryption and before
publication, GitSeal MUST authenticate the candidate header by unwrapping it
with that identity under the file-key handling rule in Section 8.

Decrypting existing ciphertext does not grant new access and need not establish
recipient trust. Trust is required before creating replacement ciphertext.

## 8. Streaming encryption interface

The crypto boundary MUST operate on streams:

```go
type HybridRecipients struct { /* unexported validated representation */ }
type HybridIdentity struct { /* unexported validated *age.HybridIdentity */ }

type Engine interface {
    Encrypt(dst io.Writer, src io.Reader, recipients HybridRecipients) error
    Decrypt(dst io.Writer, src io.Reader, identity HybridIdentity) error
}
```

The concrete V1 implementation is an `age` file engine using
`filippo.io/age` v1.3.1 or a later reviewed security patch in the same compatible
series. It MUST call only native hybrid recipient APIs and MUST NOT import or
dispatch age plugins. CLI handlers MUST NOT contain encryption logic. The engine
MUST NOT own filesystem replacement, Git operations, prompting, or output
formatting.

Only a trust-boundary constructor can create `HybridRecipients`: it parses each
value once with `age.ParseHybridRecipient`, enforces canonical byte identity,
duplicates, ordering, and count, and stores concrete hybrid recipients. The
engine may expose/pass only concrete `*age.HybridRecipient` values. General `age.Recipient`
wrappers and raw `[]string`/`[]age.Recipient` values MUST NOT cross this boundary;
otherwise recipient-label checks can be bypassed by interface wrapping.

Before accepting an artifact, a bounded structural inspector MUST reject armor,
passphrase files, plugins, unknown, grease, or mixed stanza types and excessive
headers. V1 artifacts contain exactly the configured member count of native
`mlkem768x25519` stanzas and no other stanza. Each stanza MUST have one canonical
unpadded-Base64 argument decoding to 1,120 bytes and a 32-byte body. Public
type/count/shape inspection is attacker-controlled metadata until an authorized
identity successfully verifies the header MAC; stanza count does not prove
unique recipients or their identities. The implementation MUST use reviewed
public APIs or its own bounded adapter, not import age's internal inspector.

Successful encryption means recipient parsing, streaming, writer close, exact
shape inspection, acting-identity header unwrap, file flush, and safe replacement
all succeeded. Header unwrap proves `header_decryptable`, not full payload
authentication; successful decryption authenticates the payload only after the
stream is consumed to EOF. GitSeal MUST NOT expose or log decrypted contents.
Every `DecryptHeader` use, including `doctor`, MUST minimize the returned 16-byte
file key's lifetime, never log or serialize it, and best-effort overwrite the
caller-visible buffer without claiming complete memory erasure.

Release builds require Go 1.26.6 or a later project-reviewed supported security patch because
earlier `os.Root` versions contain known path-escape vulnerabilities. The
minimum may be raised whenever the Go or age security floor changes; it MUST
never be lowered merely for compatibility.

## 9. Safe file writes

All writes MUST use a single reviewed safe-file component from the first
development phase.

For ciphertext writes:

1. Validate source, destination, and recipient trust before mutation.
2. Create a CSPRNG-suffixed name beginning `.gitseal.tmp.` with create-new/
   exclusive semantics inside the rooted destination directory. This fixed
   namespace is permanently ignored and independently forbidden in Git trees.
3. Hash the exact plaintext bytes consumed by encryption in the same stream and
   hash the exact ciphertext bytes written to the temporary file.
4. Close and flush it, checking every error.
5. Revalidate the destination path immediately before replacement.
6. Replace the destination using platform-specific safe semantics.
7. Flush the parent directory where supported.
8. Remove the temporary file on failure.

For plaintext writes, the same process applies, except the temporary file MUST
have restrictive permissions from creation time. Plaintext MUST NOT briefly
exist with permissive default permissions. Crash residues are secrets: `doctor`
reports them without content, revalidates links/type/identity before offering
cleanup, and never deletes them automatically merely because the name matches.

No operation may truncate the current destination before the replacement is
ready. GitSeal MUST handle Windows replacement behavior explicitly and test it
on Windows rather than assuming POSIX rename semantics.

On Windows, immediately before publication GitSeal MUST bind and validate the
existing destination identity, DACL, named streams, replacement temporary, and
containing-directory safety. Replacement of an existing file SHOULD use
`ReplaceFileW` when its
documented preconditions hold; creation and fallback require a separately
reviewed `MoveFileExW` strategy constrained to the same volume and MUST NOT use
`MOVEFILE_COPY_ALLOWED`. `REPLACEFILE_WRITE_THROUGH` is unsupported and MUST NOT
be treated as durability. Bounded, cancellation-aware retry is allowed only for
reviewed transient error codes. A reported `ReplaceFileW` failure can leave a
partial replacement state; reconcile destination, replacement, and backup by
open file identity and digest before any cleanup, never by blind deletion.
`ReplaceFileW` also preserves the replaced file's DACL and named streams. GitSeal
MUST refuse publication if the preconditions cannot be proven, enumerate/reject
unexpected streams, and establish the restrictive final DACL before plaintext
can become visible; it then revalidates the published object. The same ordering
applies to identities and every other sensitive GitSeal-created file. Pathname-
based Windows APIs create a final race against the rooted-handle boundary, so
Phase 0 MUST prove binding to the validated parent/destination identity, evaluate
a handle-rooted primitive such as `FILE_RENAME_INFO`, and refuse unsupported
cases rather than claim containment. On Unix, use handle-relative
same-filesystem rename. A successful rename is not considered
durable until the file and, where supported, parent directory are flushed.
Unsupported network, removable, or virtual filesystems MUST produce a warning
that crash-durability guarantees may be weaker.

Every operation captures one immutable plan containing validated paths,
the complete validated typed project configuration, recipient-set and membership-
policy digests, manifest state, open input file identity, and initial metadata.
It uses that snapshot throughout. The baseline digest MUST
be the digest of the exact bytes streamed into encryption or out of authenticated
decryption, never a separate preliminary pass. Same-handle identity/size/time
checks before and after streaming are only mutation detectors, not proof of an
atomic snapshot against an uncooperative writer. Detected mutation discards the
temporary output and reports a conflict. The GitSeal lock coordinates GitSeal
processes but is not treated as a lock on editors or other programs.

Temporary names, contents, identity material, and plaintext MUST never appear in
normal or debug logs. Cleanup failures may identify a path but not file content.

## 10. Local synchronization state

The state file is stored under the Git-local GitSeal directory and is never
committed. It contains whole-file digests only:

```yaml
version: 2
trusted_recipients_sha256: "..."
trusted_membership_policy_sha256: "..."
trusted_mappings_sha256: "..."
trusted_retained_safety_sha256: "..."
files:
  .env:
    plaintext_sha256: "..."
    ciphertext_sha256: "..."
```

All V1 digest constructions use SHA-256 and the exact serialization in Sections
4 and 7. Committed golden vectors cover recipient, recipient-set, membership-
policy, mapping, retained-safety, ciphertext, and local plaintext/ciphertext
forms before schema release. They are change-detection metadata, not encryption or authentication. Plaintext
digests remain local because low-entropy content can be guessable.

Local state schema version 2 adds the retained-safety trust pin. Legacy local
state version 1 is parsed only during the explicit project-trust migration and
is never silently upgraded by an ordinary command. Identity-selection and lock
record schemas remain independently versioned at 1.

Modification times MUST NOT determine synchronization state. Separate `age`
encryptions of the same input are expected to produce different ciphertext, so
ciphertext equality does not imply plaintext equality across encryptions.

### 10.1 State machine

Given a stored baseline and current digests:

| Plaintext changed | Ciphertext changed | State | Safe action |
|---:|---:|---|---|
| No | No | synchronized | none |
| Yes | No | plaintext changed | encrypt |
| No | Yes | incoming ciphertext | review and accept exact digest, then decrypt |
| Yes | Yes | conflict | refuse automatic action |

Additional states include missing plaintext, missing ciphertext, incoming
ciphertext requiring consent, invalid ciphertext, missing or mismatched manifest,
stale recipient set, untrusted mapping, unsafe Git attributes, missing identity,
identity-not-in-recipient-set, unauthorized identity, unmerged, busy/indeterminate,
and uninitialized state.

Before applying the table, the artifact bytes MUST match the committed manifest,
the manifest recipient digest MUST match the current semantic recipient set, and
effective Git attributes MUST be safe. Any failure is a bookkeeping
inconsistency, unsafe-input, or re-encryption-required state, not an ordinary
local synchronization change or proof of malicious authorship.

The four-row table applies only after a trusted baseline exists. It MUST NOT
authorize replacing an existing plaintext file merely because local plaintext
matches its old baseline and ciphertext changed. Any incoming, rolled-back, or
otherwise unfamiliar ciphertext first enters `incoming ciphertext requiring
consent`; automatic `sync` authenticates and reports it but does not publish
plaintext. The user must review the Git change and explicitly accept that exact
ciphertext digest before decryption may replace existing plaintext. A missing
plaintext may be restored under the first-run rule after all other validation.

Commands that require a multi-file snapshot acquire the same GitSeal lock used
by mutations, or wait for a documented bounded period. Contention returns
`busy/indeterminate`, not a manifest-integrity error. A mismatch is durable only
after a verification re-read while holding the GitSeal lock; the lock excludes
only cooperating GitSeal processes. External concurrent mutation remains a
conflict or indeterminate result. A separate generation counter is not used
because it would add another non-atomic file.

### 10.2 Establishing a baseline

When no baseline exists:

- Ciphertext exists and plaintext is absent: decrypt safely, then record both
  digests only after manifest and attribute validation.
- Plaintext exists and ciphertext is absent: report that encryption is needed;
  do not encrypt during `sync` without an explicit encrypt request.
- Both exist: decrypt ciphertext to a restrictive temporary sink or stream hash,
  compare its plaintext digest with the local plaintext, and establish a
  baseline only when they match.
- Both exist but differ: report a conflict and modify neither file.
- Neither exists: report missing files.

Comparison-only decryption MUST stream directly into a hash and discard writer;
it MUST NOT create another plaintext file.

### 10.3 Conflict resolution

`sync` MUST never resolve conflicts automatically.

An unmerged index for protected paths or GitSeal metadata is a separate state.
Ordinary mutation commands refuse it. The documented workflow serializes secret
edits where possible; otherwise the user explicitly chooses a reviewed side,
restores/decrypts it without overwriting the other side, incorporates the desired
plaintext changes, re-encrypts, then verifies the resolved prospective tree.
GitSeal never makes age encryption deterministic and never selects a merge side.

- `gitseal encrypt --force FILE` explicitly chooses local plaintext and replaces
  the ciphertext after recipient confirmation.
- `gitseal decrypt --force FILE` explicitly chooses ciphertext and replaces
  local plaintext after a clear warning.
- `--force` resolves which conflicting content wins; it never approves recipient
  trust, mapping trust, or unfamiliar ciphertext. The latter still requires the
  current exact digest through `--accept-incoming`.
- Forced operations MUST still use safe replacement and MUST update the baseline
  only after success.
- GitSeal MUST NOT create an automatic plaintext backup, because unmanaged
  backups create another secret copy.

## 11. Command semantics

### `gitseal init`

- Verify a non-bare Git worktree.
- Create valid configuration only when absent.
- Preserve valid existing configuration.
- Add only the managed `.gitignore` block.
- Add only the managed `.gitattributes` block.
- Never overwrite identity or project files silently.
- Support `--non-interactive` with explicit required flags.
- Be idempotent.

### `gitseal identity create|use|show`

- `create [--name NAME]` follows Section 6 and does not select, rotate, or replace
  an identity implicitly.
- `use NAME` validates a GitSeal hybrid identity and records only its local name/
  path selection in Git-local or user configuration, never tracked state.
- `show [--identity NAME]` displays storage path, canonical public recipient, and
  full fingerprint, never private material.
- Identity-aware commands use the local selection or an explicit
  `--identity NAME` override and never guess among identities.

### `gitseal member add|remove|list`

- `list` shows deterministic member IDs, names, full recipient fingerprints, the
  recipient-set fingerprint, and whether the explicitly selected identity is in
  the set; `--full` additionally shows canonical recipients.
- `add` and `remove` use the trust ceremony in Section 7 and never re-encrypt
  implicitly.
- A successful membership change marks every manifest entry with the old set as
  stale and reports the exact `gitseal encrypt --all` remediation. Completion is
  not claimed until every configured artifact is re-encrypted and verified.
- `remove` always warns that old commits/copies remain readable and that the
  underlying credential must be rotated when revocation is intended.

### `gitseal protect FILE`

- Validate the file and destination paths, mapping trust, recipient trust,
  acting-identity membership, ignore state, and tracked state before any write.
- If plaintext is present in the active index, refuse with no mutation and state
  plainly that ignore rules do not affect tracked files. If it exists in `HEAD`
  but the active index already stages its removal, proceed only after exact
  path-specific acknowledgement that the content was exposed and must be rotated;
  never print an unquoted repository-controlled path as a shell command.
- Register the mapping in project configuration.
- Add plaintext to the managed ignore block.
- Add the encrypted path to the managed binary-attributes block and verify the
  effective attributes with Git.
- Encrypt only after recipient trust is established.
- Create or update the corresponding manifest entry.

Individual configuration, ignore, and ciphertext writes are atomic, but a
multi-file transaction cannot be assumed. If a later step fails, the command
MUST report exactly what completed, leave a safe repairable state, and direct the
user to `status` or `doctor`. It MUST never roll back by deleting pre-existing
user data.

### `gitseal unprotect FILE`

- Remove only the protected-file mapping and manifest entry.
- Leave plaintext and ciphertext untouched.
- Never stage or delete either file.
- Move an existing plaintext path into `retained_safety.ignored_plaintext` and an
  existing or prospectively committed ciphertext path into
  `retained_safety.binary_artifacts`; managed protections remain derived and
  `doctor` reports these as safe orphans.
- Remove the ignore entry only when plaintext is absent or the user explicitly
  supplies `--make-trackable` and confirms the exact path. Non-interactive use
  requires that exact flag; a generic `--yes` is insufficient.
- Remove the binary attribute entry only after ciphertext is absent from both the
  worktree and prospective index/tree and the user supplies
  `--drop-artifact-protection` and confirms the exact retained path. A generic
  `--yes` is insufficient.
- A later invocation MAY name an already-retained plaintext path with the exact
  `--make-trackable PATH`, or an already-retained artifact path with the exact
  `--drop-artifact-protection PATH`. It MUST re-evaluate the same absence,
  prospective-index, effective-policy, and exact retained-safety acceptance
  conditions before removing only that retained entry. It MUST NOT require or
  modify an active mapping for this lifecycle step.
- Every addition or removal of a retained entry requires exact display and
  `--accept-retained-safety-changes`, bound to the post-operation retained-safety
  digest and complete canonical project snapshot. Mapping acceptance does not
  authorize retained-safety changes, and retained-safety acceptance does not
  authorize active mapping changes.

### `gitseal encrypt [FILE] [--all]`

- Encrypt only an explicit file, or with `--all`, every locally changed artifact
  and every artifact stale for the current recipient set. Thus `--all` is the
  normative re-encryption operation after membership changes.
- Validate recipient trust before any output replacement.
- Require the selected identity's recipient in the set and verify candidate
  header access before publication.
- Refuse unsafe effective Git attributes.
- Update the ciphertext and manifest entry from the same immutable operation
  plan, and report any partial multi-file completion.
- Refuse a synchronization conflict unless `--force` is supplied.
- Never modify or delete plaintext.

### `gitseal decrypt [FILE] [--all]`

- Decrypt configured ciphertext only.
- Refuse any destination tracked in `HEAD` or the active index and refuse an
  untrusted source/encrypted mapping; V1 has no overwrite-tracked escape hatch.
- Require an exact manifest/ciphertext match unless an explicit recovery flag is
  supplied with a warning that manifest bookkeeping is being bypassed.
- Refuse to overwrite changed plaintext unless `--force` is supplied.
- Require `--accept-incoming SHA256` for unfamiliar ciphertext even with
  `--force`; a generic confirmation cannot substitute for the current digest.
- Never stage plaintext.
- Never support plaintext-to-stdout in V1.

### `gitseal sync`

- Does not run Git commands that change repository state.
- Uses the state machine in Section 10.
- Validates manifest, recipient-set freshness, and Git attributes first.
- Restores missing plaintext after validation. Unfamiliar ciphertext never
  replaces existing plaintext until the exact incoming digest is explicitly
  accepted.
- `sync --accept-incoming SHA256 FILE` accepts only the currently observed exact
  artifact digest and exact configured destination after revalidation. A generic
  `--yes` or a stale digest is insufficient.
- Reports plaintext-only changes as requiring encryption.
- Refuses conflicts and partial ambiguity.
- A V1 invocation that would mutate more than one mapping MUST refuse before
  the first write and require one exact `FILE`. This conservative restriction
  remains until a reviewed whole-set transaction and partial-publication
  reconciliation protocol exists; it does not prevent project-wide status.

### `gitseal status [--json]`

- Uses content and baseline state, not timestamps.
- Reports every defined state deterministically.
- Reports each artifact whose recorded recipient set is stale after membership
  changes, including on a fresh clone.
- A successfully computed status exits 0 even when it reports conflict, stale,
  or incoming item states; nonzero means the command could not reliably
  determine status.
- JSON contains top-level `schema_version: 1` and no plaintext or private keys.
  `--schema-version 1` pins the requested schema and unsupported versions fail
  safely rather than silently changing shape.

### `gitseal doctor [--json]`

Checks Git, schemas, paths, identity location and permissions, recipients,
manifest consistency, ignore and attribute rules, tracked plaintext, ciphertext
shape, selected-identity self-membership and authenticated header access,
local-state validity, temporary files, lock health, and hook installation. The
default report calls the per-artifact result `header_decryptable`; it MUST NOT
call this full artifact decryptability. `--full-decrypt` MAY perform an explicitly
slow streaming authentication to EOF into a discard/hash sink. It MUST
distinguish errors from warnings and return documented exit codes.

`doctor --history` MAY perform the explicitly slower check for protected
plaintext paths or valid hybrid identities in an explicitly reported set of
reachable local objects, with replacement objects disabled. A clean result says
only “no match found in the scanned local scope”; it is not proof of no leak.
Output lists shallow/partial-clone limits, selected refs/reflogs, omitted remotes,
forks, pull-request refs, caches, unreachable objects, and server copies. A known
exposure always requires rotation guidance and never triggers automatic history
rewriting.

### `gitseal verify --source TREE [--json] [--require-project]`

This is the required non-secret CI validator. It MUST work from a bare repository
and read modes and blobs only from the exact selected tree. It reads no worktree
plaintext, identity, trust baseline, local state, or lock. `--require-project`
fails when the selected tree lacks canonical GitSeal metadata so deleting the
project cannot turn required CI into a successful no-op.

The command applies bounded parsing and rejects: any configured plaintext or
reserved `.gitseal.tmp.*` path in any mode; non-`100644` metadata/artifacts;
missing, malformed, noncanonical, or internally inconsistent schemas and managed
blocks; retained-safety mismatch; ignored metadata/artifacts; valid hybrid
native hybrid private identities in scanned regular blobs; unsafe attributes;
LFS pointers;
manifest/blob or recipient-set mismatch; and artifacts whose bounded native
stanza shape/type/count is invalid. Repository-only attributes and ignore rules
MUST be evaluated in a sanitized isolated Git context with system/global config,
Git-local attributes, replace refs, filters, and user programs disabled; `git
check-attr --source` alone is insufficient because it still consults local/global
attribute sources. Nested committed ignore rules must be evaluated with Git
semantics from that tree, not the live worktree.

It cannot prove recipient identities, sender authenticity, local recipient or
mapping trust, payload decryptability, plaintext freshness, identity storage,
active local overrides, or remote history. CI MUST run a trusted, pinned release
of the validator rather than build and trust validator changes from the pull
request being judged, and MUST validate the actual proposed merge or
`merge_group` tree, not only the contributor's head.

### `gitseal version`

Reports semantic version, source commit, schema/JSON compatibility ranges, and Go
version without machine-specific or wall-clock build time. Release time, if
shown, MUST derive deterministically from source metadata.

## 12. Git ignore and attribute management

### 12.1 `.gitignore`

GitSeal owns only this block:

```gitignore
# BEGIN GITSEAL
.gitseal.tmp.*
/.env
/config/private.json
# END GITSEAL
```

The reserved basename rule is mandatory in every initialized project and matches
temporary residues at any directory depth. Plaintext entries are root-anchored.
GitSeal MUST preserve all text outside the managed block, reject malformed or
duplicate managed blocks, and derive the deterministic block from the reserved
rule plus active and retained-safety plaintext paths.

Ignore status MUST be checked with Git itself, such as `git check-ignore`, not
with an incomplete custom matcher. Active-worktree checks use `--no-index -v -z
--non-matching --stdin`; tracking/index presence is checked separately. Every
active or retained plaintext and every possible temporary basename MUST be
ignored. Every ciphertext, `.gitseal/config.yaml`, `.gitseal/recipients.yaml`,
`.gitseal/manifest.yaml`, `.gitattributes`, and `.gitignore` MUST NOT be ignored.
Any failure blocks mutation and identifies the effective rule without weakening
unrelated user rules. Because `git add -f` bypasses ignore, hooks and tree
validation independently reject temporary paths and plaintext in every mode.

### 12.2 `.gitattributes`

Age output is binary and MUST reach the Git object database byte-for-byte.
GitSeal owns only this top-level block:

```gitattributes
# BEGIN GITSEAL
/.env.age -text -crlf -eol -ident -diff -merge -filter -working-tree-encoding
/config/private.json.age -text -crlf -eol -ident -diff -merge -filter -working-tree-encoding
# END GITSEAL
```

Entries MUST be exact, root-relative patterns with correct attribute escaping.
GitSeal MUST preserve all content outside its block and reject malformed or
duplicate blocks. Its sorted expected entries derive from every active artifact
plus `retained_safety.binary_artifacts`. When GitSeal writes a file it emits
canonical UTF-8 with LF; a working-tree check compares parsed canonical semantics
so platform line endings alone do not cause false failure, while an index/tree
check requires one canonical block and no extra/missing managed entry.

Before encryption and decryption it MUST use `git check-attr` to ensure effective
`text`, legacy `crlf`, `eol`, `ident`, `diff`, `merge`, `filter`, and
`working-tree-encoding` are each exactly `unset`. A `set` result, string value, or
`unspecified` result is unsafe. Existing `-eol` is therefore correct; `!eol`
would be unsafe, and `-crlf` is retained only as the documented legacy alias of
`-text`. Nearer files and `$GIT_DIR/info/attributes` can override the root block,
while global attributes still affect `--cached` and `--source`; neither option
alone proves repository-only semantics. Active local overrides are blocking
errors. Prospective-tree checks use the isolated context from `verify --source`.
Git LFS and every clean/smudge filter are outside V1. Unsafe transformation, an
LFS pointer, or a staged blob whose digest differs from the staged manifest
blocks publication.

## 13. Git hooks and tree guardrails

`gitseal hook run pre-commit` and `gitseal hook run pre-merge-commit` are stable
entry points and share the prospective-index validator.

Installation rules:

- For each of `pre-commit` and `pre-merge-commit`, install a small managed hook
  only when that hook is absent.
- If an installed hook is exactly GitSeal-managed, update it idempotently.
- If another hook exists or `core.hooksPath` is configured, do not overwrite or
  rename anything; print an integration command for the user or hook framework.
- Uninstall only an exact GitSeal-managed hook.
- Explain that local hooks are not cloned and each contributor must install one.

The hook MUST validate the exact active inherited index as required by Section 5,
including the temporary indexes used by `commit -a`, `-i`, and `--only` and the
linked-worktree index. It uses NUL-delimited Git output and blocks:

- invalid, deleted, or internally inconsistent staged GitSeal configuration,
  recipients, manifest, ignore rules, or attributes;
- a configured plaintext path present in the prospective commit tree, including
  one staged by force or represented as a symlink, submodule, or other mode;
- any reserved `.gitseal.tmp.*` path in the prospective tree in any mode;
- GitSeal configuration, recipients, manifest, or ciphertext represented by a
  symlink, submodule, executable blob, or any index mode other than regular
  non-executable `100644`;
- any introduced/changed regular blob containing a complete token accepted by
  `age.ParseHybridIdentity`, without printing the token or matching content;
- changed local plaintext whose staged encrypted blob is absent or decrypts to
  different content;
- a staged encrypted blob that is absent, malformed, transformed, inconsistent
  with the staged manifest, or stale for the staged recipient set;
- unmerged index entries for GitSeal metadata or protected paths.

Tier 1 always constructs and statically validates the prospective commit entirely
from index blobs, reusing the tree validator, then compares working-tree
plaintext digests with the local baseline. Tier 2 decrypts only an impacted
artifact: a protected plaintext changed and a matching artifact is staged, or
the artifact itself changed and local comparison is possible. Tier 2 is
mandatory when triggered, never prompts, and fails closed when the selected
identity is unavailable; it is not an opt-in safety reduction. A cache may avoid
repeat work only when keyed by immutable artifact blob ID, manifest/recipient
digests, selected public recipient, and validator version.

The hook parses
the staged configuration, recipients, manifest, `.gitignore`, and
`.gitattributes`, then validates staged encrypted blobs. Working-tree files are
consulted only for the additional stale-local-plaintext comparison. Partial
staging must therefore be safe. A mere text prefix such as `AGE-SECRET-KEY-` is
not sufficient to identify a key; tests and documentation may mention the
prefix. Native hybrid identities are currently 77 characters; tests MUST
generate and detect one at runtime rather than assume a length or HRP parser.

The hook MUST never modify files. It is a local guardrail, not a security
boundary: Git documents that pre-commit can be bypassed with `--no-verify` and
hooks are not cloned. Git also does not run these hooks for every rebase,
cherry-pick, revert, or `am` result. Public repositories MUST run the trusted
tree-only validator in required CI and protect the default branch.

## 14. Concurrency and locks

Mutating operations and consistent multi-file readers acquire a lock in the
Git-local GitSeal directory. The lock record includes a random token, process ID,
OS process creation/start identity, boot/session identity where needed, and
operation name.

- Lock acquisition MUST be atomic.
- Only the token owner may release the lock.
- A process ID alone is insufficient for stale detection because IDs are reused.
- Stale locks require conservative recovery and a diagnostic message.
- Read-only commands may avoid locks only when they do not require a consistent
  multi-file snapshot.
- Lock files are never committed.

Lock creation MUST use create-new/exclusive semantics. Authoritative process
absence, or a live PID whose process creation identity differs, proves the
recorded instance is gone; these conditions are alternatives, not cumulative.
Evidence that the recorded instance is still alive forbids removal and cannot be
overridden by confirmation. Permission denial or unknown platform state requires
explicit confirmation.
Immediately before removal GitSeal MUST reopen/re-read and match both the lock
file identity and random token. Lock metadata is untrusted and subject to strict
size and schema limits; a persistently reopenable “pidfd inode” is not assumed.

## 15. Error and output policy

Commands return stable categories:

```text
0 success
1 general failure
2 invalid or unsupported configuration
3 missing identity
4 identity not authorized
5 Git safety violation
6 encryption or decryption failure
7 synchronization conflict
8 filesystem safety violation
9 recipient trust required
10 busy or indeterminate snapshot
```

These categories describe why a requested operation could not complete, not
every state a read-only command can report. `status` follows its Section 11 exit
rule. `doctor` and `verify` exit 0 when their requested evaluation completed with
no blocking error (documented warnings remain structured warnings); otherwise
they return the most specific category under a documented stable priority while
JSON includes every finding. Hook entry points return the category that blocked
the prospective tree; a hook-specific or tree-specific number is unnecessary.
An unhandled panic is a defect and MUST be converted at the outer boundary to a
sanitized general failure after cleanup, never confused with a successful state.

Errors MUST identify the operation and affected path without including plaintext,
environment values, decrypted data, private identities, or key-file contents.
JSON mode MUST write machine output to stdout and diagnostics to stderr.
Interactive prompts are forbidden when stdin is non-interactive.

All repository-controlled strings, including member names, paths, Git errors,
and YAML diagnostics, are untrusted terminal input. Human output MUST escape or
replace control characters and ANSI escape sequences. JSON output MUST use a
real encoder. Secrets and private identities MUST never be accepted directly as
command-line flag values or environment variables because process listings,
shell history, CI logs, and crash reports can expose them.

### 15.1 Resource limits

Local policy defaults to a 1 GiB maximum ciphertext/plaintext size per file.
Tracked configuration may lower but never raise it. Raising it requires an
explicit local-only setting or per-command confirmation. Before decryption,
GitSeal MUST reject an artifact above the local limit and SHOULD check available
space, while documenting that free-space checks cannot guarantee against quotas
or concurrent consumption.

All parsing, Git subprocess output, recipient counts, file counts, path lengths,
and diagnostic aggregation require explicit bounds. Hashing and identity scans
MUST stream. Context cancellation and user interruption must close handles,
remove only unpublished temporary files created exclusively by that invocation,
report cleanup failures, and leave old destinations intact for failures before
the publication call. Cleanup on a catchable failure is best effort; crash or
power-loss residue remains diagnosable and is never deleted blindly. After a
Windows publication call, documented partial-failure states override the general
pre-publication guarantee: GitSeal reconciles every expected name by open file
identity/digest and reports a recovery state. If an implementation needs an
ephemeral replacement backup, it is an internal random reserved-name file—not a
user-facing plaintext backup—and receives the same restrictive permissions,
ignore/tree-block rules, reconciliation, and ownership-safe cleanup lifecycle.

### 15.2 Compatibility

Every JSON document has an integer `schema_version`; consumers can request a
supported version and unknown versions fail explicitly. An unsupported tracked
document error MUST name the document, encountered schema version, current tool
version, and safe upgrade path without attempting a rewrite. Local-state
migration is transactional and backward recovery is documented separately from
tracked-schema compatibility.

GitSeal's current V1 product boundary uses project configuration schema 2,
recipient and manifest schemas 1, local synchronization state schema 2, and
selection/lock schemas 1. A legacy project configuration at schema 1 MUST be
migrated only by:

```text
gitseal init --upgrade-project-trust \
  --accept-retained-safety EXACT_64_LOWERCASE_HEX_DIGEST
```

Without the exact digest, the command prints the canonical active mappings,
both retained categories, and their exact digests, returns trust-required, and
writes nothing. With acceptance, it acquires the project lock, refuses unmerged
state, rereads and strict-parses the exact legacy bytes, rechecks the digest,
binds the complete canonical project snapshot displayed by that invocation,
and publishes project schema 2 first. It then migrates an absent or legacy
state to schema 2 while preserving baselines and existing trust pins and adding
only the accepted retained-safety pin. If local-state publication fails after
the tracked schema update, the command reports partial completion; rerunning
the same exact acceptance completes the repair. State MUST NOT be written first.
Unknown versions, malformed legacy schemas, and changed review snapshots refuse
without reinterpretation.

During v0.x, tracked schemas, JSON, flags, and exit categories may change only
with release notes and safe rejection by older tools. Before v1.0, the project
MUST publish compatibility ranges and deprecation policy for each of those four
surfaces. A `min_tool_version` field is not required and cannot make an old
parser understand an unknown future schema.

## 16. Threat model additions

Documentation MUST cover:

- repository disclosure and accidental publication;
- compromised machines and authorized malicious developers;
- historical access after recipient removal;
- repository/configuration tampering and malicious recipient additions;
- mapping retargeting and why mappings require a separate local trust pin;
- valid-ciphertext substitution because encryption does not prove authorship;
- recipient-manifest falsification because anonymous age stanzas do not prove
  the recorded recipient set;
- rollback to old valid ciphertext;
- why unfamiliar ciphertext requires explicit acceptance before overwriting
  existing plaintext;
- harvest-now/decrypt-later risk and why V1 uses only hybrid recipients;
- anonymous/unauthenticated header metadata before header-MAC verification;
- filename, file-size, and change-frequency leakage;
- plaintext in editor backups, swap, crash dumps, logs, build artifacts,
  containers, antivirus, search indexes, filesystem snapshots, and cloud sync;
- ignored crash-temporary residues and forced staging despite ignore rules;
- plaintext identities on unencrypted or backed-up storage and why GitSeal cannot
  portably attest full-disk encryption or backup exclusion;
- denial of service from malformed, deeply nested, or oversized inputs;
- repository-controlled terminal escape sequences and Git pathspec injection;
- symlink, junction, mount-point, hard-link, alternate-data-stream, and TOCTOU
  filesystem attacks;
- Windows replacement preserving a prior DACL or named stream and documented
  partial-failure states;
- malicious dependencies, compromised CI actions, and substituted release
  binaries;
- local hook bypass with `--no-verify` and clones that lack installed hooks;
- randomized binary merge conflicts and explicit/serialized resolution;
- CI tree validation versus the deliberately out-of-scope delivery of production
  secrets;
- inability to guarantee secure deletion on journaling, copy-on-write, flash,
  backup, and synchronized filesystems;
- private keys and plaintext temporarily existing in process memory;
- Git hosting, branch, and commit authorization remaining outside GitSeal.

## 17. Required tests

Every security-sensitive component requires unit tests and end-to-end tests.

### Cryptography and identity

- one and multiple native hybrid recipients;
- rejection of classical, SSH, passphrase, plugin, and mixed recipient types;
- canonical parse-to-`String()` equality, uppercase/whitespace rejection,
  deterministic order, and committed fingerprint/set-digest golden vectors;
- exact native stanza argument/body shape, type/count bounds, huge/duplicate/
  unknown/greased/truncated/armored headers, and the distinction between
  unauthenticated inspection, header-MAC verification, and payload EOF;
- a wrapper attempting to bypass age recipient labels cannot enter the typed
  hybrid-recipient boundary;
- authorized and unauthorized identities;
- acting identity absent from the effective set refuses every encryption before
  mutation and the produced candidate unwraps with the acting identity;
- corrupted and truncated ciphertext;
- empty, Unicode, binary, and reasonably large files;
- repeated encryption;
- identity create without overwrite, final-path reopen/parse/recipient equality,
  permission recheck, round-trip self-test, and invocation-owned cleanup;
- private key never printed or logged;
- a runtime-generated native hybrid identity is detected by the repository
  scanner while prose containing only an identity prefix is not;
- file keys/plaintext are streamed without `io.ReadAll` or string conversion and
  are never logged/serialized, without claiming complete memory erasure;
- permissions on supported platforms;
- interoperability in both directions with the official age v1.3 CLI and
  published format test vectors;
- no production code path imports or executes the age plugin package.

### Synchronization

- all four baseline states;
- first-run baseline cases;
- missing files and identity;
- recipient changes received through Git;
- project mapping changes received through Git and retargeting a decryption to a
  tracked or otherwise untrusted destination;
- stale recipient-set detection from a committed manifest on a fresh clone;
- `encrypt --all` re-encrypts every stale artifact after add/remove and no stale
  entry remains;
- manifest tampering and acknowledgement that it is evidence, not proof;
- unfamiliar and rolled-back ciphertext cannot overwrite existing plaintext
  without acceptance of the exact digest;
- conflicts refuse modification;
- unmerged metadata/artifacts refuse ordinary mutation and follow the explicit
  resolution workflow;
- read-only multi-file snapshots return busy/indeterminate under contention and
  do not mislabel a transient partial update as corruption;
- both force-resolution directions;
- state written only after successful replacement;
- randomized ciphertext does not create false plaintext changes;
- branch switches, rebases, linked worktrees, and source mutation during an
  operation preserve the correct state-machine result;
- the baseline hashes exactly the streamed bytes under a hostile concurrent
  writer, aborting when mutation is detected without claiming an atomic snapshot;
- `status` exits 0 for successfully reported problem states and JSON schema
  negotiation rejects unsupported versions.

### Filesystem and configuration

- traversal and absolute paths;
- portable path-profile violations, device names, alternate streams, case-fold
  collisions, and Unicode/control-character rejection;
- symlinks, junctions, reparse points, mount boundaries, hard links, and
  destination replacement races;
- root-handle identity mismatch, worktree-root rename/replacement, and the exact
  GO-2026-4970 final symlink plus trailing-slash regression;
- source/destination and cross-entry collisions;
- unknown YAML fields, multiple documents, aliases, anchors, tags, merge keys,
  duplicate keys/recipients, deep nesting, and oversized config;
- project/state version-1 migration preview and exact acceptance; omission/null
  rejection for required collections; separate retained-category digest golden
  vectors; configuration-first partial repair; downgrade, unknown-version,
  unmerged, stale-review, and zero-write refusal cases;
- interrupted writes, close failures, read-only directories, and disk-full
  simulation where practical;
- Windows replacement semantics, reviewed sharing-violation retries, cancellation,
  documented `ReplaceFileW` partial-failure states, and prohibition of
  cross-volume copy/delete fallback;
- NTFS DACL and named-stream preservation is detected and final plaintext policy
  is verified before and after replacement;
- temporary plaintext permissions, fixed reserved prefix, permanent ignore,
  crash residue diagnostics, hook/tree rejection, and ownership-safe cleanup;
- regressions for relevant Go `os.Root` path-escape advisories and the minimum
  patched toolchain floor;
- local file-size limits, cancellation, and bounded subprocess output;

### Git behavior

- outside repository and bare repository;
- linked worktree paths;
- tracked plaintext;
- `protect` performs zero writes when plaintext is in the active index and uses
  the exact acknowledgement path when `HEAD` exposure is staged for removal;
- symlink, submodule, executable, and other unexpected index modes for protected
  paths and GitSeal-owned metadata;
- ignore patterns, nested negations, ignored GitSeal metadata/control files,
  malformed managed blocks, deterministic retained-safety derivation, and forced
  staging of ignored temporary/plaintext paths;
- unsafe attributes, filters, line-ending transforms, LFS pointers, and nested
  or Git-local attribute overrides;
- every managed attribute result (`unset`, `set`, value, `unspecified`) across
  live, cached, source, global, and info contexts, plus isolated tree evaluation;
- staged plaintext, a checksum-valid staged native hybrid private identity, and partially
  staged config/manifest/ciphertext/ignore/attribute combinations;
- prospective-index validation when working-tree metadata differs;
- existing hook and `core.hooksPath` preservation;
- normal commit, `-a`, `-i`, `--only`, amend, linked-worktree commit, clean and
  conflicted merge, rebase, cherry-pick, revert, and `am`, asserting validation
  saw the exact committed or proposed index and that `pre-merge-commit` is wired;
- `--no-verify` is documented and required CI catches the same tree-level
  violations;
- `verify --source` in bare SHA-1 and SHA-256 repositories, `--require-project`
  after metadata deletion, actual PR merge/merge-group trees, and a validator
  binary that cannot be replaced by the untrusted change being judged;
- skip-worktree, assume-unchanged, sparse-checkout, object replacement refs, and
  exact-case/casefold collisions on GitSeal control paths;
- shell/pathspec metacharacters are never executed or interpreted;
- a repository-local fake `git` executable and a `PATH` change between Git
  calls cannot redirect subprocess execution;
- poisoned Git environment variables and terminal escape sequences are rejected
  or safely encoded.
- `unprotect` keeps existing plaintext ignored unless exact, explicit approval
  makes it trackable and retains binary attributes while ciphertext exists;
- history diagnostics accurately report shallow/partial/ref/reflog scope and
  never turn a clean local scan into a no-leak claim;

Tests MUST run with race detection where supported. Parsers and path validators
MUST be fuzz-tested with alias/anchor/depth/duplicate/tag/multidocument/size
corpora, and output tests MUST inject secret canaries into every error/log/JSON
path. The synchronization state machine MUST have model-based/property tests.
CI MUST run on real Linux, macOS, and Windows
runners. Security-critical filesystem tests MUST exercise NTFS, APFS, and a
mainstream Linux filesystem before a stable release; emulation alone is not
sufficient.

## 18. Implementation structure

```text
cmd/gitseal/               program entry point
internal/cli/              argument parsing and presentation
internal/app/              use-case orchestration
internal/projectconfig/    strict tracked schemas
internal/manifest/         deterministic artifact bookkeeping
internal/localstate/       baselines, trust digest, and locks
internal/agefile/          typed streaming engine and bounded header inspection
internal/identity/         local identity lifecycle
internal/safefile/         path validation and atomic replacement
internal/gitrepo/          direct Git command adapter
internal/gitignore/        managed block operations
internal/gitattrs/         binary artifact attributes
internal/hooks/            hook checks and installation
internal/treeverify/       isolated exact-tree validation for hooks and CI
internal/status/           state calculation
tests/integration/         temporary-repository workflows
```

Packages MUST be small and concrete. There is no public `pkg/` API in V1. Core
services return typed results and errors; only the CLI layer prompts or formats
output.

## 19. Development order

### Phase 0: security foundation

- lowercase canonical module `github.com/raydalsayf/gitseal` and CLI shell (the
  repository display-name case may remain unchanged);
- freeze framed digest constructions with committed golden vectors;
- strict configuration, manifest, portable-path, and resource validation;
- safe-file writer, exact stream hashing, rooted-handle binding, Windows
  DACL/named-stream checks, and local-state/lock storage;
- unit, fuzz, hostile-race, and platform failure-path tests for that foundation.

### Phase 1: core vertical slice

- typed hybrid engine, bounded structural inspection, identity round-trip
  self-test, and acting-identity self-membership;
- `init`, `identity`, `member`, `protect`, `encrypt`, and `decrypt`;
- recipient and mapping trust baseline;
- managed ignore/attribute blocks and pre-mutation tracked-plaintext refusal;
- two independent identities completing an exact binary round trip;
- committed manifest and safe effective `.gitattributes`;
- unauthorized and corrupted ciphertext leaving no plaintext output.

### Phase 2: state and team workflow

- synchronization state machine;
- `sync`, `status`, and `doctor`;
- conflict and first-run tests.

### Phase 3: Git safety

- isolated `verify --source` before any hook integration;
- exact-active-index pre-commit and pre-merge-commit checks;
- existing-hook integration behavior and required merge-tree CI.

### Phase 4: release hardening

- complete cross-platform and failure-injection matrix;
- documentation and examples;
- dependency, static, CodeQL, and vulnerability checks;
- reproducible release artifacts, SBOMs, checksums, and provenance attestations;
- independent security-focused review.

Security primitives such as atomic replacement, permissions, path validation,
and symlink rejection are Phase 0 requirements, not deferred hardening.

### 19.1 Reproducible release mechanics

Release CI MUST select one exact supported patched Go toolchain from a verified
distribution and set `GOTOOLCHAIN=local`; a `toolchain` directive alone is not a
pin when automatic switching is allowed. Dependency materialization uses a
controlled proxy/checksum policy and `go mod verify`; the subsequent build is
offline with `GOPROXY=off` and `-mod=readonly`.

Each comparison build starts from a freshly materialized exact signed tag/tree,
rejects modified or untracked build inputs, uncontrolled local `replace`
directives, and dependencies outside the module graph, and uses fresh isolated
`GOCACHE`, `GOMODCACHE`, temporary directory, and `GOENV` plus an allowlisted
`GOFLAGS`/environment. Injected commit metadata is derived from that exact tree,
not the developer worktree.

Builds use `-trimpath`, `-buildvcs=false`, fixed reviewed linker flags, and
`CGO_ENABLED=0` where the target is supported without C code. Version and source
commit are injected deterministically from the selected tag/commit; wall-clock
build time is omitted. `SOURCE_DATE_EPOCH`, archive entry order, timestamps,
owners, modes, and compression settings are fixed from source metadata. Two
clean independent environments build every binary and normalized archive and
compare final SHA-256 values. Provenance then binds the published artifacts,
source, dependency graph, toolchain, and build instructions. If a supported
target cannot use `CGO_ENABLED=0`, the C compiler, linker, SDK/sysroot, versions,
and relevant flags are pinned and recorded in provenance.

## 20. Public-release gate

The repository MUST NOT be presented as production-ready until all of these are
true:

- all required commands used in the documented quick start are implemented;
- Linux, macOS, and Windows CI pass;
- tests in Section 17 pass, including failure paths;
- release builds use at least patched Go 1.26.6 and reviewed
  `filippo.io/age` v1.3.1, or later secure compatible versions;
- `go test`, race tests where supported, `go vet`, formatting, `govulncheck`, and
  a selected static analyzer pass;
- relevant Go standard-library vulnerabilities, including `os.Root` regressions,
  are absent from the build toolchain;
- dependencies are pinned and automated update review is configured;
- the documented minimum Git version is feature-tested, and all supported Git
  builds receive vendor security updates;
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, architecture,
  getting-started, security, threat-model, limitations, compatibility,
  identity-backup/recovery, credential-rotation/incident-response, and release-
  verification documents exist;
- vulnerability reports have a private channel;
- GitHub Actions use least-privilege permissions, third-party actions pinned to
  full commit SHAs, no untrusted fork code in privileged workflows, and protected
  release environments;
- dependency review, Dependabot alerts/updates, secret scanning or equivalent,
  and CodeQL are enabled where the hosting plan supports them;
- release binaries include version metadata, SHA-256 checksums, an SPDX or
  CycloneDX SBOM, and verifiable build-provenance attestations;
- two clean builds with the same source, dependency graph, and toolchain are
  reproducible under Section 19.1 or every remaining nondeterministic field is
  documented and accepted before prerelease;
- the default branch requires reviewed pull requests and passing security checks;
- required CI uses a trusted pinned validator and checks actual merge and
  merge-group trees;
- the README clearly distinguishes alpha, beta, and stable status;
- a security-focused human review has examined filesystem and hook behavior;
- a separate reviewer has performed an identity backup-and-recovery drill;
- real secrets have not been used during development or examples.

V0.x releases may be public for testing when labeled clearly as pre-release.
V1.0 requires stronger compatibility guarantees and should follow independent
security review. Publishing source code is not itself a claim that the software
is safe for production secrets.

## 21. Explicitly deferred work

Classical X25519 migration, SOPS, structured partial encryption, SSH identities,
passphrase-protected identities, plugins, keychain integrations, GitHub key
discovery, Git LFS, environment groups, recipient groups, `exec`, cloud KMS,
desktop and editor interfaces, SaaS, RBAC, SSO, telemetry, and automatic secret
rotation are outside V1.

Per-artifact manifests, trial of multiple local identities, dry-run for every
mutation, and CI/production private-identity injection are also deferred. A
future dry-run cannot establish trust or promise that a later execution sees the
same filesystem/repository state.

SOPS is not modeled as a drop-in engine because its structured-file behavior and
metadata differ from opaque age files. A future design may add capabilities and
configuration versioning after the age workflow is stable.

## 22. Final acceptance scenario

V1 is complete when two clean user profiles can perform this workflow on each
supported operating system:

1. User A creates an identity and repository configuration.
2. User B independently creates an identity.
3. User A verifies User B's full recipient fingerprint over an independently
   authenticated channel, explicitly adds it, and both users confirm that their
   selected identity is in the effective set.
4. User A protects and encrypts an arbitrary binary file.
5. Only configuration, public recipients, manifest, managed ignore/attributes,
   and ciphertext are committed.
6. User B clones, decrypts, and obtains byte-for-byte identical plaintext.
7. An unauthorized identity fails without creating or altering plaintext.
8. An unfamiliar incoming ciphertext cannot replace existing plaintext without
   explicit acceptance of its exact digest; conflicting changes never overwrite.
9. The hooks and required trusted merge-tree validator block staged plaintext,
   temporary plaintext, native hybrid private identities, unsafe attributes, and stale or
   inconsistent ciphertext from their respective observable scopes.
10. Recipient removal warns about history; `encrypt --all` re-encrypts every stale
    artifact, and actual credential rotation occurs where revocation is intended.
11. A fresh clone detects a stale artifact recipient set without relying on
    uncommitted state.
12. Official age tooling can decrypt the artifact with the hybrid identity, so
    GitSeal remains unnecessary for emergency data recovery. The recipe writes
    to a new explicit file with `age -o`; it warns that official age does not
    apply GitSeal's mapping, manifest, or safe-replacement checks.

The governing principle is: GitSeal must make the safe workflow simpler while
refusing to guess whenever guessing could disclose or destroy protected data.
