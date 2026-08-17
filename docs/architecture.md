# Architecture

GitSeal V1 is a local, whole-file encryption workflow around Git. Its security
design separates hostile repository input, local trust state, private identity
material, streaming cryptography, rooted file publication, and exact Git object
inspection. The current implementation remains pre-alpha; see
[implementation status](../IMPLEMENTATION-STATUS.md) for verified and missing
pieces.

## Boundary overview

```text
command presentation
        |
        v
internal/app ---------------> local Git-only state and locks
   |       |                         (.git/gitseal)
   |       +----> bounded Git subprocess / exact object readers
   |       +----> strict tracked YAML and canonical digests
   |       +----> native-hybrid age engine
   |       +----> rooted candidate writer / publication
   |
   +---- tracked public policy and ciphertext in the worktree
   +---- local private identity outside the repository
```

The orchestration layer may combine these boundaries, but it must not reparse
private keys, invoke general age plugins, perform ad hoc path joins, or bypass
publication checks.

## Data and trust locations

Tracked repository data includes `.gitseal/config.yaml`,
`.gitseal/recipients.yaml`, `.gitseal/manifest.yaml`, encrypted artifacts,
`.gitignore`, and `.gitattributes`. It is public, reviewable policy input—not a
trust anchor. Canonical recipient-set, membership-policy, active-mapping, and
retained-safety digests are accepted into local state only after exact review.
Project schema 2 makes the retained policy a separately pinned tracked trust
surface; legacy schema 1 is migration-only so older tools fail safely.

The per-worktree Git directory holds local state, selected identity name,
baselines, and a conservative lock under `git rev-parse --git-path gitseal`.
Plaintext digests in this state are change detectors, not cryptographic proof.
They must never enter tracked configuration.

Private native-hybrid identities live outside the repository in an
OS-appropriate per-user location. On Windows the intended base is
`FOLDERID_LocalAppData`. The implementation currently refuses identity creation
and loading because protected-directory DACL, file DACL, and named-stream
validation are unfinished.

## Implemented package boundaries

| Package | Responsibility |
| --- | --- |
| `internal/strictyaml` | Bounded YAML decoding, typed schemas, and unknown-field rejection |
| `internal/digest` | Exact streaming SHA-256 and domain-separated framed digests |
| `internal/pathpolicy` | Portable repository-relative path grammar |
| `internal/projectconfig`, `internal/manifest` | Canonical tracked schemas and semantic validation |
| `internal/agefile` | Typed native ML-KEM-768/X25519 recipient and identity wrappers, stanza inspection, streaming encryption/decryption |
| `internal/safefile` | Rooted reads, candidate files, identity checks, hashing, and platform publication policy |
| `internal/identity` | Named identity location, generation, final-path validation, and round-trip self-test |
| `internal/gitrepo` | Resolved bounded Git execution, active-index handling, attributes/ignore checks, and exact object streaming |
| `internal/localstate`, `internal/status` | Trust pins, baselines, conservative locks, and digest-based synchronization states |
| `internal/treeverify` | Identity-free index/tree validation of tracked control files and artifact bookkeeping |
| `internal/app` | Use-case orchestration and partial-operation reporting |

## Cryptographic flow

Recipient text is strictly parsed by the official `filippo.io/age` native
hybrid API and reserialized to one canonical form. GitSeal sorts and deduplicates
canonical recipients and computes domain-separated digests. An acting identity
must derive a recipient present in the accepted set before encryption begins.

Encryption streams plaintext into a random age file. Before publication, the
candidate is reopened, its native stanza count/type/shape is bounded, and the
candidate header is authenticated with the acting identity. Decryption writes
only to a sensitive candidate and consumes the payload through EOF so the age
payload authentication tag is checked. There is no plaintext-to-standard-output
application path.

The age format authenticates ciphertext integrity, not the human sender. Trust
in a recipient fingerprint must be established independently of the repository.

## Publication flow

The writer opens a rooted directory boundary, validates every relevant path and
file identity, creates a same-directory candidate in the fixed
`.gitseal.tmp.*` namespace, writes and hashes the exact stream, flushes and
closes it, and reopens it for validation. A platform publication is enabled
only when the required primitive and reconciliation are available; there is no
truncation or copy/delete fallback.

Control-file, ciphertext, and plaintext updates are multiple independent file
publications. GitSeal reports completed steps if a later step fails; it does not
claim a cross-file atomic transaction. Reserved temporary residue is never
silently deleted. A failed candidate is retained and reported when GitSeal
cannot prove an identity-bound cleanup, because deleting a substituted pathname
would be worse than leaving a bounded ignored residue.

Linux uses `renameat2(RENAME_NOREPLACE)` and macOS uses
`renameatx_np(RENAME_EXCL)` for create-if-absent publication through a bound
parent. Existing-destination replacement is currently disabled on both after
independent review found an unsafe final cleanup/rollback race. This is a
deliberate release-blocking loss of functionality, not a completed Unix
publication boundary.

On Windows, all publication is deliberately unavailable after review found
that public create/update paths still required an identity-check-to-pathname-
cleanup step or unconditional replacement. Sensitive candidate creation is
rejected before temporary allocation. No tracked control, ciphertext,
plaintext, private identity, local state, or lock may be published until DACLs,
alternate/named streams, handle-relative conditional replacement, destination
identity, and documented `ReplaceFileW` partial-failure states are implemented
and tested on real unsandboxed NTFS.

POSIX exact-identity unlink is also unavailable through the current portable
interfaces. Local-state writes and lock acquisition therefore fail before
mutation on Linux and macOS; invocation-owned candidate residue is preserved
rather than risking deletion of a substituted pathname. This containment is a
release blocker, not a completed locking design.

## Git boundary

Git is resolved once to an absolute executable outside the repository. Calls
use argument arrays, a bounded timeout and output, literal pathspecs, disabled
replacement objects, no prompts or pager, and a sanitized environment. GitSeal
checks the inherited active index only for supported worktree-local commit-index
forms and refuses unmerged entries rather than selecting a side.

Hooks are advisory local guardrails and can be bypassed. The compensating
boundary is identity-free validation of the exact prospective tree in a trusted
environment. The `treeverify` package validates canonical control data,
mappings, artifacts, hashes, native header shape, tracked plaintext, modes, and
private-identity tokens. Its invocation-owned isolated-repository evaluator
handles effective committed attributes and nested ignore files without mutating
the source repository. Targeted, exact-tree, bare-repository, and Windows Git
matrix tests pass; native Linux/macOS execution and implementation-focused
review remain required. The checked-in exact-tree workflow
intentionally fails until an independently reviewed validator binary is pinned,
so the trusted CI claim remains blocked.

A retained orphan artifact has no manifest recipient-set claim and cannot be
re-encrypted after its active mapping is removed. Exact-tree validation therefore
requires a canonical native-hybrid shape with a bounded historical stanza count
of 1 through 32, independent of the current recipient count. That check does not
claim freshness, recipient uniqueness, or current-member access.

## Failure model

Ambiguity is a refusal, not a prompt to guess. GitSeal refuses unmerged state,
unfamiliar ciphertext replacement without its exact digest, untrusted recipient
or mapping changes, tracked plaintext destinations, unsafe attributes, unknown
schema fields, path aliases, changed file identity, and uncertain lock recovery.
It never resolves a secret merge conflict automatically.
