# Threat Model

This document describes the intended GitSeal V1 security boundary and its
current pre-alpha limitations. It is not an assurance statement. Read
[implementation status](../IMPLEMENTATION-STATUS.md) and
[limitations](limitations.md) before testing the tool.

## Assets

- plaintext protected files on a developer workstation;
- native ML-KEM-768/X25519 private identities;
- integrity of recipient, membership, mapping, and artifact bookkeeping;
- exact bytes proposed for a Git commit or merge tree; and
- local trust decisions and plaintext/ciphertext synchronization baselines.

## Adversaries and hostile inputs

GitSeal assumes repository contents may be malicious, including configuration,
paths, symlinks, Git attributes, ignore rules, ciphertext headers, manifests,
and commit history. Git output, subprocess errors, environment variables,
filesystem metadata, lock files, and terminal text are also untrusted.

Relevant adversaries include a contributor controlling a branch or pull
request, an attacker who changes repository policy before a user encrypts, a
local process racing filesystem operations, and a compromised dependency or CI
action. Accidental user errors—committing plaintext, losing an identity,
accepting the wrong digest, or resolving a ciphertext conflict incorrectly—are
also in scope.

## Intended protections

- Whole-file encryption uses only the official age native
  ML-KEM-768/X25519 hybrid recipient type and random age encryption.
- Strict schemas, canonical forms, domain-separated digests, bounded parsing,
  and exact hashes make reviewed policy changes distinguishable.
- Active mappings and retained orphan safeguards have separate canonical trust
  digests. Project schema 2 and explicit migration prevent an older strict tool
  from silently accepting a retained-safety change it cannot pin.
- Encryption requires the acting identity to belong to the accepted recipient
  set and authenticates the candidate header before publication.
- Decryption authenticates the payload through EOF and never writes plaintext to
  standard output.
- Rooted file access, portable paths, candidate files, restrictive permissions,
  identity checks, and failure reconciliation aim to prevent path-race and
  partial-publication mistakes.
- Exact-digest consent prevents unfamiliar incoming ciphertext from silently
  replacing existing plaintext. A changed plaintext and changed ciphertext is a
  conflict, never an automatic merge.
- Tracked-plaintext checks do not rely on `.gitignore`. Hooks provide local
  warnings, while trusted exact-tree CI is intended to validate the actual
  merge or merge-group tree without private identities.
- Bounded Git execution and terminal escaping limit subprocess, pathspec, output,
  and presentation attacks.

## Explicit non-guarantees

GitSeal does not provide sender authentication. A valid age file proves
integrity for an authorized recipient, not which person or machine produced it.
A recipient string or repository member ID does not prove control of a private
identity; fingerprints must be verified through an authenticated independent
channel.

Removing a member affects only future encryption after all artifacts are
re-encrypted. It cannot revoke ciphertext or Git history the member already has.
GitSeal does not protect a machine after its identity or plaintext is
compromised, and it does not replace credential rotation at the underlying
service.

GitSeal does not claim secure deletion, complete memory erasure, tamper-proof
local state, secrecy of filenames or file sizes, mergeable encrypted content,
or protection from traffic and repository metadata. It cannot portably detect
or control editor backups, swap, crash dumps, build outputs, full-disk
encryption, cloud synchronization, snapshots, backups, forks, caches, or copies
outside the scanned repository.

Private identities and plaintext are deliberately out of scope for CI and
production delivery. Those environments need a dedicated secret manager.

## Platform boundary

Linux and macOS require real filesystem tests for rooted path identity,
permissions, hard links, symlinks, mount changes, publication, crash behavior,
and durability. Cross-compilation alone establishes none of those properties.
Create-if-absent currently uses an atomic no-replace rename, while replacement
of an existing destination fails closed because a reviewed race-safe displaced-
object cleanup strategy is not available.

Windows is a current release blocker. Sensitive publication and identity use
must refuse until protected DACL creation and validation, alternate/named stream
checks, rooted destination binding, same-volume replacement, sharing behavior,
and every documented partial-failure state are reconciled and tested on real
NTFS. Public publication is also disabled because its prior conditional-cleanup
and replacement proof was insufficient. No copy/delete or truncation fallback
is acceptable.

On POSIX, lock/local-state mutation is disabled because the current protocol
cannot atomically unlink only the exact acquired inode. Unknown ownership or
stale state is preserved, not guessed. This blocks normal mutation until a
reviewed protocol and native race tests exist.

## Git and CI boundary

Client hooks are bypassable with `--no-verify` and are not invoked by every Git
operation. A public repository therefore needs a trusted, pinned validator that
checks the exact pull-request merge tree and merge-group tree. Validator code
from the untrusted change being judged cannot be the trust anchor. A candidate
isolated exact-tree evaluator for effective committed attributes and nested
ignore rules is present, but it needs focused review and native platform tests.
The checked-in security-gate workflow deliberately fails closed because no
independently reviewed validator artifact is pinned, and repository settings
have not been proven here.

## Supply-chain boundary

A source checkout, checksum, or clean local test run does not authenticate a
release. Stable distribution requires reviewed pinned dependencies and Actions,
least-privilege workflows, separation of untrusted and privileged jobs,
reproducible-build evidence, checksums, an SBOM, provenance attestations,
protected release environments, and independent verification. Those controls
must be evidenced, not inferred from configuration text.

## Response to known exposure

Assume exposed plaintext and credentials have escaped GitSeal's boundary.
Rotate the underlying credential, assess all repository and hosting copies, and
follow [incident response](incident-response.md). History rewriting can reduce
some references but cannot prove that external copies no longer exist.
