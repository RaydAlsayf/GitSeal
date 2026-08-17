# Limitations

GitSeal is pre-alpha and is not ready for real secrets. The current worktree
implements important foundations, but the V1 release gate is not complete. See
[implementation status](../IMPLEMENTATION-STATUS.md) for a code-and-test
inventory.

## Current implementation blockers

- Linux and macOS create-if-absent publication uses an atomic no-replace
  rename, but replacement of an existing destination deliberately fails
  closed. Independent review found that the prior exchange/cleanup design
  could delete or lose a raced editor object. No native ext4/APFS runtime test
  has yet validated even the reduced create-only boundary.
- Windows private identity creation/loading and sensitive plaintext publication
  fail closed. Public publication also now refuses before making a destination
  visible because conditional replacement and identity-bound temporary cleanup
  are not implemented. DACL creation and validation, alternate/named stream
  inspection, handle-relative replacement, and partial-failure reconciliation
  need real NTFS implementation and fault testing.
- Linux and macOS local-state writes and lock acquisition fail before mutation.
  Portable POSIX APIs cannot atomically unlink a directory entry only if it
  still names the exact opened inode, so exact lock release and conservative
  stale-lock recovery require a reviewed protocol redesign and native tests.
- Exact-tree validation contains an isolated evaluator for effective committed
  Git attributes and nested ignore files. Targeted, worktree, bare-repository,
  and Windows hook/Git-matrix tests pass, but implementation review and native
  Linux/macOS execution remain. The pull-request/merge-group workflow
  intentionally fails closed until an independently reviewed validator binary
  is pinned.
- Native Linux and macOS filesystem tests and real unsandboxed Windows NTFS
  security tests have not been evidenced for this worktree. Linux/macOS
  cross-compilation is compile-only evidence; the Windows Git hook matrix is not
  evidence for the missing DACL/stream/publication boundary.
- Present managed-hook removal fails closed because the current portable APIs
  cannot unlink an exact open file identity atomically. New-hook installation
  also fails closed on Windows until atomic no-replace publication is added.
- The retained-safety trust-model contradiction is resolved in the source
  design with project schema 2, local-state schema 2, a separate canonical
  retained-safety digest, exact acceptance, and explicit version-1 migration.
  Successful end-to-end migration cannot yet be exercised because the platform
  lock/publication boundaries remain closed, and independent compatibility
  review is still required.
- Release provenance, reproducible artifacts, checksums, SBOMs, protected
  environments, branch controls, and a second-person recovery drill remain
  release-gate items unless independently demonstrated.
- The bounded local history diagnostic checks configured plaintext path names
  and scans every reachable local blob selected by `--all` refs for a complete
  checksum-valid native hybrid private identity. It fails if its count, byte,
  subprocess, or time budget cannot complete. It still cannot cover external
  clones, omitted refs, forks, pull-request refs, host caches, backups, or
  unreachable objects.

## Product limitations by design

- Encryption is whole-file. Ciphertext is intentionally randomized, so ordinary
  text diffs and merges are ineffective and repeated encryption changes bytes.
- GitSeal does not authenticate a sender and cannot prove that a human controls
  a listed recipient. Verify full fingerprints out of band.
- Member removal does not revoke old ciphertext or history. Re-encrypt all
  artifacts for the new set, and assume removed recipients retain anything they
  previously obtained.
- Filenames, paths, file sizes, member IDs, recipient count, and repository
  history remain visible.
- Client hooks are local and bypassable. They do not cover every rebase,
  cherry-pick, revert, or `am` result.
- GitSeal does not inject secrets into CI or production and does not provide
  KMS, plugins, passphrase identities, SSH recipients, a GUI, SaaS, telemetry,
  policy servers, partial-file encryption, or automatic conflict resolution.
- Plaintext is exposed to applications that open it. Editors, shells, build
  tools, swap, crash dumps, backups, sync agents, malware, and a compromised OS
  can copy it.
- GitSeal cannot prove full-disk encryption, backup exclusion, secure deletion,
  complete memory erasure, or removal of all historical/external copies.
- Local trust state and digests detect changes; they are not signatures and do
  not survive a fully compromised local account.

## Operational consequences

Do not place real data into this pre-alpha implementation. Use generated test
identities and synthetic plaintext in disposable repositories. Keep an
independently tested offline identity backup before relying on encrypted data;
GitSeal creates no automatic backup. For recovery outside GitSeal, the official
age CLI can decrypt to a newly named file, but it does not enforce GitSeal's
mapping, manifest, trust, destination, or publication checks.

Never treat a clean `doctor`, history scan, hook, or CI run as proof that a
secret was never exposed. If exposure is known or suspected, rotate the
underlying credential and follow [incident response](incident-response.md).
