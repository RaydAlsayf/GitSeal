# Security Policy

GitSeal is pre-alpha software. It has no production-ready release and must not
be used with real credentials or other irreplaceable secrets. Passing tests or
successfully decrypting a file is not a claim that the full security boundary is
complete.

For the implemented boundary and known blockers, read
[the implementation status](IMPLEMENTATION-STATUS.md),
[the threat model](docs/threat-model.md), and
[the limitations](docs/limitations.md).

## Supported versions

No version is currently supported for production use.

| Version | Security support |
| --- | --- |
| Unreleased pre-alpha worktree | Best-effort review and testing only |
| Published releases | None |

The project will publish an explicit support policy before a stable release.

## Reporting a vulnerability

Do not include a private identity, plaintext secret, exploit payload containing
real data, or sensitive repository details in a report.

Use GitHub's private vulnerability-reporting form for this repository if the
Security tab offers it. If no private reporting channel is available, open a
minimal public issue asking the maintainers to establish a private channel; do
not disclose vulnerability details in that issue. This repository does not
currently publish an alternative private reporting address, so the absence of a
private channel is itself a release-process blocker.

Include, when safe:

- the affected GitSeal revision and Go, Git, operating-system, and filesystem
  versions;
- a minimal reproduction using generated test identities and synthetic data;
- the expected and observed fail-closed behavior;
- whether plaintext, identity material, a Git object, or only public metadata is
  involved; and
- any evidence that a supposedly bounded parser, rooted path, publication step,
  hook, or exact-tree check was bypassed.

Do not test against repositories or systems you do not own or have explicit
authorization to assess. Maintainers should coordinate disclosure only after a
fix and affected-boundary analysis are ready; no response-time or remediation-
time guarantee is offered during pre-alpha development.

## Security boundary

GitSeal's intended V1 boundary is workstation-side whole-file encryption with
the official `filippo.io/age` native ML-KEM-768/X25519 hybrid recipient type.
Tracked configuration, repository paths, Git output, age headers, and terminal
text are hostile input. Private identities and plaintext remain local and are
not delivered to CI or production.

GitSeal does not claim:

- sender authentication or proof that a displayed member controls a recipient;
- revocation of access to ciphertext or Git history already obtained;
- secure deletion, complete memory erasure, or protection from a compromised
  endpoint;
- detection of full-disk encryption, backups, snapshots, swap, editor copies,
  or synchronization services; or
- that hooks cannot be bypassed.

All Windows publication and the sensitive identity boundary currently refuse
operation because DACL, named-stream, identity-bound replacement/cleanup, and
partial-failure reconciliation are not complete and proven on real NTFS. POSIX
local-state and lock mutation also refuse because exact-inode unlink cannot be
proven with the current protocol. Those refusals must not be weakened into a
best-effort write or pathname delete.

## Handling test material

Generate identities at test runtime. Never commit a native hybrid private
identity, a production credential, or plaintext copied from a real system.
Fixtures that resemble keys must be intentionally invalid and clearly labeled.
Before sharing logs, review them for paths, Git diagnostics, environment data,
plaintext, and private identity tokens.

## Security-sensitive changes

Changes to cryptography, canonical digests, strict schemas, path validation,
filesystem publication, identity storage, Git invocation, hook behavior,
exact-tree validation, release workflows, or trust prompts require focused
adversarial tests and implementation-oriented human review. See
[CONTRIBUTING.md](CONTRIBUTING.md) and
[release verification](docs/release-verification.md).
