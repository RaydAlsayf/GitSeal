# Compatibility Policy

GitSeal is pre-alpha (`0.x`). Compatibility surfaces may change before V1.0,
but changes must be documented, reject unsafe input explicitly, and provide a
recovery or migration path where state would otherwise be stranded.

## Current floors and formats

| Surface | Current declaration |
| --- | --- |
| Go module | `github.com/raydalsayf/gitseal` |
| Go release floor | 1.26.6 or a later project-reviewed supported security patch |
| Git feature floor | 2.43.0, plus current vendor security support |
| age dependency | `filippo.io/age` 1.3.1 |
| Cryptographic recipient | Native ML-KEM-768/X25519 hybrid only |
| Project configuration | Version 2; version 1 is migration-only |
| Recipients and manifest | Version 1 |
| Git-local synchronization state | Version 2; version 1 is migration-only |
| Identity selection and lock records | Version 1 |
| JSON documents | `schema_version` 1 |
| CLI release | `0.1.0-pre` in the current source |

A feature-compatible but unsupported Go or Git build is not sufficient for a
release. The floor may be raised in response to security advisories and must
never be lowered merely for convenience.

The Go 1.26.6 pin was raised after fresh vulnerability data reported an
imported-package standard-library advisory and additional module advisories in
Go 1.26.5. The official archive used for local validation was matched against
the SHA-256 published by `go.dev`; every release still requires the exact
reviewed toolchain and a fresh complete validation matrix.

## Tracked documents

`.gitseal/config.yaml`, `.gitseal/recipients.yaml`, and
`.gitseal/manifest.yaml` use strict, bounded versioned schemas. Unknown fields,
duplicate keys, aliases, tags, merge keys, noncanonical values, and unsupported
versions are rejected. Older tools must fail safely on a newer schema; they must
not rewrite it into an older approximation.

Tracked-schema changes require canonical golden vectors, release notes, and a
separate migration design. Project schema 2 adds persistent retained-safety
trust without changing the active mapping-digest domain. A project schema 1
file is accepted only by `gitseal init --upgrade-project-trust`; preview without
the exact displayed `--accept-retained-safety` digest writes nothing. Project
schema 2 is published before local state so an older strict tool immediately
refuses the repository. The module path and digest domain/framing rules are
protocol commitments and cannot change silently.

## Local state

Trust pins, identity selection, baselines, and locks live under the worktree-
specific Git directory and are not portable tracked state. Synchronization
state version 2 contains separate recipient-set, membership-policy, active-
mapping, and retained-safety trust pins. Legacy state version 1 is parsed only
during the explicit project migration; baselines and existing trust pins are
preserved. A configuration-first partial migration is repairable by rerunning
the same exact acceptance. Unknown versions refuse instead of resetting trust.

No compatibility promise is made for copying local state between worktrees,
accounts, filesystems, or operating systems.

## JSON and exit behavior

Every machine-readable document includes integer `schema_version: 1`. The
current `status` command accepts `--schema-version 1` and rejects unsupported
requests. Other JSON-producing commands report their schema version but do not
yet negotiate alternate versions.

Stable exit categories currently are:

| Code | Category |
| ---: | --- |
| 0 | Success |
| 1 | General failure |
| 2 | Invalid configuration |
| 3 | Missing identity |
| 4 | Unauthorized identity |
| 5 | Git safety failure |
| 6 | Cryptographic failure |
| 7 | Conflict |
| 8 | Filesystem safety failure |
| 9 | Explicit trust required |
| 10 | Busy or indeterminate lock state |

During `0.x`, fields, flags, state names, and exit categories may change only
with release notes and safe rejection by older tools. Consumers must ignore
human-readable wording as an API and must not infer success from output text.

## age interoperability

GitSeal emits standard randomized age files using the official native hybrid
recipient implementation. A compatible official age CLI can decrypt an
artifact with the matching hybrid identity to a newly named file. This provides
emergency format interoperability only: age does not understand GitSeal's
manifest, mapping trust, destination safety, baselines, or replacement policy.

GitSeal V1 intentionally rejects classical X25519-only, SSH, passphrase, plugin,
KMS, and general recipient wrappers. Adding those is a scope and compatibility
change, not graceful degradation.

## Operating systems and filesystems

The design targets Linux, macOS, and Windows. A platform is supported only after
real OS and filesystem tests pass; compilation alone is not support. Windows
sensitive identity and plaintext operations currently fail closed. Network,
synchronized, backup, FUSE-style, and unusual filesystems may weaken durability
or identity guarantees and require explicit validation or refusal.

## Deprecation before V1.0

A deprecated surface must be announced in release notes with its security
rationale, affected versions, replacement, migration steps, and last supported
release. Security-critical rejection may be immediate when accepting old input
would be unsafe. V1.0 compatibility promises will be published only after the
release gate and independent implementation review are complete.
