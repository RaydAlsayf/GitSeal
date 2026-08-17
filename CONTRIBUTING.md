# Contributing to GitSeal

GitSeal is a security-sensitive pre-alpha project. Contributions are welcome,
but a build or test pass is not enough to establish a security property. Keep
changes small, reviewable, and explicit about which boundary they affect.

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development prerequisites

- Go 1.26.6 or a later supported security patch accepted by the project;
- Git 2.43.0 or later, with a vendor-supported security update stream; and
- a disposable repository and runtime-generated test identities.

The module path is `github.com/raydalsayf/gitseal`. Do not change its case or
introduce a second module identity.

## Security constraints

- Do not commit real secrets, credentials, static private identities, or output
  that embeds them.
- Use only the official `filippo.io/age` APIs and the native
  ML-KEM-768/X25519 hybrid recipient. Do not add plugins, classical recipients,
  SSH recipients, passphrases, KMS, SaaS, or a new cryptographic format.
- Do not add plaintext-to-standard-output behavior or log private identity or
  plaintext bytes.
- Treat configuration, repository paths, Git output, headers, and terminal text
  as hostile.
- Never resolve a secret merge conflict automatically or make `.gitignore` the
  sole protection for a tracked plaintext file.
- Preserve fail-closed Windows behavior until sensitive DACL, named-stream,
  rooted replacement, and documented partial-failure semantics pass real NTFS
  tests and focused review.
- Do not weaken size, count, schema, path, permission, or subprocess bounds to
  make a test pass.

Read [SPECIFICATION.md](SPECIFICATION.md),
[SECURITY-REVIEW.md](SECURITY-REVIEW.md),
[AUDIT-DISPOSITION.md](AUDIT-DISPOSITION.md), and [README.md](README.md) in full
before changing a security boundary. When documents disagree, retain the
stricter safe behavior and document a genuine contradiction.

## Change workflow

1. Identify the normative specification section and any accepted `GS-*`
   finding affected by the change.
2. Add failure-path and adversarial tests before or with the implementation.
3. Keep presentation code separate from cryptography, Git, identity,
   filesystem, schema, and tree-verification boundaries.
4. Run the strongest applicable local validation and state what could not be
   run on the current operating system.
5. Update documentation and `IMPLEMENTATION-STATUS.md` without turning a
   partial result into a security claim.

For ordinary Go changes, run at least:

```text
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
go mod verify
git diff --check
```

Run `govulncheck ./...` when the tool is available. Parser and path changes need
bounded fuzzing. Git changes need disposable-repository integration tests for
normal commits, `-a`, `-i`, `--only`, amend, linked worktrees, merges, rebase,
cherry-pick, revert, `am`, and `--no-verify`. Platform publication changes need
real filesystem tests on every claimed platform; cross-compilation is not a
substitute.

## Dependencies and automation

Prefer the standard library and already reviewed dependencies. A new dependency
needs a documented purpose, license review, vulnerability review, maintenance
assessment, and pinned module checksum. Third-party GitHub Actions must use
reviewed full commit SHAs and least-privilege permissions. Untrusted pull-request
jobs must remain separate from privileged release jobs.

## Pull-request notes

Explain:

- the security invariant and threat addressed;
- specification and audit-finding coverage;
- tests run, with exact commands and operating systems;
- skipped, emulated, or compile-only checks; and
- compatibility, recovery, or migration impact.

Do not include a production-readiness claim. Cryptography, filesystem, Git tree,
and supply-chain changes should receive an independent specialist review.

Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public patch that
reveals a still-exploitable issue.
