# Release Verification

There is no production-ready GitSeal release to verify. Source code, a passing
test suite, or a checksum published beside a binary does not by itself
authenticate that binary. The procedure below defines evidence required for a
future pre-release or stable release; missing evidence is a failed verification,
not an optional warning.

The checked-in release workflow is currently review-only: it has read-only
repository permission, uploads short-lived review artifacts, and then
deliberately fails. It does not create a tag, GitHub release, SBOM, provenance,
attestation, signature, or published binary. No current artifact should be
treated as an official GitSeal release.

## Required release artifacts

For every supported OS and architecture, a release must provide:

- a versioned binary or normalized archive with deterministic version and source
  revision metadata;
- a SHA-256 checksum manifest;
- an SPDX or CycloneDX SBOM;
- verifiable build-provenance attestations binding source, dependency graph,
  toolchain, build instructions, and artifact digest;
- release notes naming schema, JSON, CLI, exit-code, dependency, and security
  changes; and
- reproducibility results from two clean independent builds, or an explicit
  prerelease exception describing every differing field.

The source must be an exact reviewed signed annotated tag/tree. Release
workflows must use a
verified exact Go toolchain with `GOTOOLCHAIN=local`, reviewed module checksums,
offline `-mod=readonly` builds after dependency materialization, fresh caches,
`-trimpath`, `-buildvcs=false`, fixed linker flags, and no wall-clock timestamp.
Archives require deterministic ordering, timestamps, owners, modes, and
compression settings.

## Verification procedure

1. Obtain artifacts and evidence from the project's official GitHub release
   page over an independently trusted connection. Do not follow a link supplied
   only by an untrusted repository change.
2. Confirm the tag and source commit were reviewed and that the repository name
   and lowercase module path are exact.
3. Hash the downloaded artifact locally. On Unix-like systems use an available
   SHA-256 utility; on PowerShell use:

   ```text
   Get-FileHash -Algorithm SHA256 -LiteralPath .\gitseal-artifact
   ```

   Compare every hexadecimal digit with the authenticated checksum manifest.
4. Verify GitHub artifact attestation against the expected repository, when
   attestations are published:

   ```text
   gh attestation verify gitseal-artifact --repo RaydAlsayf/GitSeal
   ```

   Inspect the returned subject digest, source repository, workflow identity,
   commit, and signer. A release must also publish the expected signer workflow;
   constrain it with `--signer-workflow` during verification. Do not accept an
   attestation for another fork or workflow.
5. Inspect the SBOM for the exact Go toolchain and dependency versions. Confirm
   `filippo.io/age` and `go.yaml.in/yaml/v3` match the reviewed release policy
   and that no plugin or unexpected cryptographic dependency is present.
6. Run `gitseal version --json` and compare `version`, `source_revision`, schema
   ranges, and Go version with the tag, attestation, and release notes. An
   `unknown` source revision is not acceptable in a release artifact.
7. Verify the release notes' compatibility and migration instructions before
   opening any existing repository or identity.
8. Rebuild twice from clean exact-source environments using the documented
   build recipe and compare final SHA-256 values. A local match strengthens
   reproducibility evidence but does not replace provenance or review.

The current official syntax and identity-validation behavior are documented in
the [GitHub CLI `gh attestation verify` manual](https://cli.github.com/manual/gh_attestation_verify).

## Trusted tree validation

Release eligibility also depends on a trusted, pinned GitSeal validator checking
the exact pull-request merge tree and merge-group tree. The validator binary and
workflow must come from a protected trusted source, not from the untrusted
change being evaluated. Record the exact validator digest and verified tree ID.

The current exact-tree implementation includes a candidate isolated evaluator
for effective committed attributes and nested ignore files. This boundary is
still incomplete until focused review, native cross-platform tests, and a
separately reviewed pinned validator replace the workflow's deliberate
fail-closed step.

The trusted check must be emitted only by its dedicated expected-source GitHub
App, must use the exact pull-request merge or `merge_group` SHA, and must invoke
`--require-project`. Candidate code or a candidate-controlled workflow cannot
approve itself. Ordinary CI, CodeQL, and dependency-review checks must also run
on `merge_group` before they can be required with a merge queue. Candidate and
CodeQL workflows now declare that trigger, but no real merge-group execution,
check context, source App, or `head_sha` has been observed in this local run.

## Repository-control evidence

Before release, apply and independently verify every control in
[Repository Security Settings](repository-security-settings.md). That document
defines the exact default-branch and release-tag rulesets, two-person review,
empty routine bypass list, expected check sources, Actions SHA/permission
policy, protected release environment, security features, read-only API audit,
and negative enforcement tests.

For each release record the ruleset and App IDs, exact check names and sources,
pull-request merge SHA, merge-group SHA, release tag, environment approval,
ruleset/audit-log bypass review, and UTC observation time. A screenshot or a
workflow file is not proof that a mutable GitHub setting was active. No setting
was changed or verified during the 2026-08-17 local implementation pass.

## Platform evidence

Require native test results for Linux, macOS, and Windows. Cross-compilation and
emulation must be labeled as such. Windows release evidence must include real
NTFS fault tests for DACLs, named streams, directory/destination identity,
sharing violations, read-only files, replacement success, every documented
partial-failure state, and unsupported filesystem refusal.

## When verification fails

Do not execute the artifact against an identity or repository. Preserve the
download, digest, provenance output, and source metadata without secrets, and
report the discrepancy under [the security policy](../SECURITY.md). Do not
repair a checksum, substitute an unsigned binary, or lower the toolchain floor.
