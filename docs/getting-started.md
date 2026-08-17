# Getting Started (Pre-Alpha Test Data Only)

GitSeal is not ready for production secrets. Use a disposable repository,
synthetic plaintext, and runtime-generated test identities. Existing-file
replacement currently fails closed on Linux and macOS after an independent
race review; POSIX locks and local state also fail before mutation. All Windows
publication plus the identity, state, and lock boundary fails closed. The
workflow below documents the intended V1 interface; it is not currently
available end to end on any platform.

Read [the limitations](limitations.md) and
[the threat model](threat-model.md) before running the tool.

## Build from the current worktree

Use Go 1.26.6 or a later project-reviewed supported security patch and Git
2.43.0 or later with vendor security updates.

```text
go mod verify
go test ./...
go build -trimpath -o gitseal ./cmd/gitseal
./gitseal version --json
```

This local build is not an authenticated release. `source_revision` may be
`unknown`, and no production assurance follows from a successful build.

## Create a disposable project

The following mutating steps are an interface preview. A safety refusal is the
expected result when the command reaches an unavailable publication boundary;
do not bypass it.

Run these steps in a new repository containing only synthetic data:

```text
git init gitseal-demo
cd gitseal-demo
gitseal init
gitseal identity create --name alice
gitseal identity use alice
gitseal identity show
```

Identity output includes a public recipient and complete fingerprint, plus the
private file's path. It never prints private material. Before depending even on
test ciphertext, perform the procedure in
[identity backup and recovery](identity-backup-recovery.md).

Add Alice as a recipient only after comparing the complete fingerprint over an
authenticated channel independent of the repository:

```text
gitseal member add --id alice --name Alice --recipient RECIPIENT --accept-fingerprint FULL_FINGERPRINT
gitseal member list --full --identity alice
```

`--accept-fingerprint` must exactly equal the complete grouped fingerprint
derived from the canonical recipient; a mismatch refuses before publication.
It records a security assertion, not proof that GitSeal authenticated the
person. Do not copy both recipient and fingerprint solely from an untrusted
branch and call that independent verification.

## Protect synthetic plaintext

Create `demo-secret.bin` with random or otherwise non-sensitive test bytes, then
run:

```text
gitseal protect demo-secret.bin --accept-recipients --accept-mapping-changes --accept-retained-safety-changes
gitseal status
gitseal doctor --full-decrypt
```

The default artifact is `demo-secret.bin.age`. `protect` must refuse if the
plaintext is already in the active index. If the path appears in `HEAD`, it also
requires exact exposure acknowledgement after reviewing whether the underlying
credential would need rotation. Do not use that acknowledgement as a shortcut
for real exposed data.

Review the tracked set before committing:

```text
git status --short
git check-ignore -v -- demo-secret.bin
git diff -- .gitseal/config.yaml .gitseal/recipients.yaml .gitseal/manifest.yaml .gitignore .gitattributes
```

Only public policy, manifest data, managed ignore/attribute rules, and
ciphertext belong in Git. Never stage `demo-secret.bin`, a file beginning
`.gitseal.tmp.`, or any identity file.

Install both local guards with:

```text
gitseal hook install
```

Hooks are defense in depth. They are not cloned, can be bypassed with
`--no-verify`, and do not cover every Git history-rewriting operation. New hook
installation fails closed on Windows, and present-hook removal fails closed on
every platform pending an identity-bound deletion primitive. A trusted exact-
tree validator is still required, and that CI boundary is not complete in the
current pre-alpha worktree.

After making a test commit, inspect that exact tree:

```text
gitseal verify --source HEAD --require-project
```

The present validator checks static invariants and has a candidate isolated
evaluator for effective committed attributes and nested ignore files. That new
boundary has targeted local test evidence only and the trusted CI gate still
fails closed until a reviewed validator is pinned. Treat a clean local result as
scoped diagnostic evidence, not release approval.

## Update plaintext or recipients

After changing synthetic plaintext, run:

```text
gitseal encrypt demo-secret.bin
```

After a reviewed recipient-set change, re-encrypt every stale artifact:

```text
gitseal encrypt --all --accept-recipient-changes
```

Encryption is randomized; different ciphertext is expected even for identical
plaintext. The selected acting identity must be in the effective recipient set.

## Recover in another clean profile

Restore or independently create an authorized test identity through the
reviewed recovery/member workflow. In a fresh clone, select it and explicitly
accept the exact configured mappings after review:

```text
gitseal identity use bob
gitseal decrypt demo-secret.bin --accept-mapping-changes --accept-retained-safety-changes
```

If existing plaintext is unfamiliar, GitSeal requires acceptance of the exact
observed ciphertext SHA-256 with `--accept-incoming`. If plaintext and
ciphertext both changed, stop and choose a side manually; GitSeal will not merge
or overwrite automatically.

GitSeal refuses one `sync` invocation that would mutate more than one mapping.
Name one exact file until a reviewed whole-set transaction protocol exists.

`decrypt` never writes plaintext to standard output. The destination must be
untracked, absent from `HEAD`, within the rooted worktree, and safely
publishable with sensitive permissions.

## Remove protection

`unprotect` changes tracked mapping policy but does not delete, stage, or make
files public automatically:

```text
gitseal unprotect demo-secret.bin --accept-mapping-changes --accept-retained-safety-changes
```

By default, ignore protection is retained while plaintext exists and binary
attribute protection is retained while the artifact exists or is staged. Use
the explicit removal flags only after reviewing those exact conditions.

For a legacy project schema 1 repository, preview and then explicitly migrate
retained-safety trust:

```text
gitseal init --upgrade-project-trust
gitseal init --upgrade-project-trust --accept-retained-safety EXACT_DISPLAYED_SHA256
```

The preview writes nothing. Ordinary commands reject schema 1 rather than
silently adding a new local trust meaning.

## Before reporting a result

State the GitSeal source revision, OS, filesystem, Go and Git versions, exact
commands, and whether tests were native, emulated, cross-compiled, skipped, or
unavailable. Never report this pre-alpha workflow as secure or production-ready.
