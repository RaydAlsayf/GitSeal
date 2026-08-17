# Credential Rotation and Incident Response

GitSeal encrypts files; it does not revoke or rotate the credentials stored in
those files. When plaintext or a private identity is exposed, rotate the
underlying service credential first where operationally possible, then restore
repository confidentiality for future ciphertext.

This is pre-alpha guidance for synthetic test incidents. Windows sensitive
identity and plaintext operations remain unavailable, and no production
response should depend on this implementation.

## Immediate actions

1. Stop automatic encryption, decryption, commits, merges, and releases for the
   affected repository. Preserve evidence without copying plaintext or private
   identities into tickets or logs.
2. Identify the affected plaintext paths, ciphertext artifacts, identities,
   recipient sets, commits, branches, tags, pull-request refs, releases,
   worktrees, clones, backups, and hosting copies.
3. Revoke or rotate the actual credential at its issuing service. Do not assume
   deleting a Git branch, removing a recipient, or re-encrypting a file revokes
   an already copied secret.
4. If a workstation or identity may be compromised, isolate that endpoint and
   use a known-clean machine. Treat every ciphertext addressed to the identity
   as readable by the attacker.
5. Record exact GitSeal, Go, Git, OS, filesystem, repository-tree, manifest, and
   ciphertext digests. Record no plaintext values or private tokens.

## Rotate an identity while it is still recoverable

Use a disposable test repository first. Replace `newname`, IDs, and recipients
with reviewed values.

1. Create `newname` on a clean supported workstation and make a tested offline
   backup following [identity backup and recovery](identity-backup-recovery.md).
2. Compare its complete public fingerprint through an authenticated channel
   independent of the repository.
3. Add the new recipient with a new stable member ID and exact
   `--accept-fingerprint FULL_FINGERPRINT` value after independent verification.
4. Run `gitseal encrypt --all --accept-recipient-changes` using a still-
   authorized selected identity. This intermediate generation lets the new
   identity decrypt every active artifact.
5. On the clean profile, run `gitseal doctor --identity newname --full-decrypt`
   and test byte-for-byte decryption of synthetic data.
6. Select the new identity with `gitseal identity use newname`.
7. Remove the compromised member only after another verified identity can
   decrypt every artifact. Acknowledge the history warning explicitly.
8. Run `gitseal encrypt --all --accept-recipient-changes` again so every active
   artifact excludes the old recipient. Verify manifest ciphertext and
   recipient-set digests, then run full payload diagnostics.

If the old identity is unavailable and no remaining authorized identity can
decrypt an artifact, it cannot be rotated by GitSeal. Recover plaintext from a
tested backup or another authorized recipient. Never add a fabricated manifest
entry or weaken decryption checks to hide the loss.

## Plaintext committed to Git

Assume the plaintext reached every clone, fork, pull-request ref, cache, backup,
and log that could observe the commit. Immediately rotate external credentials.
The local history diagnostic has a deliberately limited scope and a clean result
does not prove absence.

History rewriting may reduce reachable references but is a separate,
destructive repository-administration operation. Coordinate it with the host and
all collaborators, preserve legal/audit obligations, and obtain explicit
authorization before rewriting or force-pushing. GitSeal never performs this
automatically and cannot prove that uncontrolled copies were removed.

## Suspicious incoming ciphertext or policy

Do not accept an unfamiliar ciphertext merely because it decrypts. Age does not
authenticate its human sender. Preserve the observed ciphertext SHA-256,
candidate tree ID, mapping digest, recipient-set digest, and membership-policy
digest, then verify the change through an authenticated channel. Acceptance
must name the exact incoming ciphertext digest.

For a recipient or mapping change, compare the complete canonical fingerprint
or path change independently. A fingerprint copied from the same untrusted
branch is not independent verification. If both local plaintext and ciphertext
changed, retain both and resolve manually; GitSeal must not select a side.

## Suspected implementation or supply-chain compromise

Stop using the binary. Preserve its exact bytes, SHA-256, provenance evidence,
source revision, module graph, SBOM, and the exact candidate tree. Verify with a
separate trusted machine and report the issue through
[the security policy](../SECURITY.md). Do not run untrusted pull-request code in
a privileged release context.

## Closure criteria

An incident may be operationally contained when underlying credentials are
rotated, all current artifacts are encrypted to a reviewed set, a clean
authorized identity authenticates payloads through EOF, affected trees are
blocked from merge, and known distribution points are addressed. Closure still
does not establish deletion of historical or external copies. Document that
residual risk explicitly.
