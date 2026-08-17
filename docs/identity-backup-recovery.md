# Identity Backup and Recovery

GitSeal creates no automatic private-identity backup. Losing the only identity
that can decrypt an artifact can make its plaintext unrecoverable. A backup is
therefore an availability requirement, but copying an identity creates another
high-value plaintext key file.

This procedure is for generated test data during pre-alpha development. It must
be exercised by a second person on each supported operating system before any
stable release. Windows identity creation and use currently fail closed and the
Windows procedure cannot be approved until the DACL and named-stream boundary
is implemented and tested on real NTFS.

## What must be backed up

`gitseal identity show --json` reports the selected identity's local path,
canonical public recipient, and full fingerprint. It does not print the private
identity. On Unix-like systems, named identities are files under the OS user
configuration directory in `GitSeal/identities`; the directory must be mode
`0700`, each file must be mode `0600`, and the file must have one hard link.
Windows is intended to use `FOLDERID_LocalAppData`, not roaming AppData.

The private file contains one canonical native-hybrid identity token followed
by a line feed. Do not open it in an editor, paste it into a shell, place it in
an environment variable, attach it to an issue, or copy it into the repository.

## Backup procedure

1. Create a new test identity with `gitseal identity create --name NAME` and
   record only the public recipient and full fingerprint from the command's
   output.
2. Locate the private file through `gitseal identity show --identity NAME
   --json`. Do not print its contents.
3. Copy the file using an OS facility that preserves exact bytes to offline
   removable media or an offline backup repository protected by independently
   reviewed encryption and access control. GitSeal does not provide or attest
   that protection.
4. Keep the backup disconnected when not being tested. Store any recovery
   instructions separately from the device and limit access to people who are
   authorized recipients.
5. Validate that the source identity still loads and that its reported public
   fingerprint equals the independently recorded fingerprint.
6. Perform the recovery drill below before relying on the backup. A successful
   copy operation alone is not recovery evidence.

Full-disk encryption is recommended for every machine and backup medium, but
GitSeal cannot detect or prove it. GitSeal also cannot prove that cloud sync,
enterprise backup, snapshots, antivirus, indexing, or removable-media tooling
did not create another copy.

## Recovery drill

Use a separate disposable OS account or clean test machine, not the profile that
created the identity.

1. Install the exact reviewed GitSeal build and verify it as described in
   [release verification](release-verification.md).
2. Determine the identity path for the intended name without exposing the
   private bytes. Restore the backup as a new file; never overwrite an existing
   identity.
3. On a supported Unix-like system, ensure the identity directory is mode
   `0700`, the restored file is mode `0600`, it is a regular non-symlink file,
   and it has one hard link. Use only platform tools whose semantics you
   understand. The future Windows procedure must create and verify the required
   protected DACL and reject named streams; do not substitute inherited ACLs.
4. Run `gitseal identity show --identity NAME` and compare the complete
   fingerprint over the independent record. A mismatch is a failed recovery.
5. In a disposable repository containing synthetic ciphertext, run `gitseal
   doctor --identity NAME --full-decrypt`. This authenticates each payload
   through EOF into a discard sink without creating plaintext.
6. Decrypt a test artifact to its configured, previously absent destination and
   compare its exact SHA-256 and bytes with the original synthetic fixture.
7. Record the GitSeal revision, OS, filesystem, date, tester, and result without
   recording private material or plaintext.
8. Remove the disposable profile and test plaintext using normal platform
   procedures. Do not claim secure deletion.

If the restored identity fails permission, link, schema, recipient, or round-
trip validation, stop. Do not relax validation or rewrite the file in place.

## Emergency interoperability

The official age CLI for a compatible native-hybrid release can recover an age
artifact without GitSeal. Write to a new explicit path, for example:

```text
age -d -i PATH_TO_IDENTITY -o NEW_RECOVERY_FILE ARTIFACT.age
```

Do not use `-o -`, shell redirection, or an existing destination. The age CLI
does not apply GitSeal's mapping trust, manifest hash, tracked-destination,
rooted-publication, permission, or synchronization checks. Independently verify
the artifact and recipient before using this escape hatch.

## Lost or exposed identity

If all authorized identities are lost and no tested backup can decrypt the
ciphertext, GitSeal has no recovery key. Preserve the ciphertext and seek an
authorized recipient; do not modify the manifest to imply recoverability.

If an identity may have been copied, treat every artifact it could decrypt as
exposed. Follow [incident response](incident-response.md). Re-encryption and
member removal do not revoke historical copies.
