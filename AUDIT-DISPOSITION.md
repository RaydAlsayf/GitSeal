# Independent Audit Disposition

**Disposition date:** 2026-08-13

**Input:** Untrusted independent review containing findings `GS-A-01` through
`GS-F-12`

**Canonical evidence:** Local repository
`C:\Users\rayda\GItHub\GitSeal`, GitHub repository
`RaydAlsayf/GitSeal`, the current README/specification/security review, empirical
Git and age checks, and the primary sources referenced below

## 2026-08-17 implementation follow-up

The classifications below record the original specification audit. The current
worktree now contains an implementation, so this pass separately records what
was reproduced, contained, or remains unqualified. A unit test or compile does
not change a `GS-F` item into platform assurance.

| Finding | Current implementation disposition |
|---|---|
| GS-A-14 / GS-C-04 | **Source design remediated; qualification open.** Project schema 2 and local-state schema 2 add a separately domain-separated retained-safety digest, exact acceptance, strict non-null fields, golden vectors, and an explicit configuration-first migration from schema 1. Active mapping digest v1 is unchanged. Ordinary tools reject legacy/future versions. End-to-end migration cannot run while platform lock/publication gates are closed. |
| GS-F-02 | **Reachable unsafe paths contained; not qualified.** Existing-destination Unix publication stays disabled. POSIX identity-bound removal now returns a stable fail-closed error before unlink, and lock/local-state mutation preflights that refusal. Windows public publication also refuses before making a destination visible; sensitive candidate creation refuses before temporary allocation. Native race, crash, and durability matrices remain absent. |
| GS-F-04 | **Locally tested, human review open.** Strict project/state version separation, omitted/null collection rejection, migration preservation, ambiguity/downgrade rejection, and retained-digest vectors are committed tests. Fuzz/native evidence is reported in `IMPLEMENTATION-STATUS.md`. |
| GS-F-06 / GS-F-07 | **Still open.** Windows token-known-folder calls are now bound to an explicit process token and public/sensitive writes remain gated, but no protected DACL-at-creation writer, conditional handle-rooted replacement, ADS-integrated publication, fault executor, or unsandboxed NTFS qualification exists. |
| GS-F-08 | **Contained, not complete.** Lock records bind token, PID, boot/session and process-start identity, but exact POSIX unlink and conservative confirmed stale recovery remain unavailable. The implementation refuses before mutation rather than guessing. |
| GS-F-09 | **Partially runtime-verified.** The active-index parser now preserves and rejects skip-worktree/assume-unchanged flags on protected/control paths, normalizes relative hook cwd before validating inherited index paths, and has real Windows Git tests for `commit -a` (`index.lock`), `commit --only` (`next-index-*.lock`), and divergent automatic merge (`pre-merge-commit` on `index`). The full native operation/linked-worktree/SHA-format matrix and hostile same-user ABA review remain open. |
| GS-A-01 / GS-A-05 / GS-A-17 | **Additional orchestration fixes implemented.** `encrypt --all` selects missing and manifest-mismatched artifacts; encrypt/decrypt perform whole-set deterministic preflight and decrypt authenticates every selected payload through EOF before first publication; sync rechecks the exact observed incoming digest under its trust lock. Multi-mapping sync mutation refuses before writing until a transaction protocol exists. Adversarial tests assert that a later blocker leaves earlier mappings untouched. |
| GS-F-10 | **Additional local regression added; assurance open.** Static age payload validation now rejects the forbidden empty final STREAM chunk after a full chunk, and a regression distinguishes authenticated candidate headers from corrupted payload failure at EOF. The broader published-vector/adversarial/official-CLI matrix remains incomplete. |
| GS-F-12 | **Dependency graph and patched toolchain locally reviewed; release qualification remains open.** The production graph contains five external modules. The official Go 1.26.6 Windows archive matched the SHA-256 published by `go.dev`, all toolchain pins were raised from vulnerable Go 1.26.5, and fresh `govulncheck` reports zero symbol or imported-package vulnerabilities. Its sole module-only finding is unimported `golang.org/x/crypto/openpgp`. Independent SBOM, provenance, license, and release review remain required. |

The current local repository is unborn and all proposed project files are
untracked. This follow-up did not commit, push, publish, change repository
settings, or create a release.

### Accepted implementation findings in this pass

| Pass ID | Severity | Exploit or failure scenario | Resolution and regression evidence |
|---|---|---|---|
| GSR-01 | Critical | POSIX `RemoveOpened` rechecked an inode and then unlinked its basename; a same-user racer could substitute and cause deletion of an unfamiliar file, including at lock release. | POSIX removal, lock acquisition, and local-state writes now return `ErrIdentityBoundRemovalUnavailable` before mutation. `removal_unix_test.go` and local-state tests require object preservation and zero-write refusal. Normal POSIX mutation remains blocked. |
| GSR-02 | Critical | Windows public create/update closed a validated handle before pathname cleanup or used unconditional rooted replacement; a raced control/user file could be deleted or overwritten. | All Windows publication now refuses before a destination is made visible, and sensitive candidate creation refuses before allocation. `safefile_test.go` asserts no destination publication and reports retained reserved residue. The NTFS writer remains unimplemented. |
| GSR-03 | High | Active-only mapping trust allowed removal of `retained_safety` without changing the trusted mapping digest; an older clone/tool could silently miss the weakened orphan policy. | Separate canonical retained digest, project/state schema 2, strict migration-only v1 parsers, exact flags/snapshot binding, configuration-first migration, golden vectors, and retained-release tests. Independent schema/native migration review remains open. |
| GSR-04 | High | Multi-artifact encrypt/decrypt/sync could discover a later blocker after an earlier publication, and `encrypt --all` could falsely skip missing or manifest-mismatched artifacts. | Full-set preflight, EOF authentication before first decrypt publication, exact under-lock incoming-digest recheck, stale selection repair, and fail-closed multi-mapping sync. `sync_overwrite_test.go` and `status_sync_test.go` assert zero earlier writes. |
| GSR-05 | High | `skip-worktree` or `assume-unchanged` bits were discarded, allowing protected/control index divergence to evade Tier 1 validation. | `ls-files -v --stage -z` tags are parsed and both flags are rejected on all relevant paths; hook/tree tests cover both. |
| GSR-06 | Medium | Static age inspection accepted a forbidden empty final STREAM chunk after a full chunk, so identity-free diagnostics could call an artifact structurally valid even though official decryption rejects it. | Exact remainder rejection plus boundary vectors; a separate test proves header authentication does not replace payload authentication through EOF. |
| GSR-07 | Medium | A relative hook cwd combined with Git's relative `GIT_INDEX_FILE` could be compared against an absolute Git directory and reject before validating the candidate merge. | Repository discovery canonicalizes cwd first; real `commit -a`, `commit --only`, and divergent merge tests observe and block the exact candidate indexes. |
| GSR-08 | Medium | Git diagnostics sanitized ASCII controls but could emit C1 controls such as U+009B CSI to a terminal. | Sanitization now uses `unicode.IsControl`; regression coverage includes C1 input. |
| GSR-09 | Medium | A retained two-recipient orphan became invalid after the current recipient set changed to one even though no command can re-encrypt an orphan. | Ranged public structural inspection accepts only 1..32 canonical native stanzas, streams exact EOF, and disclaims current membership/freshness; exact-tree regression covers historical two/current one and still rejects current zero. |
| GSR-10 | Medium | Windows known-folder lookup used the implicit current-token API, leaving profile selection ambiguous under impersonation. | Identity and security helpers open the process token explicitly, resolve known folders through it, and reject an effective-token/process-SID mismatch. Sensitive writes remain gated. |
| GSR-11 | High | The exact Go 1.26.5 toolchain pin had an imported-package standard-library advisory and seven module advisories, so a nominally reproducible release would reproduce a known-vulnerable toolchain. | The official Go 1.26.6 Windows archive matched the published SHA-256; module, CI, CodeQL, release-review, build-script, and documentation pins moved together. Full tests/cross-builds pass and fresh `govulncheck` reports zero symbol/imported-package vulnerabilities. |

## Method and assurance boundary

Each labeled finding was checked independently. “Confirmed” accepts the core
finding, not every proposed fix. “Partially correct” accepts only the evidence or
recommendation stated in the disposition. “Already addressed” means the
pre-audit specification already contained the material control. “Deferred by
scope” means the idea is deliberately outside V1 and is not needed to maintain a
V1 security boundary. “Cannot be evaluated until implementation” is not an
acceptance or rejection: no product code exists yet.

At the start of review, the canonical local `main` and `origin/main` pointed to
`a5b7214` and the README, specification, and security review were untracked. An
authenticated GitHub App check confirmed that the live public `main` contained
`LICENSE`; content requests for those three design documents returned 404. This
review edits local documents only. It does not claim that a paper control works,
and it did not commit, push, change GitHub settings, or publish a release.

The disposition covers all 64 labeled findings: 23 Confirmed, 19 Partially
correct, 3 Already addressed, 3 Incorrect, 1 Duplicate, 3 Deferred by scope, and
12 Cannot be evaluated until implementation.

## A — Specification defects

| ID | Classification | Independent evidence and resolution |
|---|---|---|
| GS-A-01 | **Confirmed** | The old baseline table allowed changed ciphertext to replace unchanged existing plaintext without separate authority. Valid age ciphertext does not authenticate its human sender. Section 10 now creates an `incoming ciphertext requiring consent` state and requires acceptance of the exact digest before replacement; missing-plaintext recovery remains possible. |
| GS-A-02 | **Confirmed** | Git 2.54.0 Windows tests observed `.git/index`, `.git/index.lock`, `.git/next-index-*`, and linked-worktree indexes for different commit forms. Automatic merge invoked `pre-merge-commit`; rebase, cherry-pick, revert, and `am` did not invoke either covered hook. Sections 5 and 13 now require the inherited active index, fail-closed behavior, `pre-merge-commit`, and exact-tree CI. [GIT-HOOKS] [GIT-ENV] |
| GS-A-03 | **Confirmed** | Old `encrypt --all` selected only locally changed files, so membership staleness had no guaranteed remediation. Section 11 now defines `encrypt --all` as re-encrypting every changed **and stale** artifact. A separate `reencrypt` command would duplicate that behavior and was not added. |
| GS-A-04 | **Confirmed** | Same-directory plaintext temporaries were not covered by ignore or hook rules. Sections 5, 9, 12, 13, and 17 reserve CSPRNG names beginning `.gitseal.tmp.`, ignore them permanently, reject them from trees in every mode, and diagnose residues conservatively. Keeping them in the destination directory preserves same-filesystem/volume publication. [GIT-IGNORE] [POSIX-RENAME] [WIN-REPLACE] |
| GS-A-05 | **Confirmed** | Repository-controlled source/destination mappings lacked a local trust pin and the manifest did not bind `source`. Sections 4, 7, 10, and 11 add a canonical mapping digest, first/change confirmation, manifest source, and tracked-destination refusal. The proposed V1 overwrite-tracked escape hatch was rejected because it weakens the boundary. |
| GS-A-06 | **Confirmed** | The C2SP vector and official implementation produce a 1,959-character hybrid recipient, making full-string human comparison impractical. Sections 4 and 7 define complete domain-separated SHA-256 recipient/set fingerprints over strict canonical text and require independent authenticated comparison. A fingerprint copied from the same repository is not trusted. [AGE-SPEC] [AGE-PQ] [BIP173] |
| GS-A-07 | **Confirmed** | The old documents required tree CI but specified no command or observable scope. Section 11 now defines `verify --source TREE`, bare-repository behavior, `--require-project`, exact-tree checks, non-checks, isolated Git evaluation, trusted pinned validator use, and merge/merge-group tree validation. [GIT-CHECKATTR] [GH-MERGEQUEUE] |
| GS-A-08 | **Partially correct** | Requiring decryption of every artifact on every commit would be costly and can require an unavailable identity in noninteractive clients. The audit's opt-in Tier 2 would weaken an existing safety requirement and was rejected. Section 13 instead makes static Tier 1 universal and identity-dependent Tier 2 mandatory only for impacted mappings; it never prompts and fails closed when triggered. |
| GS-A-09 | **Confirmed** | Encryption did not require the selected acting identity's derived recipient in the set. Sections 7, 8, and 11 now refuse before mutation with no V1 bypass and authenticate the candidate header with that identity before publication. [AGE-API] |
| GS-A-10 | **Partially correct** | The safe attribute result was underspecified. However, `!eol` yields unsafe `unspecified`, existing `-eol` correctly yields `unset`, and a correct root rule outranks global attributes. Tests also showed both cached/source queries still consult some local/global sources. Section 12 requires exact `unset` for all managed attributes, blocks active overrides, and isolates tree CI. [GIT-ATTR] [GIT-CHECKATTR] |
| GS-A-11 | **Confirmed** | Git ignore rules do not affect already tracked files. Section 11 moves tracked checks before every `protect` write, refuses when plaintext is in the active index, and allows only the staged-removal case after exact exposure/rotation acknowledgement. It does not print an unsafe unquoted shell command. [GIT-IGNORE] |
| GS-A-12 | **Partially correct** | Canonicalization and digest framing needed precision. The claimed uppercase/whitespace parser bypass is false: the official hybrid parser rejects them, and raw hybrid key bytes are unexported. Sections 4 and 7 require parse-to-`String()` byte equality, deterministic text ordering, domains/count/length framing, and golden vectors. Canonical text is an injective safe hash input; another Bech32 implementation was rejected. [AGE-PARSE] [AGE-BECH] |
| GS-A-13 | **Incorrect** | The native hybrid **identity is 77 characters**, within BIP-173's 90-character limit; the public recipient is the 1,959-character value. The predicted scanner miss does not follow. The useful hardening remains: Sections 6, 13, and 17 require `age.ParseHybridIdentity` and a runtime-generated test rather than length/HRP assumptions. [AGE-SPEC] [AGE-PARSE] [BIP173] |
| GS-A-14 | **Confirmed** | Old `unprotect` removed binary attributes while leaving ciphertext. Sections 4, 11, and 12 retain an artifact entry in tracked `retained_safety` while ciphertext exists in the worktree or prospective tree and remove it only under exact explicit conditions. |
| GS-A-15 | **Confirmed** | Old checks did not require GitSeal metadata/control files to be committable. Section 12 now checks plaintext, artifacts, all three tracked metadata files, `.gitattributes`, and `.gitignore` with `check-ignore --no-index -v -z --non-matching --stdin`, with tracking checked separately. [GIT-CHECKIGNORE] |
| GS-A-16 | **Confirmed** | A preliminary digest plus later rehash need not be the digest of exactly the stream encrypted. Section 9 hashes plaintext at the encryption read boundary and ciphertext at the write boundary, uses only same-handle metadata as a mutation detector, and aborts detected mutation without claiming an atomic snapshot. [GO-IO] |
| GS-A-17 | **Confirmed** | An unlocked multi-file reader can observe ciphertext after replacement but manifest before update. Sections 10 and 14 reuse the existing lock for consistent snapshots and report contention as busy/indeterminate. A generation counter was rejected because it adds another non-atomic state file. |
| GS-A-18 | **Partially correct** | Expected status states and command failure needed separation and JSON negotiation. Section 11 makes successfully computed status exit 0 and adds `schema_version`/requested-version behavior; Section 15 defines doctor/verify/hook semantics and busy code 10. Separate hook/tree codes were unnecessary because stable reason categories already identify the failure. |

## B — Decisions that required an explicit V1 choice

| ID | Classification | Independent evidence and resolution |
|---|---|---|
| GS-B-01 | **Partially correct** | A manifest creates multi-file complexity, but its ciphertext digest is useful before commit and across index transformation, while source and recipient-set fields bind reviewable semantics. Section 4 keeps one global V1 manifest, adds `source`, and narrows every claim to bookkeeping/transformation detection. |
| GS-B-02 | **Confirmed** | Randomized opaque ciphertext has ordinary binary merge conflicts and the old state machine lacked an unmerged workflow. Sections 10, 11, 16, and 17 add an unmerged state, ordinary-operation refusal, serialized editing guidance, and explicit manual side selection/re-encryption. Deterministic encryption was rejected. |
| GS-B-03 | **Confirmed** | CI/production secret delivery was unspecified. Sections 1 and 21 choose the smallest V1 boundary: workstation encryption/decryption only; CI performs identity-free tree validation; production uses a dedicated secret manager. Identity injection is deferred. |
| GS-B-04 | **Deferred by scope** | Plain identity theft is a real documented residual risk, but passphrase identities are already outside V1 and introduce prompt/noninteractive recovery complexity. Sections 6 and 16 require documentation to recommend FDE and an offline backup while explicitly refusing to claim a portable FDE/backup attestation. |
| GS-B-05 | **Incorrect** | A deliberate GitSeal stdout ban does not prevent emergency interoperability. Official age can write to a new explicit file with `-o`; Section 22 requires that safer recovery recipe and warns that official age omits GitSeal's manifest/mapping/replacement checks. [AGE-CLI] |
| GS-B-06 | **Confirmed** | Exact native stanza size is 1,557 bytes and header size is `70 + 1,557*N`; the previous 256-member/1,024-file caps implied 408,229,888 header bytes per full generation. Section 4 reduces V1 hard caps to 32 members/128 files (6,386,432 bytes per full generation before payloads) and requires benchmarks before V1.0. [AGE-SPEC] |
| GS-B-07 | **Partially correct** | YAML has meaningful parser surface, but “wrong format” is not an evidence-based conclusion and TOML/custom formats still require strict validation. Section 4 keeps YAML, mandates the maintained pinned `go.yaml.in/yaml/v3` rather than archived `gopkg.in/yaml.v3`, and retains strict pre-validation/fuzzing. [YAML] |
| GS-B-08 | **Confirmed** | Trial of unspecified local identities makes errors depend on unrelated machine state. Sections 6 and 8 require one explicitly selected hybrid identity and defer try-all behavior. |

## C — Proposed improvements

| ID | Classification | Independent evidence and resolution |
|---|---|---|
| GS-C-01 | **Partially correct** | Bounded header shape/type/count checks strengthen rejection, but public metadata is unauthenticated until header-MAC verification; stanza count is not unique-recipient identity/count. `ExtractHeader` returns raw bytes and age-inspect uses internal packages. Section 8 requires a reviewed bounded adapter and exact native shape (one canonical Base64 argument decoding to 1,120 bytes; 32-byte body), then selected-identity MAC verification. [AGE-SPEC] [AGE-API] |
| GS-C-02 | **Confirmed** | Section 6 now reopens the final identity, rechecks type/permissions, parses it, compares the derived recipient, and runs a small production-engine round trip. Cleanup is limited to the invocation-owned file and cleanup failure is reported. |
| GS-C-03 | **Partially correct** | Per-artifact header unwrap is valuable but proves only `header_decryptable`, not payload authenticity. Section 11 names it accurately and offers explicit slow full decryption to EOF. Section 8 limits the exposed 16-byte file-key buffer for every header-decryption call without claiming erasure. [AGE-API] [AGE-SPEC] |
| GS-C-04 | **Confirmed** | Managed-block contents needed normative derivation. Sections 4 and 12 derive sorted blocks from active mappings plus tracked retained-safety entries. Canonical staged/tree form is exact; live worktree comparison uses parsed canonical semantics so CRLF alone is not a false failure. Effective checks still apply. |
| GS-C-05 | **Already addressed** | The pre-audit Section 5 already required patched `os.Root` plus no-follow and file-identity checks, and the review called it a foundation rather than the whole boundary. The correction adds root-handle/worktree binding and the exact trailing-slash regression test. [GO-ROOT] [GO-ADVISORY] |
| GS-C-06 | **Partially correct** | Bounded cancellation-aware retry for reviewed transient Windows errors is sensible; a fixed retry count is not source-backed and old text already prohibited truncation. Section 9 adds the more important documented partial-failure reconciliation, forbids copy/delete fallback, and validates final DACL/named streams. [WIN-REPLACE] [WIN-MOVE] |
| GS-C-07 | **Already addressed** | The pre-audit Section 14 already recorded PID and start time, rejected PID-only recovery, and required conservative handling. It now clarifies that authoritative absence **or** live-PID creation mismatch proves staleness, unknown/permission cases need confirmation, and token/file identity must be rechecked. The audit's suggestion that both proof conditions must hold was logically wrong. [WIN-PROCESS] [PROC-STAT] |
| GS-C-08 | **Deferred by scope** | Dry-run is useful UX but not a security boundary and becomes stale immediately. Section 21 defers it; if later added it cannot establish trust or promise future execution safety. |
| GS-C-09 | **Confirmed** | `[]string` permitted late parsing and general recipient wrappers can bypass age label defense. Section 8 introduces an unexported validated hybrid-recipient set and permits only concrete `*age.HybridRecipient` values inside the engine. [AGE-PQ] |
| GS-C-10 | **Partially correct** | Spaces, leading `#`/`!`, and bracket syntax complicate Git grammars, but `?`, `*`, and backslash were already forbidden and braces/tilde are not special as claimed. Section 5 adopts the narrower `[A-Za-z0-9._/-]` V1 profile and README states the limitation. [GIT-IGNORE] [GIT-ATTR] |
| GS-C-11 | **Deferred by scope** | Per-artifact manifests can reduce textual conflicts but add schema/files/path encoding and do not remove the ciphertext+metadata two-file publication boundary. Section 4 deliberately keeps the global manifest for V1 and Section 21 records the deferral. |

## D — Claims and assumptions

| ID | Classification | Independent evidence and resolution |
|---|---|---|
| GS-D-01 | **Already addressed** | Pre-audit Sections 2 and 4 already said a repository writer can replace ciphertext and the manifest is reviewable evidence, not proof. Section 4 now additionally calls mismatches bookkeeping consistency and states that changing both values defeats the check. |
| GS-D-02 | **Confirmed** | A clean local reachable-object scan cannot prove no leak; hosting copies, forks, PR refs, caches, direct SHA access, and external clones may survive history rewriting. Sections 11 and 17 require exact scan scope/limitations and rotation after known exposure. “Permanently public” was not adopted because host support can sometimes remove server references, while uncontrolled copies remain. [GH-HISTORY] |
| GS-D-03 | **Partially correct** | A Git commit does contain one immutable tree, but Git does not enforce GitSeal's cross-file invariant. Section 4 now says the commit is a consistency boundary only after validating that exact tree and requires every merge/rewrite result to be revalidated. Multi-ref push atomicity is irrelevant because V1 never pushes. [GIT-GLOSSARY] |
| GS-D-04 | **Partially correct** | Age has a 16-byte random file key, but the payload uses a 32-byte HKDF-derived ChaCha20-Poly1305 key. Sections 2 and 16 now describe the construction precisely without implying that hybrid encapsulation changes the symmetric payload or that ChaCha directly uses a 128-bit key. [AGE-SPEC] |
| GS-D-05 | **Incorrect** | The old specification did not claim an attacker could append a stanza, and the official age API/CLI's labels reject classical+hybrid mixing. Incoming nonconforming files remain a valid structural-rejection case under GS-C-01, not evidence for the audit's plain-age command example. [AGE-PQ] |
| GS-D-06 | **Duplicate** | This is the documentation consequence of confirmed GS-A-11. Section 11 now states plainly that ignore rules do not affect tracked files; no separate control is needed. |
| GS-D-07 | **Partially correct** | The settings table existed and its states were independently rechecked, but it lacked endpoint/auth/time provenance and could imply the local design was already published. The security review now records timestamp, authenticated context, endpoints, 404 interpretation, point-in-time limits, and the fact that remote `main` contains only `LICENSE`. |
| GS-D-08 | **Confirmed** | README said hybrid recipients were the V1 “default” while the specification made them the only type. README now says “only V1 recipient type.” |
| GS-D-09 | **Confirmed** | “Known high-risk failure classes” was too broad. The assurance statement now limits itself to classes identified in the reviews and links this full disposition. |

## E — Product and maintainability

| ID | Classification | Independent evidence and resolution |
|---|---|---|
| GS-E-01 | **Partially correct** | Honest differentiation/limitations help users, but a competitive table would require continuously refreshed external-product research and is unnecessary to a security boundary. README now states whole-file behavior, merge cost, metadata, revocation, workstation, path, KMS, and sender-auth limitations without marketing claims. |
| GS-E-02 | **Partially correct** | Go escapes uppercase module-cache path characters and module casing should be frozen before tags. This is compatibility/ergonomic debt, not a demonstrated GitHub typo-squatting vulnerability. Section 19 selects lowercase `github.com/raydalsayf/gitseal`; renaming the GitHub display repository was neither necessary nor authorized. [GO-MODULES] [GH-RENAME] |
| GS-E-03 | **Partially correct** | `member list` and tree `verify` were genuine gaps and are now specified. Re-encryption is covered by `encrypt --all`; multi-identity enumeration is unnecessary after explicit-identity selection; a separate `resolve` command adds surface, so Section 10 specifies a manual fail-closed workflow instead. `init` remains explicit/idempotent. |
| GS-E-04 | **Partially correct** | Recovery and a second-person drill already existed, but mechanics were incomplete. Section 20 now requires limitations, compatibility, rotation/incident, identity recovery, and release-verification documents. A network version-advisory feature was rejected as speculative V1 scope. [GH-ATTEST] |
| GS-E-05 | **Partially correct** | Reproducibility mechanics were missing, but a Go `toolchain` directive is not a hard pin with auto-switching and `go mod download -x` does not reject downloads. Section 19.1 requires an exact verified toolchain, `GOTOOLCHAIN=local`, verified materialization, offline/read-only builds, deterministic flags/metadata, normalized archives, and two-build hash comparison. [GO-TOOLCHAIN] [GO-BUILD] [GO-MODULES] |
| GS-E-06 | **Partially correct** | Actionable schema/compatibility behavior was missing. Sections 11 and 15 require document/version/tool/upgrade errors and separate tracked-schema, local-state, JSON, exit, and CLI compatibility promises. `min_tool_version` was rejected because an old parser cannot rely on an unknown future field. |

## F — Implementation-only verification (original audit classification)

At the time of the original audit no product implementation existed, so each
item below was classified **Cannot be evaluated until implementation**. The
dated follow-up above records current source status without rewriting that
historical classification. Corresponding tests remain release blockers, not
evidence that a platform property already holds.

| ID | Classification | Required future evidence |
|---|---|---|
| GS-F-01 | **Cannot be evaluated until implementation** | Code review/static rule proving repository-controlled file access stays inside the reviewed rooted component. |
| GS-F-02 | **Cannot be evaluated until implementation** | Hostile race/fault-injection harness around every validation/open/publish boundary. |
| GS-F-03 | **Cannot be evaluated until implementation** | Secret-canary fuzz/property tests across errors, logs, diagnostics, and JSON. |
| GS-F-04 | **Cannot be evaluated until implementation** | Strict YAML wrapper fuzzing for aliases, anchors, depth, duplicates, tags, documents, and byte/scalar bounds. |
| GS-F-05 | **Cannot be evaluated until implementation** | Runtime hybrid identity scanner tests and prefix-only false-positive tests. The audit's key-length premise was refuted, but scanner code still needs testing. |
| GS-F-06 | **Cannot be evaluated until implementation** | Real NTFS identity-file DACL/inheritance tests, including unusual local/domain accounts. |
| GS-F-07 | **Cannot be evaluated until implementation** | Real Windows replacement tests for sharing, AV/indexer/editor contention, partial failure, read-only targets, volumes, and unsupported filesystems. |
| GS-F-08 | **Cannot be evaluated until implementation** | Genuine PID reuse/boot-session/permission-denial stale-lock tests; no impractical PID-exhaustion technique is mandated. |
| GS-F-09 | **Cannot be evaluated until implementation** | GitSeal tests for the empirically established commit/index/hook matrix, proving the validator saw the exact committed bytes. |
| GS-F-10 | **Cannot be evaluated until implementation** | Adversarial bounded header inspection and MAC/full-payload distinctions. |
| GS-F-11 | **Cannot be evaluated until implementation** | Streaming/buffer review and tests that minimize file-key/plaintext copies without claiming erasure. |
| GS-F-12 | **Cannot be evaluated until implementation** | Review and vulnerability/license/provenance verification of the final pinned dependency graph. |

## Contradictions resolved

1. **GS-A-14 versus GS-C-04:** retaining safety after `unprotect` cannot coexist
   with blocks derived only from active mappings. V1 now has a tracked,
   schema-validated `retained_safety` section, and managed blocks derive from
   active plus retained entries.
2. **GS-A-08 versus existing fail-closed safety:** identity checks were narrowed
   to impacted artifacts for performance, but the audit's opt-in/off switch was
   rejected.
3. **GS-A-12/13 versus the official age API:** canonical text is sufficient and
   the identity is 77 characters. No second Bech32 decoder or wrapper scanner is
   justified.
4. **GS-C-01 versus anonymous age stanzas:** public structure is useful but not
   authenticated proof of recipients. Header-MAC verification and exact language
   now preserve that boundary.
5. **GS-C-06/07 versus platform behavior:** Windows partial replacement and lock
   proof conditions follow documented states, not the audit's arbitrary retry or
   cumulative-staleness formulas.
6. **GS-B-03/04 versus V1 scope:** V1 is explicitly workstation-only and leaves
   passphrase identities and noninteractive secret delivery for a separate
   threat model.

## Material issues the independent audit missed

- Header type/count/shape is attacker-controlled before header-MAC verification;
  full payload authenticity requires consuming decryption to EOF.
- Native hybrid stanza shape, not only its type string, must be bounded and
  validated; age-inspect's structured parser is internal rather than a public API.
- `DecryptHeader` exposes the 16-byte file key to caller memory, and age label
  checks can be bypassed by wrapping recipients behind a general interface.
- The long recipient's short Bech32 checksum is not a robust human trust ceremony
  at 1,959 characters, and a repository-provided fingerprint is not independent.
- The unordered recipient-set digest does not bind member IDs to recipients; a
  distinct trusted membership-policy digest now prevents association swaps.
- `ReplaceFileW` preserves the replaced DACL and named streams and documents
  partial failure states; this is a Phase 0 Windows release blocker.
- `os.OpenRoot` can follow links in the root path, so the handle must be bound to
  the Git-discovered worktree identity.
- Cached/source attribute queries still consult local/global sources, and
  `check-ignore` has no equivalent tree-source option; CI needs an isolated
  evaluator of the actual selected tree.
- Required CI must validate the actual merge/merge-group tree with a trusted
  pinned binary, not validator code supplied by the untrusted change.
- History results must state shallow/partial/ref/reflog/remote/fork limits;
  object IDs must be opaque across SHA-1/SHA-256; skip-worktree,
  assume-unchanged, sparse checkout, replace refs, and control-path case
  collisions need coverage.
- Wall-clock build time contradicted reproducible artifacts; release binary and
  archive metadata now have deterministic requirements.
- `FOLDERID_LocalAppData` and restrictive permissions do not prove FDE or backup
  exclusion, and ignore rules do not stop forced staging.

## Primary-source registry

[AGE-SPEC]: https://c2sp.org/age
[AGE-API]: https://pkg.go.dev/filippo.io/age@v1.3.1
[AGE-PQ]: https://github.com/FiloSottile/age/blob/v1.3.1/pq.go
[AGE-PARSE]: https://github.com/FiloSottile/age/blob/v1.3.1/parse.go
[AGE-BECH]: https://github.com/FiloSottile/age/blob/v1.3.1/internal/bech32/bech32.go
[AGE-CLI]: https://github.com/FiloSottile/age/blob/v1.3.1/README.md
[BIP173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[GIT-HOOKS]: https://git-scm.com/docs/githooks
[GIT-ENV]: https://git-scm.com/docs/git
[GIT-ATTR]: https://git-scm.com/docs/gitattributes
[GIT-CHECKATTR]: https://git-scm.com/docs/git-check-attr
[GIT-IGNORE]: https://git-scm.com/docs/gitignore
[GIT-CHECKIGNORE]: https://git-scm.com/docs/git-check-ignore
[GIT-GLOSSARY]: https://git-scm.com/docs/gitglossary
[GH-HISTORY]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
[GH-MERGEQUEUE]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
[GH-ATTEST]: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
[GO-ROOT]: https://pkg.go.dev/os#Root
[GO-ADVISORY]: https://pkg.go.dev/vuln/GO-2026-4970
[GO-IO]: https://pkg.go.dev/io#TeeReader
[GO-TOOLCHAIN]: https://go.dev/doc/toolchain
[GO-BUILD]: https://pkg.go.dev/cmd/go
[GO-MODULES]: https://go.dev/ref/mod
[YAML]: https://github.com/yaml/go-yaml
[WIN-REPLACE]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew
[WIN-MOVE]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
[WIN-PROCESS]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
[PROC-STAT]: https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
[POSIX-RENAME]: https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html
[GH-RENAME]: https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository
