# Repository Security Settings

This document defines the GitHub repository controls required before GitSeal
can call a source tree or release pipeline protected. It is a target-state
configuration and verification checklist, not evidence that the settings are
currently enabled.

**No GitHub setting was changed or remotely verified during the 2026-08-17
implementation pass.** GitHub settings are mutable external state and must be
captured again for every release review.

The local repository is currently an unborn `master` branch with no commits and
no configured Git remote. All project files are untracked. It therefore provides
no local evidence about the live GitHub default branch, rulesets, required
checks, App source bindings, environments, or security features. The `main`
target below is the normative hosted-repository target from the project review;
it must be confirmed against authenticated live state before configuration.

GitHub's current primary documentation for these controls is:

- [available repository ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets);
- [creating repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository);
- [merge queues and the `merge_group` event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group);
- [repository Actions policy](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository);
- [secure use of Actions](https://docs.github.com/en/actions/reference/security/secure-use);
- [deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments);
- [dependency review](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action);
- [code-scanning merge protection](https://docs.github.com/en/code-security/concepts/code-scanning/merge-protection);
- [secret scanning and push protection](https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository); and
- [private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).

Plan and feature availability can differ by repository visibility, owner type,
and GitHub plan. If a required control is unavailable, that is a release blocker;
it is not permission to weaken the target state silently.

## Current safe posture

The checked-in `.github/workflows/exact-tree.yml` deliberately fails. This is
correct while no independently reviewed validator is provisioned: candidate
pull-request code must never become the program that approves itself.

The current candidate and CodeQL workflows also lack a `merge_group` trigger.
GitHub documents that required Actions checks must listen for `merge_group` or a
merge queue will not receive those statuses. Code-scanning ruleset merge
protection has additional merge-queue limitations, so the actual CodeQL check
must also be observed on a merge-group commit before it is relied upon.

Until all prerequisites below exist, the safe choices are:

- keep the exact-tree job deliberately failing and accept that it can freeze
  merges when required; or
- keep the target ruleset in `Evaluate` mode, make no production-readiness
  claim, and do not merge or publish security-sensitive changes as a release.

Disabling the failure and trusting a validator built from the candidate branch
is not an acceptable transitional state.

## Prerequisites before activating the target rules

1. Provision a validator outside candidate control. It must use a reviewed
   GitSeal binary identified by version and SHA-256, fetch the exact candidate
   commit/tree, and run:

   ```text
   gitseal verify --source <EXACT_CANDIDATE_SHA> --require-project
   ```

   The validator should report a dedicated check named `gitseal/exact-tree`
   through a narrowly scoped GitHub App. Bind the required check to that exact
   App as its expected source. A repository workflow edited by the pull request
   is not the trusted source.
2. Add `merge_group: {types: [checks_requested]}` to every required candidate,
   CodeQL, dependency-review, and exact-tree workflow, then observe each exact
   check on a real merge-group SHA. Merely seeing it on a pull-request head SHA
   is insufficient.
3. Add and review `.github/CODEOWNERS`, with security-sensitive paths owned by
   at least two active maintainers or a security team. At minimum it must cover
   `internal/agefile/`, `internal/safefile/`, `internal/localstate/`,
   `internal/gitrepo/`, `internal/hooks/`, `internal/treeverify/`, `.github/`,
   `scripts/`, `go.mod`, `go.sum`, the specification, and the security/release
   documents. A code-owner rule without a matching CODEOWNERS file provides no
   meaningful review gate.
4. Add a full-SHA-pinned dependency-review job and observe its exact check name
   and GitHub App source. Configure it to fail for newly introduced known
   vulnerabilities at the reviewed threshold and for unreviewed license-policy
   changes.
5. Run all workflows successfully from the default branch once, then record the
   exact check names and source App identities. GitHub rules match check names,
   not workflow filenames or event types.

The expected check names from the current workflow job names are
`go-ubuntu-latest`, `go-macos-latest`, `go-windows-latest`, and `analyze`.
Confirm those names in GitHub before adding them to a ruleset. The present
`trusted-validator-required` check is an intentional refusal; the target trusted
check is `gitseal/exact-tree`. The dependency-review check does not exist yet.

## Required default-branch ruleset

Create one repository branch ruleset with these exact policy choices:

| Setting | Required value |
| --- | --- |
| Name | `gitseal-main-protection` |
| Enforcement | `Active`, but only after the prerequisites and an Evaluate-mode trial pass |
| Target | Default branch (`main`) only |
| Bypass list | Empty; no administrator, maintainer, GitHub App, or repository-role bypass |
| Restrict deletions | Enabled |
| Block force pushes | Enabled |
| Require pull request before merging | Enabled |
| Required approvals | 2 |
| Dismiss stale approvals on new reviewable commits | Enabled |
| Require review from Code Owners | Enabled |
| Require approval of the most recent reviewable push | Enabled; approver must not be the pusher |
| Require conversation resolution | Enabled |
| Require merge queue | Enabled |
| Required status checks | Every check in the table below |
| Direct pushes to `main` | Not permitted; all updates go through the protected pull-request/merge-queue path |

Do not add a routine bypass for repository administrators. If GitHub plan or
repository-owner constraints make an empty bypass impossible, document the
exact unavoidable actor, require a two-person break-glass procedure, alert on
every bypass, and treat each bypass as a release exception requiring independent
tree verification. A bypassed tree is not automatically release eligible.

Do not enable signed-commit enforcement merely to imply sender authentication.
Signed commits can be useful governance evidence, but they do not replace the
two-person review, trusted exact-tree, or release-tag verification boundaries.

### Required checks

| Required context | Expected source | Required events | Current status |
| --- | --- | --- | --- |
| `go-ubuntu-latest` | GitHub Actions | `pull_request`, `merge_group` | Both triggers are configured; neither merge-group execution nor emitted context is evidenced |
| `go-macos-latest` | GitHub Actions | `pull_request`, `merge_group` | Both triggers are configured; neither merge-group execution nor emitted context is evidenced |
| `go-windows-latest` | GitHub Actions | `pull_request`, `merge_group` | Both triggers are configured; neither merge-group execution nor emitted context is evidenced |
| `analyze` | GitHub Actions / CodeQL | `pull_request`, `merge_group` | Both triggers are configured; merge-group execution and the exact emitted context still require verification |
| `dependency-review` | GitHub Actions | `pull_request`, `merge_group` | Not implemented |
| `gitseal/exact-tree` | Dedicated trusted validator GitHub App | exact pull-request merge SHA and `merge_group` SHA | Not provisioned |

Select the expected source integration for every required check. In particular,
`gitseal/exact-tree` must accept results only from the dedicated trusted App,
not “any source” and not generic GitHub Actions. The App must have only the
repository read permissions and check/status write permission needed for this
job; it must not receive private identities, plaintext, release credentials, or
general repository write access.

If any required job is skipped, neutral, missing, or reports against a different
commit than the candidate merge/merge-group SHA, do not merge even if the GitHub
UI would otherwise permit it. The security policy is stricter than GitHub's
generic interpretation of some status conclusions.

## Required release-tag ruleset

Do not activate release-tag creation until a reviewed publisher exists. At that
point create a separate active tag ruleset:

| Setting | Required value |
| --- | --- |
| Name | `gitseal-release-tags` |
| Target | Tags matching `v*` |
| Restrict tag creation | Enabled |
| Restrict tag updates | Enabled |
| Restrict tag deletion | Enabled |
| Authorized bypass actor | Only the dedicated reviewed release-publisher GitHub App |

The publisher may create a tag only after the exact commit passed the active
default-branch rules and the release approval procedure. Release tags must be
signed annotated tags and independently verified by the release procedure;
GitHub tag rules alone are not treated as proof of that signature.

Do not authorize a personal access token or ordinary maintainer account as the
routine publisher. Any emergency manual tag must be documented as a break-glass
event, independently verified, and cannot reuse the normal production-release
claim without a full release review.

## Required Actions policy

Under **Settings → Actions → General**, require:

- allow only the reviewed GitHub-owned actions used by the workflows and
  explicitly reviewed local/reusable workflows; do not allow arbitrary
  Marketplace actions;
- require every action reference to be pinned to a full-length commit SHA;
- default `GITHUB_TOKEN` workflow permissions to read-only repository contents;
- disable “Allow GitHub Actions to create and approve pull requests”;
- give write permissions only to the eventual release job, at job scope, after
  its protected environment approval;
- never pass repository secrets or release credentials to untrusted
  `pull_request` jobs;
- do not use `pull_request_target` to check out or execute candidate code; and
- do not run untrusted pull-request code on a persistent self-hosted runner.

The current workflows use full commit SHA references and default read-only
permissions. The review release workflow also intentionally has read-only
contents permission and fails after uploading short-lived review artifacts.
Those are good fail-closed properties, but they are not a publisher.

Every Actions-SHA update requires review of the upstream repository, release
notes, source commit, permissions, and changed transitive behavior. Dependabot
may propose an update; it may not approve or merge it.

## Required release environment

After—not before—a release publisher is implemented, create an environment
named `release` with:

- required reviewers drawn from an active security/release team;
- “Prevent self-review” enabled;
- deployment branches/tags restricted to the protected `v*` release-tag path;
- no administrator bypass;
- no long-lived repository credential when GitHub OIDC and short-lived scoped
  credentials can be used; and
- environment secrets limited to the publisher's minimum need.

GitHub environments require only one approval from the configured reviewer list.
GitSeal therefore also requires the two default-branch approvals and a recorded
independent release-evidence review; listing two environment reviewers does not
create a two-approval environment gate by itself.

The publishing job alone may request the minimum write permissions needed for
release assets and provenance, such as `contents: write`, `id-token: write`, and
`attestations: write` when the reviewed design actually uses them. Build and
test jobs remain read-only and pass artifacts to publication only by verified
digest.

## Required repository security features

Enable and continuously monitor:

- dependency graph;
- Dependabot alerts and security updates;
- reviewed Dependabot version updates from `.github/dependabot.yml`;
- dependency review on every pull request;
- CodeQL/code scanning, including scheduled default-branch analysis and the
  required pull-request/merge-group check;
- secret scanning and push protection, including review of every bypass;
- private vulnerability reporting with notifications reaching active
  maintainers; and
- a visible `SECURITY.md` policy.

Where supported, configure code-scanning merge protection for CodeQL findings at
`high` or `critical` security severity and for analysis failure. Because GitHub
documents that code-scanning ruleset protection does not cover merge groups,
retain the observed CodeQL status as a merge-queue required check as well.

Secret scanning is defense in depth, not the private-identity boundary. GitSeal's
exact-tree validator must still reject complete checksum-valid native hybrid
identities because hosting patterns and availability can change.

## Read-only verification procedure

Perform this procedure before every release and save the timestamped, sanitized
output with the review record. The commands read settings; they do not change
them. Administrative authentication is needed to distinguish an absent control
from an endpoint hidden by insufficient permission.

1. Record repository identity, visibility, default branch, and security feature
   fields:

   ```text
   gh api repos/RaydAlsayf/GitSeal
   ```

2. List and inspect every repository ruleset. Confirm the target, active state,
   bypass actors, pull-request parameters, force-push/deletion rules, required
   check contexts, and expected integration IDs:

   ```text
   gh api repos/RaydAlsayf/GitSeal/rulesets
   gh api repos/RaydAlsayf/GitSeal/rulesets/<RULESET_ID>
   ```

   Do not infer an empty bypass list from a summary view; inspect the detailed
   ruleset response and the GitHub UI.
3. Inspect Actions enablement, allowed-action policy, SHA requirement, and
   default token permissions:

   ```text
   gh api repos/RaydAlsayf/GitSeal/actions/permissions
   gh api repos/RaydAlsayf/GitSeal/actions/permissions/selected-actions
   gh api repos/RaydAlsayf/GitSeal/actions/permissions/workflow
   ```

4. Inspect the release environment, protection rules, reviewers, and deployment
   branch policy:

   ```text
   gh api repos/RaydAlsayf/GitSeal/environments/release
   ```

   A 404 is evidence that the environment is absent or inaccessible, not that a
   protected environment exists.
5. Inspect the repository's advanced-security UI and API-visible state for the
   dependency graph, Dependabot alerts/security updates, CodeQL analyses,
   secret scanning/push protection, and private vulnerability reporting. Useful
   read-only endpoints include:

   ```text
   gh api repos/RaydAlsayf/GitSeal/vulnerability-alerts
   gh api repos/RaydAlsayf/GitSeal/code-scanning/analyses
   gh api repos/RaydAlsayf/GitSeal/private-vulnerability-reporting
   ```

   Interpret 204/404/403 responses according to the specific endpoint and the
   authenticated account's permission. Do not generalize one endpoint's 404
   semantics to another.
6. For one successful pull-request merge SHA and one successful merge-group SHA,
   enumerate checks:

   ```text
   gh api repos/RaydAlsayf/GitSeal/commits/<EXACT_SHA>/check-runs
   ```

   Confirm each required check's exact `name`, `conclusion`, `head_sha`, App
   `slug`/ID, workflow origin, and timestamps. For `gitseal/exact-tree`, verify
   the validator binary's version and SHA-256 in the App's evidence and confirm
   it evaluated the same exact SHA with `--require-project`.
7. Verify every external Action reference in `.github/workflows/*.yml` is a
   40-character lowercase hexadecimal commit and independently resolve it to
   the intended upstream release. Run `actionlint` and review permissions for
   each workflow and job.
8. Review ruleset insights and audit logs for bypasses, force-push attempts,
   rule changes, failed evaluations, secret-scanning bypasses, environment
   approvals, and unexpected Apps. Investigate every bypass before release.

## Enforcement tests

Use synthetic branches and generated test material only. Do not push a real or
test private identity merely to test a hosting control.

Before declaring the rules effective, demonstrate that:

- a direct push, force push, and deletion of `main` are rejected;
- a pull request with fewer than two valid approvals cannot merge;
- a new reviewable commit dismisses approvals and requires an independent
  review of the latest push;
- unresolved review conversations block merge;
- a missing, failed, or wrong-source required status blocks merge;
- editing the candidate exact-tree workflow cannot produce the trusted
  `gitseal/exact-tree` result;
- a merge-queue entry runs every required check against the reported
  `merge_group` SHA and cannot merge on pull-request-head-only results;
- a pull request that deletes `.gitseal` metadata fails the trusted validator
  because `--require-project` is mandatory;
- an untrusted fork pull request receives no release secret or write-capable
  token;
- an unapproved release-environment deployment and an unauthorized `v*` tag
  creation are rejected; and
- the release publisher refuses a commit, tag, binary, SBOM, provenance record,
  or checksum whose exact digests do not match its reviewed inputs.

Record the exact test repository, ruleset IDs, App IDs, commit/tree SHAs, check
run IDs, UTC timestamps, and sanitized results. Configuration screenshots are
useful supporting evidence but do not replace API output and negative tests.

## Release decision

All controls in this document are necessary but not sufficient. They do not
repair GitSeal's open Unix publication, Windows NTFS, POSIX lock-release,
retained-safety trust, native testing, independent review, recovery, or artifact
provenance blockers. A repository with perfect rules can still contain an unsafe
program; a safe program can still be released through an untrusted pipeline.

Any missing, bypassed, unverified, or plan-unavailable required control keeps
the project pre-alpha and prevents a production release.
