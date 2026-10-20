# Reviewing GitHub Action upgrades

The local-vault workflow pins actions to full commit SHAs rather than movable
major-version tags. Adjacent comments identify the reviewed release.

To update an action:

1. Read the release notes and compare the proposed changes in the action's
   official `actions/checkout` or `actions/setup-node` GitHub repository.
   Check permission, credential handling, runtime and platform changes.
2. Resolve the exact release tag using that official repository's Git refs API.
   Dereference annotated tags and confirm the resulting commit exists in that
   same repository. Review GitHub's commit/tag signature verification; do not
   copy a hash from an unrelated fork or third-party post.
3. Replace the complete 40-character commit SHA in
   `workflows/local-vault-regressions.yml` and update its version comment in
   the same review. Update the reviewed-pin expectations in
   `projects/local-vault/tests/ci-action-pins.test.mjs` alongside them.
   Keep read-only permissions and disabled checkout credential persistence.
4. Open a reviewed change, never automatically merge version updates. Require
   the six Windows/macOS/Linux and Node 20/24 source-sync jobs to pass before
   merging. If a release is unsafe, keep the existing reviewed pin.

The current pins were checked against the official release tags and verified
commits. Release comments are for humans; only the full SHAs determine what runs.

## Automated proposals, manual acceptance

`dependabot.yml` requests weekly Monday GitHub Actions update proposals, limited
to `actions/checkout` and `actions/setup-node`, with at most two open version-update
PRs. It does not enable updates for application packages or other actions, and
does not configure automatic merging. GitHub reads this configuration from the
repository's default branch.

Treat every bot proposal as unreviewed. Keep the full commit pin and matching
release comment; reject a proposal that replaces them with a mutable tag.
The exact reviewed-pin expectations intentionally make an action update fail CI
until a maintainer performs the review above and updates the expected SHA/release
pair in `projects/local-vault/tests/ci-action-pins.test.mjs`. Do not remove that
gate or generate its expectations from the proposed workflow.

Before accepting an update:

- Review the official release, resolved commit, permissions, runtime and
  credential/platform changes.
- Update the workflow pin, release comment and reviewed test expectation
  together, only after that review.
- Preserve `permissions: contents: read` and `persist-credentials: false`.
- Require all six Windows/macOS/Linux × Node 20/24 regression jobs to pass.
- Have a human approve and merge; do not use an auto-merge rule for these PRs.

Run the local, offline policy check with:

```sh
node --test projects/local-vault/tests/ci-action-pins.test.mjs
```

The configuration and tests do not set GitHub branch-protection rules or
repository-level merge settings. Repository owners must enforce the human-review
and required-check rules there as well; a green local test is not release approval.
