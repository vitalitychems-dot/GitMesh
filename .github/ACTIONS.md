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
