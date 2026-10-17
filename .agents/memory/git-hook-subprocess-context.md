---
name: Git hook subprocess context
description: Git hooks may pass repository-location variables that mislead child Git commands when their working directory changes.
---

When Git invokes a hook, it can export `GIT_DIR` and `GIT_INDEX_FILE` without setting `GIT_WORK_TREE`. A child Git command launched from a subdirectory can then mistake that subdirectory for the worktree root, causing root-relative staged path checks to miss files.

**Why:** A linked-worktree commit initially passed the credential check because `rev-parse --show-toplevel` resolved the scanner directory instead of the worktree root.

**How to apply:** For child Git commands that use a known working directory, clear `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, and `GIT_PREFIX` so Git discovers the worktree from that directory. Preserve `GIT_INDEX_FILE` when the command must inspect the index Git is currently committing.
