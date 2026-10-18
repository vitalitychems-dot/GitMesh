---
name: Branch drift during tasks
description: Verify the active checkout after task handoffs or branch-selection changes.
---

The active branch and checkout contents can change during a task handoff. A requested file may be absent because the workspace moved to another branch while task context still refers to the previous tree.

**Why:** An attempted patch and worktree setup failed because the active checkout changed asynchronously after the user selected the target branch.

**How to apply:** Before editing after a branch-selection exchange or a missing-target-path error, check `git branch --show-current` and confirm the target files exist. Avoid switching over unrelated staged changes; use the selected branch once the workspace reflects it.
