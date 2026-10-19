---
name: Subprocess timeout tests
description: Assert timed-child termination without assuming JavaScript cleanup hooks run.
---

When verifying that a Node subprocess was killed by a synchronous timeout, assert that its PID is no longer alive rather than expecting a JavaScript `exit` handler to run.

**Why:** A genuinely hung Node child timed out by `spawnSync` did not execute its registered `exit` callback when terminated with the platform's timeout signal.

**How to apply:** For isolated subprocess-timeout tests, record the child's PID and confirm `process.kill(pid, 0)` reports `ESRCH` after the timed spawn returns. Keep all child-process output private and verify the timeout fails closed.
