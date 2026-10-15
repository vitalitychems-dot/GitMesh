---
name: Security preflight boundary
description: Keep publish preflight mandatory while allowing regression tests to avoid recursive runs.
---

The source-sync command should always run its regression preflight before making GitHub requests. Tests should mock the Python child-process invocation to simulate success or failure; do not add a runtime environment flag that skips preflight.

**Why:** A skip flag can accidentally become a production bypass, while mocking only the child process avoids recursive test runs without weakening the publish path.

**How to apply:** When changing source-sync preflight or its tests, preserve the unconditional production call and control mocked outcomes in the test preload.
