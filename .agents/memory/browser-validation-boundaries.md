---
name: Browser validation boundaries
description: Evidence required before claiming rotating admin-key saving works across phone browsers.
---

Treat Chromium phone emulation, WebKit phone emulation and physical mobile Safari
as separate verification targets. Passing backend/session tests or installing a
browser package does not verify clipboard, download or save-sheet behavior.

**Why:** The key-rotation flow depends on browser and operating-system APIs.
Official WebKit binaries have failed native-library loading in this Nix workspace
even when dependency probes appeared successful. Do not repeat setup indefinitely
or infer an engine pass from those probes.

**How to apply:** Require actual scenario results from each engine and report
physical-iOS coverage separately. Recheck a real launch when the environment
changes rather than assuming an old limitation is permanent. Never use the real
administrator or bypass authentication to obtain browser screenshots.
