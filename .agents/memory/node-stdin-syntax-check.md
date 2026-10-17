---
name: Node stdin syntax checks
description: Validate exact JavaScript source bytes from stdin without reopening a path.
---

For ES module syntax validation from stdin, invoke Node with `--input-type=module --check` and pass the already-validated byte snapshot as stdin. Plain `--check` treats stdin as CommonJS and rejects valid `import` statements. Keep diagnostics captured; syntax errors can echo source lines.

**Why:** Source should be syntax-checked from the same bytes that passed file-handle validation, without reopening a potentially replaced path or leaking source through error output.

**How to apply:** When source preflight reads allowlisted JavaScript through an open descriptor, pass those bytes to Node in module mode. Never print raw parser diagnostics; when Node's stdin header and caret safely identify a location, expose only numeric line/column values and otherwise keep the generic error.
