---
name: Targeted Python unittest reruns
description: How to construct safe commands that rerun selected tests from this script-runner suite.
---

When running the regression file directly, selected test names must include the class, such as `GitHubSyncTests.test_example`. A bare method name is not resolved as a module attribute.

**Why:** The script uses `unittest.main()`, which loads command-line selections from the module namespace; test methods are attributes of their test classes.

**How to apply:** Generate rerun arguments as allowlisted `TestClass.test_method` pairs, and keep the class and method allowlists synchronized with the regression suite. Continue suppressing raw child output.
