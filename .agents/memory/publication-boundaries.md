---
name: Publication boundaries
description: Safe GitHub publication and separation between the public room and local admin state.
---

Publish vetted public working-tree snapshots on top of GitHub's existing main branch rather than blindly pushing the local branch's entire history.

**Why:** The local history contains private admin credential-verifier state that was not present in the public repository's main-branch history. A clean public snapshot avoids introducing that private history.

**How to apply:** Review the public file selection, exclude vault state, credential material, attachments and agent memory, preserve remote-only files, and never force-update a branch. Keep local private files intact.

The user authorized publication of GitMesh source on GitHub and its existing public room on Replit. Public web hosting must not expose the local vault/keypad server or private Gitbook.

**Why:** The local administrator interface is not a public web application. Hosting only the public page avoids exposing administrative credentials or private storage.

**How to apply:** Use an isolated public build directory containing only explicitly approved public assets. Actual Replit publication requires the user's Publish action; do not report a live deployment until deployment metadata confirms it.
