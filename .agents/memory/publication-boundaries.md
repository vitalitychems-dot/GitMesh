---
name: Publication boundaries
description: Safe GitHub publication and separation between the public room and local admin state.
---

Publish vetted public working-tree snapshots on top of GitHub's existing main branch rather than blindly pushing the local branch's entire history.

**Why:** The local history contains private admin credential-verifier state that was not present in the public repository's main-branch history. A clean public snapshot avoids introducing that private history.

**How to apply:** Review the public file selection, exclude vault state, credential material, attachments and agent memory, preserve remote-only files, and never force-update a branch. Keep local private files intact.

A healthy GitHub connection does not guarantee permission to update workflow files.

**Why:** Repository contents and workflows have separate authorization requirements; connection health alone does not establish endpoint-specific permission.

**How to apply:** Treat workflow permission separately from general repository access. Follow the integration's authorization-recovery flow and retry once rather than exporting credentials or bypassing the integration.

The user authorized publication of GitMesh source on GitHub and web hosting on Replit, then clarified that the web workspace is private. Hosting must not expose the local vault/keypad server or private Gitbook.

**Why:** The local administrator interface is not the web application. Isolating the web build and backend avoids exposing offline credentials or private storage.

**How to apply:** Use an isolated public build directory containing only explicitly approved public assets. Actual Replit publication requires the user's Publish action; do not report a live deployment until deployment metadata confirms it.

Keep web-admin identity separate from the offline rotating sigil. Use private first-party admin-key authentication, never social identity, a first signup or a matching display name.

**Why:** The user rejected external/social login and needs mobile admin access without uploading offline vault credentials. Public signup or username-based ownership would let another person claim the role.

**How to apply:** Preserve the local sigil workflow. Use a separately provisioned web-admin key and server-side checks, not a cloud proxy for the local vault. Never reset consumed-key history through a routine configuration change.
