---
name: Publication boundaries
description: Safe GitHub publication and separation between the public room and local admin state.
---

Publish vetted public working-tree snapshots on top of GitHub's existing main branch rather than blindly pushing the local branch's entire history.

**Why:** The local history contains private admin credential-verifier state that was not present in the public repository's main-branch history. A clean public snapshot avoids introducing that private history.

**How to apply:** Review the public file selection, exclude vault state, credential material, attachments and agent memory, preserve remote-only files, and never force-update a branch. Keep local private files intact.

The user authorized publication of GitMesh source on GitHub and its public room on Replit, then requested a redesigned UI and web-admin login. Public web hosting must not expose the local vault/keypad server or private Gitbook.

**Why:** The local administrator interface is not a public web application. Hosting only the public page avoids exposing administrative credentials or private storage.

**How to apply:** Use an isolated public build directory containing only explicitly approved public assets. Actual Replit publication requires the user's Publish action; do not report a live deployment until deployment metadata confirms it.

Keep web-admin identity separate from the offline rotating sigil. Grant web administration only through the configured repository owner's verified GitHub identity, never the first signup or a matching display name.

**Why:** The user needs mobile web-admin access without uploading private vault credentials. First-signup and username-based ownership would allow another person to claim the administrator role.

**How to apply:** Preserve the local sigil workflow. Use managed web authentication and server-side owner checks; do not offer the local vault as a cloud-admin feature. GitHub sign-in must be enabled separately for the Development and Production Auth environments.
