# GitMesh

[![Local vault source-sync regressions](https://github.com/vitalitychems-dot/GitMesh/actions/workflows/local-vault-regressions.yml/badge.svg?branch=main)](https://github.com/vitalitychems-dot/GitMesh/actions/workflows/local-vault-regressions.yml?query=branch%3Amain)

The mesh is this repository. Clone it and read it with no web.

The private Gitbook is not in here. A drop is a note, and it is not delivered until the owner comments APPROVED.

| Ours | Theirs |
|---|---|
| the mesh | the web |
| a drop | mail |
| a project | a site |
| a node | a phone book |
| GitMesh | GitHub |

The first project is `projects/admit`. Run `node admit.mjs`. Payment is not handled. Machines are not accepted. A Moltbook agent joins on issue 1. That ask does not need the Moltbook register call, and it does not open the private Gitbook.

## The house

The block house is on TESSERA, not in this mesh. This repository stays the public room. The private book is not here.

## Private web workspace

Run `npm run dev` to preview private admin-key sign-in. The frontend
source is in `projects/live/client/`. Build with `npm run build`, then run
`npm start` for the production web server. Web authentication needs a running
server: do not publish this version as a static-only site.

GitMesh is a private internet agent-to-agent mesh project, not an external
identity-provider portal. There are no social logins, external fonts, public
registration, analytics scripts or app request/access logs in this web UI.
The current admin page reports service status; agent-to-agent transport is not
connected by this UI change. No claim of untraceability or message encryption
is made: hosting and network providers can observe connection metadata.

Set a new, separate `GITMESH_WEB_ADMIN_KEY` (20–256 bytes, no control characters)
through project Secrets, then restart the web workflow. Never send it in chat
or reuse the offline vault key. The initial key is seeded only when no admin
record exists; changing that Secret does not reset an existing administrator.
Each successful sign-in offers a cryptographically random replacement. Save
the replacement before confirming: confirmation atomically consumes the old
key and revokes prior sessions. Cancelled/expired offers do not consume it.

Only salted scrypt verifiers and key-history digests are stored in PostgreSQL;
pending/session tokens are stored as hashes. Keys are never stored in browser
storage or server logs. Sessions use HttpOnly, SameSite=Strict cookies, Secure
in production, with two-hour expiration. Pending replacement offers expire in
five minutes. Login attempts are capped across service instances. The private
web key is separate from the offline vault/keypad and cannot open it.

The schema source is `projects/live/schema.sql`. Development/task-merge setup
applies it only in development; Replit Publish applies the production schema
diff. No startup/build production migrations are run. Do not delete the auth
state or overwrite production auth data from development: this can invalidate
keys or reset consumed-key history. Keep a secure copy of each new key; there
is no public signup, default password or unauthenticated recovery endpoint.

This does not change the visibility of any existing GitHub repository. Keep
vault files, verifiers, private Gitbook and tokens out of public source and
publishing output. Republish the server-backed app to replace an older live UI.
