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

## Public web page

Run `npm run dev` to preview the public room and web-admin sign-in. The frontend
source is in `projects/live/client/`. Build with `npm run build`, then run
`npm start` for the production web server. Web authentication needs a running
server: do not publish this version as a static-only site.

The welcome preview remains browser-only and clears on reload. The separate
web-admin area uses managed Clerk authentication and requires a verified GitHub
connection whose numeric GitHub ID matches `GITMESH_ADMIN_GITHUB_ID`. Display
names, arbitrary account creation, email addresses and client-side role values
cannot grant admin access. The initial owner is the GitMesh repository owner.

In Replit's **Auth → Configure → SSO providers**, enable **GitHub** in both
Development and Production. Visit `/sign-in` and continue with the owner GitHub
account (`vitalitychems-dot`). Enable the provider before trying to sign in;
email-only or Google-only accounts will not receive admin access. Secrets
`CLERK_SECRET_KEY`, `CLERK_PUBLISHABLE_KEY`, and
`VITE_CLERK_PUBLISHABLE_KEY` are managed through Auth/Secrets, never source.
`GITMESH_ADMIN_GITHUB_LOGIN` is the public display name; the numeric ID is the
server-side authority.

The web-admin page reports the running service and security boundary; it does
not open or serve the local vault/keypad. Local sigil rotation is unchanged.
Never enter a vault sigil or GitHub token in the welcome preview or web login.
Keep credential verifiers, tokens, and private Gitbook files out of public source,
deployment packages and build output. A Replit publish/republish is required to
put this server-backed version online.
