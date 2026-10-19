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

Run `PORT=5000 node projects/live/live.mjs` to preview the public room. For a static publication, run `node scripts/build-public.mjs` and publish only `generated-artifacts/public`.

The public page is a browser-only welcome demo. It does not store entries, create accounts, grant access, or serve the local vault/keypad. Keep sigils, credential verifiers, tokens, and private Gitbook files out of public source and publishing output.
