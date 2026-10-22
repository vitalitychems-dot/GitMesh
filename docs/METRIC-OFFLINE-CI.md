# Metric: offline mesh projects checked by CI

Owner: Network. Labels: **TESTED** = we ran it.

## Definition

The number of projects in `mesh/index.json` whose `run` command exits 0 with no
network (`unshare -rn`, 15 s timeout) **and** whose path is an argument of the
step named `Offline mesh projects (canary must fail)` in
`.github/workflows/local-vault-regressions.yml`. The metric is a text check of
that one step. `on:` must include `pull_request`, the step must have no `if:`
and no `continue-on-error`, and `"${wrap[@]}" bash tools/offline-mesh-check.sh`
must be the first command on its line. Arguments run through backslash
continuations and stop at `;`, `&&`, `||`, `|`, `#`, or the end of the command.
Re-run this tree's metric against a checkout of main `0e44c621` (needs bash, jq, unshare). That checkout prints `METRIC offline+ci: 0/9`:

```sh
git worktree add --detach /tmp/offline-ci-0e44c621 0e44c621
tools/metric-offline-ci.sh /tmp/offline-ci-0e44c621
git worktree remove --force /tmp/offline-ci-0e44c621
```

`tools/metric-offline-ci.sh` on this tree prints `METRIC offline+ci: 6/9`.
`tools/test-metric-offline-ci.sh` asserts `0/9` on that `0e44c621` checkout and `6/9` here.

CI PASS lines from that step are the proof that the run actually exited 0.
The metric is only the text check. It does not invent a pass.

The CI side is `tools/offline-mesh-check.sh`, run by the step "Offline mesh
projects (canary must fail)" in `local-vault-regressions.yml`. `curl`, `getent`,
and `node` must be on `PATH` (missing tool: exit 4). Interfaces come from
`/proc/self/net/dev` and must be exactly `lo`. The canary is `curl
https://github.com`, `getent hosts github.com`, and a Node `fetch` whose catch
prints `err.cause?.code`. The only accepted failures are curl 6, getent 2, and
node exit 1 with `ENOTFOUND` or `EAI_AGAIN`. Anything else, including curl 7 or
28 and `ECONNREFUSED`, `ECONNRESET`, or `UND_ERR_*`, is `CANARY INCONCLUSIVE`
and exits 5. A probe that succeeds exits 3. Then each listed project's `run`
command runs with `timeout 15`.

## Baseline (TESTED, main `0e44c621`, 2026-10-22)

| Project | Offline run passes | In CI |
|---|---|---|
| admit | yes | no |
| carry | yes | no |
| house | no (no run command) | no |
| live | no (a server; does not exit) | no |
| pass | yes | no |
| shift | yes | no |
| spin | yes | no |
| tie | yes | no |
| local-vault | no (interactive) | no |

**0/9.**

## After this change (expected 6/9)

admit, carry, pass, shift, spin and tie run offline in CI: **6/9**.

## Next

- live: a self-test mode that serves one request on loopback and exits (7/9).
- local-vault: a non-interactive check, such as the existing sigil-auth tests (8/9).
- house has no run command and stays out until it has one.
