# Metric: offline mesh projects checked by CI

Owner: Network. Labels: **TESTED** = we ran it.

## Definition

The number of projects in `mesh/index.json` whose `run` command exits 0 with no
network (`unshare -rn`, 15 s timeout) **and** whose `PASS <path>` line appears
in the `Offline mesh projects (canary must fail)` step of a successful run of
`Local vault source-sync regressions` at the measured SHA. The line counts only
when the text after the timestamp begins with `PASS <path>`. No successful run
at that SHA means CI is 0 for every project. CI PASS lines are the proof.

```sh
tools/metric-offline-ci.sh <repo-root> <ci-log-file>   # needs bash, jq, unshare
```

Fetch the log (`gh run view --log` labels every step `UNKNOWN STEP` in gh 2.102,
so keep the section that starts at `step: Offline mesh projects (canary must fail)`):

```sh
sha=0e44c621
id=$(gh run list --workflow local-vault-regressions.yml --commit "$sha" --status success --json databaseId -q '.[0].databaseId')
if [ -z "$id" ] || [ "$id" = null ]; then : > /tmp/ci-$sha.log
else gh run view "$id" --log > /tmp/ci-$sha.log; fi
git worktree add --detach /tmp/offline-ci-$sha "$sha"
tools/metric-offline-ci.sh /tmp/offline-ci-$sha /tmp/ci-$sha.log
```

That baseline log has no `PASS` lines, so the metric prints `METRIC offline+ci: 0/9`.
For this tree, use `sha=$(git rev-parse HEAD)` and keep only the offline step:

```sh
gh run view "$id" --log | awk '/step: Offline mesh projects \(canary must fail\)/{p=1} p&&/Post job cleanup/{exit} p' > /tmp/ci-$sha.log
tools/metric-offline-ci.sh . /tmp/ci-$sha.log
```

That prints `METRIC offline+ci: 6/9`. `tools/test-metric-offline-ci.sh` checks the
same rule on fixture logs.

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

## Actions directory (TESTED)

The wrapper log printed `actions dir writable: yes` and `actions dir probed: /home/runner/work/_actions`. `$GITHUB_WORKSPACE/../../_actions` is that same path, so it was probed once. This is not part of the metric.

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
