# Metric: offline mesh projects checked by CI

Owner: Network. Labels: **TESTED** = we ran it.

## Definition

The number of projects in `mesh/index.json` whose `run` command exits 0 with no
network (`unshare -rn`, 15 s timeout) **and** whose path is an argument of
`tools/offline-mesh-check.sh` in a workflow `run` step. The count follows that
invocation through its continuation lines and ignores comments. A comment, or
any other mention of the path, is not CI coverage. Re-run it from a checkout:

```sh
tools/metric-offline-ci.sh          # needs bash, jq, unshare; prints METRIC offline+ci: N/9
tools/test-metric-offline-ci.sh     # base workflow plus a path comment stays 0/9; this tree is 6/9
```

CI PASS lines from that step are the ground truth that the run actually exited 0.
The metric only records that the path was passed in. It does not invent a pass.

The CI side is `tools/offline-mesh-check.sh`, run by the step "Offline mesh
projects (canary must fail)" in `local-vault-regressions.yml`. `curl`, `getent`,
and `node` must be on `PATH` (missing tool: exit 4). `ls /sys/class/net` must be
exactly `lo`. The canary is `curl https://github.com`, `getent hosts github.com`,
and a Node `fetch` whose catch prints `err.cause?.code`. Accepted failures are
curl 6, 7, or 28; getent 2; and the Node codes ENOTFOUND, EAI_AGAIN,
ENETUNREACH, ECONNREFUSED, UND_ERR_CONNECT_TIMEOUT, or a similar network code
(ETIMEDOUT, EHOSTUNREACH, ENETDOWN, ECONNRESET, EHOSTDOWN, UND_ERR_SOCKET).
Any other non-zero code is `CANARY INCONCLUSIVE` and exits 5. A probe that
succeeds exits 3. Then each listed project's `run` command runs with `timeout 15`.

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
