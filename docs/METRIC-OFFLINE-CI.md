# Metric: offline mesh projects checked by CI

Owner: Network. Labels: **TESTED** = we ran it.

## Definition

The number of projects in `mesh/index.json` whose `run` command exits 0 with no
network (`unshare -rn`, 15 s timeout) **and** whose path appears in
`.github/workflows/*.yml`. Re-run it from a checkout of this repo:

```sh
tools/metric-offline-ci.sh          # needs bash, jq, unshare; prints METRIC offline+ci: N/9
```

The CI side is `tools/offline-mesh-check.sh`, run by the step "Offline mesh
projects (canary must fail)" in `local-vault-regressions.yml`. It first probes
the network (`curl https://github.com`, `getent hosts github.com`, a Node
`fetch`). Every probe must fail, or it exits 3 and the job fails. Then it runs
each listed project's `run` command from `mesh/index.json` with `timeout 15`.

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
| local-vault | no (interactive) | yes |

**0/9.**

## After this change (expected 6/9)

admit, carry, pass, shift, spin and tie run offline in CI: **6/9**.

## Next

- live: a self-test mode that serves one request on loopback and exits (7/9).
- local-vault: a non-interactive check, such as the existing sigil-auth tests (8/9).
- house has no run command and stays out until it has one.
