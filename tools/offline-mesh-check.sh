#!/usr/bin/env bash
# Run inside a network namespace with no network (CI uses unshare -rn or sudo unshare -n).
# 1) Canary: reaching the network MUST fail; if any probe succeeds, exit 3.
# 2) Run each given project's `run` command from mesh/index.json with a timeout.
# Usage: tools/offline-mesh-check.sh projects/admit projects/carry ...
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || { echo "usage: $0 projects/<name> ..." >&2; exit 2; }

leak=0
probe() { if timeout 10 "$@" >/dev/null 2>&1; then echo "CANARY LEAK: $*"; leak=1; else echo "canary ok (failed as expected): $*"; fi; }
probe curl -sS --max-time 5 https://github.com
probe getent hosts github.com
probe node -e 'fetch("https://github.com",{signal:AbortSignal.timeout(5000)}).then(()=>process.exit(0),()=>process.exit(1))'
[ "$leak" -eq 0 ] || { echo "FAIL: network is reachable, refusing to call this offline" >&2; exit 3; }

fail=0
for path in "$@"; do
  run=$(jq -r --arg p "$path" '.projects[] | select(.path == $p) | .run' mesh/index.json)
  if [ -z "$run" ]; then echo "FAIL $path: not in mesh/index.json or no run command"; fail=1; continue; fi
  if out=$(cd "$path" && timeout 15 bash -c "$run" </dev/null 2>&1); then
    echo "PASS $path: $run -> ${out//$'\n'/ | }"
  else
    echo "FAIL $path (exit $?): $run -> ${out//$'\n'/ | }"; fail=1
  fi
done
exit "$fail"
