#!/usr/bin/env bash
# Run inside a network namespace with no network. 1) curl, getent, and node
# must exist. 2) /proc/self/net/dev must list exactly lo. 3) The canary must
# fail with curl 6, getent 2, or node exit 1 and ENOTFOUND or EAI_AGAIN.
# 4) Run each project's `run` with a timeout.
# Usage: tools/offline-mesh-check.sh projects/admit projects/carry ...
set -euo pipefail
case "$0" in
  */*) cd "${0%/*}/.." ;;
  *) cd "$(dirname "$0")/.." ;;
esac
[ $# -gt 0 ] || { echo "usage: $0 projects/<name> ..." >&2; exit 2; }

missing=0
for tool in curl getent node; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "CANARY MISSING: $tool" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 4

netdevs=$(awk -F: 'NR>2{gsub(/ /,"",$1);print $1}' /proc/self/net/dev)
echo "interfaces: ${netdevs//$'\n'/ }"
[ "$netdevs" = "lo" ] || { echo "FAIL: interfaces are not exactly lo" >&2; exit 6; }

leak=0
inconclusive=0
probe() {
  local label="$1" ec=0 out="" code=""
  shift
  set +e
  if [ "$label" = node ]; then
    out=$(timeout 10 "$@" 2>/dev/null)
    ec=$?
  else
    timeout 10 "$@" >/dev/null 2>&1
    ec=$?
  fi
  set -e
  if [ "$ec" -eq 0 ]; then
    echo "CANARY LEAK: $label exit 0"
    leak=1
    return
  fi
  case "$label" in
    curl)
      if [ "$ec" -eq 6 ]; then
        echo "canary ok (failed as expected): curl exit $ec"
      else
        echo "CANARY INCONCLUSIVE: curl exit $ec"
        inconclusive=1
      fi
      ;;
    getent)
      if [ "$ec" -eq 2 ]; then
        echo "canary ok (failed as expected): getent exit $ec"
      else
        echo "CANARY INCONCLUSIVE: getent exit $ec"
        inconclusive=1
      fi
      ;;
    node)
      code=$(printf '%s' "$out" | tr -d '\r')
      if [ "$ec" -eq 1 ] && { [ "$code" = ENOTFOUND ] || [ "$code" = EAI_AGAIN ]; }; then
        echo "canary ok (failed as expected): node exit $ec code $code"
      else
        echo "CANARY INCONCLUSIVE: node exit $ec code ${code:-<empty>}"
        inconclusive=1
      fi
      ;;
  esac
}

probe curl curl -sS --max-time 5 https://github.com
probe getent getent hosts github.com
probe node node -e 'fetch("https://github.com",{signal:AbortSignal.timeout(5000)}).then(()=>process.exit(0),(err)=>{process.stdout.write(String(err.cause?.code||""));process.exit(1)})'
[ "$leak" -eq 0 ] || { echo "FAIL: network is reachable, refusing to call this offline" >&2; exit 3; }
[ "$inconclusive" -eq 0 ] || exit 5

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
