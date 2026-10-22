#!/usr/bin/env bash
# Run inside a network namespace with no network (CI uses unshare -rn, or
# sudo unshare -n then setpriv). 1) curl, getent, and node must exist.
# 2) /sys/class/net must be exactly lo. 3) Each canary must fail with a
# network-failure code. 4) Run each project's `run` with a timeout.
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

netdevs=$(ls -1 /sys/class/net 2>/dev/null || true)
if [ "$netdevs" != "lo" ]; then
  # Host sysfs does not follow this netns until it is mounted in the netns.
  # Do that in a nested mount namespace so the caller's /sys is left alone.
  refresh='mount -t sysfs sysfs /sys && ls -1 /sys/class/net'
  if refreshed=$(unshare -m bash -c "$refresh" 2>/dev/null); then
    netdevs=$refreshed
  elif refreshed=$(sudo -n unshare -m bash -c "$refresh" 2>/dev/null); then
    netdevs=$refreshed
  fi
fi
echo "ls /sys/class/net: ${netdevs//$'\n'/ }"
[ "$netdevs" = "lo" ] || { echo "FAIL: /sys/class/net is not exactly lo" >&2; exit 6; }

echo "id: $(id)"

node_code_ok() {
  case "$1" in
    ENOTFOUND|EAI_AGAIN|ENETUNREACH|ECONNREFUSED|UND_ERR_CONNECT_TIMEOUT|ETIMEDOUT|EHOSTUNREACH|ENETDOWN|ECONNRESET|EHOSTDOWN|UND_ERR_SOCKET) return 0 ;;
    *) return 1 ;;
  esac
}

leak=0
inconclusive=0
probe() {
  local label="$1" ec=0 out="" code=""
  shift
  set +e
  out=$(timeout 10 "$@" 2>&1)
  ec=$?
  set -e
  if [ "$ec" -eq 0 ]; then
    echo "CANARY LEAK: $label exit 0"
    leak=1
    return
  fi
  case "$label" in
    curl)
      case "$ec" in
        6|7|28) echo "canary ok (failed as expected): curl exit $ec" ;;
        *) echo "CANARY INCONCLUSIVE: curl exit $ec"; inconclusive=1 ;;
      esac
      ;;
    getent)
      case "$ec" in
        2) echo "canary ok (failed as expected): getent exit $ec" ;;
        *) echo "CANARY INCONCLUSIVE: getent exit $ec"; inconclusive=1 ;;
      esac
      ;;
    node)
      code=$(printf '%s' "$out" | tr -d '\r')
      if node_code_ok "$code"; then
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
