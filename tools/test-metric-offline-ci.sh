#!/usr/bin/env bash
# Fixture logs only. Six real PASS lines are 6/9. An empty log, a missing
# log, an echoed or quoted PASS, and a FAIL line are 0/9.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
metric=$root/tools/metric-offline-ci.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
paths='projects/admit projects/carry projects/pass projects/shift projects/spin projects/tie'
stamp='2026-10-22T00:00:00.0000000Z'
: > "$tmp/empty.log"
: > "$tmp/pass.log"
: > "$tmp/decoy.log"
for path in $paths; do
  printf '%s %s\n' "$stamp" "PASS $path: ok" >> "$tmp/pass.log"
  printf '%s %s\n' "$stamp" "echo \"PASS $path: no\"" >> "$tmp/decoy.log"
  printf '%s %s\n' "$stamp" "\"PASS $path: no\"" >> "$tmp/decoy.log"
  printf '%s %s\n' "$stamp" "FAIL $path: no" >> "$tmp/decoy.log"
done

check() {
  local label="$1" file="$2" want="$3" out
  out=$(bash "$metric" "$root" "$file")
  printf '== %s ==\n%s\n' "$label" "$out"
  printf '%s\n' "$out" | grep -qx "$want" || { echo "expected $want from $label" >&2; exit 1; }
}
check 'six PASS lines' "$tmp/pass.log" "METRIC offline+ci: 6/9"
check 'empty log' "$tmp/empty.log" "METRIC offline+ci: 0/9"
check 'missing log' "$tmp/no-such.log" "METRIC offline+ci: 0/9"
check 'echo, quote, FAIL' "$tmp/decoy.log" "METRIC offline+ci: 0/9"
echo "test-metric-offline-ci: ok"
