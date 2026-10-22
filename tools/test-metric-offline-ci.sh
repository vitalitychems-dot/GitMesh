#!/usr/bin/env bash
# A comment that names the six paths on the base workflow must stay 0/9.
# This checkout, where those paths are real arguments, must be 6/9.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
metric=$root/tools/metric-offline-ci.sh
base=0e44c6215253aef203f85e24d415c2b0acbddc28
tmp=$(mktemp -d)
cleanup() { git -C "$root" worktree remove --force "$tmp" >/dev/null 2>&1 || rm -rf "$tmp"; }
trap cleanup EXIT
git -C "$root" worktree add --detach "$tmp" "$base" >/dev/null
printf '\n# projects/admit projects/carry projects/pass projects/shift projects/spin projects/tie\n' >> "$tmp/.github/workflows/local-vault-regressions.yml"

check() {
  local label="$1" dir="$2" want="$3" out
  out=$(bash "$metric" "$dir")
  printf '== %s ==\n%s\n' "$label" "$out"
  printf '%s\n' "$out" | grep -qx "$want" || { echo "expected $want" >&2; exit 1; }
}
check "base+comment" "$tmp" "METRIC offline+ci: 0/9"
check "head" "$root" "METRIC offline+ci: 6/9"
echo "test-metric-offline-ci: ok"
