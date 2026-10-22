#!/usr/bin/env bash
# Metric: a project's run exits 0 with no network (unshare -rn, 15s) AND a
# successful "Local vault source-sync regressions" log has a line whose text
# after the timestamp begins with "PASS <path>".
# Usage: tools/metric-offline-ci.sh <repo-root> <ci-log-file>
# A missing or empty log is CI=0 for every project. Needs bash, jq, unshare.
set -euo pipefail
cd "${1:?repo root}"
log=${2:-}
unshare -rn true 2>/dev/null || { echo "unshare -rn unavailable; cannot measure offline" >&2; exit 2; }

ci_has() {
  local path="$1" line msg
  [ -n "$log" ] && [ -f "$log" ] && [ -s "$log" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    msg=$line
    if [[ "$line" =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[[:space:]](.*)$ ]]; then
      msg=${BASH_REMATCH[1]}
    fi
    case "$msg" in
      "PASS $path"|"PASS $path "*|"PASS $path:"*) return 0 ;;
    esac
  done < "$log"
  return 1
}

n=0 both=0
while IFS=$'\t' read -r name path run; do
  n=$((n + 1)); o=no; c=no
  if [ -n "$run" ] && (cd "$path" && unshare -rn timeout 15 bash -c "$run" </dev/null >/dev/null 2>&1); then o=yes; fi
  if ci_has "$path"; then c=yes; fi
  if [ "$o$c" = yesyes ]; then both=$((both + 1)); fi
  printf '%-12s offline=%s ci=%s\n' "$name" "$o" "$c"
done < <(jq -r '.projects[] | [.name, .path, .run] | @tsv' mesh/index.json)
echo "METRIC offline+ci: $both/$n"
