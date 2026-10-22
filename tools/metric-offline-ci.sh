#!/usr/bin/env bash
# Metric: projects in mesh/index.json whose `run` exits 0 with no network
# (unshare -rn, 15 s timeout) AND whose path appears in .github/workflows/*.yml.
# Usage: tools/metric-offline-ci.sh [repo-root]   (needs bash, jq, unshare)
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
unshare -rn true 2>/dev/null || { echo "unshare -rn unavailable; cannot measure offline" >&2; exit 2; }
n=0 both=0
while IFS=$'\t' read -r name path run; do
  n=$((n + 1)); o=no; c=no
  if [ -n "$run" ] && (cd "$path" && unshare -rn timeout 15 bash -c "$run" </dev/null >/dev/null 2>&1); then o=yes; fi
  if grep -qs -- "$path" .github/workflows/*.yml; then c=yes; fi
  if [ "$o$c" = yesyes ]; then both=$((both + 1)); fi
  printf '%-12s offline=%s ci=%s\n' "$name" "$o" "$c"
done < <(jq -r '.projects[] | [.name, .path, .run] | @tsv' mesh/index.json)
echo "METRIC offline+ci: $both/$n"
