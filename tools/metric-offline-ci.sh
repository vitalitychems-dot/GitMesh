#!/usr/bin/env bash
# Metric: projects in mesh/index.json whose `run` exits 0 with no network
# (unshare -rn, 15 s timeout) AND whose path is an argument of
# tools/offline-mesh-check.sh in a workflow run step.
# A comment, or any other mention of the path, does not count.
# CI PASS lines from that step are the ground truth that the run exited 0.
# Usage: tools/metric-offline-ci.sh [repo-root]   (needs bash, jq, unshare)
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
unshare -rn true 2>/dev/null || { echo "unshare -rn unavailable; cannot measure offline" >&2; exit 2; }

strip_comment() {
  local s="$1"
  [[ "$s" == \#* ]] && { printf ''; return; }
  printf '%s' "${s%% \#*}"
}

# Arguments of tools/offline-mesh-check.sh, one per line.
# Starts at the invocation and follows trailing-backslash continuations.
workflow_offline_args() {
  local file="$1" line indent=0 rest content stripped in_run=0 run_indent=0 collecting=0 buf="" cmd tok seen
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    indent=0
    rest=$line
    while [ "${rest:0:1}" = " " ]; do indent=$((indent + 1)); rest=${rest:1}; done
    content=$rest
    if [ "$collecting" -eq 1 ]; then
      stripped=$(strip_comment "$content")
      buf+=" ${stripped%\\}"
      if [[ "$stripped" == *\\ ]]; then continue; fi
      collecting=0
      # fall through to emit via the shared splitter below
      content=""
      stripped=$buf
      buf=""
      seen=0
      set -f
      for tok in $stripped; do
        if [ "$seen" -eq 0 ]; then
          case "$tok" in
            tools/offline-mesh-check.sh|*/tools/offline-mesh-check.sh) seen=1 ;;
          esac
          continue
        fi
        printf '%s\n' "$tok"
      done
      set +f
      continue
    fi
    if [ "$in_run" -eq 1 ] && [ -n "$content" ] && [ "$indent" -le "$run_indent" ]; then
      in_run=0
    fi
    if [ "$in_run" -eq 0 ]; then
      case "$content" in
        "run: |"*) in_run=1; run_indent=$indent; continue ;;
        "run:"*)
          cmd=${content#run:}
          cmd=${cmd#"${cmd%%[![:space:]]*}"}
          stripped=$(strip_comment "$cmd")
          ;;
        *) continue ;;
      esac
    else
      stripped=$(strip_comment "$content")
    fi
    [[ "$stripped" == *"tools/offline-mesh-check.sh"* ]] || continue
    if [[ "$stripped" == *\\ ]]; then
      collecting=1
      buf=${stripped%\\}
      continue
    fi
    seen=0
    set -f
    for tok in $stripped; do
      if [ "$seen" -eq 0 ]; then
        case "$tok" in
          tools/offline-mesh-check.sh|*/tools/offline-mesh-check.sh) seen=1 ;;
        esac
        continue
      fi
      printf '%s\n' "$tok"
    done
    set +f
  done < "$file"
}

shopt -s nullglob
ci_args=()
for workflow in .github/workflows/*.yml; do
  while IFS= read -r arg; do
    [ -n "$arg" ] && ci_args+=("$arg")
  done < <(workflow_offline_args "$workflow")
done

n=0 both=0
while IFS=$'\t' read -r name path run; do
  n=$((n + 1)); o=no; c=no
  if [ -n "$run" ] && (cd "$path" && unshare -rn timeout 15 bash -c "$run" </dev/null >/dev/null 2>&1); then o=yes; fi
  for arg in "${ci_args[@]+"${ci_args[@]}"}"; do
    if [ "$arg" = "$path" ]; then c=yes; break; fi
  done
  if [ "$o$c" = yesyes ]; then both=$((both + 1)); fi
  printf '%-12s offline=%s ci=%s\n' "$name" "$o" "$c"
done < <(jq -r '.projects[] | [.name, .path, .run] | @tsv' mesh/index.json)
echo "METRIC offline+ci: $both/$n"
