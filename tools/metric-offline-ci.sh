#!/usr/bin/env bash
# Metric: a project's run exits 0 with no network (unshare -rn, 15s) AND its
# path is an argument of the one step "Offline mesh projects (canary must fail)"
# in .github/workflows/local-vault-regressions.yml. This is a text check of
# that step. CI PASS lines are the proof the run exited 0.
# Usage: tools/metric-offline-ci.sh [repo-root]   (needs bash, jq, unshare)
set -euo pipefail

step_name='Offline mesh projects (canary must fail)'
prefix='"${wrap[@]}" bash tools/offline-mesh-check.sh'
wf_rel=.github/workflows/local-vault-regressions.yml

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

on_has_pull_request() {
  local line in=0 t
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    if [ "$in" -eq 0 ]; then
      case "$line" in
        on:*) in=1; case "$line" in *pull_request*) return 0 ;; esac ;;
      esac
      continue
    fi
    case "$line" in
      [[:space:]]*)
        t=$(trim "$line")
        case "$t" in \#*) continue ;; *pull_request*) return 0 ;; esac
        ;;
      *) break ;;
    esac
  done < "$1"
  return 1
}

# Print path arguments of a bare invocation in the named step.
# An operator (; & | #) means the command is not bare, so it counts as nothing.
step_paths() {
  local line rest indent=0 in=0 step_indent=0 bad=0 collecting=0 buf="" content
  local -a held=()
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    indent=0
    rest=$line
    while [ "${rest:0:1}" = " " ]; do indent=$((indent + 1)); rest=${rest:1}; done
    if [ "$in" -eq 0 ]; then
      [ "$rest" = "- name: $step_name" ] || continue
      in=1
      step_indent=$indent
      continue
    fi
    if [ -n "$rest" ] && [ "$indent" -le "$step_indent" ]; then
      break
    fi
    case "$rest" in
      if:*|continue-on-error:*) bad=1; held=() ;;
    esac
    content=$rest
    if [ "$collecting" -eq 1 ]; then
      buf+=" ${content%\\}"
      [[ "$content" == *\\ ]] && continue
      collecting=0
      [ "$bad" -eq 0 ] && emit_paths "$buf"
      continue
    fi
    case "$content" in
      "$prefix"|"$prefix "*|"$prefix"\\*)
        if [[ "$content" == *\\ ]]; then
          collecting=1
          buf=${content%\\}
        elif [ "$bad" -eq 0 ]; then
          emit_paths "$content"
        fi
        ;;
    esac
  done < "$1"
  if [ "$collecting" -eq 1 ] && [ "$bad" -eq 0 ]; then
    emit_paths "$buf"
  fi
  [ "$bad" -eq 0 ] && [ "${#held[@]}" -gt 0 ] || return 0
  printf '%s\n' "${held[@]}"
}

emit_paths() {
  local cmd="$1" rest tok
  rest=${cmd#"$prefix"}
  case "$rest" in
    *';'*|*'&'*|*'|'*|*'#'*) return 0 ;;
  esac
  set -f
  for tok in $rest; do
    [ -n "$tok" ] && held+=("$tok")
  done
  set +f
}

# main
cd "${1:-$(dirname "$0")/..}"
unshare -rn true 2>/dev/null || { echo "unshare -rn unavailable; cannot measure offline" >&2; exit 2; }

ci_args=()
if [ -f "$wf_rel" ] && on_has_pull_request "$wf_rel"; then
  while IFS= read -r arg; do
    [ -n "$arg" ] && ci_args+=("$arg")
  done < <(step_paths "$wf_rel")
fi

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
