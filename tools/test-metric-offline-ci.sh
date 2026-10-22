#!/usr/bin/env bash
# A pristine checkout of 0e44c621 (the command in docs/METRIC-OFFLINE-CI.md)
# prints METRIC offline+ci: 0/9. Fakes of the offline step on that base stay
# 0/9. This checkout, where the real step passes the six paths, is 6/9.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
metric=$root/tools/metric-offline-ci.sh
base=0e44c6215253aef203f85e24d415c2b0acbddc28
paths='projects/admit projects/carry projects/pass projects/shift projects/spin projects/tie'
tmp=$(mktemp -d)
cleanup() { git -C "$root" worktree remove --force "$tmp" >/dev/null 2>&1 || rm -rf "$tmp"; }
trap cleanup EXIT
git -C "$root" worktree add --detach "$tmp" "$base" >/dev/null
wf=$tmp/.github/workflows/local-vault-regressions.yml
saved=$(mktemp)
cp "$wf" "$saved"

check() {
  local label="$1" dir="$2" want="$3" out
  out=$(bash "$metric" "$dir")
  printf '== %s ==\n%s\n' "$label" "$out"
  printf '%s\n' "$out" | grep -qx "$want" || { echo "expected $want from $label" >&2; exit 1; }
}

reset() { cp "$saved" "$wf"; }
add_step() {
  local label="$1"
  reset
  {
    printf '%s\n' '      - name: Offline mesh projects (canary must fail)'
    cat
  } >> "$wf"
  check "$label" "$tmp" "METRIC offline+ci: 0/9"
}

check '0e44c621' "$tmp" "METRIC offline+ci: 0/9"
reset
printf '\n# %s\n' "$paths" >> "$wf"
check comment "$tmp" "METRIC offline+ci: 0/9"

add_step echo <<EOF
        run: |
          echo "\${wrap[@]}" bash tools/offline-mesh-check.sh $paths
EOF
add_step '|| true' <<EOF
        run: |
          "\${wrap[@]}" bash tools/offline-mesh-check.sh $paths || true
EOF
add_step 'if: false' <<EOF
        if: false
        run: |
          "\${wrap[@]}" bash tools/offline-mesh-check.sh \\
            $paths
EOF
add_step continue-on-error <<EOF
        continue-on-error: true
        run: |
          "\${wrap[@]}" bash tools/offline-mesh-check.sh \\
            $paths
EOF
add_step 'words after ;' <<EOF
        run: |
          "\${wrap[@]}" bash tools/offline-mesh-check.sh; $paths
EOF

check head "$root" "METRIC offline+ci: 6/9"
echo "test-metric-offline-ci: ok"
