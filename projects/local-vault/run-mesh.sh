#!/bin/sh
set -eu
cd "$(dirname "$0")"

command -v node >/dev/null 2>&1 || {
  echo "Node.js is required. Install Node.js 20 or newer, then retry." >&2
  exit 1
}
command -v git >/dev/null 2>&1 || {
  echo "Git is required. Install Git, then retry." >&2
  exit 1
}

exec node ./gitmesh-ultimate-core.mjs
