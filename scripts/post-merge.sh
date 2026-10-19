#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

npm ci --ignore-scripts --no-audit
node scripts/setup-web-dev.mjs

node --test \
  gitmesh-template/test/sigil-auth.test.mjs \
  projects/local-vault/tests/sync-public-source.test.mjs
