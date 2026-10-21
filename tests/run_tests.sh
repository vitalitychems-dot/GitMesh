#!/usr/bin/env bash
# tests/run_tests.sh: runnable tests for tools/bundle-export.sh and
# tools/bundle-verify-import.sh. Everything (gpg homes, keys, repos, bundles)
# lives under one mktemp dir that is removed on exit. Throwaway keys only;
# nothing here is a real key and nothing is written outside the temp dir.
#
# Sender, receiver and attacker each get their own GNUPGHOME.
#
# Optional: ORIG_IMPORT=/path/to/old/bundle-verify-import.sh also runs the
# attack cases against that script, to show the before/after difference.
set -uo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
EXPORT="$HERE/tools/bundle-export.sh"
IMPORT="$HERE/tools/bundle-verify-import.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/airgap-tests.XXXXXX"); chmod 700 "$T"
SEND="$T/gnupg-sender" RECV="$T/gnupg-receiver" ATK="$T/gnupg-attacker"
mkdir -m 700 "$SEND" "$RECV" "$ATK" "$T/tmp"
export TMPDIR="$T/tmp"   # scripts' temp dirs land here so leftovers are countable
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
cleanup() { for h in "$SEND" "$RECV" "$ATK"; do gpgconf --homedir "$h" --kill all >/dev/null 2>&1; done; rm -rf "$T"; }
trap cleanup EXIT

PASS=0 FAIL=0 SKIP=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL  $*"; }
skip() { SKIP=$((SKIP+1)); echo "SKIP  $*"; }
indent() { sed 's/^/      | /'; }
# run_as HOME cmd...: run with that GNUPGHOME, capture output to $T/out, return rc
run_as() { local h=$1; shift; GNUPGHOME="$h" "$@" >"$T/out" 2>&1; local rc=$?; indent <"$T/out"; return $rc; }
expect_ok()   { local name=$1; shift; if run_as "$@"; then ok "$name"; else bad "$name (expected success)"; fi; }
expect_fail() { local name=$1 pat=$2; shift 2
  if run_as "$@"; then bad "$name (expected rejection)"
  elif grep -Eq "$pat" "$T/out"; then ok "$name (rejected: $pat)"
  else bad "$name (failed, but not with /$pat/)"; fi; }

gen() { # gen HOME UID -> prints primary fingerprint
  gpg --homedir "$1" --batch --passphrase '' --quick-gen-key "$2" default default never >/dev/null 2>&1
  gpg --homedir "$1" --batch --with-colons --list-keys "$2" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}'
}
pubto() { gpg --homedir "$1" --batch --export "$2" | gpg --homedir "$3" --batch --quiet --import 2>/dev/null; }

echo "run $(date '+%Y-%m-%d %H:%M %Z')"; gpg --version | head -1; git --version
command -v age >/dev/null && age --version | sed 's/^/age /' || echo "age: not installed"

S=$(gen "$SEND" "sender <s@example.invalid>")
S2=$(gen "$SEND" "sender-to-revoke <s2@example.invalid>")
R=$(gen "$RECV" "receiver <r@example.invalid>")
A=$(gen "$ATK" "attacker <a@example.invalid>")
pubto "$RECV" "$R" "$SEND"; pubto "$RECV" "$R" "$ATK"
pubto "$SEND" "$S" "$RECV"; pubto "$SEND" "$S2" "$RECV"; pubto "$ATK" "$A" "$RECV"
echo "keys: sender, sender2, receiver, attacker generated in separate GNUPGHOMEs (fingerprints not printed)"

# Source and target repos
SRC="$T/src" DST="$T/dst"
git init -q -b main "$SRC"; for i in 1 2; do echo "$i" >"$SRC/f"; git -C "$SRC" add f; git -C "$SRC" commit -qm "c$i"; done
GOOD=$(git -C "$SRC" rev-parse main)
git init -q -b main "$DST"; git -C "$DST" commit -q --allow-empty -m base
PLOG="$T/prov.jsonl"

echo "== 1 good path (export, verify-only, import)"
expect_ok "export gpg" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/o1" --name t1 --sign-key "$S" --gpg-recipient "$R"
[ "$(ls -A "$T/o1" | wc -l)" = 4 ] && ! ls -A "$T/o1" | grep -q '\.tmp\.' && ok "exactly 4 files, no staging leftovers" || bad "out dir contents: $(ls -A "$T/o1")"
jq -e 'has("exporter_host")|not' "$T/o1/t1.provenance.json" >/dev/null && ok "no exporter_host by default" || bad "host leaked"
expect_ok "verify-only" "$RECV" "$IMPORT" --in "$T/o1" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
[ -z "$(git -C "$DST" for-each-ref refs/remotes/airgap)" ] && ok "verify-only imported nothing" || bad "verify-only imported refs"
expect_ok "import" "$RECV" "$IMPORT" --in "$T/o1" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG"
[ "$(git -C "$DST" rev-parse refs/remotes/airgap/t1/main 2>/dev/null)" = "$GOOD" ] && ok "imported ref = source main" || bad "imported ref wrong"
jq -e '.refs[0].ref=="refs/remotes/airgap/t1/main"' "$PLOG" >/dev/null && ok "provenance log line is valid JSON (jq)" || bad "provenance log invalid"
expect_ok "lowercase/spaced fingerprint accepted" "$RECV" "$IMPORT" --in "$T/o1" --name t1 --signer "$(echo "$S" | tr A-F a-f | sed 's/..../& /g')" --target "$DST" --provenance-log "$PLOG" --verify-only

echo "== 2 wrong key"
expect_ok "attacker export (signed by attacker key)" "$ATK" "$EXPORT" --repo "$SRC" --out "$T/oA" --name t1 --sign-key "$A" --gpg-recipient "$R"
expect_fail "attacker-signed bundle, --signer=sender" "signature (not from|rejected)|exactly one GOODSIG|BADSIG" "$RECV" "$IMPORT" --in "$T/oA" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
expect_fail "signer not in receiver keyring" "not in your keyring" "$RECV" "$IMPORT" --in "$T/o1" --name t1 --signer "0123456789ABCDEF0123456789ABCDEF01234567" --target "$DST" --provenance-log "$PLOG" --verify-only
expect_fail "export with short KEYID recipient" "full 40/64-hex" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oK" --name k --sign-key "$S" --gpg-recipient "${R: -16}"

echo "== 3 revoked signer key"
expect_ok "export signed by sender2 (before revocation)" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oR" --name rv --sign-key "$S2" --gpg-recipient "$R"
expect_ok "verify-only before revocation" "$RECV" "$IMPORT" --in "$T/oR" --name rv --signer "$S2" --target "$DST" --provenance-log "$PLOG" --verify-only
sed 's/^:-----BEGIN/-----BEGIN/' "$SEND/openpgp-revocs.d/$S2.rev" | gpg --homedir "$RECV" --batch --quiet --import 2>/dev/null
gpg --homedir "$RECV" --batch --with-colons --list-keys "$S2" | grep -q '^pub:r:' && echo "      | (sender2 now revoked in receiver keyring)"
expect_fail "revoked signer rejected" "REVOKED|REVKEYSIG|KEYREVOKED" "$RECV" "$IMPORT" --in "$T/oR" --name rv --signer "$S2" --target "$DST" --provenance-log "$PLOG" --verify-only
if [ -n "${ORIG_IMPORT:-}" ]; then
  if run_as "$RECV" bash "$ORIG_IMPORT" --in "$T/oR" --name rv --signer "$S2" --target "$DST" --provenance-log "$T/orig.jsonl" --verify-only
  then echo "INFO  original script ACCEPTS the revoked key (bug reproduced)"; else echo "INFO  original script rejected the revoked key"; fi
fi

echo "== 4 tampering"
cp -r "$T/o1" "$T/oT"; printf 'x' >> "$T/oT/t1.bundle.gpg"
expect_fail "1 byte appended to encrypted bundle" "checksum mismatch" "$RECV" "$IMPORT" --in "$T/oT" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
cp -r "$T/o1" "$T/oM"; sed -i 's/^\(.\)/0/' "$T/oM/t1.SHA256SUMS"
expect_fail "edited manifest" "BADSIG|signature" "$RECV" "$IMPORT" --in "$T/oM" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
# A correctly signed manifest that leaves the provenance out
cp -r "$T/o1" "$T/oP"; grep -v provenance "$T/oP/t1.SHA256SUMS" > "$T/oP/s" && mv "$T/oP/s" "$T/oP/t1.SHA256SUMS"
GNUPGHOME="$SEND" gpg --batch --yes --local-user "$S!" --armor --detach-sign --output "$T/oP/t1.SHA256SUMS.asc" "$T/oP/t1.SHA256SUMS"
expect_fail "signed manifest without provenance" "manifest must list" "$RECV" "$IMPORT" --in "$T/oP" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
cp -r "$T/o1" "$T/oL"; mv "$T/oL/t1.provenance.json" "$T/oL/real.json"; ln -s real.json "$T/oL/t1.provenance.json"
expect_fail "symlink in --in" "symlink" "$RECV" "$IMPORT" --in "$T/oL" --name t1 --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only

echo "== 5 file swap after verify (TOCTOU)"
# Attacker commit, signed by the attacker, encrypted to the receiver, same name t1.
git clone -q "$SRC" "$T/evil"; echo pwned >"$T/evil/f"; git -C "$T/evil" commit -qam evil
EVIL=$(git -C "$T/evil" rev-parse HEAD)
GNUPGHOME="$ATK" "$EXPORT" --repo "$T/evil" --out "$T/oE" --name t1 --sign-key "$A" --gpg-recipient "$R" >/dev/null 2>&1 \
  && ok "attacker bundle built" || bad "attacker bundle build"
# PATH shim: the real sha256sum runs, then right after the first "-c" check it
# overwrites the bundle + provenance on the medium (--in) with the attacker's.
mkdir -p "$T/shim"; REAL=$(command -v sha256sum)
cat > "$T/shim/sha256sum" <<SH
#!/usr/bin/env bash
"$REAL" "\$@"; rc=\$?
case " \$* " in *" -c "*) if [ ! -e "$T/swapped" ]; then touch "$T/swapped"
  cp -f "$T/oE/t1.bundle.gpg" "$T/oE/t1.provenance.json" "\$SWAP_TO/"; fi;; esac
exit \$rc
SH
chmod +x "$T/shim/sha256sum"
swap_run() { # swap_run SCRIPT TARGET -> prints the ref that got imported
  rm -rf "$T/oS" "$T/swapped"; cp -r "$T/o1" "$T/oS"
  git init -q -b main "$2"; git -C "$2" commit -q --allow-empty -m base
  SWAP_TO="$T/oS" PATH="$T/shim:$PATH" run_as "$RECV" bash "$1" --in "$T/oS" --name t1 --signer "$S" --target "$2" --provenance-log "$T/swap.jsonl"
  echo "      | swap performed: $([ -e "$T/swapped" ] && echo yes || echo no)"
}
swap_run "$IMPORT" "$T/dswap"
GOTREF=$(git -C "$T/dswap" rev-parse -q --verify refs/remotes/airgap/t1/main || true)
if [ "$GOTREF" = "$GOOD" ] && [ -e "$T/swapped" ]; then ok "swap after check had no effect: imported the signed commit"
elif [ "$GOTREF" = "$EVIL" ]; then bad "attacker commit imported after swap"; else bad "swap test inconclusive (ref=$GOTREF)"; fi
if [ -n "${ORIG_IMPORT:-}" ]; then
  swap_run "$ORIG_IMPORT" "$T/dswap-orig"
  O=$(git -C "$T/dswap-orig" rev-parse -q --verify refs/remotes/airgap/t1/main || true)
  [ "$O" = "$EVIL" ] && echo "INFO  original script imported the ATTACKER commit after the swap (bug reproduced)" \
                     || echo "INFO  original script imported: ${O:-nothing}"
fi

echo "== 6 --signer as regex"
expect_fail "--signer '.*'" "full 40/64-hex" "$RECV" "$IMPORT" --in "$T/oA" --name t1 --signer '.*' --target "$DST" --provenance-log "$PLOG" --verify-only
expect_fail "--signer short KEYID" "full 40/64-hex" "$RECV" "$IMPORT" --in "$T/o1" --name t1 --signer "${S: -16}" --target "$DST" --provenance-log "$PLOG" --verify-only
if [ -n "${ORIG_IMPORT:-}" ]; then
  if run_as "$RECV" bash "$ORIG_IMPORT" --in "$T/oA" --name t1 --signer '.*' --target "$DST" --provenance-log "$T/orig.jsonl" --verify-only
  then echo "INFO  original script ACCEPTS the attacker key with --signer '.*' (bug reproduced)"; else echo "INFO  original script rejected '.*'"; fi
fi

echo "== 7 branch name with a quote"
git -C "$SRC" branch 'feat"quote' main
expect_ok "export with quoted branch" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oQ" --name q1 --sign-key "$S" --gpg-recipient "$R"
jq -e '.heads|map(.ref)|index("refs/heads/feat\"quote")!=null' "$T/oQ/q1.provenance.json" >/dev/null && ok "provenance JSON valid, quoted ref intact" || bad "provenance JSON with quote"
expect_ok "import quoted branch" "$RECV" "$IMPORT" --in "$T/oQ" --name q1 --signer "$S" --target "$DST" --provenance-log "$PLOG"
tail -1 "$PLOG" | jq -e '.refs|map(.ref)|index("refs/remotes/airgap/q1/feat\"quote")!=null' >/dev/null && ok "import log JSON valid with quoted ref" || bad "import log JSON with quote"
git -C "$SRC" branch -q -D 'feat"quote'
expect_ok "export --redact-provenance" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oX" --name rx --sign-key "$S" --gpg-recipient "$R" --redact-provenance
jq -e '(has("heads")|not) and (has("source_origin")|not)' "$T/oX/rx.provenance.json" >/dev/null && ok "redacted provenance has no heads/origin" || bad "redaction"
expect_ok "import redacted bundle" "$RECV" "$IMPORT" --in "$T/oX" --name rx --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only

echo "== 8 fsck on import"
TREE=$(git -C "$SRC" rev-parse 'main^{tree}')
BADC=$(printf 'tree %s\nauthor no-email-here 1 +0000\ncommitter x <x@y> 1 +0000\n\nbad\n' "$TREE" | git -C "$SRC" hash-object -t commit --literally -w --stdin)
git -C "$SRC" update-ref refs/heads/badobj "$BADC"
if GNUPGHOME="$SEND" "$EXPORT" --repo "$SRC" --out "$T/oF" --name fk --sign-key "$S" --gpg-recipient "$R" --refs badobj >/dev/null 2>&1; then
  git init -q -b main "$T/dfsck"
  expect_fail "malformed commit object rejected by fsck" "missingEmail|fsck|bad|error" "$RECV" "$IMPORT" --in "$T/oF" --name fk --signer "$S" --target "$T/dfsck" --provenance-log "$PLOG"
  [ -z "$(git -C "$T/dfsck" for-each-ref refs/remotes/airgap)" ] && ok "no ref created for malformed object" || bad "malformed object imported"
else skip "could not build a bundle with a malformed object"; fi
git -C "$SRC" update-ref -d refs/heads/badobj

echo "== 9 age round trip"
if command -v age >/dev/null && command -v age-keygen >/dev/null; then
  age-keygen -o "$T/age.key" 2>/dev/null; AR=$(age-keygen -y "$T/age.key")
  expect_ok "export age" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oG" --name ag --sign-key "$S" --age-recipient "$AR"
  expect_ok "import age" "$RECV" env AGE_IDENTITY="$T/age.key" "$IMPORT" --in "$T/oG" --name ag --signer "$S" --target "$DST" --provenance-log "$PLOG"
  [ "$(git -C "$DST" rev-parse refs/remotes/airgap/ag/main 2>/dev/null)" = "$GOOD" ] && ok "age import ref = source main" || bad "age import ref"
  age-keygen -o "$T/age2.key" 2>/dev/null
  expect_fail "age with wrong identity" "age decrypt failed" "$RECV" env AGE_IDENTITY="$T/age2.key" "$IMPORT" --in "$T/oG" --name ag --signer "$S" --target "$DST" --provenance-log "$PLOG" --verify-only
else skip "age not installed"; fi

echo "== 10 refuse overwrite"
expect_fail "re-export same name" "refusing to overwrite" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/o1" --name t1 --sign-key "$S" --gpg-recipient "$R"

echo "== temp dirs left by the scripts: $(ls -A "$T/tmp" | wc -l)"
[ -z "$(ls -A "$T/tmp")" ] && ok "no temp dirs left" || bad "leftover temp: $(ls -A "$T/tmp")"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
