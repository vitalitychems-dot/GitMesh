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
T=$(mktemp -d "${TMPDIR:-/tmp}/airgap-tests.XXXXXX") || { echo "ABORT: mktemp failed" >&2; exit 2; }
[ -n "$T" ] && [ -d "$T" ] && [ ! -L "$T" ] || { echo "ABORT: bad temp dir '$T'" >&2; exit 2; }
chmod 700 "$T" || { echo "ABORT: chmod failed" >&2; exit 2; }
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
cp -r "$T/o1" "$T/oM"; # Flip the first hex digit of the first line (always a real change, never a no-op).
awk 'NR==1{c=substr($0,1,1); $0=(c=="0"?"1":"0") substr($0,2)} {print}' "$T/oM/t1.SHA256SUMS" > "$T/oM/s" && mv "$T/oM/s" "$T/oM/t1.SHA256SUMS"
cmp -s "$T/o1/t1.SHA256SUMS" "$T/oM/t1.SHA256SUMS" && bad "manifest edit was a no-op"
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

echo "== 11 mid-export failure leaves nothing in --out"
mkdir -p "$T/fshim"
for tool in cp mv; do REALT=$(command -v $tool)
cat > "$T/fshim/$tool" <<SH
#!/usr/bin/env bash
# Fail (as if the disk were full) on the Nth $tool whose last arg is inside \$FAIL_OUT.
last="\${@: -1}"
case "\$last" in "\$FAIL_OUT"/*)
  n=\$(( \$(cat "\$FAIL_OUT.cnt.$tool" 2>/dev/null || echo 0) + 1 )); echo \$n > "\$FAIL_OUT.cnt.$tool"
  if [ "\$n" = "\${FAIL_AT_$tool:-0}" ]; then echo "$tool: No space left on device (simulated)" >&2; exit 1; fi;;
esac
exec "$REALT" "\$@"
SH
chmod +x "$T/fshim/$tool"; done
for mode in "cp 2" "mv 3"; do set -- $mode
  OUTF="$T/oFail-$1"; rm -rf "$OUTF"
  expect_fail "export fails on $1 #$2 into --out" "nothing left behind" "$SEND" env PATH="$T/fshim:$PATH" FAIL_OUT="$OUTF" "FAIL_AT_$1=$2" \
    "$EXPORT" --repo "$SRC" --out "$OUTF" --name mf --sign-key "$S" --gpg-recipient "$R"
  [ -d "$OUTF" ] && [ -z "$(ls -A "$OUTF")" ] && ok "--out is empty after $1 failure (no bundle, no temp files)" || bad "leftovers after $1 failure: $(ls -A "$OUTF" 2>&1)"
done
expect_ok "same export succeeds afterwards" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oFail-cp" --name mf --sign-key "$S" --gpg-recipient "$R"

echo "== 12 signing subkey"
gpg --homedir "$SEND" --batch --passphrase '' --quick-gen-key "subkey-signer <sk@example.invalid>" ed25519 cert never >/dev/null 2>&1
SK=$(gpg --homedir "$SEND" --batch --with-colons --list-keys sk@example.invalid 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
gpg --homedir "$SEND" --batch --passphrase '' --quick-add-key "$SK" ed25519 sign never >/dev/null 2>&1
SUBF=$(gpg --homedir "$SEND" --batch --with-colons --list-keys "$SK" 2>/dev/null | awk -F: '$1=="fpr"{n++; if(n==2){print $10; exit}}')
pubto "$SEND" "$SK" "$RECV"
[ -n "$SUBF" ] && [ "$SUBF" != "$SK" ] && ok "cert-only primary with a separate signing subkey" || bad "subkey setup"
expect_ok "export with --sign-key = primary (signs with subkey)" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oSK" --name sk --sign-key "$SK" --gpg-recipient "$R"
VS=$(GNUPGHOME="$RECV" gpg --batch --status-fd 1 --verify "$T/oSK/sk.SHA256SUMS.asc" "$T/oSK/sk.SHA256SUMS" 2>/dev/null | awk '$2=="VALIDSIG"{print $3, $NF}')
[ "$VS" = "$SUBF $SK" ] && ok "VALIDSIG: signed by subkey, primary = --sign-key" || bad "VALIDSIG fields: $VS"
expect_ok "import with --signer = primary" "$RECV" "$IMPORT" --in "$T/oSK" --name sk --signer "$SK" --target "$DST" --provenance-log "$PLOG" --verify-only
expect_fail "import with --signer = subkey fpr" "fingerprint mismatch|full 40/64-hex|not from" "$RECV" "$IMPORT" --in "$T/oSK" --name sk --signer "$SUBF" --target "$DST" --provenance-log "$PLOG" --verify-only

echo "== 13 credentials stripped from origin URL"
git clone -q "$SRC" "$T/cred"
git -C "$T/cred" remote set-url origin 'https://user:s3cret@example.invalid/org/repo.git?token=AAA&access_token=BBB#frag-CCC'
expect_ok "export from repo with credentialed origin" "$SEND" "$EXPORT" --repo "$T/cred" --out "$T/oC" --name cr --sign-key "$S" --gpg-recipient "$R"
O=$(jq -r .source_origin "$T/oC/cr.provenance.json"); echo "      | source_origin: $O"
[ "$O" = "https://example.invalid/org/repo.git" ] && ok "userinfo, query and fragment stripped" || bad "origin not stripped: $O"
grep -Eq 's3cret|AAA|BBB|CCC|token' "$T/oC/cr.provenance.json" && bad "credential text in provenance" || ok "no credential text anywhere in provenance"
# Unusual forms (GitAI P3): uppercase scheme, scp-style user:tok@, '/' in the password, ;token= params.
n=0
while IFS='|' read -r url want; do n=$((n+1))
  git -C "$T/cred" remote set-url origin "$url"
  if GNUPGHOME="$SEND" "$EXPORT" --repo "$T/cred" --out "$T/oC$n" --name "cr$n" --sign-key "$S" --gpg-recipient "$R" >"$T/out" 2>&1; then
    O=$(jq -r .source_origin "$T/oC$n/cr$n.provenance.json"); echo "      | $url -> $O"
    if [ "$O" = "$want" ] && ! grep -Eq 'S3CRET|scptok|pa/ss|semitok' "$T/oC$n/cr$n.provenance.json"; then ok "origin stripped: $want"
    else bad "origin form $n: got '$O', want '$want'"; fi
  else indent <"$T/out"; bad "export with origin form $n"; fi
done <<'URLS'
HTTPS://User:S3CRET@Example.invalid/org/repo.git|https://Example.invalid/org/repo.git
deploy:scptok@git.example.invalid:org/repo.git|git.example.invalid:org/repo.git
https://user:pa/ss@example.invalid/org/repo.git|https://example.invalid/org/repo.git
https://example.invalid/org/repo.git;token=semitok;x=1|https://example.invalid/org/repo.git
URLS

echo "== 14 expired signer key"
gpg --homedir "$SEND" --batch --passphrase '' --faked-system-time 20200101T000000 \
    --quick-gen-key "expired <ex@example.invalid>" default default 2020-06-01 >/dev/null 2>&1
EX=$(gpg --homedir "$SEND" --batch --with-colons --list-keys ex@example.invalid 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
gpg --homedir "$SEND" --batch --with-colons --list-keys "$EX" 2>/dev/null | grep -q '^pub:e:' && ok "key created 2020-01-01, expired 2020-06-01" || bad "expired key setup"
pubto "$SEND" "$EX" "$RECV"
expect_fail "export refuses an expired --sign-key" "revoked, expired" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/oEx0" --name ex --sign-key "$EX" --gpg-recipient "$R"
# Hand-build a bundle signed while the key was still valid (faked 2020-03-01 clock).
cp -r "$T/o1" "$T/oEx"; for f in "$T/oEx"/t1.*; do mv "$f" "${f/\/t1./\/ex.}"; done
jq -c --arg s "$EX" '.name="ex" | .signer=$s' "$T/oEx/ex.provenance.json" > "$T/oEx/p" && mv "$T/oEx/p" "$T/oEx/ex.provenance.json"
( cd "$T/oEx" && sha256sum ex.bundle.gpg ex.provenance.json > ex.SHA256SUMS )
GNUPGHOME="$SEND" gpg --batch --yes --faked-system-time 20200301T000000 --local-user "$EX" --armor --detach-sign \
  --output "$T/oEx/ex.SHA256SUMS.asc" "$T/oEx/ex.SHA256SUMS" 2>/dev/null
expect_fail "signature by now-expired key rejected" "EXPIRED|EXPKEYSIG|KEYEXPIRED" "$RECV" "$IMPORT" --in "$T/oEx" --name ex --signer "$EX" --target "$DST" --provenance-log "$PLOG" --verify-only
if [ -n "${ORIG_IMPORT:-}" ]; then
  if run_as "$RECV" bash "$ORIG_IMPORT" --in "$T/oEx" --name ex --signer "$EX" --target "$DST" --provenance-log "$T/orig.jsonl" --verify-only
  then echo "INFO  original script ACCEPTS the expired key"; else echo "INFO  original script rejected the expired key"; fi
fi

echo "== 15 replay and re-import"
D15="$T/d15"; L15="$T/p15.jsonl"; git init -q -b main "$D15"; git -C "$D15" commit -q --allow-empty -m base
expect_ok "export OLD (main at c2) as 'rp'" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/rpOld" --name rp --sign-key "$S" --gpg-recipient "$R"
sleep 1; echo 3 >"$SRC/f"; git -C "$SRC" commit -qam c3; NEW=$(git -C "$SRC" rev-parse main)
expect_ok "export NEW (main at c3) as 'rp'" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/rpNew" --name rp --sign-key "$S" --gpg-recipient "$R"
expect_ok "import NEW" "$RECV" "$IMPORT" --in "$T/rpNew" --name rp --signer "$S" --target "$D15" --provenance-log "$L15"
expect_ok "re-import the same NEW bundle (idempotent)" "$RECV" "$IMPORT" --in "$T/rpNew" --name rp --signer "$S" --target "$D15" --provenance-log "$L15"
[ "$(git -C "$D15" rev-parse refs/remotes/airgap/rp/main)" = "$NEW" ] && ok "ref unchanged by re-import" || bad "ref changed by re-import"
expect_fail "replay OLD signed bundle under same name" "possible replay" "$RECV" "$IMPORT" --in "$T/rpOld" --name rp --signer "$S" --target "$D15" --provenance-log "$L15"
expect_fail "replay OLD with --allow-replay: git refuses non-fast-forward" "non-fast-forward|rejected" "$RECV" "$IMPORT" --in "$T/rpOld" --name rp --signer "$S" --target "$D15" --provenance-log "$L15" --allow-replay
[ "$(git -C "$D15" rev-parse refs/remotes/airgap/rp/main)" = "$NEW" ] && ok "quarantine ref still at NEW (no rollback)" || bad "ref rolled back"
# Diverged history under the same name (e.g. force-pushed source): newer, but not a fast-forward.
git clone -q "$SRC" "$T/div"; git -C "$T/div" reset -q --hard HEAD~1; echo div >"$T/div/f"; git -C "$T/div" commit -qam div
sleep 1; expect_ok "export diverged history as 'rp'" "$SEND" "$EXPORT" --repo "$T/div" --out "$T/rpDiv" --name rp --sign-key "$S" --gpg-recipient "$R"
expect_fail "import diverged over existing ref" "non-fast-forward|rejected" "$RECV" "$IMPORT" --in "$T/rpDiv" --name rp --signer "$S" --target "$D15" --provenance-log "$L15"
[ "$(git -C "$D15" rev-parse refs/remotes/airgap/rp/main)" = "$NEW" ] && ok "existing quarantine ref not overwritten" || bad "ref overwritten"
tail -1 "$L15" | jq -e '.status=="rejected" and .name=="rp"' >/dev/null && ok "failed import leaves a status=rejected log record" || bad "no failure record"
# Replay of an old bundle under a NEW name is NOT detected: it lands in its own namespace.
# Renaming the files does not help: the signed manifest names rp.* and the signed provenance says name "rp".
mkdir "$T/rpRen"; for f in "$T/rpOld"/rp.*; do b=${f##*/}; cp "$f" "$T/rpRen/rp2.${b#rp.}"; done
expect_fail "old bundle renamed to another --name" "manifest (must list|lists unexpected)|provenance name" "$RECV" "$IMPORT" --in "$T/rpRen" --name rp2 --signer "$S" --target "$D15" --provenance-log "$L15" --verify-only
D15b="$T/d15b"; git init -q -b main "$D15b"; git -C "$D15b" commit -q --allow-empty -m base
expect_ok "old bundle into a fresh receiver (no log): accepted, documented limitation" "$RECV" "$IMPORT" --in "$T/rpOld" --name rp --signer "$S" --target "$D15b" --provenance-log "$T/p15b.jsonl"
jq -e 'has("created_utc")' "$L15" >/dev/null && ok "import log records signed created_utc" || bad "no created_utc in log"

echo "== 16 atomic import: diverged main + new branch creates no refs (GitAI P1)"
D16="$T/d16"; L16="$T/p16.jsonl"; git init -q -b main "$D16"; git -C "$D16" commit -q --allow-empty -m base
expect_ok "import NEW as 'rp' into a fresh receiver" "$RECV" "$IMPORT" --in "$T/rpNew" --name rp --signer "$S" --target "$D16" --provenance-log "$L16"
git clone -q "$T/div" "$T/div2"; git -C "$T/div2" branch newbr
sleep 1; expect_ok "export diverged main + new branch 'newbr' as 'rp'" "$SEND" "$EXPORT" --repo "$T/div2" --out "$T/rpDivNew" --name rp --sign-key "$S" --gpg-recipient "$R"
expect_fail "import diverged main + new branch" "non-fast-forward|rejected" "$RECV" "$IMPORT" --in "$T/rpDivNew" --name rp --signer "$S" --target "$D16" --provenance-log "$L16"
git -C "$D16" rev-parse -q --verify refs/remotes/airgap/rp/newbr >/dev/null && bad "new branch ref created despite rejected main (not atomic)" || ok "no ref created for the new branch (atomic)"
[ "$(git -C "$D16" rev-parse refs/remotes/airgap/rp/main)" = "$NEW" ] && ok "main quarantine ref unchanged" || bad "main ref changed"
[ "$(git -C "$D16" for-each-ref refs/remotes/airgap | wc -l)" = 1 ] && ok "quarantine namespace has exactly the one earlier ref" || bad "unexpected refs: $(git -C "$D16" for-each-ref refs/remotes/airgap)"
tail -1 "$L16" | jq -e '.status=="rejected" and (.refs|length)==1' >/dev/null && ok "failure record written (status rejected, refs as they still are)" || bad "failure record missing/wrong"
expect_ok "failure record does not advance the replay guard: NEW re-import still a no-op" "$RECV" "$IMPORT" --in "$T/rpNew" --name rp --signer "$S" --target "$D16" --provenance-log "$L16"

echo "== 17 replay guard: equal created_utc, different bundle (GitAI P2)"
D17="$T/d17"; L17="$T/p17.jsonl"; git init -q -b main "$D17"; git -C "$D17" commit -q --allow-empty -m base
# Two validly signed bundles under name 'eq' with the SAME created_utc but different
# contents/manifests (as two exports in the same second would have).
expect_ok "export A as 'eq'" "$SEND" "$EXPORT" --repo "$SRC" --out "$T/eqA" --name eq --sign-key "$S" --gpg-recipient "$R"
git clone -q "$SRC" "$T/eqsrc"; echo 4 >"$T/eqsrc/f"; git -C "$T/eqsrc" commit -qam c4; EQB=$(git -C "$T/eqsrc" rev-parse main)
expect_ok "export B (fast-forward of A) as 'eq'" "$SEND" "$EXPORT" --repo "$T/eqsrc" --out "$T/eqB" --name eq --sign-key "$S" --gpg-recipient "$R"
CA=$(jq -r .created_utc "$T/eqA/eq.provenance.json")
jq -c --arg c "$CA" '.created_utc=$c' "$T/eqB/eq.provenance.json" > "$T/eqB/p" && mv "$T/eqB/p" "$T/eqB/eq.provenance.json"
( cd "$T/eqB" && sha256sum eq.bundle.gpg eq.provenance.json > eq.SHA256SUMS )
GNUPGHOME="$SEND" gpg --batch --yes --local-user "$S" --armor --detach-sign --output "$T/eqB/eq.SHA256SUMS.asc" "$T/eqB/eq.SHA256SUMS" 2>/dev/null
[ "$(jq -r .created_utc "$T/eqB/eq.provenance.json")" = "$CA" ] && ! cmp -s "$T/eqA/eq.SHA256SUMS" "$T/eqB/eq.SHA256SUMS" \
  && ok "A and B: same created_utc, different signed manifests" || bad "equal-timestamp setup"
expect_ok "import A" "$RECV" "$IMPORT" --in "$T/eqA" --name eq --signer "$S" --target "$D17" --provenance-log "$L17"
expect_ok "re-import identical A (same manifest hash): no-op" "$RECV" "$IMPORT" --in "$T/eqA" --name eq --signer "$S" --target "$D17" --provenance-log "$L17"
grep -q 're-import is a no-op' "$T/out" && ok "identical re-import reported as no-op" || bad "no no-op note"
expect_fail "B with equal created_utc, different manifest = replay" "possible replay.*same created_utc" "$RECV" "$IMPORT" --in "$T/eqB" --name eq --signer "$S" --target "$D17" --provenance-log "$L17"
[ "$(git -C "$D17" rev-parse refs/remotes/airgap/eq/main)" = "$NEW" ] && ok "ref still at A after refused B" || bad "ref moved after refused B"
expect_ok "B with --allow-replay (fast-forward) imports" "$RECV" "$IMPORT" --in "$T/eqB" --name eq --signer "$S" --target "$D17" --provenance-log "$L17" --allow-replay
[ "$(git -C "$D17" rev-parse refs/remotes/airgap/eq/main)" = "$EQB" ] && ok "ref at B after --allow-replay" || bad "ref not at B"
jq -e 'has("manifest_sha256") and .status=="imported"' "$L17" >/dev/null && ok "import log records manifest_sha256 and status" || bad "log lacks manifest_sha256/status"

echo "== temp dirs left by the scripts: $(ls -A "$T/tmp" | wc -l)"
[ -z "$(ls -A "$T/tmp")" ] && ok "no temp dirs left" || bad "leftover temp: $(ls -A "$T/tmp")"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
