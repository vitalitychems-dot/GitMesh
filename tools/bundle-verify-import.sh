#!/usr/bin/env bash
# bundle-verify-import.sh: verify an air-gap bundle made by bundle-export.sh,
# then (optionally) import it into a quarantine namespace of a target repo.
# Order is fixed: copy-in -> signature -> manifest -> checksums -> decrypt ->
# git bundle verify -> fsck'd import. Any failure stops before anything touches
# the target repo.
#
# Hardening (network/harden-pr9):
#   * Every input is first copied out of --in into a private mode-700 temp dir.
#     Symlinks and non-regular files are refused. All checks and the import use
#     ONLY those copies, so swapping files on the medium after a check has no
#     effect (time-of-check/time-of-use).
#   * The signature is checked in a throwaway keyring holding only the expected
#     signer's public key. It needs exactly one GOODSIG, a VALIDSIG whose primary
#     fingerprint equals --signer exactly, and no BADSIG/ERRSIG/EXPSIG/EXPKEYSIG/
#     REVKEYSIG/KEYREVOKED/KEYEXPIRED. Revoked or expired signer keys fail.
#   * --signer must be a full 40- (or 64-) hex fingerprint. It is compared as a
#     plain string, never as a regex.
#   * The manifest must list exactly one encrypted bundle and the provenance file.
#   * The import runs with transfer.fsckObjects and fetch.fsckObjects on.
#   * JSON is read and written with jq, never with sed or printf.
#
# Import never overwrites existing branches: refs land under
# refs/remotes/airgap/<name>/* and a human/bot opens a reviewed PR from there.
set -euo pipefail

usage() {
  cat <<'U'
Usage: bundle-verify-import.sh --in DIR --name NAME --signer FPR --target REPO
                               [--provenance-log FILE] [--verify-only]
  --signer          full primary-key fingerprint (40 hex, or 64 for v5 keys)
                    the SHA256SUMS signature must come from. Its public key
                    (plus any revocation) must already be in your gpg keyring.
  --provenance-log  JSONL file to append an import record to
                    (default: $HOME/.airgap/provenance.jsonl, outside any repo)
  --verify-only     run every check, import nothing (dry run)
U
}

IN="" NAME="" SIGNER="" TARGET="" PLOG="${HOME}/.airgap/provenance.jsonl" VERIFY_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN=$2; shift 2;;
    --name) NAME=$2; shift 2;;
    --signer) SIGNER=$2; shift 2;;
    --target) TARGET=$2; shift 2;;
    --provenance-log) PLOG=$2; shift 2;;
    --verify-only) VERIFY_ONLY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done
die() { echo "bundle-verify-import: FAIL: $*" >&2; exit 1; }
[ -n "$IN" ] && [ -n "$NAME" ] && [ -n "$SIGNER" ] && [ -n "$TARGET" ] || { usage; exit 2; }
case "$NAME" in *[!A-Za-z0-9._-]*|""|.*) die "bad --name";; esac
command -v gpg >/dev/null || die "gpg is required"
command -v jq >/dev/null || die "jq is required"

# --signer: exact full fingerprint only (no short ids, no regex, no user ids).
SIGNER=${SIGNER// /}; SIGNER=${SIGNER^^}
[[ "$SIGNER" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]] || die "--signer must be a full 40/64-hex fingerprint"
[ -d "$IN" ] || die "--in is not a directory"

# 0. Private work dir; copy inputs in before looking at them.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bundle-import.XXXXXX"); chmod 700 "$WORK"
KR="$WORK/keyring"
cleanup() {
  gpgconf --homedir "$KR" --kill all >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -m 700 "$WORK/in"

# copy_in FILE: copy $IN/FILE to $WORK/in/FILE. Refuse symlinks and anything that
# is not a regular file, both before the copy and on the copy itself (cp -P never
# follows a link, so a link swapped in mid-copy is caught on the copy).
copy_in() {
  local f=$1 src="$IN/$1" dst="$WORK/in/$1"
  [ ! -L "$src" ] || die "$f is a symlink (refused)"
  [ -f "$src" ] || die "$f is missing or not a regular file"
  cp -P -- "$src" "$dst" || die "could not copy $f"
  [ ! -L "$dst" ] && [ -f "$dst" ] || die "$f changed type during copy (refused)"
  chmod 600 "$dst"
}
SUMS="$NAME.SHA256SUMS"; SIG="$SUMS.asc"; PROVF="$NAME.provenance.json"
copy_in "$SUMS"; copy_in "$SIG"

# 1. Signature: isolated keyring holding only the expected signer.
mkdir -m 700 "$KR"
gpg --batch --export "$SIGNER" > "$WORK/signer.pub" 2>/dev/null || true
[ -s "$WORK/signer.pub" ] || die "signer $SIGNER not in your keyring (import its public key first)"
gpg --homedir "$KR" --batch --quiet --import "$WORK/signer.pub" >/dev/null 2>&1 || die "could not load signer key"
# Exactly one primary key, and it must be the expected one, not revoked/expired.
KEYS=$(gpg --homedir "$KR" --batch --with-colons --fixed-list-mode --list-keys 2>/dev/null)
NPUB=$(printf '%s\n' "$KEYS" | grep -c '^pub:' || true)
[ "$NPUB" = 1 ] || die "signer keyring must hold exactly one key (got $NPUB)"
VALIDITY=$(printf '%s\n' "$KEYS" | awk -F: '$1=="pub"{print $2; exit}')
KFPR=$(printf '%s\n' "$KEYS" | awk -F: '$1=="fpr"{print $10; exit}')
[ "$KFPR" = "$SIGNER" ] || die "signer keyring fingerprint mismatch"
case "$VALIDITY" in r) die "signer key $SIGNER is REVOKED";; e) die "signer key $SIGNER is EXPIRED";; esac

STATUS=$(gpg --homedir "$KR" --batch --trust-model always --status-fd 1 \
          --verify "$WORK/in/$SIG" "$WORK/in/$SUMS" 2>/dev/null || true)
if printf '%s\n' "$STATUS" | grep -Eq '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|NO_PUBKEY) '; then
  die "signature rejected: $(printf '%s\n' "$STATUS" | grep -Eo '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|NO_PUBKEY)' | head -1 | cut -d' ' -f2)"
fi
NGOOD=$(printf '%s\n' "$STATUS" | grep -c '^\[GNUPG:\] GOODSIG ' || true)
[ "$NGOOD" = 1 ] || die "need exactly one GOODSIG (got $NGOOD)"
# VALIDSIG <sig-fpr> ... <primary-fpr> (field 12 when split on spaces incl. the [GNUPG:] tag)
PRIM=$(printf '%s\n' "$STATUS" | awk '$1=="[GNUPG:]" && $2=="VALIDSIG"{print $NF}')
[ "$(printf '%s\n' "$PRIM" | grep -c .)" = 1 ] && [ "$PRIM" = "$SIGNER" ] \
  || die "signature not from $SIGNER"
echo "ok   signature from $SIGNER (GOODSIG, key not revoked/expired)"

# 2. Manifest: exactly one encrypted bundle + the provenance file, nothing else.
ENC="" HAVE_PROV=0 N=0
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] || continue
  N=$((N+1))
  [[ "$line" =~ ^[0-9a-f]{64}\ [\ \*](.+)$ ]] || die "malformed manifest line $N"
  f=${BASH_REMATCH[1]}
  if [ "$f" = "$PROVF" ]; then HAVE_PROV=$((HAVE_PROV+1))
  elif [ "$f" = "$NAME.bundle.gpg" ] || [ "$f" = "$NAME.bundle.age" ]; then
    [ -z "$ENC" ] || die "manifest lists more than one bundle"; ENC=$f
  else die "manifest lists unexpected file: $f"; fi
done < "$WORK/in/$SUMS"
[ "$N" = 2 ] && [ "$HAVE_PROV" = 1 ] && [ -n "$ENC" ] \
  || die "manifest must list exactly $NAME.bundle.(gpg|age) and $PROVF"

# 3. Checksums, on the private copies only.
copy_in "$ENC"; copy_in "$PROVF"
( cd "$WORK/in" && sha256sum --quiet --strict -c "$SUMS" ) || die "checksum mismatch"
echo "ok   sha256 manifest ($ENC, $PROVF)"

# Provenance (signed via the manifest) must be valid JSON and agree with us.
jq -e 'type=="object"' "$WORK/in/$PROVF" >/dev/null 2>&1 || die "provenance is not a JSON object"
WANT=$(jq -r '.plaintext_bundle_sha256 // ""' "$WORK/in/$PROVF")
PNAME=$(jq -r '.name // ""' "$WORK/in/$PROVF")
PSIGN=$(jq -r '.signer // "" | ascii_upcase' "$WORK/in/$PROVF")
[[ "$WANT" =~ ^[0-9a-f]{64}$ ]] || die "provenance has no valid plaintext_bundle_sha256"
[ "$PNAME" = "$NAME" ] || die "provenance name '$PNAME' != --name '$NAME'"
[ "$PSIGN" = "$SIGNER" ] || die "provenance signer does not match --signer"

# 4. Decrypt the private copy.
case "$ENC" in
  *.gpg) DST=$(gpg --batch --status-fd 1 --quiet --decrypt --output "$WORK/b.bundle" "$WORK/in/$ENC" 2>/dev/null) \
           || die "gpg decrypt failed"
         printf '%s\n' "$DST" | grep -q '^\[GNUPG:\] DECRYPTION_OKAY' || die "input was not encrypted (no DECRYPTION_OKAY)";;
  *.age) command -v age >/dev/null || die "age not installed"
         [ -n "${AGE_IDENTITY:-}" ] || die "set AGE_IDENTITY to your age identity file"
         age --decrypt --identity "$AGE_IDENTITY" --output "$WORK/b.bundle" "$WORK/in/$ENC" || die "age decrypt failed";;
esac
GOT=$(sha256sum "$WORK/b.bundle" | cut -d' ' -f1)
[ "$WANT" = "$GOT" ] || die "decrypted bundle sha256 does not match provenance"
echo "ok   decrypted bundle sha256 matches provenance"

# 5. git's own check (prerequisite commits must exist in target).
git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1 || die "target is not a git repo"
git -C "$TARGET" bundle verify "$WORK/b.bundle" >/dev/null 2>&1 || die "git bundle verify failed (missing prerequisites?)"
echo "ok   git bundle verify against target"

if [ "$VERIFY_ONLY" = 1 ]; then
  echo "VERIFY-ONLY OK: nothing imported"; exit 0
fi

# 6. Import into a quarantine namespace (no branch is overwritten; no force),
#    with object fsck so a malformed object aborts the fetch.
git -C "$TARGET" -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
  fetch --no-tags --no-write-fetch-head "$WORK/b.bundle" "refs/heads/*:refs/remotes/airgap/$NAME/*" 2>&1 | sed 's/^/     /' \
  || die "git fetch/fsck rejected the bundle; nothing imported"
echo "ok   import with transfer.fsckObjects + fetch.fsckObjects"

# 7. Provenance record, kept outside the repo; commit a copy via reviewed PR if wanted.
mkdir -p "$(dirname "$PLOG")"
git -C "$TARGET" for-each-ref --format='%(refname)%09%(objectname)' "refs/remotes/airgap/$NAME/" \
| jq -cR --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg n "$NAME" --arg s "$SIGNER" --arg b "$GOT" \
      --arg tg "$(basename "$(cd "$TARGET" && pwd)")" \
      -s '{imported_utc:$t,name:$n,signer:$s,bundle_sha256:$b,target:$tg,
           refs:[split("\n")[]|select(length>0)|split("\t")|{ref:.[0],sha:.[1]}]}' >> "$PLOG"
echo "IMPORT OK: refs under refs/remotes/airgap/$NAME/ ; provenance -> $PLOG"
