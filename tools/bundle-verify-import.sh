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
#   * The import runs with transfer.fsckObjects and fetch.fsckObjects on, and
#     with git fetch --atomic, so it is all-or-nothing across refs.
#   * JSON is read and written with jq, never with sed or printf.
#
# Import never overwrites existing branches: refs land under
# refs/remotes/airgap/<name>/* and a human/bot opens a reviewed PR from there.
set -euo pipefail

usage() {
  cat <<'U'
Usage: bundle-verify-import.sh --in DIR --name NAME --signer FPR --target REPO
                               [--provenance-log FILE] [--verify-only] [--allow-replay]
  --signer          full primary-key fingerprint (40 hex, or 64 for v5 keys)
                    the SHA256SUMS signature must come from. Its public key
                    (plus any revocation) must already be in your gpg keyring.
  --provenance-log  JSONL file to append an import record to
                    (default: $HOME/.airgap/provenance.jsonl, outside any repo)
  --verify-only     run every check, import nothing (dry run)
  --allow-replay    accept a bundle whose signed created_utc is older than, or
                    equal to with a different signed manifest, the newest one
                    already imported under the same --name (per the provenance log). Off by default. See "Replay and re-import"
                    in docs/SECURE-DATA-FLOW.md for what this does and doesn't cover.
U
}

IN="" NAME="" SIGNER="" TARGET="" PLOG="${HOME}/.airgap/provenance.jsonl" VERIFY_ONLY=0 ALLOW_REPLAY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN=$2; shift 2;;
    --name) NAME=$2; shift 2;;
    --signer) SIGNER=$2; shift 2;;
    --target) TARGET=$2; shift 2;;
    --provenance-log) PLOG=$2; shift 2;;
    --verify-only) VERIFY_ONLY=1; shift;;
    --allow-replay) ALLOW_REPLAY=1; shift;;
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
CREATED=$(jq -r '.created_utc // ""' "$WORK/in/$PROVF")
[[ "$CREATED" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || die "provenance has no valid created_utc"
# Replay guard (best effort, local only): refuse a bundle whose signed created_utc
# is OLDER THAN OR EQUAL TO the newest one already imported under this --name,
# according to the local log. created_utc has 1-second resolution, so an equal
# timestamp only counts as the same bundle (an idempotent re-import) when the
# signed manifest hash also matches a successful import with that timestamp.
# Only successful imports (status "imported", or older records without a status)
# count; failure records never advance the guard.
MSHA=$(sha256sum "$WORK/in/$SUMS" | cut -d' ' -f1)
LAST="" SAME=0
if [ -f "$PLOG" ]; then
  OKREC='fromjson? | select(type=="object" and .name==$n and ((.status // "imported")=="imported"))'
  LAST=$(jq -rR --arg n "$NAME" "$OKREC"' | .created_utc // empty' "$PLOG" 2>/dev/null | sort | tail -1)
  if [ -n "$LAST" ] && [ "$CREATED" = "$LAST" ]; then
    # Same bundle = same signed manifest hash; records from before manifest_sha256
    # was logged fall back to the signed plaintext_bundle_sha256 (= logged bundle_sha256).
    SAME=$(jq -rR --arg n "$NAME" --arg c "$CREATED" --arg m "$MSHA" \
      "$OKREC"' | select(.created_utc==$c and .manifest_sha256==$m) | 1' "$PLOG" 2>/dev/null | grep -c . || true)
    [ "$SAME" -gt 0 ] && SAME=1 || SAME=0
    if [ "$SAME" = 0 ]; then
      LEGACY=$(jq -rR --arg n "$NAME" --arg c "$CREATED" \
        "$OKREC"' | select(.created_utc==$c and (has("manifest_sha256")|not)) | .bundle_sha256 // empty' "$PLOG" 2>/dev/null || true)
      [ -n "$LEGACY" ] && printf '%s\n' "$LEGACY" | grep -qxF -- "$WANT" && SAME=1
    fi
  fi
fi
if [ -n "$LAST" ] && { [[ "$CREATED" < "$LAST" ]] || { [ "$CREATED" = "$LAST" ] && [ "$SAME" = 0 ]; }; }; then
  if [ "$CREATED" = "$LAST" ]; then
    WHY="has the same created_utc ($CREATED) as the last import of '$NAME' but a different signed manifest"
  else
    WHY="created $CREATED is older than the last import of '$NAME' ($LAST)"
  fi
  [ "$ALLOW_REPLAY" = 1 ] || die "possible replay: bundle $WHY; pass --allow-replay only if intended"
  echo "WARN possible replay: bundle $WHY; continuing because of --allow-replay"
fi
[ "$SAME" = 1 ] && echo "note same bundle as the last import of '$NAME' (manifest sha256 matches): re-import is a no-op"
echo "ok   provenance (name, signer, created_utc $CREATED${LAST:+, last import $LAST})"

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

# Import record, kept outside the repo (append-only JSONL, built with jq).
# log_record STATUS [DETAIL]: STATUS is "imported" or "rejected".
log_record() {
  mkdir -p "$(dirname "$PLOG")"
  git -C "$TARGET" for-each-ref --format='%(refname)%09%(objectname)' "refs/remotes/airgap/$NAME/" \
  | jq -cR --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg n "$NAME" --arg s "$SIGNER" --arg b "$GOT" --arg c "$CREATED" \
        --arg m "$MSHA" --arg st "$1" --arg d "${2:-}" --arg tg "$(basename "$(cd "$TARGET" && pwd)")" \
        -s '{imported_utc:$t,status:$st,name:$n,created_utc:$c,signer:$s,bundle_sha256:$b,manifest_sha256:$m,target:$tg,
             refs:[split("\n")[]|select(length>0)|split("\t")|{ref:.[0],sha:.[1]}]}
            + (if $d!="" then {detail:$d} else {} end)' >> "$PLOG"
}

# 6. Import into a quarantine namespace (no branch is overwritten; no force),
#    with object fsck so a malformed object aborts the fetch. --atomic makes the
#    ref update all-or-nothing: if ANY ref is rejected (e.g. a diverged main next
#    to a brand-new branch), NO ref is created or moved.
if ! git -C "$TARGET" -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
     fetch --atomic --no-tags --no-write-fetch-head "$WORK/b.bundle" "refs/heads/*:refs/remotes/airgap/$NAME/*" \
     >"$WORK/fetch.log" 2>&1; then
  sed 's/^/     /' "$WORK/fetch.log"
  # A failure record (status "rejected") is written for the audit trail; the
  # replay guard ignores it. refs[] shows the quarantine refs as they still are.
  log_record rejected "git fetch --atomic rejected the bundle; no refs changed" \
    || echo "WARN could not write failure record to $PLOG" >&2
  die "git fetch rejected the bundle (fsck error, or a non-fast-forward update of an existing quarantine ref); atomic fetch: no refs created or changed; failure record (status rejected) -> $PLOG"
fi
sed 's/^/     /' "$WORK/fetch.log"
echo "ok   atomic import with transfer.fsckObjects + fetch.fsckObjects"

# 7. Provenance record; commit a copy via reviewed PR if wanted.
log_record imported
echo "IMPORT OK: refs under refs/remotes/airgap/$NAME/ ; provenance -> $PLOG"
