#!/usr/bin/env bash
# bundle-export.sh: make an encrypted, signed, checksummed git bundle for an
# offline / air-gapped hand-off. Part of docs/SECURE-DATA-FLOW.md (Network lane).
#
# Output directory gets exactly four files (no plaintext bundle is left behind):
#   <name>.bundle.gpg | <name>.bundle.age   encrypted git bundle
#   <name>.provenance.json                  who/what/when (no secrets)
#   <name>.SHA256SUMS                       sha256 of the two files above
#   <name>.SHA256SUMS.asc                   detached gpg signature of SHA256SUMS
#
# Keys never live in the repo. Pass key ids / recipients by argument; the
# private keys stay in the operator's keyring or hardware token.
set -euo pipefail

usage() {
  cat <<'U'
Usage: bundle-export.sh --repo PATH --out DIR --name NAME --sign-key FPR
                        (--gpg-recipient KEYID | --age-recipient AGE_PUBKEY)
                        [--refs "main other-branch" | --since REV] [--dry-run]
  --refs    refs to include (default: all branches)
  --since   only commits after REV on the given refs (incremental bundle)
  --dry-run build and self-check in a temp dir, print the plan, keep nothing
U
}

REPO="" OUT="" NAME="" SIGN_KEY="" GPG_RCPT="" AGE_RCPT="" REFS="--branches" SINCE="" DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --name) NAME=$2; shift 2;;
    --sign-key) SIGN_KEY=$2; shift 2;;
    --gpg-recipient) GPG_RCPT=$2; shift 2;;
    --age-recipient) AGE_RCPT=$2; shift 2;;
    --refs) REFS=$2; shift 2;;
    --since) SINCE=$2; shift 2;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

die() { echo "bundle-export: $*" >&2; exit 1; }
[ -n "$REPO" ] && [ -n "$NAME" ] && [ -n "$SIGN_KEY" ] || { usage; exit 2; }
[ "$DRY" = 1 ] || [ -n "$OUT" ] || die "--out is required unless --dry-run"
[ -n "$GPG_RCPT" ] || [ -n "$AGE_RCPT" ] || die "need --gpg-recipient or --age-recipient"
[ -z "$GPG_RCPT" ] || [ -z "$AGE_RCPT" ] || die "pick one of --gpg-recipient / --age-recipient"
case "$NAME" in *[!A-Za-z0-9._-]*|"") die "--name may only use A-Z a-z 0-9 . _ -";; esac
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repo: $REPO"
command -v gpg >/dev/null || die "gpg is required (signing, and encryption unless age is used)"
[ -z "$AGE_RCPT" ] || command -v age >/dev/null || die "age not installed"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bundle-export.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# 1. Build the bundle (plaintext only ever exists inside $WORK).
BUNDLE="$WORK/$NAME.bundle"
# shellcheck disable=SC2086
if [ -n "$SINCE" ]; then
  git -C "$REPO" bundle create "$BUNDLE" $REFS "^$SINCE" 2>"$WORK/bundle.log" || { cat "$WORK/bundle.log" >&2; die "git bundle create failed"; }
else
  git -C "$REPO" bundle create "$BUNDLE" $REFS 2>"$WORK/bundle.log" || { cat "$WORK/bundle.log" >&2; die "git bundle create failed"; }
fi
git -C "$REPO" bundle verify "$BUNDLE" >/dev/null 2>&1 || die "bundle failed self-verify"
PLAIN_SHA=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
HEADS=$(git bundle list-heads "$BUNDLE" | awk '{printf "%s{\"sha\":\"%s\",\"ref\":\"%s\"}", (NR>1?",":""), $1, $2}')

# 2. Encrypt, then drop the plaintext.
if [ -n "$GPG_RCPT" ]; then
  ENC="$WORK/$NAME.bundle.gpg"; METHOD="gpg"
  gpg --batch --yes --auto-key-locate local --trust-model always --encrypt --recipient "$GPG_RCPT" --output "$ENC" "$BUNDLE"
else
  ENC="$WORK/$NAME.bundle.age"; METHOD="age"
  age --encrypt --recipient "$AGE_RCPT" --output "$ENC" "$BUNDLE"
fi
rm -f "$BUNDLE"

# 3. Provenance record (no secrets: only key fingerprints / public recipients).
ORIGIN=$(git -C "$REPO" config --get remote.origin.url 2>/dev/null | sed -E 's#https://[^@/]+@#https://#' || true)
cat > "$WORK/$NAME.provenance.json" <<J
{"name":"$NAME","created_utc":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","exporter_host":"$(hostname -s 2>/dev/null || echo unknown)",
 "source_origin":"${ORIGIN:-local}","since":"${SINCE:-}","heads":[${HEADS}],
 "plaintext_bundle_sha256":"$PLAIN_SHA","encryption":"$METHOD",
 "recipient":"${GPG_RCPT:-$AGE_RCPT}","signer":"$SIGN_KEY"}
J

# 4. Manifest + detached signature.
( cd "$WORK" && sha256sum "$(basename "$ENC")" "$NAME.provenance.json" > "$NAME.SHA256SUMS" )
gpg --batch --yes --local-user "$SIGN_KEY" --armor --detach-sign --output "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS"

# 5. Self-check before handing anything over.
( cd "$WORK" && sha256sum --quiet -c "$NAME.SHA256SUMS" ) || die "manifest self-check failed"
gpg --batch --verify "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS" 2>/dev/null || die "signature self-check failed"

if [ "$DRY" = 1 ]; then
  echo "DRY-RUN OK: would write to ${OUT:-<out>}:"; ( cd "$WORK" && ls -1 "$NAME".* | grep -v '\.bundle$' )
  echo "heads: $HEADS"; exit 0
fi
mkdir -p "$OUT"
for f in "$(basename "$ENC")" "$NAME.provenance.json" "$NAME.SHA256SUMS" "$NAME.SHA256SUMS.asc"; do
  [ ! -e "$OUT/$f" ] || die "refusing to overwrite $OUT/$f"
  cp "$WORK/$f" "$OUT/$f"
done
echo "EXPORT OK: $OUT/$NAME.* (encryption=$METHOD, signer=$SIGN_KEY)"
