#!/usr/bin/env bash
# bundle-verify-import.sh: verify an air-gap bundle made by bundle-export.sh,
# then (optionally) import it into a quarantine namespace of a target repo.
# Order is fixed: signature -> checksums -> decrypt -> git bundle verify -> import.
# Any failure stops before anything touches the target repo.
#
# Import never overwrites existing branches: refs land under
# refs/remotes/airgap/<name>/* and a human/bot opens a reviewed PR from there.
set -euo pipefail

usage() {
  cat <<'U'
Usage: bundle-verify-import.sh --in DIR --name NAME --signer FPR --target REPO
                               [--provenance-log FILE] [--verify-only]
  --signer          full fingerprint the SHA256SUMS signature must come from
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
case "$NAME" in *[!A-Za-z0-9._-]*|"") die "bad --name";; esac
SUMS="$IN/$NAME.SHA256SUMS"; SIG="$SUMS.asc"; PROV="$IN/$NAME.provenance.json"
[ -f "$SUMS" ] && [ -f "$SIG" ] && [ -f "$PROV" ] || die "missing manifest, signature or provenance"

# 1. Signature must be valid AND from the expected fingerprint.
STATUS=$(gpg --batch --status-fd 1 --verify "$SIG" "$SUMS" 2>/dev/null || true)
echo "$STATUS" | grep -q "^\[GNUPG:\] VALIDSIG ${SIGNER^^} " \
  || echo "$STATUS" | grep -Eq "^\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ${SIGNER^^}\$" \
  || die "signature missing, invalid, or not from $SIGNER"
echo "ok   signature from $SIGNER"

# 2. Only files named in the manifest, and all must match.
( cd "$IN" && sha256sum --quiet --strict -c "$NAME.SHA256SUMS" ) || die "checksum mismatch"
ENC=$(awk '{print $2}' "$SUMS" | grep -E "^$NAME\.bundle\.(gpg|age)$" | head -1)
[ -n "$ENC" ] || die "manifest names no encrypted bundle"
echo "ok   sha256 manifest ($ENC, $NAME.provenance.json)"

# 3. Decrypt into a private temp dir that is always removed.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bundle-import.XXXXXX"); chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
case "$ENC" in
  *.gpg) gpg --batch --quiet --decrypt --output "$WORK/b.bundle" "$IN/$ENC" 2>/dev/null || die "gpg decrypt failed";;
  *.age) command -v age >/dev/null || die "age not installed"
         age --decrypt ${AGE_IDENTITY:+--identity "$AGE_IDENTITY"} --output "$WORK/b.bundle" "$IN/$ENC" || die "age decrypt failed";;
esac
WANT=$(sed -n 's/.*"plaintext_bundle_sha256":"\([0-9a-f]*\)".*/\1/p' "$PROV")
GOT=$(sha256sum "$WORK/b.bundle" | cut -d' ' -f1)
[ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || die "decrypted bundle sha256 does not match provenance"
echo "ok   decrypted bundle sha256 matches provenance"

# 4. git's own check (prerequisite commits must exist in target).
git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1 || die "target is not a git repo"
git -C "$TARGET" bundle verify "$WORK/b.bundle" >/dev/null 2>&1 || die "git bundle verify failed (missing prerequisites?)"
echo "ok   git bundle verify against target"

if [ "$VERIFY_ONLY" = 1 ]; then
  echo "VERIFY-ONLY OK: nothing imported"; exit 0
fi

# 5. Import into a quarantine namespace (no branch is overwritten; no force).
git -C "$TARGET" fetch --no-tags "$WORK/b.bundle" "refs/heads/*:refs/remotes/airgap/$NAME/*" 2>&1 | sed 's/^/     /'
IMPORTED=$(git -C "$TARGET" for-each-ref --format='%(refname) %(objectname)' "refs/remotes/airgap/$NAME/" | tr '\n' ';')

# 6. Provenance record, kept outside the repo; commit a copy via reviewed PR if wanted.
mkdir -p "$(dirname "$PLOG")"
printf '{"imported_utc":"%s","name":"%s","signer":"%s","bundle_sha256":"%s","target":"%s","refs":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NAME" "$SIGNER" "$GOT" "$(basename "$(cd "$TARGET" && pwd)")" "$IMPORTED" >> "$PLOG"
echo "IMPORT OK: refs under refs/remotes/airgap/$NAME/ ; provenance -> $PLOG"
