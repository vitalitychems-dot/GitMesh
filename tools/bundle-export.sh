#!/usr/bin/env bash
# bundle-export.sh: make an encrypted, signed, checksummed git bundle for an
# offline / air-gapped hand-off. Part of docs/SECURE-DATA-FLOW.md (Network lane).
#
# Output directory gets exactly four files (no plaintext bundle is left behind):
#   <name>.bundle.gpg | <name>.bundle.age   encrypted git bundle
#   <name>.provenance.json                  who/what/when (no secrets, but PLAINTEXT:
#                                           see docs/SECURE-DATA-FLOW.md "What the
#                                           plaintext files reveal")
#   <name>.SHA256SUMS                       sha256 of the two files above
#   <name>.SHA256SUMS.asc                   detached gpg signature of SHA256SUMS
#
# Keys never live in the repo. Pass full fingerprints / age recipients by
# argument; the private keys stay in the operator's keyring or hardware token.
set -euo pipefail

usage() {
  cat <<'U'
Usage: bundle-export.sh --repo PATH --out DIR --name NAME --sign-key FPR
                        (--gpg-recipient FPR | --age-recipient AGE_PUBKEY)
                        [--refs "main other-branch" | --since REV]
                        [--redact-provenance] [--with-host] [--dry-run]
  --sign-key / --gpg-recipient   full 40- (or 64-) hex fingerprint, no short ids
  --refs    refs to include (default: all branches)
  --since   only commits after REV on the given refs (incremental bundle)
  --redact-provenance  leave source_origin, since and heads (ref names + SHAs)
                       out of the plaintext provenance file
  --with-host          record the exporter's short hostname (off by default)
  --dry-run build and self-check in a temp dir, print the plan, keep nothing
U
}

REPO="" OUT="" NAME="" SIGN_KEY="" GPG_RCPT="" AGE_RCPT="" REFS="--branches" SINCE="" DRY=0 REDACT=0 WITH_HOST=0
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
    --redact-provenance) REDACT=1; shift;;
    --with-host) WITH_HOST=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

die() { echo "bundle-export: $*" >&2; exit 1; }
is_fpr() { [[ "$1" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]]; }
[ -n "$REPO" ] && [ -n "$NAME" ] && [ -n "$SIGN_KEY" ] || { usage; exit 2; }
[ "$DRY" = 1 ] || [ -n "$OUT" ] || die "--out is required unless --dry-run"
[ -n "$GPG_RCPT" ] || [ -n "$AGE_RCPT" ] || die "need --gpg-recipient or --age-recipient"
[ -z "$GPG_RCPT" ] || [ -z "$AGE_RCPT" ] || die "pick one of --gpg-recipient / --age-recipient"
case "$NAME" in *[!A-Za-z0-9._-]*|""|.*) die "--name may only use A-Z a-z 0-9 . _ - (not starting with .)";; esac
SIGN_KEY=${SIGN_KEY// /}; SIGN_KEY=${SIGN_KEY^^}
is_fpr "$SIGN_KEY" || die "--sign-key must be a full 40/64-hex fingerprint"
if [ -n "$GPG_RCPT" ]; then
  GPG_RCPT=${GPG_RCPT// /}; GPG_RCPT=${GPG_RCPT^^}
  is_fpr "$GPG_RCPT" || die "--gpg-recipient must be a full 40/64-hex fingerprint (no short KEYID)"
fi
[ -z "$AGE_RCPT" ] || [[ "$AGE_RCPT" =~ ^age1[0-9a-z]{58}$ ]] || die "--age-recipient must be an age1... public key"
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repo: $REPO"
command -v gpg >/dev/null || die "gpg is required (signing, and encryption unless age is used)"
command -v jq >/dev/null || die "jq is required"
[ -z "$AGE_RCPT" ] || command -v age >/dev/null || die "age not installed"

# key_ok FPR CAP: the exact key exists, is not revoked/expired, and has capability CAP (s|e).
key_ok() {
  local cols; cols=$(gpg --batch --with-colons --fixed-list-mode --list-keys -- "$1" 2>/dev/null) || return 1
  printf '%s\n' "$cols" | awk -F: -v f="$1" -v cap="$2" '
    $1=="pub"{v=$2; c=$12} $1=="fpr" && !seen {seen=1; if ($10==f && v!="r" && v!="e" && index(c, toupper(cap))) ok=1}
    END{exit ok?0:1}'
}
key_ok "$SIGN_KEY" s || die "sign key $SIGN_KEY missing, revoked, expired or cannot sign"
[ -z "$GPG_RCPT" ] || key_ok "$GPG_RCPT" e || die "recipient $GPG_RCPT missing, revoked, expired or cannot encrypt"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bundle-export.XXXXXX"); chmod 700 "$WORK"
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
# Heads as JSON built by jq, so quotes/backslashes in ref names stay valid JSON.
HEADS_JSON=$(git bundle list-heads "$BUNDLE" | jq -cR -s '[split("\n")[]|select(length>0)|capture("^(?<sha>[0-9a-f]+) (?<ref>.+)$")]')

# 2. Encrypt to the exact recipient (full primary fingerprint; gpg picks that key's
#    encryption subkey), then drop the plaintext. --trust-model always is acceptable
#    only because the recipient is pinned by full fingerprint and checked above.
if [ -n "$GPG_RCPT" ]; then
  ENC="$WORK/$NAME.bundle.gpg"; METHOD="gpg"
  gpg --batch --yes --trust-model always --encrypt --recipient "$GPG_RCPT" --output "$ENC" "$BUNDLE"
else
  ENC="$WORK/$NAME.bundle.age"; METHOD="age"
  age --encrypt --recipient "$AGE_RCPT" --output "$ENC" "$BUNDLE"
fi
rm -f "$BUNDLE"

# 3. Provenance record (no secrets; PLAINTEXT on the medium, see the doc).
ORIGIN=$(git -C "$REPO" config --get remote.origin.url 2>/dev/null | sed -E 's#^([a-z+]+://)[^@/]+@#\1#' || true)
HOST=""; [ "$WITH_HOST" = 0 ] || HOST=$(hostname -s 2>/dev/null || echo unknown)
jq -cn --arg name "$NAME" --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg origin "${ORIGIN:-local}" --arg since "$SINCE" --argjson heads "$HEADS_JSON" \
      --arg psha "$PLAIN_SHA" --arg method "$METHOD" --arg rcpt "${GPG_RCPT:-$AGE_RCPT}" \
      --arg signer "$SIGN_KEY" --arg host "$HOST" --argjson redact "$REDACT" '
  {name:$name, created_utc:$created, plaintext_bundle_sha256:$psha, encryption:$method,
   recipient:$rcpt, signer:$signer}
  + (if $redact==1 then {redacted:true} else {source_origin:$origin, since:$since, heads:$heads} end)
  + (if $host!="" then {exporter_host:$host} else {} end)' > "$WORK/$NAME.provenance.json"

# 4. Manifest + detached signature with the exact signing key.
( cd "$WORK" && sha256sum "$(basename "$ENC")" "$NAME.provenance.json" > "$NAME.SHA256SUMS" )
gpg --batch --yes --local-user "${SIGN_KEY}!" --armor --detach-sign --output "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS"

# 5. Self-check before handing anything over.
( cd "$WORK" && sha256sum --quiet --strict -c "$NAME.SHA256SUMS" ) || die "manifest self-check failed"
ST=$(gpg --batch --status-fd 1 --verify "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS" 2>/dev/null || true)
printf '%s\n' "$ST" | grep -q '^\[GNUPG:\] GOODSIG ' \
  && [ "$(printf '%s\n' "$ST" | awk '$2=="VALIDSIG"{print $NF}')" = "$SIGN_KEY" ] || die "signature self-check failed"

FILES=("$(basename "$ENC")" "$NAME.provenance.json" "$NAME.SHA256SUMS" "$NAME.SHA256SUMS.asc")
if [ "$DRY" = 1 ]; then
  echo "DRY-RUN OK: would write to ${OUT:-<out>}:"; printf '%s\n' "${FILES[@]}"
  echo "heads: $HEADS_JSON"; exit 0
fi

# 6. Atomic hand-over: stage each file as a temp file inside OUT (same filesystem),
#    then rename with no-clobber. A reader never sees a half-written file.
mkdir -p "$OUT"
for f in "${FILES[@]}"; do
  [ ! -e "$OUT/$f" ] && [ ! -L "$OUT/$f" ] || die "refusing to overwrite $OUT/$f"
done
STAGED=()
for f in "${FILES[@]}"; do
  t=$(mktemp "$OUT/.${f}.tmp.XXXXXX"); STAGED+=("$t")
  cp -- "$WORK/$f" "$t"; sync -- "$t" 2>/dev/null || true
done
trap 'rm -f "${STAGED[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
for i in "${!FILES[@]}"; do
  f=${FILES[$i]}; t=${STAGED[$i]}
  mv -n -- "$t" "$OUT/$f" 2>/dev/null || true
  [ ! -e "$t" ] || die "refusing to overwrite $OUT/$f (appeared during export)"
done
echo "EXPORT OK: $OUT/$NAME.* (encryption=$METHOD, signer=$SIGN_KEY)"
