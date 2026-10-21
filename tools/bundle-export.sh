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
Needs bash >= 4, GNU coreutils (sha256sum), git, gpg, jq (and age for --age-recipient).
Exit codes: 0 ok | 1 error | 2 usage | 129/130/143 interrupted by HUP/INT/TERM
(the cleanup trap removes everything this run wrote).
Temp space: the plaintext and the encrypted bundle sit side by side in
$TMPDIR/bundle-export.XXXXXX (mode 700), about 2x the bundle size. Point TMPDIR
at an encrypted volume with room to spare; see docs/SECURE-DATA-FLOW.md.
U
}

# need FLAG ARGS...: a flag that takes a value must have one (usage + rc 2, not a raw bash error).
need() { [ $# -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }; }
REPO="" OUT="" NAME="" SIGN_KEY="" GPG_RCPT="" AGE_RCPT="" REFS="--branches" SINCE="" DRY=0 REDACT=0 WITH_HOST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) need "$@"; REPO=$2; shift 2;;
    --out) need "$@"; OUT=$2; shift 2;;
    --name) need "$@"; NAME=$2; shift 2;;
    --sign-key) need "$@"; SIGN_KEY=$2; shift 2;;
    --gpg-recipient) need "$@"; GPG_RCPT=$2; shift 2;;
    --age-recipient) need "$@"; AGE_RCPT=$2; shift 2;;
    --refs) need "$@"; REFS=$2; shift 2;;
    --since) need "$@"; SINCE=$2; shift 2;;
    --redact-provenance) REDACT=1; shift;;
    --with-host) WITH_HOST=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

die() { echo "bundle-export: $*" >&2; exit 1; }
((BASH_VERSINFO[0] >= 4)) || die "bash >= 4 required (macOS: brew install bash)"
grep -q GNU <<<"$(sha256sum --version 2>/dev/null)" || die "GNU sha256sum required (macOS: brew install coreutils)"
is_fpr() { [[ "$1" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]]; }
[ -n "$REPO" ] && [ -n "$NAME" ] && [ -n "$SIGN_KEY" ] || { usage; exit 2; }
[ "$DRY" = 1 ] || [ -n "$OUT" ] || die "--out is required unless --dry-run"
[ -n "$GPG_RCPT" ] || [ -n "$AGE_RCPT" ] || die "need --gpg-recipient or --age-recipient"
[ -z "$GPG_RCPT" ] || [ -z "$AGE_RCPT" ] || die "pick one of --gpg-recipient / --age-recipient"
case "$NAME" in *[!A-Za-z0-9._-]*|""|[.-]*) die "--name may only use A-Z a-z 0-9 . _ - (not starting with . or -)";; esac
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
EXT=gpg; [ -z "$AGE_RCPT" ] || EXT=age
FILES=("$NAME.bundle.$EXT" "$NAME.provenance.json" "$NAME.SHA256SUMS" "$NAME.SHA256SUMS.asc")
# Early overwrite check, before any expensive work (the late check below stays, for races).
if [ "$DRY" != 1 ]; then
  for f in "${FILES[@]}"; do
    [ ! -e "$OUT/$f" ] && [ ! -L "$OUT/$f" ] || die "refusing to overwrite $OUT/$f"
  done
fi

# key_ok FPR CAP: the exact key exists, is not revoked/expired, and has capability CAP (s|e).
key_ok() {
  local cols; cols=$(gpg --batch --with-colons --fixed-list-mode --list-keys -- "$1" 2>/dev/null) || return 1
  printf '%s\n' "$cols" | awk -F: -v f="$1" -v cap="$2" '
    $1=="pub"{v=$2; c=$12} $1=="fpr" && !seen {seen=1; if ($10==f && v!="r" && v!="e" && index(c, toupper(cap))) ok=1}
    END{exit ok?0:1}'
}
key_ok "$SIGN_KEY" s || die "sign key $SIGN_KEY missing, revoked, expired or cannot sign"
[ -z "$GPG_RCPT" ] || key_ok "$GPG_RCPT" e || die "recipient $GPG_RCPT missing, revoked, expired or cannot encrypt"

# Cleanup is armed before the first write. Until the export completes (DONE=1),
# any exit (error, full disk, signal) removes the work dir AND every file this
# run staged or placed in --out, so a failed export leaves nothing behind.
WORK="" STAGED=() PLACED=() DONE=0
cleanup() {
  if [ "$DONE" != 1 ]; then
    local x
    for x in "${STAGED[@]}" "${PLACED[@]}"; do [ -n "$x" ] && rm -f -- "$x"; done
  fi
  [ -z "$WORK" ] || rm -rf -- "$WORK"
}
trap cleanup EXIT
# Conventional 128+signal exit codes; the EXIT trap still cleans up.
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bundle-export.XXXXXX") || die "mktemp failed"; chmod 700 "$WORK"

# 1. Build the bundle (plaintext only ever exists inside $WORK).
BUNDLE="$WORK/$NAME.bundle"
# --refs is split on whitespace into an array with globbing OFF, so a pattern such
# as 'main*' reaches git as written and is never expanded against files in the
# caller's current directory (which could silently pick the wrong refs).
set -f; read -r -a REF_ARR <<<"$REFS"; set +f
[ "${#REF_ARR[@]}" -gt 0 ] || die "--refs is empty"
git -C "$REPO" bundle create "$BUNDLE" "${REF_ARR[@]}" ${SINCE:+"^$SINCE"} 2>"$WORK/bundle.log" \
  || { cat "$WORK/bundle.log" >&2; die "git bundle create failed"; }
git -C "$REPO" bundle verify "$BUNDLE" >"$WORK/bverify.log" 2>&1 \
  || { cat "$WORK/bverify.log" >&2; die "bundle failed self-verify"; }
# The importer only takes refs/heads/*: refuse a bundle with no branch (e.g. --refs
# HEAD or a tag only) here, instead of handing over a bundle that imports nothing.
LIST_HEADS=$(git bundle list-heads "$BUNDLE")
grep -q ' refs/heads/' <<<"$LIST_HEADS" \
  || die "bundle has no branches (refs/heads/*); the importer would import nothing. Pass branch names in --refs"
PLAIN_SHA=$(sha256sum -- "$BUNDLE" | cut -d' ' -f1)
# Heads as JSON built by jq, so quotes/backslashes in ref names stay valid JSON.
HEADS_JSON=$(printf '%s\n' "$LIST_HEADS" | jq -cR -s '[split("\n")[]|select(length>0)|capture("^(?<sha>[0-9a-f]+) (?<ref>.+)$")]')

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
# strip_origin URL: keep only scheme://host[:port]/path (or host:path for scp-style),
# never userinfo, query, fragment or ;params, which can all carry credentials.
#   * scheme is matched case-insensitively and printed lower-case (HTTPS://u:p@ ok)
#   * userinfo: if there is an '@' before the first '/', drop through it; else if a
#     ':' comes before the first '/' and an '@' follows (a password containing '/',
#     e.g. user:pa/ss@host), drop through the LAST '@'. This can over-strip a path
#     like host:8080/a@b to "b"; losing text is preferred to leaking a token.
#   * scp-style user:tok@host:path -> host:path (user part dropped too)
#   * everything from the first '?', '#' or ';' on is dropped
#   * plain local paths (/x, ./x, ~/x, C:\x) are kept as they are
strip_origin() {
  local u=$1 scheme="" rest
  if [[ "$u" =~ ^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$ ]]; then
    scheme="${BASH_REMATCH[1],,}://"; rest=${BASH_REMATCH[2]}
  elif [[ "$u" =~ ^[^/]*: ]] && [[ ! "$u" =~ ^[A-Za-z]:[\\/] ]] && [[ "$u" != [./~]* ]]; then
    rest=$u                                    # scp-style [user[:tok]@]host:path
  else
    printf '%s' "$u"; return                   # local path
  fi
  if [[ "$rest" =~ ^[^/@]*@ ]]; then rest=${rest#*@}
  elif [[ "$rest" =~ ^[^/@]*:[^@]*@ ]]; then rest=${rest##*@}
  fi
  rest=${rest%%[?#;]*}
  printf '%s%s' "$scheme" "$rest"
}
ORIGIN=$(strip_origin "$(git -C "$REPO" config --get remote.origin.url 2>/dev/null || true)")
HOST=""; [ "$WITH_HOST" = 0 ] || HOST=$(hostname -s 2>/dev/null || echo unknown)
jq -cn --arg name "$NAME" --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg origin "${ORIGIN:-local}" --arg since "$SINCE" --argjson heads "$HEADS_JSON" \
      --arg psha "$PLAIN_SHA" --arg method "$METHOD" --arg rcpt "${GPG_RCPT:-$AGE_RCPT}" \
      --arg signer "$SIGN_KEY" --arg host "$HOST" --argjson redact "$REDACT" '
  {name:$name, created_utc:$created, plaintext_bundle_sha256:$psha, encryption:$method,
   recipient:$rcpt, signer:$signer}
  + (if $redact==1 then {redacted:true} else {source_origin:$origin, since:$since, heads:$heads} end)
  + (if $host!="" then {exporter_host:$host} else {} end)' > "$WORK/$NAME.provenance.json"

# 4. Manifest + detached signature. --local-user is the primary fingerprint without
#    "!", so gpg may use a signing SUBKEY of that primary (subkey-signing setups).
#    The self-check below and the importer both bind the signature to the PRIMARY
#    fingerprint (last field of VALIDSIG), so no other key can stand in.
( cd "$WORK" && sha256sum -- "$(basename "$ENC")" "$NAME.provenance.json" > "$NAME.SHA256SUMS" )
gpg --batch --yes --local-user "$SIGN_KEY" --armor --detach-sign --output "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS"

# 5. Self-check before handing anything over.
( cd "$WORK" && sha256sum --quiet --strict -c -- "$NAME.SHA256SUMS" ) || die "manifest self-check failed"
# gpg's stderr is kept in a log and printed (with the status lines) on failure.
# Here-strings, not pipes into grep -q, so pipefail can never turn an early grep
# exit (SIGPIPE on the writer) into a false failure.
ST=$(gpg --batch --status-fd 1 --verify "$WORK/$NAME.SHA256SUMS.asc" "$WORK/$NAME.SHA256SUMS" 2>"$WORK/verify.log" || true)
if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"$ST" \
   || [ "$(awk '$2=="VALIDSIG"{print $NF}' <<<"$ST")" != "$SIGN_KEY" ]; then
  { echo "gpg --verify stderr:"; cat "$WORK/verify.log"; echo "gpg status:"; printf '%s\n' "$ST"; } >&2
  die "signature self-check failed"
fi

[ "${FILES[0]}" = "$(basename "$ENC")" ] || die "internal: file list mismatch"
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
for f in "${FILES[@]}"; do
  t=$(mktemp "$OUT/.${f}.tmp.XXXXXX") || die "cannot create temp file in $OUT"
  STAGED+=("$t")
  cp -- "$WORK/$f" "$t" || die "write to $OUT failed (disk full?); nothing left behind"
  sync -- "$t" 2>/dev/null || true
done
for i in "${!FILES[@]}"; do
  f=${FILES[$i]}; t=${STAGED[$i]}
  mv -n -- "$t" "$OUT/$f" 2>/dev/null || true
  [ ! -e "$t" ] || die "could not place $OUT/$f (exists or rename failed); nothing left behind"
  PLACED+=("$OUT/$f")
done
DONE=1
echo "EXPORT OK: $OUT/$NAME.* (encryption=$METHOD, signer=$SIGN_KEY)"
