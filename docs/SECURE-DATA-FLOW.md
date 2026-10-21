# Secure data flow: online and air-gapped (Network lane)

Status: DRAFT, written by Command Center for the Network lane on 2026-10-21. Network owns this file from here on.
Labels: **TESTED** = we ran it, **REPORTED** = read from a cited source, **SIMULATION** = sketch or estimate, not run.

## 1. Rules (apply to both paths)

- GitHub (memory + storage + this repo) is home base. The shared box holds only what the current task needs and is cleared after.
- No keys, tokens, passphrases or endpoint secrets in any repo. Keys stay in the operator's keyring, a hardware token or the connector's own auth.
- Least privilege: read-only scopes unless the task writes; one repo or one bucket per credential where the provider allows it.
- Everything that lands goes in through a reviewed PR. No force-push, no merges by the bot that wrote it, no deletes without Collin's yes.
- Every transfer leaves a provenance record: what, from where, sha256, signer, who imported it, when.

## 2. Online path (GitHub + connectors)

| Step | How | Notes |
|---|---|---|
| Find | memory `connectors/INDEX.md` (memory PR 3) and the facet cards | A card is not the live schema: read the connector's live schema before any call. |
| Pull | `gh api` contents / sparse checkout of just the needed paths; connector read tools | Snippet-first: path + line range, not whole trees. |
| Land | small files → storage repo via PR; big blobs → object store (section 5), with only the manifest + sha256 in storage | GitHub blocks files over 100 MiB (REPORTED, GitHub docs). |
| Record | one provenance line (same fields as section 3) in the PR body or `provenance.jsonl` | |
| Gate | connectors flagged SPEND / SEND / DELETE / SIGN / SHARE / EXEC / SECRETS in the index need Collin's explicit OK per call | |

## 3. Offline / air-gapped path (git bundle + encryption + signature)

Tools in this PR: `tools/bundle-export.sh` and `tools/bundle-verify-import.sh`.

**Export (connected side):**
1. `git bundle create` from the chosen refs (full, or incremental with `--since REV`), then `git bundle verify`.
2. Encrypt to the receiver's key: gpg (`--gpg-recipient` = the receiver's **full 40-hex fingerprint**; short KEYIDs are refused) or age (`--age-recipient age1...`). The signing key (`--sign-key`) is also a full **primary-key** fingerprint. If that key has a signing subkey (e.g. a cert-only primary kept offline), gpg signs with the subkey. The export self-check and the importer both require the `VALIDSIG` *primary* fingerprint to equal it, so a subkey works and no other key can stand in. Passing a subkey fingerprint as `--signer` is refused. Both keys are checked first: they must exist and must not be revoked or expired. The plaintext bundle exists only in a mode-700 temp dir that is removed on exit.
3. Write `<name>.provenance.json` with `jq`, never by string concatenation, so branch names containing quotes stay valid JSON. Fields: name, UTC time, plaintext sha256, encryption method, recipient, signer fingerprint, plus source origin reduced to `scheme://host[:port]/path` (or `host:path` for scp-style remotes): userinfo such as `user:token@` is removed, including scp-style `user:tok@host:path`, upper-case schemes (`HTTPS://u:p@`) and passwords containing `/`, and everything from the first `?`, `#` or `;` is dropped, since `?token=`, `&access_token=` or `;token=` can carry credentials. When it can't tell userinfo from path (e.g. `host:8080/a@b`) it strips too much rather than too little; use `--redact-provenance` for unusual remotes, `--since` and heads, unless `--redact-provenance` is given. The exporter hostname is left out unless `--with-host` is given.
4. Write `<name>.SHA256SUMS` over the encrypted bundle and the provenance file, and a detached gpg signature `<name>.SHA256SUMS.asc`.
5. Self-check the checksums and the signature (GOODSIG whose primary fingerprint is exactly `--sign-key`). Then stage each file as a temp file inside `--out` and rename it into place with no-clobber, so a reader never sees a half-written file and nothing existing is overwritten. The cleanup trap is armed before the first write. If anything fails part-way (a full disk, a failed rename, Ctrl-C), every file this run staged or placed in `--out` is removed, along with the temp dir, so a failed export leaves nothing behind.

**Carry:** USB, SD card or any one-way medium.

What the 4 files protect: the bundle **contents** (code, history, file data) are encrypted, and all 4 files are **tamper-evident** (signed manifest). They are **not confidential as a set**. `<name>.provenance.json`, `<name>.SHA256SUMS` and the `.asc` travel in **plaintext**, so anyone who sees the medium learns:

| Plaintext field | Default | With `--redact-provenance` |
|---|---|---|
| bundle name, UTC export time, encryption method | shown | shown |
| plaintext bundle sha256, encrypted file sha256s | shown | shown |
| recipient fingerprint / age public key, signer fingerprint (also in the `.asc`) | shown | shown |
| source origin URL (credentials stripped) | shown | omitted |
| branch names and head commit SHAs, `--since` REV | shown | omitted |
| exporter hostname | omitted | omitted (only with `--with-host`) |

Use `--redact-provenance` when the repo name, branch names or commit SHAs are themselves sensitive. The importer needs none of the redacted fields.

**Removable media hygiene (the USB hop):**
- Turn off automount and autorun on **both** machines (desktop automounters such as udisks or GNOME, and anything else that opens or previews new media). Mount by hand only.
- Mount read-only on the air-gapped side, without executables, device files or setuid: `mount -o ro,noexec,nodev,nosuid /dev/sdX1 /mnt/airgap`. On the connected side use `noexec,nodev,nosuid` too.
- Never run anything from the medium, including the tools. The importer comes from the target machine's own reviewed copy of this repo, and you pass the medium only as `--in`.
- Use a dedicated, freshly formatted medium for each direction. Unmount and eject before carrying it.
- The importer copies the 4 files off the medium before checking anything, so a medium that changes underneath it (a malicious device, a hot swap) cannot change what is verified and imported.

**Verify, then import (air-gapped side).** Order is fixed, and any failure stops before the repo is touched:
0. Copy the manifest, signature, bundle and provenance from `--in` into a private temp dir (mode 700, always removed). Symlinks and anything that isn't a regular file are refused. Every later step reads **only these copies**.
1. Signature: `--signer` must be the signer's **full 40-hex (or 64-hex) primary-key fingerprint**. It is compared as an exact string, never as a regex. The signer's public key, and any revocation for it, must already be in the receiver's gpg keyring. The check runs in a throwaway keyring that holds only that key. It needs exactly one `GOODSIG` and a `VALIDSIG` whose primary fingerprint equals `--signer`. Any `BADSIG`, `ERRSIG`, `EXPSIG`, `EXPKEYSIG`, `REVKEYSIG`, `KEYREVOKED`, `KEYEXPIRED` or `NO_PUBKEY`, or a signer key that is revoked or expired, rejects the bundle.
2. The manifest must list exactly two files, `<name>.bundle.gpg|age` and `<name>.provenance.json`, and nothing else. Then `sha256sum --strict -c` runs on the copies.
3. The provenance must be a JSON object whose `name` and `signer` match the command line and that has a valid `created_utc`. If the local provenance log shows a successful import under the same `--name` with a newer `created_utc`, or the same `created_utc` but a different signed manifest hash, the import is refused as a possible replay unless `--allow-replay` is given. Decrypt the copy (gpg must report `DECRYPTION_OKAY`; age needs `AGE_IDENTITY`). The decrypted sha256 must match the provenance.
4. `git bundle verify` against the target, which catches missing prerequisite commits.
5. Import with `git -c transfer.fsckObjects=true -c fetch.fsckObjects=true fetch --atomic` into the quarantine namespace `refs/remotes/airgap/<name>/*`. Malformed objects abort the fetch. `--atomic` makes the ref update all-or-nothing: if any ref is rejected (for example a diverged `main` next to a brand-new branch), no ref is created or moved. No branch is overwritten and nothing is forced. Promotion to a real branch happens by a reviewed PR.
6. Append an import record (built with `jq`) to `~/.airgap/provenance.jsonl`, which sits outside every repo. Records carry `status`: `imported` on success, or `rejected` when step 5 fails (with the quarantine refs as they still are). Both carry `created_utc`, `bundle_sha256` and `manifest_sha256` (sha256 of the signed `SHA256SUMS`). Failures before step 5 (signature, manifest, checksum, decrypt, bundle verify, replay) only print the error and write no record. Commit a copy via PR if the lane wants it on GitHub.

`--verify-only` runs steps 0–4 and imports nothing (dry run).

**Replay and re-import (honest limits).** There is no cryptographic replay protection: no nonce, no sequence number, and no receiver-side state that the sender signs. An older bundle that was validly signed stays valid. What exists, all tested in `tests/run_tests.sh`:
- **Same name, older bundle:** refused when the receiver's provenance log (`--provenance-log`, default `~/.airgap/provenance.jsonl`) has a newer `created_utc` for that name, or the same `created_utc` with a different `manifest_sha256` (`created_utc` has 1-second resolution, so two exports in the same second share it; the compare is `<=` plus a manifest-hash check). Only `status: imported` records count; `rejected` records never advance the guard. `created_utc` sits inside the signed manifest, so it can't be edited, but it is the sender's clock. With `--allow-replay`, git still refuses to move an existing quarantine ref backwards (non-fast-forward), so nothing is rolled back.
- **Same bundle again** (same `created_utc` and same signed manifest hash): accepted and idempotent; refs are unchanged and the importer says it is a no-op. Older log records without `manifest_sha256` fall back to comparing `bundle_sha256`.
- **Same name, diverged history** (for example a force-pushed source): refused as non-fast-forward. Because the fetch is atomic, the existing quarantine ref is untouched and no other ref from that bundle (e.g. a new branch) is created either. A `status: rejected` record is written to the log. Fix it on the sender side, or import under a new name for review.
- **Renaming an old bundle to a new name:** refused, because the signed manifest and provenance carry the original name.
- **Not caught:** an old bundle given to a receiver whose log doesn't have the newer import (a fresh machine, a deleted or different `--provenance-log`), or an old bundle the sender re-signs under a new name. Either lands in its own `refs/remotes/airgap/<name>/` quarantine namespace and changes no branch.

Mitigation: keep one provenance log per receiver and back it up. Before promoting a quarantine ref by PR, check the bundle's `created_utc` (printed by the importer and kept in the log) and compare its commits against what is already on the real branch. Promotion is a reviewed PR, so a stale replay shows up there as an old or diverging history.

**Keys and who can import.** Keys are never committed. A receiver can import only if it holds (a) the private key the bundle was encrypted to, gpg or age, and (b) the sender's public signing key, checked out-of-band against its full fingerprint. Revocations must be imported into the receiver's keyring when they are issued. The importer rejects revoked or expired signers only if the receiver's keyring knows about them.

### Tests: `tests/run_tests.sh` (TESTED, network/harden-pr9)

Run `tests/run_tests.sh`. It needs bash, gpg, git and jq; age is optional and its cases are skipped without it. Sender, receiver and attacker use separate `GNUPGHOME`s under one `mktemp -d`, with throwaway keys that are deleted on exit. Set `ORIG_IMPORT=<path to the ed4192a importer>` to also run the attack cases against the pre-hardening script.

Cases: good path (export, verify-only, import, JSON log), wrong signing key, signer not in keyring, short KEYID refused, revoked signer, 1 byte appended to the bundle, edited manifest, signed manifest without provenance, symlink on the medium, **file swap on the medium after the checksum check** (a PATH shim swaps in an attacker's bundle and provenance right after `sha256sum -c`), `--signer '.*'` and short KEYIDs refused, branch name containing `"`, `--redact-provenance`, malformed commit object rejected by fsck, age round trip plus age with the wrong identity, refusal to overwrite, and no temp dirs left behind.

Also covered: a mid-export failure (simulated full disk on a write, and a failed rename into `--out`) leaves `--out` empty; signing with a subkey under `--sign-key <primary>`; credentials in the origin URL's userinfo, query and fragment are stripped; an expired signer key (created and signed with a faked 2020 clock) is rejected; replay of an older signed bundle and re-import over existing refs (see above); upper-case scheme, scp-style `user:tok@host:path`, `/` in the password and `;token=` params are stripped from the origin; an import whose bundle has a diverged `main` plus a new branch creates no refs (atomic) and writes a `rejected` record that doesn't advance the replay guard; a different bundle with the same `created_utc` is refused as a replay while an identical re-import stays a no-op.

Result on the shared box (gpg 2.4.7, git 2.47.3, age 1.2.1), after GitAI's P1-P4 follow-up: **93 passed, 0 failed, 0 skipped.** (The run before the follow-up was 69/0/0.) Against the ed4192a importer, the same harness reproduced GitAI's findings: it accepted a revoked signer, accepted an expired signer, accepted an attacker's key with `--signer '.*'`, and imported the attacker's commit after the file swap. The hardened importer rejected the first three and imported the signed commit in the fourth. The full output is in the PR description and the network/harden-pr9 patch notes.

Correction: an earlier commit message said the old edited-manifest test (`sed 's/^\(.\)/0/'`) was a no-op about 1 in 256 runs. It changed one hex digit, so it was a no-op whenever the manifest already started with `0`: about **1 in 16** runs (GitAI measured 25 of 300). The current test flips the first digit and checks with `cmp` that the file changed.

### Earlier test result (pre-hardening, ed4192a): TESTED on the shared box, 2026-10-21 15:24 CDT

Kept for history. These 10 cases ran from a log with one shared gpg home; `tests/run_tests.sh` above replaces them.

Throwaway gpg home, keys and repos under `/tmp/airgap-test.*`, all deleted afterward. gpg 2.4.7, git 2.47.3. Fingerprints are redacted below.

| # | Case | Expected | Result |
|---|---|---|---|
| 1 | dry-run export | plan printed, nothing written | PASS |
| 2 | export | 4 files, 0 plaintext bundles | PASS |
| 3 | verify-only | all 4 checks ok, 0 refs imported | PASS |
| 4 | import | `refs/remotes/airgap/t1/main`, 2 commits, 1 provenance line | PASS |
| 5 | wrong signer fingerprint | FAIL at signature | PASS (rejected) |
| 6 | 1 byte appended to the encrypted bundle | FAIL at checksum | PASS (rejected) |
| 7 | edited manifest | FAIL at signature | PASS (rejected) |
| 8 | incremental (`--since HEAD~1`) export + import | imports on top of t1 (3 commits) | PASS |
| 9 | incremental into an empty repo | FAIL at `git bundle verify` (missing prerequisite) | PASS (rejected) |
| 10 | re-export with the same name | refuse to overwrite | PASS |
| — | temp dirs left by the scripts | 0 | PASS |

At that time the age path wasn't tested (it is now, in `tests/run_tests.sh`). A real removable-media hop is still **SIMULATION** until someone runs it.

<details><summary>Raw log (fingerprints redacted)</summary>

```
run 2026-10-21 15:24 CDT
gpg (GnuPG) 2.4.7
git version 2.47.3
== 1 dry-run export
DRY-RUN OK: would write to <out>:
t1.SHA256SUMS
t1.SHA256SUMS.asc
t1.bundle.gpg
t1.provenance.json
heads: {"sha":"52f286b02059998a585de26df1819ba05efc5ff4","ref":"refs/heads/main"}
rc=0
no out dir written (expected)
== 2 export
EXPORT OK: out/t1.* (encryption=gpg, signer=<FPR>)
rc=0
t1.SHA256SUMS
t1.SHA256SUMS.asc
t1.bundle.gpg
t1.provenance.json
plaintext bundles left: 0
== 3 verify-only
ok   signature from <FPR>
ok   sha256 manifest (t1.bundle.gpg, t1.provenance.json)
ok   decrypted bundle sha256 matches provenance
ok   git bundle verify against target
VERIFY-ONLY OK: nothing imported
rc=0
refs in dst after verify-only: 0
== 4 import
ok   signature from <FPR>
ok   sha256 manifest (t1.bundle.gpg, t1.provenance.json)
ok   decrypted bundle sha256 matches provenance
ok   git bundle verify against target
     From /tmp/bundle-import.XXXX/b.bundle
      * [new branch]      main       -> airgap/t1/main
IMPORT OK: refs under refs/remotes/airgap/t1/ ; provenance -> /tmp/airgap-test.XXXX/prov.jsonl
rc=0
refs/remotes/airgap/t1/main
commits imported: 2
provenance lines: 1
== 5 wrong signer (expect FAIL)
bundle-verify-import: FAIL: signature missing, invalid, or not from <FPR>
rc=1
== 6 tampered bundle (expect FAIL)
ok   signature from <FPR>
t1.bundle.gpg: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
bundle-verify-import: FAIL: checksum mismatch
rc=1
== 7 tampered manifest (expect FAIL)
bundle-verify-import: FAIL: signature missing, invalid, or not from <FPR>
rc=1
== 8 incremental export+import
EXPORT OK: out/t2.* (encryption=gpg, signer=<FPR>)
rc=0
ok   signature from <FPR>
ok   sha256 manifest (t2.bundle.gpg, t2.provenance.json)
ok   decrypted bundle sha256 matches provenance
ok   git bundle verify against target
     From /tmp/bundle-import.XXXX/b.bundle
      * [new branch]      main       -> airgap/t2/main
IMPORT OK: refs under refs/remotes/airgap/t2/ ; provenance -> /tmp/airgap-test.XXXX/prov.jsonl
rc=0
commits on airgap/t2/main: 3
== 9 incremental into empty repo (expect FAIL: missing prerequisite)
ok   signature from <FPR>
ok   sha256 manifest (t2.bundle.gpg, t2.provenance.json)
ok   decrypted bundle sha256 matches provenance
bundle-verify-import: FAIL: git bundle verify failed (missing prerequisites?)
rc=1
== 10 re-export same name (expect refuse overwrite)
bundle-export: refusing to overwrite out/t1.bundle.gpg
rc=1
== temp dirs left by scripts: 0
test dir removed: yes
```
</details>

## 4. How agents request data through Network

1. The requester opens an issue (or comments on the board item) in `network` titled `data-request: <what>`. It says what's needed, which repo it lands in, the sensitivity, and online or air-gapped.
2. Network picks the path. Online: connector or `gh` read with the smallest scope. Air-gapped: a bundle via the tools above.
3. Network delivers by PR into the requester's repo (small data) or by object-store path + sha256 manifest in storage (big data). Every delivery carries a provenance line.
4. The requester pulls just in time, uses only the facet or snippet it needs, and clears the box copy after the task.
5. TESSERA sees the request and delivery on the Tessera Mesh board. Status changes are kept current there.

## 5. Massive storage: free and cheap options

Checked on the vendors' own pages on 2026-10-21. All rows are **REPORTED**. Prices change, so recheck before you commit.

| Option | Free tier (vendor page) | Paid rate (vendor page) | Fit / caution |
|---|---|---|---|
| Cloudflare R2 | 10 GB-month storage, 1M Class A + 10M Class B ops per month, egress free ([pricing](https://developers.cloudflare.com/r2/pricing/)) | $0.015/GB-month Standard | S3 API, free egress. Good primary hot store. A card is required for the account. |
| Backblaze B2 | first 10 GB free ([pricing](https://www.backblaze.com/cloud-storage/pricing)) | $6.95/TB/month; free egress up to 3× stored, then $0.01/GB | Cheapest big S3-compatible store of these. Free egress through Cloudflare and other partner CDNs. |
| Hugging Face Hub | private storage 100 GB for free users; public is "best-effort" ([limits](https://huggingface.co/docs/hub/storage-limits)) | PRO: 1 TB private + $18/TB/month over that | Natural home for **model weights and datasets**. Keep files under 200 GB each (hard cap 500 GB). Public uploads should be useful to the community. |
| Internet Archive | free account, upload page states no quota ([guide](https://help.archive.org/help/uploading-a-basic-guide/)) | — | **Public and permanent.** Only for material we're happy to publish. Never private or encrypted mirrors. |
| GitHub Releases | assets each < 2 GiB, up to 1,000 per release, no total size or bandwidth limit stated ([docs](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)) | — | Good for encrypted bundles in a private repo. Not a database. |
| GitHub LFS | Free plan: 10 GiB storage + 10 GiB bandwidth per month ([billing](https://docs.github.com/en/billing/concepts/product-billing/git-lfs)) | metered | Small. Every push of a changed file counts the full size again. |
| GitHub repo itself | warns at 50 MiB, blocks files > 100 MiB; repos ideally < 1 GB, < 5 GB strongly recommended ([docs](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)) | — | Manifests, facets and code only. |
| Google Drive | 15 GB shared across Gmail, Drive and Photos ([Google One help](https://support.google.com/googleone/answer/9312312)) | Google One plans | Already connected. Shared quota, so it fills up with mail. |
| Oracle Cloud Always Free | 20 GB Object Storage (Always-Free-only accounts) + 200 GB block volume, 10 TB/month outbound ([docs](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)) | pay-as-you-go | The 200 GB block volume plus an Arm VM (2 OCPU / 12 GB on Always Free tenancies) could host a peer node. Idle VMs may be reclaimed. |
| IPFS via Filebase | 5 GB, 500 pinned files, 10 GB IPFS egress ([pricing](https://filebase.com/pricing/)) | Pro $7.50/month for 500 GB | Content-addressed by CID. Pinned data is public unless encrypted first. |
| Filecoin via Fil One | trial: 1 TB + 2 TB egress for 30 days, no card ([pricing](https://storacha.network/pricing), which now redirects to Fil One) | $5.99/TB/month, $5.99 monthly minimum | Cheap per TB. No permanent free tier. |
| Storj | free trial ([pricing](https://www.storj.io/pricing)) | $7/TB/month storage, $7/TB egress, $5 monthly minimum, 30-day minimum retention | Already erasure-coded across many nodes. No permanent free tier. |

What it means for us: free tiers together give tens of GB, not TB. Example: R2 10 GB + B2 10 GB + HF 100 GB private + Oracle 20 GB object + Drive 15 GB. Mass storage (TB) means about $6–7/TB/month (B2, Fil One, Storj) or Collin's own disks. That's a budget question for Collin.

## 6. Sketch: our own encrypted store across free providers and peers (SIMULATION, nothing built)

```
           GitHub (storage repo)  <- manifests + facet cards only (paths, sha256, sizes, which backends hold each chunk)
                    |
   bot asks Network for facet X  ->  Network reads manifest  ->  fetches 2 of N chunks  ->  verifies sha256  ->  decrypts locally
                    |
   backends (each sees only ciphertext):  R2 | B2 | HF private | Oracle block vol | Drive | Collin's own disks / peer nodes
```

- **Chunk and encrypt client-side.** Split each object into fixed-size chunks and encrypt with age or gpg before upload, so no provider sees plaintext. An existing tool such as `restic` or `rclone crypt` could do this. Both are open source, and the choice needs a review before use.
- **Replicate.** Put each chunk on at least 2 independent backends (3 for anything we can't regenerate). Reed-Solomon erasure coding (k-of-n) would cut overhead below full copies. SIMULATION: 2× replication of 100 GB uses 200 GB of free tiers, which is about all the free quota listed above.
- **Manifests on GitHub.** `storage/manifests/<dataset>.json` holds the chunk list, sha256 of every chunk, backend locations and the key **fingerprint**, never the key. Memory facet cards point at the manifest path + commit sha.
- **Peers.** Collin's own machines and an Oracle Always Free VM can act as peer nodes over a VPN (the LOW-GPU write-up says the same for RPC workers: trusted LAN or VPN only). The node list lives in `mesh/nodes/registry.json`.
- **Health.** A scheduled job re-hashes a random sample of chunks on each backend and re-replicates anything missing. It would run in GitHub Actions or on a peer, never on the shared box.
- **Air-gap bridge.** The same manifests travel inside the bundles from section 3, so an offline site can verify what it holds without network access.

## 7. Open questions for Collin

1. Which storage accounts may we open: R2, B2, Oracle Always Free, HF, Filebase/Storj? Several need a payment card even for the free tier.
2. Budget for TB-scale storage, if any. List prices run about $6–7/TB/month.
3. Who holds the signing and encryption keys (gpg or age), and on which device? Should it be a hardware token?
4. Is Internet Archive acceptable for material that's meant to be public?
