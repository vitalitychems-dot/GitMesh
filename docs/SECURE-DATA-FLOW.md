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
2. Encrypt to the receiver's key: gpg (`--gpg-recipient FPR`) or age (`--age-recipient`). The plaintext bundle exists only in a temp dir that is removed on exit.
3. Write `<name>.provenance.json` (source origin with any credential stripped, heads, plaintext sha256, recipient, signer fingerprint, UTC time).
4. Write `<name>.SHA256SUMS` over the encrypted bundle and the provenance file, and a detached gpg signature `<name>.SHA256SUMS.asc`.
5. Self-check the checksums and signature, then copy the 4 files to `--out`. It refuses to overwrite.

**Carry:** USB, SD card or any one-way medium. The 4 files are safe to carry: they're encrypted and tamper-evident.

**Verify, then import (air-gapped side).** Order is fixed, and any failure stops before the repo is touched:
1. The signature must be valid **and** come from the expected `--signer` fingerprint.
2. `sha256sum --strict -c` on the manifest.
3. Decrypt into a private temp dir (mode 700, always removed). The decrypted sha256 must match the provenance file.
4. `git bundle verify` against the target, which catches missing prerequisite commits.
5. Import with `git fetch` into the quarantine namespace `refs/remotes/airgap/<name>/*`. No branch is overwritten and nothing is forced. Promotion to a real branch happens by a reviewed PR.
6. Append an import record to `~/.airgap/provenance.jsonl`, which sits outside every repo. Commit a copy via PR if the lane wants it on GitHub.

`--verify-only` runs steps 1–4 and imports nothing (dry run).

### Test result: TESTED on the shared box, 2026-10-21 15:24 CDT

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

Not tested: the age path (age isn't installed on the box) and a real removable-media hop. Both stay **SIMULATION** until someone runs them.

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
