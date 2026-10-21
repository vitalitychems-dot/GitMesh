# Non-IP Mesh: carrying mesh data without IP addresses or ISPs (Network lane)

Status: **DRAFT, design and simulation only**, written 2026-10-21. **No RF is transmitted.** Nothing in this PR calls radio hardware, opens a serial port, or starts a network listener. `tools/kiss_frame.py` writes `.kiss` files and nothing else.
Labels: **TESTED** = we ran it here, **REPORTED** = from a cited source (recheck before relying on it), **SIMULATION** = a sketch or estimate, not run on hardware.

## 1. Goal

Move mesh data (the signed, encrypted bundles from network PR #9, and small control messages) between our own nodes **without IP addresses, DNS or an ISP**. Nodes are named by cryptographic hashes, links are radios or cables we own, and nothing on the wire names a host, an IP or a tracking id. When an IP overlay is used at all, it runs only on links we own and sits behind an explicit boundary policy (section 4).

## 2. Layers at a glance

```
 PR #9 bundle (gpg/age encrypted + signed SHA256SUMS)
   -> strip (text payloads only; refuse if anything identifying is left)     tools/kiss_frame.py strip()
   -> chunk  (49-byte header: magic, ver, msg id, seq, total, len, sha256)   tools/kiss_frame.py chunk()
   -> KISS   (FEND/FESC escaping, port/cmd byte)                            tools/kiss_frame.py encode()
   -> link:  RNode (LoRa 915 MHz) via Reticulum  |  simulated link (in memory, tests only)
```

## 3. Reticulum role (primary transport, REPORTED)

- **Destination hashes instead of IPs.** Reticulum addresses a destination by a 16-byte (128-bit) truncated SHA-256 hash of its identity public key and its aspect names, not by an IP or hostname. Routing works on those hashes, so no IP plan, DHCP, DNS or ISP is involved. Links are end-to-end encrypted (X25519 + AES) by Reticulum itself. Our payload is *also* already encrypted and signed by PR #9, so a Reticulum compromise exposes no bundle contents. Source: Reticulum manual, "Understanding Reticulum" (https://reticulum.network/manual/understanding.html).
- **Interface: `RNodeInterface` on LILYGO LoRa boards** (T-Beam, LoRa32 v2.1, T3S3) flashed with the open RNode firmware (`rnodeconf --autoinstall`). Example config, **not deployed**, with a placeholder port:

  ```ini
  # ~/.reticulum/config  (EXAMPLE ONLY - do not enable until the FCC review below is done)
  [[RNode 915 LoRa]]
    type = RNodeInterface
    enabled = no                # stays off in this PR
    port = /dev/ttyACM0         # placeholder
    frequency = 915000000       # 915 MHz, US 902-928 MHz ISM band
    bandwidth = 125000
    spreadingfactor = 7
    codingrate = 5
    txpower = 7                 # dBm, low; see the Part 15 notes
    airtime_limit_short = 33    # % over 15 s, a self-imposed duty cap
    airtime_limit_long = 10     # % over 1 h
  ```
- **Large transfers.** Reticulum's packet MTU is 500 bytes, and its `Resource` API already segments, sequences, checksums and retransmits large data over a Link. For real Reticulum use, hand the PR #9 files to a `Resource`. The chunk/KISS layer in this PR is for (a) the offline simulation and tests, (b) a plain KISS TNC path without Reticulum, and (c) carrying `.kiss` files on removable media. The RNode firmware speaks KISS on its *serial* side (host to radio). Escaping applies only on that serial hop; the over-the-air LoRa frame carries the unescaped bytes.

### FCC Part 15 (US) notes: verify before any transmission

**Nothing here authorizes transmitting.** Before anyone enables a radio, a person checks the current 47 CFR Part 15 text and the module's FCC ID grant. REPORTED summary (eCFR, 47 CFR 15.247 and 15.249; recheck):
- **902–928 MHz** is an unlicensed ISM band in the US. Use 915 MHz-band hardware (LILYGO "915" variants), never 868 MHz EU firmware or settings.
- **§15.247, digital modulation (DTS):** the 6 dB bandwidth must be at least 500 kHz. Up to 1 W (30 dBm) conducted with up to a 6 dBi antenna, and PSD ≤ 8 dBm per 3 kHz. LoRa at **500 kHz** bandwidth is the setting usually argued to fit here.
- **§15.247, frequency hopping (FHSS):** with a 20 dB bandwidth under 250 kHz, at least 50 channels and at most **0.4 s dwell per channel in any 20 s**. A single fixed 125 kHz channel is *not* hopping.
- **§15.249:** fixed-channel, narrow-band devices are limited to a field strength of 50 mV/m at 3 m (on the order of 1 mW EIRP).
- **Our rule:** until a person signs off, settings stay at the lowest power, the device stays a certified module in its granted configuration, and the Reticulum `airtime_limit_*` caps stay on. No amplifiers, and no antennas above what the grant lists.

## 4. Yggdrasil role (optional overlay, our links only)

Yggdrasil is an encrypted IPv6 overlay whose addresses (`200::/7`) are derived from node keys. It **is** IP, so it is never the base layer here. It is allowed only as an optional overlay on links we own (our own Ethernet/Wi-Fi between our machines, or a cable). It can carry Reticulum (`TCPClientInterface`/`AutoInterface` over it) when two of our sites have such a link.

**Boundary policy (what may cross the overlay):**
| Allowed | Denied |
|---|---|
| Reticulum traffic between our own nodes | Public Yggdrasil peers. `Peers: []`, and no multicast peering beyond our own interfaces |
| PR #9 bundles (encrypted + signed), and `.kiss` files built by `tools/kiss_frame.py` | Any route to the clearnet or an ISP: no NAT, no gateway, no exit node |
| | DNS, NTP, telemetry and package updates over the overlay |
| | Inbound connections, except the one Reticulum port, from our listed node keys only (`AllowedPublicKeys`) |
| | Yggdrasil addresses inside payloads. The strip list (section 5) redacts every IPv6 literal, including `200::/7` |

## 5. Strip list (runs before framing, text payloads only)

`kiss_frame.strip()` redacts, in this order. Then it **re-scans the result and its percent-decoded form, and refuses to frame if anything is left**:
1. **Tracking/identifying headers:** `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Via`, `True-Client-IP`, `CF-Connecting-IP`, `Referer`, `Cookie`, `Set-Cookie`, `User-Agent`, `X-Request-ID`, `X-Amzn-Trace-Id`, `X-Device-ID` and similar. The value becomes `[redacted]`.
2. **Tracking pixels:** `<img>` tags that are 0/1 px or whose src looks like a pixel, beacon or collector become `[pixel]`.
3. **URLs:** the host becomes `[host]`, and userinfo and the fragment are dropped. Tracking params are dropped: `utm_*`, `fbclid`, `gclid`, `dclid`, `gbraid`, `wbraid`, `msclkid`, `yclid`, `igshid`, `twclid`, `ttclid`, `mc_cid`/`mc_eid`, `_hsenc`/`_hsmi`, `mkt_tok`, `_ga`/`_gl` and others. Other params are kept.
4. **E-mail addresses** become `[email]`.
5. **IPv4 and IPv6 literals** (with port, brackets or zone, e.g. `[2001:db8::1]:80`, `fe80::1%eth0`) become `[ip]`. IPv6 candidates are validated with `ipaddress`, so times like `12:30:45` are kept.
6. **Bare hostnames** (`node7.mesh.example`, `localhost`) become `[host]`. Common file names (`README.md`, `t1.bundle.gpg`, `a.tar.gz`) are kept.

Refused leftovers include percent-encoded tracking (`utm%5Fsource`), encoded URLs with IPs, and integer/hex IP URLs.

**Binary payloads are not stripped.** The CLI frames binary data only with `--encrypted`, and only if it starts as age or OpenPGP *encrypted* data (what PR #9 produces). Any other binary is refused. Signed text files (`SHA256SUMS`, provenance) must use `--text --require-clean`, which refuses if strip would change a byte, since a change would break the signature. Export with PR #9's `--redact-provenance` so the provenance holds no origin URL.

## 6. Packet pipeline and formats (TESTED in `tests/test_kiss_frame.py`)

**Chunk header** (big-endian, 49 bytes): `magic "NM"(2) | version 1(1) | msg_id(8) = sha256(message)[:8] | seq(2, 0-based) | total(2) | len(2) | sha256(payload)(32)`, followed by the payload.
`reassemble()` is strict. It rejects a bad chunk (magic, version, length, per-chunk sha256), a chunk from another message, a changed total, a **duplicate**, an **out-of-order** or **missing** chunk, extra chunks, and finally a whole-message `msg_id` mismatch, which catches a self-consistent forged chunk. Transport integrity only detects corruption. Authenticity comes from PR #9's signature, which the receiver checks after reassembly.

**KISS frame:** `FEND(0xC0) | type = port<<4 | cmd | data | FEND`, with `0xC0 -> 0xDB 0xDC` and `0xDB -> 0xDB 0xDD`. The type byte is escaped too (port 12 gives 0xC0). Data frames use cmd 0. `decode()` skips empty frames and rejects bad escapes and unterminated frames.

**CLI** (writes `.kiss` files only, never overwrites, publishes atomically):
```
python3 tools/kiss_frame.py frame --in t1.bundle.gpg --out t1.kiss --encrypted
python3 tools/kiss_frame.py frame --in t1.SHA256SUMS --out t1-sums.kiss --text --require-clean
python3 tools/kiss_frame.py check --in t1.kiss          # decode + reassemble, prints JSON, writes nothing
python3 tools/kiss_frame.py strip-check --in notes.txt  # prints what would be redacted or refused
```

## 7. LoRa MTU budget and duty cycle

- The LoRa PHY payload maximum is **255 bytes** (SX127x/SX126x). Default chunk = 49 header + **200 payload = 249 bytes**. `chunk()` refuses any size above the MTU. KISS escaping adds bytes on the serial hop only, about 0.8% on encrypted data on average and 2× worst case. It doesn't count against the air MTU.
- Overhead: 49/249 ≈ 20%. A 1 MB bundle is 5,243 chunks. The header allows up to 65,535 chunks (about 13 MB at 200 B per chunk). Bigger bundles are split with `--since` (incremental, PR #9) or carried on media.
- **Time on air** for one 249-byte frame, from the Semtech SX127x formula (`kiss_frame.lora_airtime_ms`, explicit header, CRC on, CR 4/5, 8-symbol preamble; SIMULATION):

  | SF / BW | ms per 249-byte frame | 1 MB (5,243 frames) at 100% airtime | at a 10% self-cap |
  |---|---|---|---|
  | SF7 / 125 kHz | 389 | ~34 min | ~5.7 h |
  | SF9 / 125 kHz | 1,230 | ~1.8 h | ~18 h |
  | SF12 / 125 kHz | 8,856 | ~12.9 h | ~5.4 days |
  | SF7 / 250 kHz | 195 | ~17 min | ~2.8 h |
  | SF7 / 500 kHz | 97 | ~8.5 min | ~1.4 h |

- The US has no ETSI-style duty-cycle percentage, but FHSS has the **0.4 s dwell** limit. SF7/125 kHz at 249 bytes (389 ms) just fits, and SF9 and up do not, so slow spreading factors would need smaller chunks under FHSS. We still apply a self-imposed airtime cap (Reticulum `airtime_limit_long = 10`) so a shared band stays usable for others. LoRa is for control messages and small incrementals. Full bundles travel on media (PR #9's USB hop) or on an overlay link we own.

## 8. Peer graph format (adopted from Rick's physarum-r0)

The future peer ranker plugs in through this JSON, unchanged from physarum-r0:

```json
{
  "nodes": ["<id>", "..."],
  "edges": [ {"u": "<id>", "v": "<id>", "latency_ms": 0, "quota_pressure": 0} ]
}
```

- **Node ids are Reticulum destination hashes** (32 hex chars = 16 bytes), **never IPs or hostnames**. The strip list applies to this file as well.
- `latency_ms` (number, measured or estimated per link; LoRa links use the airtime table above) and `quota_pressure` (number, 0 = idle, larger = closer to a quota or airtime cap).
- **Ranker API:** `rank(graph, src, dst) -> ordered paths` (best first, each path a list of node ids). It will be implemented standalone in collab `tools/physarum/`, which is **not built yet**. Nothing in this repo depends on it.
- **Edge cost: TBD with Einstein.** The current candidate is `cost = latency_ms * (1 + quota_pressure)`.

Example (ids are made-up hashes):
```json
{
  "nodes": ["a3f1c9e07b2d4e5f8a9b0c1d2e3f4a5b", "5b7e2d1c0f9a8b7c6d5e4f3a2b1c0d9e", "e0d1c2b3a4958677c8b9aadbecfd0e1f"],
  "edges": [
    {"u": "a3f1c9e07b2d4e5f8a9b0c1d2e3f4a5b", "v": "5b7e2d1c0f9a8b7c6d5e4f3a2b1c0d9e", "latency_ms": 389, "quota_pressure": 0.2},
    {"u": "5b7e2d1c0f9a8b7c6d5e4f3a2b1c0d9e", "v": "e0d1c2b3a4958677c8b9aadbecfd0e1f", "latency_ms": 12,  "quota_pressure": 0.0},
    {"u": "a3f1c9e07b2d4e5f8a9b0c1d2e3f4a5b", "v": "e0d1c2b3a4958677c8b9aadbecfd0e1f", "latency_ms": 1230, "quota_pressure": 0.5}
  ]
}
```
With the candidate cost, `rank(g, "a3f1…", "e0d1…")` would return the two-hop path first (389·1.2 + 12·1.0 = 478.8) and the direct LoRa SF9 link second (1230·1.5 = 1845).

## 9. Tests (TESTED)

`python3 -m unittest discover -s tests -v`. Stdlib only, offline, about 0.5 s. It covers KISS round trips including FEND/FESC (and an escaped type byte), exact escape bytes, bad streams, 500 fuzzed payloads biased towards FEND/FESC, and 200 fuzzed message and chunk sizes. It also covers tamper detection (payload bits, header magic, truncation, a self-consistent forged chunk caught by `msg_id`); missing, duplicate, out-of-order, foreign and extra chunks; the strip list (redaction, encoded leftovers refused, clean text unchanged); and a simulated lossy link (20% loss, 10% duplicates, 10% reordering, 5% bit flips). One-shot transfers are either exact or rejected, never wrong, and a simulated stop-and-wait resend loop always completes. The airtime formula, the encrypted-input check, and the CLI (frame/check, `.kiss`-only, no overwrite, refusals) are covered as well.

## 10. Open questions

1. Who signs off on the Part 15 review, and which mode do we use: 500 kHz DTS, or hopping?
2. Which boards, and how many (T-Beam with GPS, or LoRa32)? Buying them needs Collin's yes.
3. Do we want Yggdrasil at all, or only Reticulum over our own Ethernet/Wi-Fi (`AutoInterface`)?
4. The edge cost function for the ranker (with Einstein).
