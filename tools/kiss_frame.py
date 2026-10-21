#!/usr/bin/env python3
"""kiss_frame.py: offline framing for the Non-IP Mesh (docs/NON-IP-MESH.md).

DESIGN / SIMULATION ONLY. Python standard library only. This module opens no
sockets, no serial ports and no radios, and it transmits nothing. The CLI only
writes .kiss files (and prints reports to stdout).

Pipeline (see the doc):
    signed+encrypted bundle (network PR #9)
      -> strip()        text payloads only: redact IP literals, hostnames,
                        tracking params/pixels/headers; refuse if anything is left
      -> chunk()        49-byte header: magic, version, msg id, seq, total, len, sha256
      -> encode()       KISS framing with FEND/FESC escaping and a port/cmd byte
      -> RNode or SimulatedLink (in-memory only)
    and back: decode() -> reassemble() (verifies every chunk and the message).
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import struct
import sys
import tempfile
import urllib.parse
from typing import Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- KISS
FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD
CMD_DATA = 0x00


class KissError(ValueError):
    """A malformed KISS stream (bad escape, bad type byte, unterminated frame)."""


def _escape(data: bytes) -> bytes:
    return data.replace(bytes([FESC]), bytes([FESC, TFESC])).replace(bytes([FEND]), bytes([FESC, TFEND]))


def encode(data: bytes, port: int = 0, cmd: int = CMD_DATA) -> bytes:
    """One KISS frame: FEND, type byte (port<<4 | cmd), escaped data, FEND."""
    if not 0 <= port <= 15 or not 0 <= cmd <= 15:
        raise ValueError("port and cmd must each be 0..15")
    return bytes([FEND]) + _escape(bytes([(port << 4) | cmd]) + bytes(data)) + bytes([FEND])


def decode(stream: bytes) -> List[Tuple[int, int, bytes]]:
    """Split a KISS byte stream into (port, cmd, data) frames.

    Empty frames (back-to-back FENDs) are skipped, as KISS allows. A FESC not
    followed by TFEND/TFESC, or bytes after the last FEND, raise KissError.
    """
    frames: List[Tuple[int, int, bytes]] = []
    buf = bytearray()
    in_frame = False
    esc = False
    for b in stream:
        if b == FEND:
            if esc:
                raise KissError("FESC immediately before FEND")
            if in_frame and buf:
                t = buf[0]
                frames.append((t >> 4, t & 0x0F, bytes(buf[1:])))
            buf = bytearray()
            in_frame = True
            continue
        if not in_frame:
            raise KissError("data before the first FEND")
        if esc:
            if b == TFEND:
                buf.append(FEND)
            elif b == TFESC:
                buf.append(FESC)
            else:
                raise KissError("invalid escape 0x%02X after FESC" % b)
            esc = False
        elif b == FESC:
            esc = True
        else:
            buf.append(b)
    if esc or buf:
        raise KissError("unterminated frame at end of stream")
    return frames


# ------------------------------------------------------------------------ chunks
MAGIC = b"NM"
VERSION = 1
# magic(2) version(1) msg_id(8) seq(2) total(2) len(2) sha256(payload)(32)
HEADER = struct.Struct(">2sB8sHHH32s")
HEADER_LEN = HEADER.size  # 49
LORA_MAX_PAYLOAD = 255    # SX127x/SX126x max LoRa payload, bytes on air
DEFAULT_CHUNK = 200       # 49 + 200 = 249 <= 255


class ChunkError(ValueError):
    """Bad, missing, duplicate or out-of-order chunks, or a failed integrity check."""


def msg_id(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()[:8]


def chunk(message: bytes, size: int = DEFAULT_CHUNK, mtu: int = LORA_MAX_PAYLOAD) -> List[bytes]:
    """Split message into chunks of header + up to `size` payload bytes.

    seq is 0-based, total is the chunk count (an empty message is 1 empty chunk).
    Every chunk carries the sha256 of its payload; msg_id is sha256(message)[:8]
    and is re-checked over the whole message on reassembly.
    """
    if size < 1:
        raise ValueError("chunk size must be >= 1")
    if HEADER_LEN + size > mtu:
        raise ValueError("header (%d) + chunk size (%d) exceeds MTU %d" % (HEADER_LEN, size, mtu))
    total = max(1, math.ceil(len(message) / size))
    if total > 0xFFFF:
        raise ValueError("message needs %d chunks; the header allows 65535" % total)
    mid = msg_id(message)
    out = []
    for seq in range(total):
        p = message[seq * size:(seq + 1) * size]
        out.append(HEADER.pack(MAGIC, VERSION, mid, seq, total, len(p), hashlib.sha256(p).digest()) + p)
    return out


def parse_chunk(c: bytes) -> Tuple[bytes, int, int, bytes]:
    """Check one chunk on its own; returns (msg_id, seq, total, payload)."""
    if len(c) < HEADER_LEN:
        raise ChunkError("bad chunk: shorter than the %d-byte header" % HEADER_LEN)
    magic, ver, mid, seq, total, ln, digest = HEADER.unpack_from(c)
    p = c[HEADER_LEN:]
    if magic != MAGIC:
        raise ChunkError("bad chunk: wrong magic")
    if ver != VERSION:
        raise ChunkError("bad chunk: unsupported version %d" % ver)
    if total == 0 or seq >= total:
        raise ChunkError("bad chunk: seq %d / total %d" % (seq, total))
    if ln != len(p):
        raise ChunkError("bad chunk %d: length %d != header %d" % (seq, len(p), ln))
    if hashlib.sha256(p).digest() != digest:
        raise ChunkError("bad chunk %d: sha256 mismatch" % seq)
    return mid, seq, total, p


def reassemble(chunks: Iterable[bytes]) -> bytes:
    """Strictly rebuild one message from chunks in arrival order.

    Rejects (ChunkError): a bad chunk (magic, version, length, sha256), a chunk
    from another message or with a different total, a duplicate, a chunk out of
    order, a missing chunk, extra chunks, and a whole-message msg_id mismatch.
    """
    mid0: Optional[bytes] = None
    total0 = None
    parts: List[bytes] = []
    for c in chunks:
        mid, seq, total, p = parse_chunk(c)
        if mid0 is None:
            mid0, total0 = mid, total
        elif mid != mid0:
            raise ChunkError("chunk %d belongs to another message" % seq)
        elif total != total0:
            raise ChunkError("chunk %d: total %d != %d" % (seq, total, total0))
        if seq < len(parts):
            raise ChunkError("duplicate chunk %d" % seq)
        if seq > len(parts):
            raise ChunkError("out-of-order or missing chunk: got %d, expected %d" % (seq, len(parts)))
        if len(parts) == total0:
            raise ChunkError("extra chunk after the last one")
        parts.append(p)
    if mid0 is None:
        raise ChunkError("no chunks")
    if len(parts) != total0:
        raise ChunkError("missing chunks: got %d of %d" % (len(parts), total0))
    message = b"".join(parts)
    if msg_id(message) != mid0:
        raise ChunkError("message integrity check failed (msg_id)")
    return message


def frame_message(message: bytes, size: int = DEFAULT_CHUNK, port: int = 0) -> bytes:
    return b"".join(encode(c, port=port) for c in chunk(message, size))


def unframe_message(stream: bytes) -> bytes:
    return reassemble(d for (_p, cmd, d) in decode(stream) if cmd == CMD_DATA)


# ------------------------------------------------------------------------- strip
class StripRefused(ValueError):
    """Something identifying is still present after redaction; nothing may be framed."""


TRACKING_PARAMS = re.compile(
    r"^(utm_[a-z0-9_]*|fbclid|gclid|dclid|gbraid|wbraid|msclkid|yclid|igshid|twclid|ttclid|li_fat_id|"
    r"mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|_ga|_gl|oly_anon_id|oly_enc_id|vero_id|s_cid|spm)$", re.I)
TRACKING_HEADERS = re.compile(
    r"(?im)^[ \t]*(x-forwarded-for|x-real-ip|x-client-ip|forwarded|via|true-client-ip|cf-connecting-ip|"
    r"x-cluster-client-ip|client-ip|referer|referrer|cookie|set-cookie|user-agent|x-request-id|"
    r"x-amzn-trace-id|x-tracking-id|x-device-id|dnt|x-originating-ip)[ \t]*:[^\r\n]*")
PIXEL = re.compile(
    r"(?is)<img\b(?=[^>]*\b(?:width\s*=\s*['\"]?[01]\b|height\s*=\s*['\"]?[01]\b|"
    r"src\s*=\s*['\"]?[^'\" >]*(?:pixel|beacon|track|/tr\?|/collect\?|open\.gif)))[^>]*>")
URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*)://([^\s<>\"'`)]+)")
EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@([a-z0-9-]+\.)+[a-z]{2,63}\b")
IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])")
IPV6_CAND = re.compile(r"(?i)\[?(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f.:]*(?:%[a-z0-9._-]+)?\]?")
# Bare host names: labels + a letter TLD, minus common file extensions (README.md, a.tar.gz).
FILE_EXT = {"md", "txt", "json", "jsonl", "py", "sh", "gpg", "age", "asc", "kiss", "log", "csv", "png", "jpg",
            "jpeg", "gif", "pdf", "html", "htm", "js", "mjs", "ts", "yml", "yaml", "toml", "tar", "gz", "zip",
            "bundle", "pub", "key", "rev", "c", "h", "rs", "go", "lock", "ini", "cfg", "conf", "xml", "svg"}
HOSTNAME = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63})(?![\w-])\.?")
LOCALHOST = re.compile(r"(?i)\blocalhost\b")
RESIDUAL = [
    ("tracking parameter", re.compile(r"(?i)\b(utm_[a-z]|fbclid|gclid|msclkid|dclid|gbraid|wbraid)")),
    ("integer/hex IP in URL", re.compile(r"(?i)://(?:0x[0-9a-f]{6,8}|\d{8,10})(?![\w.])")),
    ("tracking header", re.compile(TRACKING_HEADERS.pattern.replace(r"[ \t]*:[^\r\n]*", r"[ \t]*:(?![ \t]*\[redacted\][ \t]*$)"))),
    ("tracking pixel", PIXEL),
]


def _is_ipv6(tok: str) -> bool:
    t = tok.strip("[]").split("%", 1)[0]
    if t.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(t)
        return True
    except ValueError:
        return False


def _redact_ipv6(text: str, counts: dict) -> str:
    def sub(m):
        if _is_ipv6(m.group(0)):
            counts["ipv6"] = counts.get("ipv6", 0) + 1
            return "[ip]"
        return m.group(0)
    return IPV6_CAND.sub(sub, text)


def _clean_url(m, counts: dict) -> str:
    scheme, rest = m.group(1), m.group(2)
    trail = ""
    while rest and rest[-1] in ".,;:!?":
        trail, rest = rest[-1] + trail, rest[:-1]
    parts = urllib.parse.urlsplit("%s://%s" % (scheme, rest))
    host_redacted = "[host]" if parts.netloc else ""
    if parts.netloc:
        counts["host"] = counts.get("host", 0) + 1
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    kept = [(k, v) for (k, v) in q if not TRACKING_PARAMS.match(k)]
    if len(kept) != len(q):
        counts["tracking_param"] = counts.get("tracking_param", 0) + len(q) - len(kept)
    query = urllib.parse.urlencode(kept)
    out = "%s://%s%s" % (scheme.lower(), host_redacted, parts.path)
    if query:
        out += "?" + query
    return out + trail  # fragment dropped: it can carry tracking ids too


def scan(text: str) -> List[str]:
    """Kinds of identifying data present in text (used to refuse after redaction)."""
    found = []
    for t in (text, urllib.parse.unquote(text)):
        if IPV4.search(t):
            found.append("ipv4")
        if any(_is_ipv6(m.group(0)) for m in IPV6_CAND.finditer(t)):
            found.append("ipv6")
        for kind, rx in RESIDUAL:
            if rx.search(t):
                found.append(kind)
        if URL.search(t) and any(u.group(2).split("/", 1)[0] not in ("[host]", "") for u in URL.finditer(t)):
            found.append("url host")
        if EMAIL.search(t):
            found.append("email")
        for h in HOSTNAME.finditer(t):
            if h.group(1).lower() not in FILE_EXT:
                found.append("hostname")
                break
        if LOCALHOST.search(t):
            found.append("hostname")
    return sorted(set(found))


def strip(text: str) -> Tuple[str, dict]:
    """Redact identifying data, then refuse (StripRefused) if anything is left.

    Order: tracking headers -> tracking pixels -> URLs (host replaced, userinfo,
    tracking params and fragment dropped) -> e-mail addresses -> IPv4 -> IPv6 ->
    bare hostnames. Then scan() runs on the result AND on its percent-decoded form;
    any hit raises StripRefused, so nothing half-cleaned is ever framed.
    Returns (clean_text, counts per kind).
    """
    counts: dict = {}

    def count(kind, rx, repl, s):
        n = len(rx.findall(s))
        if n:
            counts[kind] = counts.get(kind, 0) + n
        return rx.sub(repl, s)

    s = TRACKING_HEADERS.sub(lambda m: m.group(1) + ": [redacted]", text)
    if s != text:
        counts["tracking_header"] = len(TRACKING_HEADERS.findall(text))
    s = count("tracking_pixel", PIXEL, "[pixel]", s)
    s = URL.sub(lambda m: _clean_url(m, counts), s)
    s = count("email", EMAIL, "[email]", s)
    s = count("ipv4", IPV4, "[ip]", s)
    s = _redact_ipv6(s, counts)

    def host_sub(m):
        if m.group(1).lower() in FILE_EXT:
            return m.group(0)
        counts["hostname"] = counts.get("hostname", 0) + 1
        return "[host]"
    s = HOSTNAME.sub(host_sub, s)
    s = count("hostname", LOCALHOST, "[host]", s)
    left = scan(s)
    if left:
        raise StripRefused("refusing to frame: still present after redaction: " + ", ".join(left))
    return s, counts


# ---------------------------------------------------------- encrypted payload check
def looks_encrypted(data: bytes) -> bool:
    """True for age or OpenPGP *encrypted* data (what PR #9 exports)."""
    if data.startswith(b"age-encryption.org/v1\n") or data.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"):
        return True
    if data.startswith(b"-----BEGIN PGP MESSAGE-----"):
        return True
    if not data:
        return False
    b = data[0]
    if b & 0x80 == 0:
        return False
    tag = (b & 0x3F) if b & 0x40 else ((b >> 2) & 0x0F)
    return tag in (1, 3)  # PKESK or SKESK starts an encrypted OpenPGP message


# ------------------------------------------------------------ LoRa airtime budget
def lora_airtime_ms(payload: int, sf: int = 7, bw_hz: int = 125000, cr: int = 1, preamble: int = 8,
                    explicit_header: bool = True, crc: bool = True, low_dr_opt: Optional[bool] = None) -> float:
    """Semtech SX127x time-on-air formula (AN1200.13). cr: 1..4 for 4/5..4/8."""
    tsym = (2 ** sf) / bw_hz * 1000.0
    de = (tsym > 16.0) if low_dr_opt is None else low_dr_opt
    ih = 0 if explicit_header else 1
    num = 8 * payload - 4 * sf + 28 + (16 if crc else 0) - 20 * ih
    n = 8 + max(math.ceil(num / (4 * (sf - 2 * (1 if de else 0)))) * (cr + 4), 0)
    return (preamble + 4.25) * tsym + n * tsym


# ---------------------------------------------------------------- simulated link
class SimulatedLink:
    """In-memory lossy link (no I/O): drops, duplicates, reorders and flips bits."""

    def __init__(self, loss=0.0, dup=0.0, reorder=0.0, flip=0.0, seed=0):
        self.loss, self.dup, self.reorder, self.flip = loss, dup, reorder, flip
        self.rng = random.Random(seed)

    def send(self, frames: List[bytes]) -> List[bytes]:
        out = []
        for f in frames:
            if self.rng.random() < self.loss:
                continue
            g = bytearray(f)
            if self.rng.random() < self.flip and len(g) > 2:
                i = self.rng.randrange(1, len(g) - 1)
                g[i] ^= 1 << self.rng.randrange(8)
            out.append(bytes(g))
            if self.rng.random() < self.dup:
                out.append(bytes(g))
        for i in range(len(out) - 1):
            if self.rng.random() < self.reorder:
                out[i], out[i + 1] = out[i + 1], out[i]
        return out


# --------------------------------------------------------------------------- CLI
def _write_kiss(path: str, data: bytes) -> None:
    if not path.endswith(".kiss"):
        raise SystemExit("kiss_frame: --out must end in .kiss (this tool writes .kiss files only)")
    if os.path.lexists(path):
        raise SystemExit("kiss_frame: refusing to overwrite %s" % path)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".kiss.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, path)  # no-clobber publish
    finally:
        os.unlink(tmp)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline KISS framing for the Non-IP Mesh. Transmits nothing; "
                                             "writes .kiss files only.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("frame", help="chunk + KISS-frame a payload into a .kiss file")
    f.add_argument("--in", dest="inp", required=True)
    f.add_argument("--out", required=True, help="output path ending in .kiss (never overwritten)")
    g = f.add_mutually_exclusive_group(required=True)
    g.add_argument("--encrypted", action="store_true", help="payload is a PR #9 age/gpg encrypted bundle")
    g.add_argument("--text", action="store_true", help="UTF-8 text: run strip() first, refuse if anything is left")
    f.add_argument("--require-clean", action="store_true",
                   help="with --text: refuse if strip() would change anything (use for signed files)")
    f.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)
    f.add_argument("--port", type=int, default=0)
    c = sub.add_parser("check", help="decode + reassemble a .kiss file; print a JSON report, write nothing")
    c.add_argument("--in", dest="inp", required=True)
    s = sub.add_parser("strip-check", help="print what strip() would redact or refuse; write nothing")
    s.add_argument("--in", dest="inp", required=True)
    a = ap.parse_args(argv)
    with open(a.inp, "rb") as fh:
        data = fh.read()
    try:
        if a.cmd == "frame":
            if a.encrypted:
                if not looks_encrypted(data):
                    raise SystemExit("kiss_frame: --encrypted input is not age/OpenPGP encrypted data; refusing")
                payload = data
            else:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise SystemExit("kiss_frame: --text input is not UTF-8; refusing")
                clean, counts = strip(text)
                if a.require_clean and clean != text:
                    raise SystemExit("kiss_frame: --require-clean: strip() would redact %s; refusing" % counts)
                payload = clean.encode("utf-8")
            _write_kiss(a.out, frame_message(payload, a.chunk_size, a.port))
            print(json.dumps({"wrote": a.out, "bytes": len(payload), "chunks": len(chunk(payload, a.chunk_size)),
                              "sha256": hashlib.sha256(payload).hexdigest()}))
        elif a.cmd == "check":
            msg = unframe_message(data)
            print(json.dumps({"ok": True, "bytes": len(msg), "sha256": hashlib.sha256(msg).hexdigest()}))
        else:
            clean, counts = strip(data.decode("utf-8"))
            print(json.dumps({"ok": True, "redactions": counts}))
    except (KissError, ChunkError, StripRefused, ValueError) as e:
        print("kiss_frame: FAIL: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
