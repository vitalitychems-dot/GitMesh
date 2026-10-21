"""Tests for tools/kiss_frame.py. Offline only: no sockets, serial ports or radios.

Run: python3 -m unittest discover -s tests -v
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(os.path.dirname(HERE), "tools")
sys.path.insert(0, TOOLS)
import kiss_frame as k  # noqa: E402


class TestKiss(unittest.TestCase):
    def test_roundtrip_with_fend_fesc(self):
        data = bytes([0xC0, 0xDB, 0xDC, 0xDD, 0xC0, 0xC0, 0xDB, 0xDB, 0x00, 0xFF])
        f = k.encode(data, port=3)
        self.assertEqual(f[0], k.FEND)
        self.assertEqual(f[-1], k.FEND)
        self.assertNotIn(k.FEND, f[1:-1], "no raw FEND inside a frame")
        self.assertEqual(k.decode(f), [(3, 0, data)])

    def test_escape_bytes_exact(self):
        self.assertEqual(k.encode(b"\xc0", 0), b"\xc0\x00\xdb\xdc\xc0")
        self.assertEqual(k.encode(b"\xdb", 0), b"\xc0\x00\xdb\xdd\xc0")

    def test_type_byte_escaped_when_needed(self):
        # port 12, cmd 0 -> type byte 0xC0, which must itself be escaped
        f = k.encode(b"x", port=12)
        self.assertEqual(k.decode(f), [(12, 0, b"x")])

    def test_multiple_and_empty_frames(self):
        s = k.encode(b"a") + b"\xc0\xc0" + k.encode(b"b", 1)
        self.assertEqual(k.decode(s), [(0, 0, b"a"), (1, 0, b"b")])

    def test_bad_streams(self):
        for bad in (b"\xc0\x00\xdb\x41\xc0", b"\xc0\x00abc", b"abc\xc0", b"\xc0\x00\xdb\xc0"):
            with self.assertRaises(k.KissError, msg=bad):
                k.decode(bad)

    def test_bad_port(self):
        with self.assertRaises(ValueError):
            k.encode(b"x", port=16)

    def test_fuzz_random_payloads(self):
        rng = random.Random(1337)
        for _ in range(500):
            n = rng.randrange(0, 600)
            # bias towards FEND/FESC so escaping is exercised heavily
            data = bytes(rng.choice((0xC0, 0xDB, 0xDC, 0xDD, rng.randrange(256))) for _ in range(n))
            port = rng.randrange(16)
            self.assertEqual(k.decode(k.encode(data, port)), [(port, 0, data)] if data or True else [])


class TestChunks(unittest.TestCase):
    def msg(self, n=1000, seed=7):
        return random.Random(seed).randbytes(n)

    def test_roundtrip_and_mtu(self):
        m = self.msg(1000)
        cs = k.chunk(m)
        self.assertEqual(len(cs), 5)
        self.assertTrue(all(len(c) <= k.LORA_MAX_PAYLOAD for c in cs))
        self.assertEqual(k.reassemble(cs), m)
        self.assertEqual(k.unframe_message(k.frame_message(m)), m)

    def test_empty_message(self):
        self.assertEqual(k.reassemble(k.chunk(b"")), b"")

    def test_mtu_enforced(self):
        with self.assertRaises(ValueError):
            k.chunk(b"x", size=k.LORA_MAX_PAYLOAD - k.HEADER_LEN + 1)

    def test_fuzz_sizes(self):
        rng = random.Random(42)
        for _ in range(200):
            m = rng.randbytes(rng.randrange(0, 3000))
            size = rng.randrange(1, 207)
            self.assertEqual(k.unframe_message(k.frame_message(m, size)), m)

    def test_tamper_payload_detected(self):
        cs = k.chunk(self.msg())
        for i in (k.HEADER_LEN, k.HEADER_LEN + 50, len(cs[2]) - 1):
            bad = bytearray(cs[2]); bad[i] ^= 0x01
            with self.assertRaisesRegex(k.ChunkError, "sha256 mismatch"):
                k.reassemble(cs[:2] + [bytes(bad)] + cs[3:])

    def test_tamper_header_detected(self):
        cs = k.chunk(self.msg())
        bad = bytearray(cs[0]); bad[0] ^= 0xFF
        with self.assertRaisesRegex(k.ChunkError, "magic"):
            k.reassemble([bytes(bad)] + cs[1:])
        with self.assertRaisesRegex(k.ChunkError, "length|shorter"):
            k.reassemble([cs[0][:-1]] + cs[1:])

    def test_consistent_forgery_caught_by_msg_id(self):
        # Replace a chunk with a self-consistent one (own sha256 fixed up): the
        # whole-message check still fails.
        m = self.msg()
        cs = k.chunk(m)
        mid, seq, total, p = k.parse_chunk(cs[1])
        p2 = bytes([p[0] ^ 1]) + p[1:]
        forged = k.HEADER.pack(k.MAGIC, k.VERSION, mid, seq, total, len(p2), hashlib.sha256(p2).digest()) + p2
        with self.assertRaisesRegex(k.ChunkError, "integrity"):
            k.reassemble([cs[0], forged] + cs[2:])

    def test_missing_duplicate_order_extra_foreign(self):
        cs = k.chunk(self.msg())
        with self.assertRaisesRegex(k.ChunkError, "missing chunks"):
            k.reassemble(cs[:-1])
        with self.assertRaisesRegex(k.ChunkError, "out-of-order or missing"):
            k.reassemble(cs[:1] + cs[2:])
        with self.assertRaisesRegex(k.ChunkError, "duplicate"):
            k.reassemble(cs[:2] + cs[1:])
        with self.assertRaisesRegex(k.ChunkError, "out-of-order"):
            k.reassemble([cs[1], cs[0]] + cs[2:])
        other = k.chunk(self.msg(seed=8))
        with self.assertRaisesRegex(k.ChunkError, "another message"):
            k.reassemble(cs[:2] + other[2:3] + cs[3:])
        with self.assertRaisesRegex(k.ChunkError, "no chunks"):
            k.reassemble([])


class TestStrip(unittest.TestCase):
    def test_redacts_everything(self):
        src = ("GET https://user:pw@tracker.example.com/a?utm_source=x&id=3&fbclid=9&gclid=8#frag\n"
               "peer 192.168.1.20:4242 and [2001:db8::1]:80 and fe80::1%eth0 and 200:1234::5\n"
               "X-Forwarded-For: 10.0.0.1\nUser-Agent: curl/8\n"
               '<img src="https://px.example.net/open.gif" width="1" height="1">\n'
               "mail ops@example.org, host node7.mesh.example.\n"
               "keep README.md, a.tar.gz, 12:30:45 and v1.2.3\n")
        clean, counts = k.strip(src)
        for leak in ("user", "pw@", "tracker", "utm_", "fbclid", "gclid", "frag", "192.168", "2001:db8", "fe80",
                     "200:1234", "10.0.0.1", "curl", "px.example", "ops@", "node7", "example"):
            self.assertNotIn(leak, clean, leak)
        for keep in ("id=3", "README.md", "a.tar.gz", "12:30:45", "v1.2.3", "X-Forwarded-For: [redacted]"):
            self.assertIn(keep, clean, keep)
        self.assertEqual(k.scan(clean), [])
        self.assertGreaterEqual(counts["ipv6"], 3)

    def test_refuses_leftovers(self):
        for bad in ("see utm%5Fsource=1", "x fbclid", "go https%3A%2F%2F10.0.0.1%2F"):
            with self.assertRaises(k.StripRefused, msg=bad):
                k.strip(bad)

    def test_clean_text_unchanged(self):
        t = "name t1, sha256 ab12, time 2026-10-21T21:36:57Z, file t1.bundle.gpg"
        self.assertEqual(k.strip(t), (t, {}))


class TestLossyLink(unittest.TestCase):
    def test_loss_is_detected_and_arq_recovers(self):
        """A lossy, duplicating, reordering, bit-flipping link never yields a wrong
        message; a simple stop-and-wait resend loop (simulated) always completes."""
        rng = random.Random(99)
        m = rng.randbytes(4000)
        frames = [k.encode(c) for c in k.chunk(m)]
        link = k.SimulatedLink(loss=0.2, dup=0.1, reorder=0.1, flip=0.05, seed=5)
        # 1. one-shot over the lossy link: either exact, or rejected; never wrong
        rejected = 0
        for _ in range(50):
            got = b"".join(link.send(frames))
            try:
                self.assertEqual(k.unframe_message(got), m)
            except (k.ChunkError, k.KissError):
                rejected += 1
        self.assertGreater(rejected, 0)
        # 2. stop-and-wait ARQ: send chunk i until a valid chunk i arrives
        accepted, sends = [], 0
        for i, f in enumerate(frames):
            while True:
                sends += 1
                self.assertLess(sends, 10000)
                for rx in link.send([f]):
                    try:
                        frs = k.decode(rx)
                        if len(frs) != 1:
                            continue
                        _mid, seq, _t, _p = k.parse_chunk(frs[0][2])
                    except (k.KissError, k.ChunkError):
                        continue
                    if seq == i:
                        accepted.append(frs[0][2])
                        break
                else:
                    continue
                break
        self.assertEqual(k.reassemble(accepted), m)


class TestAirtimeAndEncrypted(unittest.TestCase):
    def test_airtime_known_value(self):
        # 249-byte frame at SF7/125 kHz/CR4/5: ~389 ms, under the 400 ms FHSS dwell limit
        self.assertAlmostEqual(k.lora_airtime_ms(249, 7, 125000), 389.4, delta=1.0)
        self.assertGreater(k.lora_airtime_ms(249, 9, 125000), 400)

    def test_looks_encrypted(self):
        self.assertTrue(k.looks_encrypted(b"age-encryption.org/v1\n-> X25519 abc"))
        self.assertTrue(k.looks_encrypted(b"\x85\x01\x0c\x03"))   # old-format PKESK
        self.assertTrue(k.looks_encrypted(b"\xc1\x4c\x03"))       # new-format PKESK
        self.assertFalse(k.looks_encrypted(b"plain text"))
        self.assertFalse(k.looks_encrypted(b""))


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(TOOLS, "kiss_frame.py"), *args],
                              capture_output=True, text=True)

    def test_cli_frame_check_and_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            enc = os.path.join(d, "b.bundle.age")
            with open(enc, "wb") as f:
                f.write(b"age-encryption.org/v1\n" + random.Random(3).randbytes(3000))
            out = os.path.join(d, "b.kiss")
            r = self.run_cli("frame", "--in", enc, "--out", out, "--encrypted")
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.run_cli("check", "--in", out)
            self.assertEqual(json.loads(r.stdout)["bytes"], 3022)
            self.assertNotEqual(self.run_cli("frame", "--in", enc, "--out", out, "--encrypted").returncode, 0)  # no overwrite
            self.assertNotEqual(self.run_cli("frame", "--in", enc, "--out", os.path.join(d, "x.bin"), "--encrypted").returncode, 0)
            txt = os.path.join(d, "t.txt")
            with open(txt, "w") as f:
                f.write("peer 10.1.2.3 via https://h.example.com/?utm_source=a\n")
            self.assertNotEqual(self.run_cli("frame", "--in", txt, "--out", os.path.join(d, "t0.kiss"), "--encrypted").returncode, 0)
            self.assertNotEqual(self.run_cli("frame", "--in", txt, "--out", os.path.join(d, "t1.kiss"), "--text", "--require-clean").returncode, 0)
            self.assertEqual(self.run_cli("frame", "--in", txt, "--out", os.path.join(d, "t2.kiss"), "--text").returncode, 0)
            with open(txt, "w") as f:
                f.write("utm%5Fsource leftover\n")
            r = self.run_cli("frame", "--in", txt, "--out", os.path.join(d, "t3.kiss"), "--text")
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(os.path.exists(os.path.join(d, "t3.kiss")))
            self.assertEqual(sorted(x for x in os.listdir(d) if x.endswith(".kiss")), ["b.kiss", "t2.kiss"])


if __name__ == "__main__":
    unittest.main()
