#!/usr/bin/env python3
"""Isolated security regression checks for the GitMesh console and source sync."""

import base64
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "gitmesh-ultimate-core.mjs"
SYNC = ROOT / "sync-public-source.mjs"
INITIAL_SIGIL = "fixture-admin-sigil-one"
CUSTOM_SIGIL = "fixture-admin-sigil-custom"
FAKE_GITHUB_TOKEN = "test-only-not-a-real-token"
ALLOWED_GITHUB_PATHS = {
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
}


def drive_console(workdir, steps, timeout=30):
    """Drive a fresh console process through a PTY without echoing sigils."""
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(workdir)
        os.execvp("node", ["node", str(workdir / CONSOLE.name)])

    output = bytearray()
    cursor = 0
    try:
        for prompt, response in steps:
            deadline = time.monotonic() + timeout
            prompt_bytes = prompt.encode()
            while prompt_bytes not in output[cursor:]:
                if time.monotonic() >= deadline:
                    raise AssertionError(f"Timed out waiting for prompt: {prompt!r}")
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        chunk = b""
                    if chunk:
                        output.extend(chunk)
                    else:
                        break
                ended, status = os.waitpid(pid, os.WNOHANG)
                if ended:
                    pid = 0
                    raise AssertionError(
                        f"Console exited before prompt {prompt!r}; status={status}"
                    )
            cursor = output.find(prompt_bytes, cursor) + len(prompt_bytes)
            os.write(master, response.encode() + b"\r")

        deadline = time.monotonic() + timeout
        while pid:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                pid = 0
                break
            if time.monotonic() >= deadline:
                raise AssertionError("Timed out waiting for the console to exit.")
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
        exit_code = os.waitstatus_to_exitcode(status)
        return exit_code, output.decode(errors="replace")
    finally:
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        os.close(master)


class SigilRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gitmesh-auth-test-")
        self.workdir = pathlib.Path(self.temp.name)
        shutil.copy2(CONSOLE, self.workdir / CONSOLE.name)
        self.auth_path = self.workdir / "SovereignMeshVault" / "active_sigil.hash"

    def tearDown(self):
        self.temp.cleanup()

    def enter(self, sigil, saved=True, menu_choice="0", extra_steps=None):
        steps = [
            ("Current admin sigil (hidden): ", sigil),
            ("Type SAVED to activate it and open the console: ", "SAVED" if saved else "NO"),
        ]
        if saved:
            if extra_steps:
                steps.extend(extra_steps)
            steps.append(("Select: ", menu_choice))
        return drive_console(self.workdir, steps)

    def reject(self, sigil):
        return drive_console(
            self.workdir,
            [("Current admin sigil (hidden): ", sigil)],
        )

    def test_rotation_failure_recovery_and_never_reuses_active_sigil(self):
        code, output = drive_console(
            self.workdir,
            [
                ("New admin sigil: ", INITIAL_SIGIL),
                ("Confirm admin sigil: ", INITIAL_SIGIL),
                ("Select: ", "0"),
            ],
        )
        self.assertEqual(code, 0)
        initial_bytes = self.auth_path.read_bytes()
        self.assertNotIn(INITIAL_SIGIL.encode(), initial_bytes)
        self.assertEqual(stat.S_IMODE(self.auth_path.stat().st_mode), 0o600)

        code, output = self.reject("wrong-fixture-sigil")
        self.assertNotEqual(code, 0)
        self.assertIn("Access denied.", output)
        self.assertEqual(self.auth_path.read_bytes(), initial_bytes)

        code, output = self.enter(INITIAL_SIGIL)
        self.assertEqual(code, 0)
        self.assertNotIn(INITIAL_SIGIL, output)
        first_rotation = re.search(r"gm-1-[A-Za-z0-9_-]{43}", output)
        self.assertIsNotNone(first_rotation, "A fresh first-generation sigil was not issued.")
        first_active = first_rotation.group(0)
        first_bytes = self.auth_path.read_bytes()
        first_auth = json.loads(first_bytes)
        self.assertEqual(first_auth["generation"], 1)
        self.assertEqual(first_auth["usedSigilHashes"], [hashlib.sha256(INITIAL_SIGIL.encode()).hexdigest()])
        self.assertNotIn(first_active.encode(), first_bytes)

        code, output = self.reject(INITIAL_SIGIL)
        self.assertNotEqual(code, 0)
        self.assertIn("Access denied.", output)
        self.assertEqual(self.auth_path.read_bytes(), first_bytes)

        code, output = self.enter(first_active, saved=False)
        self.assertNotEqual(code, 0)
        self.assertIn("Rotation cancelled.", output)
        second_candidate = re.search(r"gm-2-[A-Za-z0-9_-]{43}", output)
        self.assertIsNotNone(second_candidate, "Cancellation path did not issue a replacement.")
        self.assertEqual(self.auth_path.read_bytes(), first_bytes)

        code, output = self.enter(first_active)
        self.assertEqual(code, 0)
        second_active_match = re.search(r"gm-2-[A-Za-z0-9_-]{43}", output)
        self.assertIsNotNone(second_active_match, "Retry did not issue the next-generation sigil.")
        second_active = second_active_match.group(0)
        self.assertNotEqual(first_active, second_active)
        second_bytes = self.auth_path.read_bytes()
        second_auth = json.loads(second_bytes)
        self.assertEqual(second_auth["generation"], 2)
        self.assertEqual(
            second_auth["usedSigilHashes"],
            [
                hashlib.sha256(INITIAL_SIGIL.encode()).hexdigest(),
                hashlib.sha256(first_active.encode()).hexdigest(),
            ],
        )
        self.assertNotIn(second_active.encode(), second_bytes)

        code, output = self.enter(
            second_active,
            extra_steps=[
                ("Select: ", "5"),
                ("New admin sigil: ", CUSTOM_SIGIL),
                ("Confirm new admin sigil: ", CUSTOM_SIGIL),
            ],
        )
        self.assertEqual(code, 0)
        self.assertIn("Admin sigil updated.", output)
        self.assertNotIn(CUSTOM_SIGIL, output)
        third_auto_match = re.search(r"gm-3-[A-Za-z0-9_-]{43}", output)
        self.assertIsNotNone(third_auto_match, "Sign-in did not rotate before the manual key change.")
        third_auto = third_auto_match.group(0)
        custom_bytes = self.auth_path.read_bytes()
        custom_auth = json.loads(custom_bytes)
        self.assertEqual(custom_auth["generation"], 3)
        self.assertEqual(
            custom_auth["usedSigilHashes"],
            [
                hashlib.sha256(INITIAL_SIGIL.encode()).hexdigest(),
                hashlib.sha256(first_active.encode()).hexdigest(),
                hashlib.sha256(second_active.encode()).hexdigest(),
                hashlib.sha256(third_auto.encode()).hexdigest(),
            ],
        )
        self.assertEqual(
            custom_auth["usedSigilHashes"][-1],
            hashlib.sha256(third_auto.encode()).hexdigest(),
        )
        self.assertNotIn(CUSTOM_SIGIL.encode(), custom_bytes)
        self.assertEqual(stat.S_IMODE(self.auth_path.stat().st_mode), 0o600)

        for retired in (INITIAL_SIGIL, first_active, second_active):
            code, output = self.reject(retired)
            self.assertNotEqual(code, 0)
            self.assertIn("Access denied.", output)
            self.assertEqual(self.auth_path.read_bytes(), custom_bytes)


class GitHubSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gitmesh-sync-test-")
        self.temp_path = pathlib.Path(self.temp.name)
        self.capture = self.temp_path / "requests.json"
        self.preload = self.temp_path / "mock-github.mjs"
        self.preload.write_text(
            """
import fs from "node:fs";
const requests = [];
const capture = process.env.GITMESH_TEST_CAPTURE;
const base = "/repos/vitalitychems-dot/GitMesh";
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input));
  const method = init.method ?? "GET";
  const body = init.body ? JSON.parse(init.body) : null;
  requests.push({
    path: url.pathname,
    method,
    body,
    hasExpectedBearer: init.headers?.Authorization === "Bearer " + process.env.GITHUB_TOKEN,
  });
  let data;
  if (method === "GET" && url.pathname === base + "/git/ref/heads/main") {
    data = { object: { sha: "a".repeat(40) } };
  } else if (method === "GET" && url.pathname === base + "/git/commits/" + "a".repeat(40)) {
    data = { tree: { sha: "b".repeat(40) } };
  } else if (method === "POST" && url.pathname === base + "/git/blobs") {
    data = { sha: "1".repeat(40) };
  } else if (method === "POST" && url.pathname === base + "/git/trees") {
    data = { sha: "c".repeat(40) };
  } else if (method === "POST" && url.pathname === base + "/git/commits") {
    data = { sha: "d".repeat(40) };
  } else if (method === "PATCH" && url.pathname === base + "/git/refs/heads/main") {
    data = { object: { sha: body.sha } };
  } else {
    throw new Error("Unexpected mocked GitHub request.");
  }
  fs.writeFileSync(capture, JSON.stringify(requests));
  return { ok: true, status: 200, json: async () => data };
};
process.on("exit", () => fs.writeFileSync(capture, JSON.stringify(requests)));
""".strip()
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_sync(self, with_token=True):
        env = os.environ.copy()
        env["GITMESH_TEST_CAPTURE"] = str(self.capture)
        if with_token:
            env["GITHUB_TOKEN"] = FAKE_GITHUB_TOKEN
        else:
            env.pop("GITHUB_TOKEN", None)
        return subprocess.run(
            ["node", "--import", str(self.preload), str(SYNC)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_sync_publishes_only_the_fixed_source_allowlist(self):
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, "Mocked source sync did not complete.")
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        requests = json.loads(self.capture.read_text())
        self.assertTrue(all(request["hasExpectedBearer"] for request in requests))
        tree_calls = [request for request in requests if request["path"].endswith("/git/trees")]
        self.assertEqual(len(tree_calls), 1)
        tree_items = tree_calls[0]["body"]["tree"]
        uploaded_paths = {item["path"] for item in tree_items}
        self.assertEqual(uploaded_paths, ALLOWED_GITHUB_PATHS)
        self.assertTrue(all(item["mode"] == "100644" and item["type"] == "blob" for item in tree_items))

        uploaded_contents = {
            base64.b64decode(request["body"]["content"])
            for request in requests
            if request["method"] == "POST" and request["path"].endswith("/git/blobs")
        }
        expected_contents = {
            (ROOT / source).read_bytes()
            for source in (
                "gitmesh-ultimate-core.mjs",
                "README.md",
                "sync-public-source.mjs",
            )
        }
        self.assertEqual(uploaded_contents, expected_contents)
        self.assertEqual(len(uploaded_contents), 3)
        self.assertFalse(any("SovereignMeshVault" in item["path"] for item in tree_items))

    def test_missing_secret_fails_before_any_github_request(self):
        result = self.run_sync(with_token=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set GITHUB_TOKEN through Replit Secrets", result.stderr)
        requests = json.loads(self.capture.read_text())
        self.assertEqual(requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
