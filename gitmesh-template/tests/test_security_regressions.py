#!/usr/bin/env python3
"""Isolated security regression checks for the GitMesh console and source sync."""

import base64
from collections import Counter
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
FAKE_REQUEST_BODY = "MOCK_REQUEST_BODY_SENTINEL"
FAKE_AUTHORIZATION = f"Bearer {FAKE_GITHUB_TOKEN}"
ALLOWED_GITHUB_PATHS = {
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
}
ALLOWED_SOURCE_NAMES = (
    "gitmesh-ultimate-core.mjs",
    "README.md",
    "sync-public-source.mjs",
)


def reported_changed_paths(output):
    lines = output.splitlines()
    try:
        start = lines.index("Changed files:") + 1
    except ValueError:
        return []
    return [line[2:] for line in lines[start:] if line.startswith("- ")]


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
        self.remote_contents = self.temp_path / "remote-contents.json"
        self.preload = self.temp_path / "mock-github.mjs"
        self.source_root = self.temp_path / "isolated-source"
        self.source_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, self.source_root / name)

        # Private sentinels prove the sync process neither reads nor uploads
        # records, credentials, bundles, assets, or arbitrary workspace files.
        private_files = {
            "SovereignMeshVault/active_sigil.hash": b"PRIVATE_SIGIL_FILE_SENTINEL",
            "SovereignMeshVault/security_audit.log": b"PRIVATE_AUDIT_SENTINEL",
            "SovereignMeshVault/ledger_matrix/private-record.json": b"PRIVATE_RECORD_SENTINEL",
            "SovereignMeshVault/bundles_outbound/private.bundle": b"PRIVATE_BUNDLE_SENTINEL",
            "SovereignMeshVault/drops_inbound/incoming.bundle": b"PRIVATE_INBOUND_SENTINEL",
            "attached_assets/private.txt": b"PRIVATE_ASSET_SENTINEL",
            "workspace-private.txt": b"PRIVATE_WORKSPACE_SENTINEL",
        }
        for relative_path, content in private_files.items():
            target = self.source_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        self.remote_contents.write_text("{}")

        self.preload.write_text(
            """
import fs from "node:fs";
import path from "node:path";
const requests = [];
const filesystemReads = [];
const capture = process.env.GITMESH_TEST_CAPTURE;
const remoteContents = JSON.parse(fs.readFileSync(process.env.GITMESH_TEST_REMOTE_CONTENTS, "utf8"));
const base = "/repos/vitalitychems-dot/GitMesh";
for (const name of ["lstatSync", "readFileSync"]) {
  const original = fs[name].bind(fs);
  fs[name] = (target, ...args) => {
    if (typeof target === "string" || target instanceof URL) {
      filesystemReads.push({ method: name, path: path.resolve(String(target)) });
    }
    return original(target, ...args);
  };
}
const saveCapture = () => fs.writeFileSync(
  capture,
  JSON.stringify({ requests, filesystemReads }),
);
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
  const route = url.pathname.slice(base.length);
  const failAt = process.env.GITMESH_TEST_FAIL_AT;
  if (failAt === method + " " + route) {
    saveCapture();
    if (process.env.GITMESH_TEST_FAIL_MODE === "network") {
      throw new Error("mock connection failure " + process.env.GITHUB_TOKEN + " MOCK_REQUEST_BODY_SENTINEL");
    }
    return {
      ok: false,
      status: Number(process.env.GITMESH_TEST_FAIL_STATUS ?? "500"),
      headers: {
        get: name => {
          if (name.toLowerCase() === "retry-after") return process.env.GITMESH_TEST_RETRY_AFTER ?? null;
          if (name.toLowerCase() === "x-ratelimit-remaining") return process.env.GITMESH_TEST_RATE_REMAINING ?? null;
          return null;
        },
      },
      json: async () => ({
        message: "mock failure " + process.env.GITHUB_TOKEN,
        authorization: "Bearer " + process.env.GITHUB_TOKEN,
        requestBody: "MOCK_REQUEST_BODY_SENTINEL",
      }),
    };
  }
  let data;
  if (method === "GET" && url.pathname === base + "/git/ref/heads/main") {
    data = { object: { sha: "a".repeat(40) } };
  } else if (method === "GET" && url.pathname === base + "/git/commits/" + "a".repeat(40)) {
    data = { tree: { sha: "b".repeat(40) } };
  } else if (method === "GET" && url.pathname.startsWith(base + "/contents/")) {
    const target = url.pathname.slice((base + "/contents/").length);
    const remoteEntry = remoteContents[target];
    if (remoteEntry === undefined) {
      saveCapture();
      return { ok: false, status: 404, json: async () => ({ message: "not found" }) };
    }
    if (remoteEntry?.fixture === "oversized") {
      data = {
        type: "file",
        encoding: "base64",
        content: Buffer.alloc(512 * 1024 + 1).toString("base64"),
      };
    } else if (typeof remoteEntry === "string") {
      data = { type: "file", encoding: "base64", content: remoteEntry };
    } else {
      data = remoteEntry;
    }
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
  saveCapture();
  return { ok: true, status: 200, json: async () => data };
};
process.on("exit", saveCapture);
""".strip()
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_sync(
        self,
        token_value=FAKE_GITHUB_TOKEN,
        fail_at=None,
        fail_mode=None,
        fail_status=None,
        retry_after=None,
        rate_remaining=None,
    ):
        env = os.environ.copy()
        env["GITMESH_TEST_CAPTURE"] = str(self.capture)
        env["GITMESH_TEST_REMOTE_CONTENTS"] = str(self.remote_contents)
        if token_value is not None:
            env["GITHUB_TOKEN"] = token_value
        else:
            env.pop("GITHUB_TOKEN", None)
        for key, value in (
            ("GITMESH_TEST_FAIL_AT", fail_at),
            ("GITMESH_TEST_FAIL_MODE", fail_mode),
            ("GITMESH_TEST_FAIL_STATUS", str(fail_status) if fail_status is not None else None),
            ("GITMESH_TEST_RETRY_AFTER", retry_after),
            ("GITMESH_TEST_RATE_REMAINING", rate_remaining),
        ):
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return subprocess.run(
            ["node", "--import", str(self.preload), str(self.source_root / SYNC.name)],
            cwd=self.source_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def assert_safe_failure_output(self, result):
        combined = result.stdout + result.stderr
        for sensitive in (FAKE_GITHUB_TOKEN, FAKE_AUTHORIZATION, FAKE_REQUEST_BODY):
            self.assertNotIn(sensitive, combined)

    def set_remote_snapshot(self, overrides=None):
        contents = {
            f"projects/local-vault/{name}": base64.b64encode(
                (self.source_root / name).read_bytes()
            ).decode("ascii")
            for name in ALLOWED_SOURCE_NAMES
        }
        contents.update(overrides or {})
        self.remote_contents.write_text(json.dumps(contents))

    def test_sync_publishes_only_the_fixed_source_allowlist(self):
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, "Mocked source sync did not complete.")
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        self.assertNotIn(FAKE_AUTHORIZATION, result.stdout + result.stderr)
        reported_paths = reported_changed_paths(result.stdout)
        self.assertEqual(set(reported_paths), ALLOWED_GITHUB_PATHS)
        self.assertEqual(len(reported_paths), len(ALLOWED_GITHUB_PATHS))
        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
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
            (self.source_root / source).read_bytes() for source in ALLOWED_SOURCE_NAMES
        }
        self.assertEqual(uploaded_contents, expected_contents)
        self.assertEqual(len(uploaded_contents), 3)
        self.assertFalse(any("SovereignMeshVault" in item["path"] for item in tree_items))
        self.assertIs(requests[-1]["body"]["force"], False)

        expected_reads = Counter(
            (method, str((self.source_root / source).resolve()))
            for source in ALLOWED_SOURCE_NAMES
            for method in ("lstatSync", "readFileSync")
        )
        observed_reads = Counter(
            (event["method"], event["path"]) for event in capture["filesystemReads"]
        )
        self.assertEqual(observed_reads, expected_reads)
        self.assertFalse(any("SovereignMeshVault" in event["path"] for event in capture["filesystemReads"]))
        for sentinel in (
            b"PRIVATE_SIGIL_FILE_SENTINEL",
            b"PRIVATE_RECORD_SENTINEL",
            b"PRIVATE_BUNDLE_SENTINEL",
            b"PRIVATE_INBOUND_SENTINEL",
            b"PRIVATE_ASSET_SENTINEL",
            b"PRIVATE_WORKSPACE_SENTINEL",
        ):
            self.assertNotIn(sentinel, uploaded_contents)

    def test_unchanged_source_skips_blob_tree_commit_and_branch_update(self):
        self.set_remote_snapshot()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0)
        self.assertIn("already match", result.stdout)
        self.assertIn("no commit created", result.stdout)
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        capture = json.loads(self.capture.read_text())
        self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
        writes = [
            request for request in capture["requests"]
            if request["method"] in ("POST", "PATCH")
        ]
        self.assertEqual(writes, [])
        self.assertEqual(
            sum(request["method"] == "GET" and "/contents/" in request["path"]
                for request in capture["requests"]),
            3,
        )

    def test_malformed_remote_files_stop_before_any_github_write(self):
        target = "projects/local-vault/gitmesh-ultimate-core.mjs"
        malformed_cases = (
            (
                "invalid base64",
                {target: {"type": "file", "encoding": "base64", "content": "@@not-base64!!"}},
                "invalid or oversized source content",
            ),
            (
                "unexpected file type",
                {target: {"type": "symlink", "encoding": "base64", "content": "YQ=="}},
                "invalid source file",
            ),
            (
                "oversized remote file",
                {target: {"fixture": "oversized"}},
                "invalid or oversized source content",
            ),
        )
        for case_name, overrides, expected_error in malformed_cases:
            with self.subTest(case=case_name):
                self.set_remote_snapshot(overrides)
                result = self.run_sync()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
                writes = [
                    request for request in capture["requests"]
                    if request["method"] in ("POST", "PATCH")
                ]
                self.assertEqual(writes, [])

    def test_changed_source_updates_only_the_changed_allowlisted_file(self):
        self.set_remote_snapshot()
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nLocal-only regression marker.\n")
        result = self.run_sync()
        self.assertEqual(result.returncode, 0)
        self.assertIn("Synced 1 changed allowlisted source files", result.stdout)
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        self.assertNotIn(FAKE_AUTHORIZATION, result.stdout + result.stderr)
        self.assertEqual(
            reported_changed_paths(result.stdout),
            ["projects/local-vault/README.md"],
        )
        capture = json.loads(self.capture.read_text())
        blobs = [
            request for request in capture["requests"]
            if request["method"] == "POST" and request["path"].endswith("/git/blobs")
        ]
        self.assertEqual(len(blobs), 1)
        self.assertEqual(
            base64.b64decode(blobs[0]["body"]["content"]),
            readme.read_bytes(),
        )
        tree_updates = [
            request for request in capture["requests"]
            if request["method"] == "POST" and request["path"].endswith("/git/trees")
        ]
        self.assertEqual(len(tree_updates), 1)
        self.assertEqual(
            [item["path"] for item in tree_updates[0]["body"]["tree"]],
            ["projects/local-vault/README.md"],
        )
        self.assertIs(capture["requests"][-1]["body"]["force"], False)

    def test_missing_secret_fails_before_any_github_request(self):
        result = self.run_sync(token_value=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set GITHUB_TOKEN through Replit Secrets", result.stderr)
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["filesystemReads"], [])

    def test_malformed_credentials_fail_before_reading_sources_or_requesting_github(self):
        for bad_value in ("", "bad\ntoken", "x" * 4097):
            with self.subTest(length=len(bad_value)):
                result = self.run_sync(token_value=bad_value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Set GITHUB_TOKEN through Replit Secrets", result.stderr)
                if bad_value:
                    self.assertNotIn(bad_value, result.stdout + result.stderr)
                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(capture["filesystemReads"], [])

    def test_http_and_network_failures_stop_without_printing_token(self):
        failure_cases = (
            ("GET /git/ref/heads/main", "http", 401),
            ("GET /git/commits/" + "a" * 40, "network", None),
        )
        for route, mode, status in failure_cases:
            with self.subTest(route=route, mode=mode):
                result = self.run_sync(
                    fail_at=route,
                    fail_mode=mode,
                    fail_status=status,
                )
                self.assertNotEqual(result.returncode, 0)
                if mode == "network":
                    self.assertIn("Could not reach GitHub", result.stderr)
                    self.assertIn("retry", result.stderr)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
                self.assertEqual(capture["requests"][-1]["path"], "/repos/vitalitychems-dot/GitMesh" + route.split(" ", 1)[1])

    def test_branch_conflict_uses_non_force_update_and_stops(self):
        result = self.run_sync(
            fail_at="PATCH /git/refs/heads/main",
            fail_mode="http",
            fail_status=409,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 409", result.stderr)
        self.assertIn("branch changed while syncing", result.stderr)
        self.assertIn("No force update was attempted.", result.stderr)
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        update = capture["requests"][-1]
        self.assertEqual(update["method"], "PATCH")
        self.assertIs(update["body"]["force"], False)

    def test_authentication_and_permission_errors_give_safe_recovery_guidance(self):
        auth_result = self.run_sync(
            fail_at="GET /git/ref/heads/main",
            fail_mode="http",
            fail_status=401,
        )
        self.assertNotEqual(auth_result.returncode, 0)
        self.assertIn("GITHUB_TOKEN Secret", auth_result.stderr)
        self.assertIn("current", auth_result.stderr)
        self.assert_safe_failure_output(auth_result)

        permission_result = self.run_sync(
            fail_at="GET /git/ref/heads/main",
            fail_mode="http",
            fail_status=403,
        )
        self.assertNotEqual(permission_result.returncode, 0)
        self.assertIn("GitHub denied access", permission_result.stderr)
        self.assertIn("Contents:read", permission_result.stderr)
        self.assert_safe_failure_output(permission_result)

    def test_rate_limit_and_transient_errors_give_safe_retry_guidance(self):
        for status, retry_after in ((403, "30"), (429, None)):
            with self.subTest(status=status, retry_after=retry_after):
                rate_result = self.run_sync(
                    fail_at="GET /git/ref/heads/main",
                    fail_mode="http",
                    fail_status=status,
                    retry_after=retry_after,
                )
                self.assertNotEqual(rate_result.returncode, 0)
                self.assertIn("rate limit", rate_result.stderr)
                self.assertIn("then retry", rate_result.stderr)
                self.assert_safe_failure_output(rate_result)

        transient_result = self.run_sync(
            fail_at="GET /git/ref/heads/main",
            fail_mode="http",
            fail_status=503,
        )
        self.assertNotEqual(transient_result.returncode, 0)
        self.assertIn("temporarily unavailable", transient_result.stderr)
        self.assertIn("Wait briefly and retry", transient_result.stderr)
        self.assert_safe_failure_output(transient_result)

    def test_gitignore_excludes_local_vault_from_normal_git_operations(self):
        patterns = (ROOT / ".gitignore").read_text().splitlines()
        self.assertIn("SovereignMeshVault/", patterns)
        self.assertIn(".env", patterns)
        self.assertIn(".env.*", patterns)


if __name__ == "__main__":
    unittest.main(verbosity=2)
