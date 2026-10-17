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
PRE_COMMIT_HOOK = ROOT / "hooks" / "pre-commit"
HOOK_INSTALLER = ROOT / "install-pre-commit-hook.mjs"
INITIAL_SIGIL = "fixture-admin-sigil-one"
CUSTOM_SIGIL = "fixture-admin-sigil-custom"
FAKE_GITHUB_TOKEN = "test-only-not-a-real-token"
FAKE_REQUEST_BODY = "MOCK_REQUEST_BODY_SENTINEL"
FAKE_AUTHORIZATION = f"Bearer {FAKE_GITHUB_TOKEN}"
INITIAL_COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"
MOVED_COMMIT_SHA = "abcdef0" + "f" * 33
SECOND_MOVED_COMMIT_SHA = "7654321" + "e" * 33
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
        shutil.copy2(HOOK_INSTALLER, self.source_root / HOOK_INSTALLER.name)
        source_hooks = self.source_root / "hooks"
        source_hooks.mkdir()
        shutil.copy2(PRE_COMMIT_HOOK, source_hooks / "pre-commit")
        self.preflight_harness = self.source_root / "tests" / "test_security_regressions.py"
        self.preflight_harness.parent.mkdir()
        shutil.copy2(pathlib.Path(__file__), self.preflight_harness)

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
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
const requests = [];
const filesystemReads = [];
const preflightCalls = [];
const openedFiles = new Map();
const mutationWriters = new Map();
let replacementTriggered = false;
const capture = process.env.GITMESH_TEST_CAPTURE;
const remoteContents = JSON.parse(fs.readFileSync(process.env.GITMESH_TEST_REMOTE_CONTENTS, "utf8"));
const base = "/repos/vitalitychems-dot/GitMesh";
const initialCommitSha = process.env.GITMESH_TEST_INITIAL_SHA;
const invalidShaStage = process.env.GITMESH_TEST_INVALID_SHA_STAGE;
const invalidSha = process.env.GITMESH_TEST_INVALID_SHA;
let mainRefReadCount = 0;
const originalSpawnSync = childProcess.spawnSync.bind(childProcess);
childProcess.spawnSync = (command, ...args) => {
  if (command === "python3") {
    preflightCalls.push({
      command,
      args: args[0],
      hasGitHubToken: Boolean(args[1]?.env?.GITHUB_TOKEN),
    });
    const mode = process.env.GITMESH_TEST_PREFLIGHT_MODE ?? "success";
    const childOutput = process.env.GITMESH_TEST_PREFLIGHT_OUTPUT ?? "";
    const childStderr = process.env.GITMESH_TEST_PREFLIGHT_STDERR ?? childOutput;
    if (mode === "start") {
      return {
        error: { code: "ENOENT", message: childOutput },
        status: null,
        signal: null,
        stdout: childOutput,
        stderr: childStderr,
        pid: null,
        output: [],
      };
    }
    if (mode === "timeout") {
      return {
        error: { code: "ETIMEDOUT", message: childOutput },
        status: null,
        signal: "SIGTERM",
        stdout: childOutput,
        stderr: childStderr,
        pid: 123,
        output: [],
      };
    }
    if (mode === "output-limit") {
      return {
        error: { code: "ENOBUFS", message: childOutput },
        status: null,
        signal: null,
        stdout: childOutput,
        stderr: childStderr,
        pid: 123,
        output: [],
      };
    }
    const failed = mode === "failure";
    return {
      error: undefined,
      status: failed ? 1 : 0,
      signal: null,
      stdout: failed ? childOutput : "",
      stderr: failed ? childStderr : "",
      pid: 123,
      output: [],
    };
  }
  return originalSpawnSync(command, ...args);
};
syncBuiltinESMExports();
for (const name of ["lstatSync", "openSync", "readFileSync"]) {
  const original = fs[name].bind(fs);
  fs[name] = (target, ...args) => {
    const isPath = typeof target === "string" && !target.startsWith("file:");
    const resolvedPath = isPath ? path.resolve(String(target)) : null;
    if (name === "lstatSync") {
      const result = original(target, ...args);
      if (isPath) filesystemReads.push({ method: name, path: resolvedPath });
      const replaceAfter = process.env.GITMESH_TEST_REPLACE_AFTER_LSTAT;
      const replaceTarget = process.env.GITMESH_TEST_REPLACE_TARGET;
      if (!replacementTriggered && replaceAfter && replaceTarget &&
          resolvedPath === path.resolve(replaceAfter)) {
        replacementTriggered = true;
        fs.unlinkSync(target);
        if (process.env.GITMESH_TEST_REPLACE_KIND === "regular") {
          fs.writeFileSync(target, "PRIVATE_RECORD_SENTINEL");
        } else {
          fs.symlinkSync(replaceTarget, target);
        }
      }
      return result;
    }
    if (name === "openSync") {
      if (isPath) filesystemReads.push({ method: name, path: resolvedPath });
      const descriptor = original(target, ...args);
      if (isPath) {
        openedFiles.set(descriptor, resolvedPath);
        const mutatePath = process.env.GITMESH_TEST_MUTATE_DURING_READ_PATH;
        if (mutatePath && resolvedPath === path.resolve(mutatePath)) {
          const writer = original(
            resolvedPath,
            fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
          );
          mutationWriters.set(descriptor, writer);
        }
      }
      return descriptor;
    }
    if (typeof target === "number") {
      const openedPath = openedFiles.get(target);
      if (openedPath) filesystemReads.push({ method: name, path: openedPath });
      const content = original(target, ...args);
      const writer = mutationWriters.get(target);
      if (writer !== undefined) {
        const changedContent = Buffer.from(
          process.env.GITMESH_TEST_MUTATE_DURING_READ_CONTENT ?? "",
        );
        fs.ftruncateSync(writer, 0);
        fs.writeSync(writer, changedContent, 0, changedContent.length, 0);
        fs.closeSync(writer);
        mutationWriters.delete(target);
      }
      return content;
    } else if (isPath) {
      filesystemReads.push({ method: name, path: resolvedPath });
    }
    return original(target, ...args);
  };
}
const saveCapture = () => fs.writeFileSync(
  capture,
  JSON.stringify({ requests, filesystemReads, preflightCalls }),
);
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input));
  const method = init.method ?? "GET";
  const body = init.body ? JSON.parse(init.body) : null;
  requests.push({
    path: url.pathname,
    ref: url.searchParams.get("ref"),
    method,
    body,
    hasExpectedBearer: init.headers?.Authorization === "Bearer " + process.env.GITHUB_TOKEN,
  });
  const route = url.pathname.slice(base.length);
  const failAt = process.env.GITMESH_TEST_FAIL_AT;
    const failRef = process.env.GITMESH_TEST_FAIL_REF;
    if (failAt === method + " " + route &&
        (!failRef || url.searchParams.get("ref") === failRef)) {
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
    mainRefReadCount += 1;
    const movedHeadSha = process.env.GITMESH_TEST_MOVED_HEAD_SHA;
    const secondMovedHeadSha = process.env.GITMESH_TEST_SECOND_MOVED_HEAD_SHA;
    let previewSha = initialCommitSha;
    if (mainRefReadCount > 1 && movedHeadSha) previewSha = movedHeadSha;
    if (mainRefReadCount > 2 && secondMovedHeadSha) previewSha = secondMovedHeadSha;
    if (invalidShaStage === "main-ref") previewSha = invalidSha;
    data = {
      object: {
        sha: previewSha,
      },
    };
  } else if (method === "GET" && url.pathname === base + "/git/commits/" + initialCommitSha) {
    data = {
      tree: {
        sha: invalidShaStage === "base-tree" ? invalidSha : "b".repeat(40),
      },
    };
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
    data = { sha: invalidShaStage === "blob" ? invalidSha : "1".repeat(40) };
  } else if (method === "POST" && url.pathname === base + "/git/trees") {
    data = { sha: invalidShaStage === "tree" ? invalidSha : "c".repeat(40) };
  } else if (method === "POST" && url.pathname === base + "/git/commits") {
    data = { sha: invalidShaStage === "commit" ? invalidSha : "d".repeat(40) };
  } else if (method === "PATCH" && url.pathname === base + "/git/refs/heads/main") {
    data = {
      object: {
        sha: invalidShaStage === "updated-ref" ? invalidSha : body.sha,
      },
    };
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
        args=(),
        replace_after_lstat=None,
        replace_target=None,
        replace_kind=None,
        mutate_during_read_path=None,
        mutate_during_read_content=None,
        preflight_mode=None,
        preflight_output=None,
        preflight_stderr=None,
        moved_head_sha=None,
        second_moved_head_sha=None,
        fail_ref=None,
        invalid_sha_stage=None,
        invalid_sha=None,
    ):
        env = os.environ.copy()
        env["GITMESH_TEST_CAPTURE"] = str(self.capture)
        env["GITMESH_TEST_REMOTE_CONTENTS"] = str(self.remote_contents)
        env["GITMESH_TEST_INITIAL_SHA"] = INITIAL_COMMIT_SHA
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
            ("GITMESH_TEST_REPLACE_AFTER_LSTAT", replace_after_lstat),
            ("GITMESH_TEST_REPLACE_TARGET", replace_target),
            ("GITMESH_TEST_REPLACE_KIND", replace_kind),
            ("GITMESH_TEST_MUTATE_DURING_READ_PATH", mutate_during_read_path),
            ("GITMESH_TEST_MUTATE_DURING_READ_CONTENT", mutate_during_read_content),
            ("GITMESH_TEST_PREFLIGHT_MODE", preflight_mode),
            ("GITMESH_TEST_PREFLIGHT_OUTPUT", preflight_output),
            ("GITMESH_TEST_PREFLIGHT_STDERR", preflight_stderr),
            ("GITMESH_TEST_MOVED_HEAD_SHA", moved_head_sha),
            ("GITMESH_TEST_SECOND_MOVED_HEAD_SHA", second_moved_head_sha),
            ("GITMESH_TEST_FAIL_REF", fail_ref),
            ("GITMESH_TEST_INVALID_SHA_STAGE", invalid_sha_stage),
            ("GITMESH_TEST_INVALID_SHA", invalid_sha),
        ):
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return subprocess.run(
            [
                "node",
                "--import",
                str(self.preload),
                str(self.source_root / SYNC.name),
                *args,
            ],
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

    def assert_content_reads_use_initial_snapshot(self, capture):
        content_reads = [
            request for request in capture["requests"]
            if request["method"] == "GET" and "/contents/" in request["path"]
        ]
        self.assertTrue(content_reads)
        self.assertTrue(all(request["ref"] == INITIAL_COMMIT_SHA for request in content_reads))
        return content_reads[0]["ref"]

    def assert_preview_snapshot_matches_content_reads(self, output, capture):
        snapshot = self.assert_content_reads_use_initial_snapshot(capture)
        displayed_snapshot = re.search(
            r"(?:compared with commit |\(commit )([a-f0-9]{7})",
            output,
        )
        self.assertIsNotNone(displayed_snapshot)
        self.assertEqual(displayed_snapshot.group(1), snapshot[:7])

    def assert_no_source_contents_in_output(self, output):
        for source in ALLOWED_SOURCE_NAMES:
            content = (self.source_root / source).read_text()
            self.assertNotIn(content, output)

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
        self.assert_content_reads_use_initial_snapshot(capture)
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
            for method in ("lstatSync", "openSync", "readFileSync")
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

    def test_normal_sync_stops_safely_on_malformed_object_ids(self):
        readme = self.source_root / "README.md"
        original_content = readme.read_bytes()
        changed_content = original_content + b"\nLocal-only malformed SHA test marker.\n"
        stages = {
            "main-ref": ("main branch commit", []),
            "base-tree": ("base tree", []),
            "blob": ("blob SHA", ["/git/blobs"]),
            "tree": ("tree SHA", ["/git/blobs", "/git/trees"]),
            "commit": ("commit SHA", ["/git/blobs", "/git/trees", "/git/commits"]),
            "updated-ref": (
                None,
                ["/git/blobs", "/git/trees", "/git/commits", "/git/refs/heads/main"],
            ),
        }
        repository_prefix = "/repos/vitalitychems-dot/GitMesh"
        for stage, (label, expected_write_routes) in stages.items():
            with self.subTest(stage=stage):
                readme.write_bytes(changed_content)
                self.set_remote_snapshot({
                    "projects/local-vault/README.md": base64.b64encode(
                        original_content
                    ).decode("ascii"),
                })
                invalid_sha = f"UNTRUSTED_INVALID_{stage.upper()}_SHA_SENTINEL"
                result = self.run_sync(
                    invalid_sha_stage=stage,
                    invalid_sha=invalid_sha,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                if label is None:
                    self.assertIn("GitHub did not confirm the source sync commit", result.stderr)
                else:
                    self.assertIn(f"invalid {label}", result.stderr)
                    self.assertIn("sync stopped", result.stderr)
                self.assertNotIn(invalid_sha, output)
                self.assertNotIn("Synced ", output)
                self.assertEqual(reported_changed_paths(result.stdout), [])
                self.assert_safe_failure_output(result)
                self.assert_no_source_contents_in_output(output)

                capture = json.loads(self.capture.read_text())
                requests = capture["requests"]
                self.assertTrue(all(request["hasExpectedBearer"] for request in requests))
                self.assertNotIn(invalid_sha, json.dumps(requests))
                content_reads = [
                    request for request in requests
                    if request["method"] == "GET" and "/contents/" in request["path"]
                ]
                if stage == "main-ref":
                    self.assertEqual(content_reads, [])
                else:
                    self.assertEqual(len(content_reads), 3)
                    self.assertEqual(
                        [request["ref"] for request in content_reads],
                        [INITIAL_COMMIT_SHA] * 3,
                    )
                write_routes = [
                    request["path"][len(repository_prefix):]
                    for request in requests
                    if request["method"] in ("POST", "PATCH")
                ]
                self.assertEqual(write_routes, expected_write_routes)

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

    def test_dry_run_with_no_changes_reports_no_commit_and_makes_no_writes(self):
        self.set_remote_snapshot()
        result = self.run_sync(args=("--dry-run",))
        self.assertEqual(result.returncode, 0)
        self.assertIn("Dry run:", result.stdout)
        self.assertIn("already match", result.stdout)
        self.assertIn("no commit was created", result.stdout)
        self.assertNotIn("Warning:", result.stdout + result.stderr)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
        self.assertTrue(all(request["method"] == "GET" for request in capture["requests"]))
        self.assert_preview_snapshot_matches_content_reads(result.stdout, capture)
        self.assertFalse(any("/git/commits/" in request["path"] for request in capture["requests"]))
        self.assertEqual(
            sum(request["path"] == "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main"
                for request in capture["requests"]),
            2,
        )

    def test_dry_run_lists_only_changed_paths_without_contents_or_writes(self):
        self.set_remote_snapshot()
        private_file_content = b"DRY_RUN_PRIVATE_FILE_CONTENT_SENTINEL"
        (self.source_root / "README.md").write_bytes(private_file_content)

        result = self.run_sync(args=("--dry-run",))
        self.assertEqual(result.returncode, 0)
        self.assertIn("would be published", result.stdout)
        self.assertIn("no GitHub changes were made", result.stdout)
        self.assertNotIn("Warning:", result.stdout + result.stderr)
        self.assertEqual(
            reported_changed_paths(result.stdout),
            ["projects/local-vault/README.md"],
        )
        self.assertNotIn(private_file_content.decode(), result.stdout + result.stderr)
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
        self.assertTrue(all(request["method"] == "GET" for request in capture["requests"]))
        self.assert_preview_snapshot_matches_content_reads(result.stdout, capture)
        self.assertEqual(
            sum("/contents/" in request["path"] for request in capture["requests"]),
            3,
        )

    def test_dry_run_refreshes_once_when_main_advances(self):
        self.set_remote_snapshot()
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nLocal-only preview marker.\n")

        result = self.run_sync(
            args=("--dry-run",),
            moved_head_sha=MOVED_COMMIT_SHA,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("compared with commit " + MOVED_COMMIT_SHA[:7], result.stdout)
        self.assertNotIn("Warning:", result.stdout + result.stderr)
        self.assertIn("no GitHub changes were made", result.stdout)
        self.assertEqual(
            reported_changed_paths(result.stdout),
            ["projects/local-vault/README.md"],
        )
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        head_reads = [
            request for request in requests
            if request["path"] == "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main"
        ]
        content_reads = [
            request for request in requests
            if request["method"] == "GET" and "/contents/" in request["path"]
        ]
        self.assertEqual(len(head_reads), 3)
        self.assertEqual(len(content_reads), 6)
        self.assertEqual(
            [request["ref"] for request in content_reads],
            [INITIAL_COMMIT_SHA] * 3 + [MOVED_COMMIT_SHA] * 3,
        )
        self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_dry_run_stops_after_second_head_advance(self):
        result = self.run_sync(
            args=("--dry-run",),
            moved_head_sha=MOVED_COMMIT_SHA,
            second_moved_head_sha=SECOND_MOVED_COMMIT_SHA,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("advanced again", result.stderr)
        self.assertIn(MOVED_COMMIT_SHA[:7], result.stderr)
        self.assertIn(SECOND_MOVED_COMMIT_SHA[:7], result.stderr)
        self.assertIn("Rerun the dry run before publishing", result.stderr)
        self.assertIn("No GitHub changes were made", result.stderr)
        self.assertNotIn("would be published", output)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(output)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        head_reads = [
            request for request in requests
            if request["path"] == "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main"
        ]
        content_reads = [
            request for request in requests
            if request["method"] == "GET" and "/contents/" in request["path"]
        ]
        self.assertEqual(len(head_reads), 3)
        self.assertEqual(len(content_reads), 6)
        self.assertEqual(
            [request["ref"] for request in content_reads],
            [INITIAL_COMMIT_SHA] * 3 + [MOVED_COMMIT_SHA] * 3,
        )
        self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_dry_run_stops_safely_when_refreshed_commit_id_is_invalid(self):
        self.set_remote_snapshot()
        invalid_sha = "UNTRUSTED_INVALID_REFRESHED_SHA_SENTINEL"
        result = self.run_sync(
            args=("--dry-run",),
            moved_head_sha=MOVED_COMMIT_SHA,
            second_moved_head_sha=invalid_sha,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Dry run could not complete a consistent comparison", result.stderr)
        self.assertIn("invalid main branch commit", result.stderr)
        self.assertIn("Rerun the dry run before publishing", result.stderr)
        self.assertIn("No GitHub changes were made", result.stderr)
        self.assertNotIn(invalid_sha, output)
        self.assertNotIn("would be published", output)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(output)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        head_reads = [
            request for request in requests
            if request["path"] == "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main"
        ]
        content_reads = [
            request for request in requests
            if request["method"] == "GET" and "/contents/" in request["path"]
        ]
        self.assertEqual(len(head_reads), 3)
        self.assertEqual(len(content_reads), 6)
        self.assertEqual(
            [request["ref"] for request in content_reads],
            [INITIAL_COMMIT_SHA] * 3 + [MOVED_COMMIT_SHA] * 3,
        )
        self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_dry_run_refresh_failure_requests_rerun(self):
        self.set_remote_snapshot()
        result = self.run_sync(
            args=("--dry-run",),
            moved_head_sha=MOVED_COMMIT_SHA,
            fail_at="GET /contents/projects/local-vault/README.md",
            fail_ref=MOVED_COMMIT_SHA,
            fail_status=503,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Dry run could not complete a consistent comparison", result.stderr)
        self.assertIn("temporarily unavailable", result.stderr)
        self.assertIn("Rerun the dry run before publishing", result.stderr)
        self.assertIn("No GitHub changes were made", result.stderr)
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(output)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        failed_retry_reads = [
            request for request in requests
            if request["path"].endswith("/contents/projects/local-vault/README.md")
            and request["ref"] == MOVED_COMMIT_SHA
        ]
        self.assertEqual(len(failed_retry_reads), 1)
        self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_unknown_sync_option_stops_before_github_request(self):
        result = self.run_sync(args=("--unexpected-option",))
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Usage: node ./sync-public-source.mjs [--dry-run | --check-credentials | --check-staged-credentials].",
            result.stderr,
        )
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])

    def test_local_credential_check_passes_without_token_or_github_requests(self):
        result = self.run_sync(token_value=None, args=("--check-credentials",))
        self.assertEqual(result.returncode, 0)
        self.assertIn("Credential check passed", result.stdout)
        self.assertIn("3 allowlisted source files", result.stdout)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])
        expected_reads = Counter(
            (method, str((self.source_root / source).resolve()))
            for source in ALLOWED_SOURCE_NAMES
            for method in ("lstatSync", "openSync", "readFileSync")
        )
        observed_reads = Counter(
            (event["method"], event["path"])
            for event in capture["filesystemReads"]
        )
        self.assertEqual(observed_reads, expected_reads)

    def test_local_credential_check_reports_location_without_exposing_value(self):
        source_path = self.source_root / "README.md"
        credential = "ghp_" + "R" * 36
        source_line = f"Example configuration value: {credential}"
        source_path.write_text(source_line + "\n")

        result = self.run_sync(token_value=None, args=("--check-credentials",))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"{source_path.name} (line 1)", result.stderr)
        self.assertIn("Remove the value from this file", result.stderr)
        self.assertIn("No GitHub requests were made", result.stderr)
        self.assertNotIn(credential, result.stdout + result.stderr)
        self.assertNotIn(source_line, result.stdout + result.stderr)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])

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

    def test_unsafe_local_sources_stop_before_github_and_do_not_leak_contents(self):
        source_name = "gitmesh-ultimate-core.mjs"
        source_path = self.source_root / source_name
        symlink_target = self.source_root / "SovereignMeshVault/active_sigil.hash"
        unsafe_cases = (
            (
                "symlink",
                lambda: source_path.symlink_to(symlink_target),
                "invalid, linked, or oversized source file",
                "Review and save the intended file as a regular file within the size limit, then rerun sync. No GitHub requests were made.",
                (b"PRIVATE_SIGIL_FILE_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "oversized",
                lambda: source_path.write_bytes(
                    b"OVERSIZED_LOCAL_CONTENT_SENTINEL" + b"x" * (512 * 1024)
                ),
                "invalid, linked, or oversized source file",
                "Review and save the intended file as a regular file within the size limit, then rerun sync. No GitHub requests were made.",
                (b"OVERSIZED_LOCAL_CONTENT_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "unavailable",
                lambda: None,
                "unavailable source file",
                "Review and save the intended file state, then rerun sync. No GitHub requests were made.",
                (),
                [],
            ),
            (
                "binary invalid utf-8",
                lambda: source_path.write_bytes(b"\xffBINARY_LOCAL_CONTENT_SENTINEL"),
                "non-text source file",
                "Save the intended source as valid UTF-8 plain text, then rerun sync. No GitHub requests were made.",
                (b"BINARY_LOCAL_CONTENT_SENTINEL",),
                [
                    ("lstatSync", str(source_path)),
                    ("openSync", str(source_path)),
                    ("readFileSync", str(source_path)),
                ],
            ),
            (
                "binary containing nul",
                lambda: source_path.write_bytes(b"\x00BINARY_NUL_LOCAL_CONTENT_SENTINEL"),
                "non-text source file",
                "Save the intended source as valid UTF-8 plain text, then rerun sync. No GitHub requests were made.",
                (b"BINARY_NUL_LOCAL_CONTENT_SENTINEL",),
                [
                    ("lstatSync", str(source_path)),
                    ("openSync", str(source_path)),
                    ("readFileSync", str(source_path)),
                ],
            ),
        )
        for (
            case_name,
            create_unsafe_source,
            expected_error,
            expected_guidance,
            sentinels,
            expected_reads,
        ) in unsafe_cases:
            with self.subTest(source_type=case_name):
                source_path.unlink(missing_ok=True)
                create_unsafe_source()

                result = self.run_sync()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)
                self.assertIn(source_name, result.stderr)
                if expected_guidance:
                    self.assertIn(expected_guidance, result.stderr)
                self.assert_safe_failure_output(result)
                for sentinel in sentinels:
                    self.assertNotIn(sentinel.decode(), result.stdout + result.stderr)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                observed_source_reads = [
                    (event["method"], event["path"])
                    for event in capture["filesystemReads"]
                    if event["path"] == str(source_path)
                ]
                self.assertEqual(observed_source_reads, expected_reads)

    def test_hard_linked_private_source_is_rejected_before_read_or_github_request(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        private_path = self.source_root / "SovereignMeshVault/ledger_matrix/private-record.json"
        source_path.unlink()
        os.link(private_path, source_path)
        self.assertEqual(os.stat(source_path).st_nlink, 2)

        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("linked", result.stderr)
        self.assertIn(source_path.name, result.stderr)
        self.assertIn(
            "Review and save the intended file as a regular file within the size limit, then rerun sync. No GitHub requests were made.",
            result.stderr,
        )
        self.assertNotIn("PRIVATE_RECORD_SENTINEL", result.stdout + result.stderr)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        observed_source_reads = [
            (event["method"], event["path"])
            for event in capture["filesystemReads"]
            if event["path"] == str(source_path)
        ]
        self.assertEqual(observed_source_reads, [("lstatSync", str(source_path))])

    def test_source_replaced_after_metadata_check_is_not_followed_or_read(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        private_path = self.source_root / "SovereignMeshVault/ledger_matrix/private-record.json"

        for replacement_kind in ("symlink", "regular"):
            with self.subTest(replacement_kind=replacement_kind):
                source_path.unlink(missing_ok=True)
                shutil.copy2(ROOT / source_path.name, source_path)
                result = self.run_sync(
                    replace_after_lstat=str(source_path),
                    replace_target=str(private_path),
                    replace_kind=replacement_kind,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("changed or could not be safely opened", result.stderr)
                self.assertIn(source_path.name, result.stderr)
                self.assertIn(
                    "Review and save the intended file state, then rerun sync. No GitHub requests were made.",
                    result.stderr,
                )
                self.assertNotIn("PRIVATE_RECORD_SENTINEL", result.stdout + result.stderr)
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                source_reads = [
                    (event["method"], event["path"])
                    for event in capture["filesystemReads"]
                    if event["path"] == str(source_path)
                ]
                self.assertEqual(source_reads, [
                    ("lstatSync", str(source_path)),
                    ("openSync", str(source_path)),
                ])
                self.assertFalse(any(
                    event["path"] == str(private_path)
                    for event in capture["filesystemReads"]
                ))

    def test_in_place_source_edit_during_read_is_rejected_before_github(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        original_info = source_path.stat()
        changed_secret = "ghp_" + "M" * 36
        secret_bytes = changed_secret.encode("ascii")
        self.assertGreater(len(original_content), len(secret_bytes))
        changed_content = (
            secret_bytes + b"X" * (len(original_content) - len(secret_bytes))
        ).decode("ascii")

        result = self.run_sync(
            mutate_during_read_path=str(source_path),
            mutate_during_read_content=changed_content,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed or could not be safely opened", result.stderr)
        self.assertIn(source_path.name, result.stderr)
        self.assertIn(
            "Review and save the intended file state, then rerun sync. No GitHub requests were made.",
            result.stderr,
        )
        self.assertNotIn(changed_secret, result.stdout + result.stderr)
        self.assertNotIn(changed_content, result.stdout + result.stderr)
        self.assert_safe_failure_output(result)
        self.assertEqual(source_path.stat().st_ino, original_info.st_ino)
        self.assertEqual(source_path.stat().st_size, original_info.st_size)
        self.assertEqual(source_path.read_text(), changed_content)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        source_reads = [
            (event["method"], event["path"])
            for event in capture["filesystemReads"]
            if event["path"] == str(source_path)
        ]
        self.assertEqual(source_reads, [
            ("lstatSync", str(source_path)),
            ("openSync", str(source_path)),
            ("readFileSync", str(source_path)),
        ])

    def test_invalid_javascript_stops_before_github_without_printing_source(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        invalid_source = "const INVALID_JS_SOURCE_SENTINEL = ;\n"
        source_path.write_text(invalid_source)

        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node syntax validation", result.stderr)
        self.assertIn(source_path.name, result.stderr)
        self.assertIn(
            "Review and correct this file, save it, then rerun sync. No GitHub requests were made.",
            result.stderr,
        )
        self.assertNotIn(invalid_source.strip(), result.stdout + result.stderr)
        self.assertNotIn("INVALID_JS_SOURCE_SENTINEL", result.stdout + result.stderr)
        self.assertNotIn("SyntaxError", result.stdout + result.stderr)
        self.assertNotIn("Unexpected token", result.stdout + result.stderr)
        self.assertNotIn("Node.js v", result.stdout + result.stderr)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])

    def test_embedded_credentials_stop_before_github_without_leaking_values(self):
        source_path = self.source_root / "README.md"
        credential_samples = (
            ("GitHub classic token", "ghp_" + "A" * 36),
            ("GitHub fine-grained token", "github_pat_" + "B" * 40),
            ("GitLab token", "glpat-" + "F" * 24),
            ("npm token", "npm_" + "G" * 36),
            ("Slack token", "xoxb-" + "C" * 24),
            ("Google API key", "AIza" + "D" * 35),
            ("OpenAI project key", "sk-proj-" + "H" * 40),
            ("OpenAI legacy key", "sk-" + "I" * 48),
            ("Stripe secret key", "sk_live_" + "E" * 24),
            (
                "PEM private key",
                "-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY_BODY_SENTINEL\n-----END PRIVATE KEY-----",
            ),
        )
        original_content = source_path.read_bytes()
        try:
            for label, credential in credential_samples:
                with self.subTest(credential_type=label):
                    source_line = f"Example configuration value: {credential}"
                    source_path.write_text(f"{source_line}\n")
                    result = self.run_sync()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("credential-like value", result.stderr)
                    self.assertIn(source_path.name, result.stderr)
                    self.assertIn("(line 1)", result.stderr)
                    self.assertIn("Remove the value from this file", result.stderr)
                    self.assertIn("Replit Secrets", result.stderr)
                    self.assertIn(
                        "Rotate it only if it was already shared or published elsewhere",
                        result.stderr,
                    )
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn(source_line, result.stdout + result.stderr)
                    self.assertNotIn(credential, result.stdout + result.stderr)
                    self.assertNotIn("PRIVATE_KEY_BODY_SENTINEL", result.stdout + result.stderr)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])

            first_secret = "ghp_" + "J" * 36
            second_secret = "github_pat_" + "K" * 40
            first_line = f"token={first_secret}"
            second_line = f"private_key=-----BEGIN PRIVATE KEY-----{second_secret}"
            source_path.write_text(
                "SAFE_HEADER_CONTEXT\n"
                f"{first_line}\n"
                "SAFE_MIDDLE_CONTEXT\n"
                f"{second_line}\n"
            )
            result = self.run_sync()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"{source_path.name} (lines 2, 4)", result.stderr)
            for private_text in (
                first_secret,
                second_secret,
                first_line,
                second_line,
                "SAFE_HEADER_CONTEXT",
                "SAFE_MIDDLE_CONTEXT",
            ):
                self.assertNotIn(private_text, result.stdout + result.stderr)
            self.assertIn("No GitHub requests were made", result.stderr)
            self.assert_safe_failure_output(result)
            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_credentials_in_multiple_sources_are_all_reported_without_leaking(self):
        readme = self.source_root / "README.md"
        console = self.source_root / "gitmesh-ultimate-core.mjs"
        original_contents = {
            source_path: source_path.read_bytes()
            for source_path in (readme, console)
        }
        readme_secret = "ghp_" + "N" * 36
        console_secret = "github_pat_" + "P" * 40
        readme_line = f"README_TOKEN={readme_secret}"
        console_line = f"CONSOLE_TOKEN={console_secret}"
        readme.write_bytes(
            f"SAFE_README_CONTEXT\r\n{readme_line}\r\nSAFE_README_FOOTER".encode("utf-8")
        )
        console.write_bytes(
            f"SAFE_CONSOLE_HEADER\rSAFE_CONSOLE_CONTEXT\r{console_line}".encode("utf-8")
        )

        try:
            for mode, args, token_value in (
                ("sync", (), FAKE_GITHUB_TOKEN),
                ("local check without token", ("--check-credentials",), None),
            ):
                with self.subTest(mode=mode):
                    result = self.run_sync(args=args, token_value=token_value)
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(
                        result.stderr.count(
                            "Refusing to sync source files containing a credential-like value:"
                        ),
                        1,
                    )
                    self.assertIn("README.md (line 2)", result.stderr)
                    self.assertIn("gitmesh-ultimate-core.mjs (line 3)", result.stderr)
                    self.assertIn("; ", result.stderr)
                    self.assertIn("No GitHub requests were made", result.stderr)
                    for private_text in (
                        readme_secret,
                        console_secret,
                        readme_line,
                        console_line,
                        "SAFE_README_CONTEXT",
                        "SAFE_README_FOOTER",
                        "SAFE_CONSOLE_HEADER",
                        "SAFE_CONSOLE_CONTEXT",
                    ):
                        self.assertNotIn(private_text, output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            for source_path, content in original_contents.items():
                source_path.write_bytes(content)

    def test_embedded_credentials_report_lines_for_crlf_and_bare_cr_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        first_secret = "ghp_" + "L" * 36
        second_secret = "github_pat_" + "M" * 40
        first_line = f"token={first_secret}"
        second_line = f"token={second_secret}"
        try:
            for label, line_ending in (
                ("CRLF", "\r\n"),
                ("bare CR", "\r"),
            ):
                source_text = line_ending.join(
                    (
                        "SAFE_HEADER_CONTEXT",
                        first_line,
                        "SAFE_MIDDLE_CONTEXT",
                        second_line,
                        "SAFE_FOOTER_CONTEXT",
                    )
                )
                source_path.write_bytes(source_text.encode("utf-8"))

                for mode, args, token_value in (
                    ("sync", (), FAKE_GITHUB_TOKEN),
                    ("local check without token", ("--check-credentials",), None),
                ):
                    with self.subTest(line_ending=label, mode=mode):
                        result = self.run_sync(args=args, token_value=token_value)
                        output = result.stdout + result.stderr
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"{source_path.name} (lines 2, 4)", result.stderr)
                        self.assertIn("No GitHub requests were made", result.stderr)
                        for private_text in (
                            first_secret,
                            second_secret,
                            first_line,
                            second_line,
                            "SAFE_HEADER_CONTEXT",
                            "SAFE_MIDDLE_CONTEXT",
                            "SAFE_FOOTER_CONTEXT",
                        ):
                            self.assertNotIn(private_text, output)
                        self.assert_safe_failure_output(result)

                        capture = json.loads(self.capture.read_text())
                        self.assertEqual(capture["requests"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_embedded_credentials_report_lines_for_unicode_separators_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        first_secret = "ghp_" + "N" * 36
        second_secret = "github_pat_" + "P" * 40
        first_line = f"token={first_secret}"
        second_line = f"token={second_secret}"
        try:
            for label, line_ending in (
                ("U+2028", "\u2028"),
                ("U+2029", "\u2029"),
            ):
                source_text = line_ending.join(
                    (
                        "SAFE_UNICODE_HEADER_CONTEXT",
                        first_line,
                        "SAFE_UNICODE_MIDDLE_CONTEXT",
                        second_line,
                        "SAFE_UNICODE_FOOTER_CONTEXT",
                    )
                )
                source_path.write_bytes(source_text.encode("utf-8"))

                for mode, args, token_value in (
                    ("sync", (), FAKE_GITHUB_TOKEN),
                    ("local check without token", ("--check-credentials",), None),
                ):
                    with self.subTest(line_ending=label, mode=mode):
                        result = self.run_sync(args=args, token_value=token_value)
                        output = result.stdout + result.stderr
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"{source_path.name} (lines 2, 4)", result.stderr)
                        self.assertIn("No GitHub requests were made", result.stderr)
                        for private_text in (
                            first_secret,
                            second_secret,
                            first_line,
                            second_line,
                            "SAFE_UNICODE_HEADER_CONTEXT",
                            "SAFE_UNICODE_MIDDLE_CONTEXT",
                            "SAFE_UNICODE_FOOTER_CONTEXT",
                        ):
                            self.assertNotIn(private_text, output)
                        self.assert_safe_failure_output(result)

                        capture = json.loads(self.capture.read_text())
                        self.assertEqual(capture["requests"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_embedded_credentials_report_lines_for_mixed_line_breaks_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        credentials = (
            "ghp_" + "A" * 36,
            "github_pat_" + "B" * 40,
            "npm_" + "C" * 36,
            "xoxb-" + "D" * 24,
        )
        credential_lines = tuple(f"token={value}" for value in credentials)
        source_text = "\r\n".join(("SAFE_MIXED_HEADER_CONTEXT", credential_lines[0]))
        source_text += "\r" + credential_lines[1]
        source_text += "\u2028" + credential_lines[2]
        source_text += "\u2029" + credential_lines[3]
        source_text += "\r\nSAFE_MIXED_FOOTER_CONTEXT"

        try:
            source_path.write_bytes(source_text.encode("utf-8"))

            for mode, args, token_value in (
                ("sync", (), FAKE_GITHUB_TOKEN),
                ("local check without token", ("--check-credentials",), None),
            ):
                with self.subTest(mode=mode):
                    result = self.run_sync(args=args, token_value=token_value)
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{source_path.name} (lines 2, 3, 4, 5)",
                        result.stderr,
                    )
                    self.assertIn("No GitHub requests were made", result.stderr)
                    for private_text in (
                        *credentials,
                        *credential_lines,
                        "SAFE_MIXED_HEADER_CONTEXT",
                        "SAFE_MIXED_FOOTER_CONTEXT",
                    ):
                        self.assertNotIn(private_text, output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
        finally:
            source_path.write_bytes(original_content)

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

    def test_preflight_safe_name_allowlist_matches_regression_tests(self):
        sync_source = SYNC.read_text()
        safe_name_block = re.search(
            r"const SAFE_PREFLIGHT_TEST_NAMES = new Set\(\[(.*?)\]\);",
            sync_source,
            re.DOTALL,
        )
        self.assertIsNotNone(safe_name_block, "Could not find the safe preflight test-name allowlist.")
        safe_names = set(
            re.findall(r'"(test_[A-Za-z0-9_]+)"', safe_name_block.group(1))
        )
        regression_test_names = set(
            re.findall(
                r"^\s+def (test_[A-Za-z0-9_]+)\(",
                pathlib.Path(__file__).read_text(),
                re.MULTILINE,
            )
        )
        self.assertEqual(
            safe_names,
            regression_test_names,
            "Keep the safe preflight names in sync with all regression tests.",
        )

    def test_missing_preflight_harness_has_safe_recovery_guidance(self):
        readme = self.source_root / "README.md"
        original_readme = readme.read_bytes()
        source_sentinel = "PREFLIGHT_SOURCE_CONTENT_SENTINEL"
        credential_sentinel = "ghp_" + "V" * 36
        safe_test_name = "test_sync_publishes_only_the_fixed_source_allowlist"
        mocked_python_output = (
            f"FAIL: {safe_test_name} (__main__.GitHubSyncTests.{safe_test_name})\n"
            f"{source_sentinel}\n{credential_sentinel}"
        )
        readme.write_text(f"{source_sentinel}\n")
        self.preflight_harness.unlink()

        try:
            result = self.run_sync(
                preflight_mode="failure",
                preflight_output=mocked_python_output,
            )
            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Security regression preflight harness is missing: tests/test_security_regressions.py",
                result.stderr,
            )
            self.assertIn("Restore it from the complete GitMesh workspace, then rerun sync.", result.stderr)
            self.assertIn(
                "python3 gitmesh-template/tests/test_security_regressions.py",
                result.stderr,
            )
            self.assertIn("No GitHub requests were made", result.stderr)
            for private_text in (
                source_sentinel,
                credential_sentinel,
                mocked_python_output,
            ):
                self.assertNotIn(private_text, output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
        finally:
            readme.write_bytes(original_readme)

    def test_failed_security_preflight_stops_before_github_without_leaking_output(self):
        expected_source_reads = Counter(
            (method, str((self.source_root / source).resolve()))
            for source in ALLOWED_SOURCE_NAMES
            for method in ("lstatSync", "openSync", "readFileSync")
        )
        safe_test_name = "test_sync_publishes_only_the_fixed_source_allowlist"
        second_safe_test_name = "test_invalid_javascript_stops_before_github_without_printing_source"
        expected_multiple_summary = (
            f"Security regression preflight failed in: "
            f"{safe_test_name}, {second_safe_test_name}"
        )
        source_sentinel = "PREFLIGHT_SOURCE_CONTENT_SENTINEL"
        credential_sentinel = "ghp_" + "Q" * 36
        unlisted_test_name = f"test_{credential_sentinel}"
        stdout_output = (
            f"FAIL: {safe_test_name} (__main__.GitHubSyncTests.{safe_test_name})\n"
            f"ERROR: {unlisted_test_name} (__main__.GitHubSyncTests.{unlisted_test_name})\n"
            f"{source_sentinel}"
        )
        stderr_output = (
            f"ERROR: {second_safe_test_name} (__main__.GitHubSyncTests.{second_safe_test_name})\n"
            f"FAIL: {safe_test_name} (__main__.GitHubSyncTests.{safe_test_name})\n"
            f"{credential_sentinel}"
        )
        injected_output = f"{stdout_output}\n{stderr_output}"
        cases = (
            ("failure", "publish", (), expected_multiple_summary),
            ("failure", "dry run", ("--dry-run",), expected_multiple_summary),
            (
                "start",
                "python start",
                (),
                "Install Python 3 or make python3 available on PATH, then rerun the regression checks and sync",
            ),
            ("timeout", "python timeout", (), "preflight timed out"),
            ("output-limit", "large output", (), "exceeded its output limit"),
        )
        for preflight_mode, mode, args, expected_summary in cases:
            with self.subTest(mode=mode):
                result = self.run_sync(
                    args=args,
                    preflight_mode=preflight_mode,
                    preflight_output=stdout_output if preflight_mode == "failure" else injected_output,
                    preflight_stderr=stderr_output if preflight_mode == "failure" else None,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_summary, result.stderr)
                self.assertIn(
                    "python3 gitmesh-template/tests/test_security_regressions.py",
                    result.stderr,
                )
                self.assertIn("No GitHub requests were made", result.stderr)
                self.assertNotIn(source_sentinel, result.stdout + result.stderr)
                self.assertNotIn(credential_sentinel, result.stdout + result.stderr)
                self.assertNotIn(unlisted_test_name, result.stdout + result.stderr)
                self.assertNotIn(injected_output, result.stdout + result.stderr)
                if preflight_mode == "failure":
                    for recognized_name in (safe_test_name, second_safe_test_name):
                        self.assertEqual(result.stderr.count(recognized_name), 1)
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(len(capture["preflightCalls"]), 1)
                self.assertEqual(capture["preflightCalls"][0]["command"], "python3")
                self.assertFalse(capture["preflightCalls"][0]["hasGitHubToken"])
                self.assertEqual(
                    capture["preflightCalls"][0]["args"],
                    [str(self.source_root / "tests" / "test_security_regressions.py")],
                )
                observed_source_reads = Counter(
                    (event["method"], event["path"])
                    for event in capture["filesystemReads"]
                )
                self.assertEqual(observed_source_reads, expected_source_reads)
                self.assertFalse(any(
                    "SovereignMeshVault" in event["path"]
                    for event in capture["filesystemReads"]
                ))

        unknown_only_output = (
            f"ERROR: {unlisted_test_name} (__main__.GitHubSyncTests.{unlisted_test_name})\n"
            f"{source_sentinel}\n{credential_sentinel}"
        )
        with self.subTest(mode="unknown test only"):
            result = self.run_sync(
                preflight_mode="failure",
                preflight_output=unknown_only_output,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no safe failing test name was available", result.stderr)
            for unsafe_text in (
                unlisted_test_name,
                source_sentinel,
                credential_sentinel,
                unknown_only_output,
            ):
                self.assertNotIn(unsafe_text, result.stdout + result.stderr)
            self.assert_safe_failure_output(result)
            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])

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
            ("GET /git/commits/" + INITIAL_COMMIT_SHA, "network", None),
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


class PreCommitHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gitmesh-precommit-test-")
        self.repo_root = pathlib.Path(self.temp.name)
        self.template_root = self.repo_root / "gitmesh-template"
        self.template_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, self.template_root / name)
        hook_dir = self.template_root / "hooks"
        hook_dir.mkdir()
        shutil.copy2(PRE_COMMIT_HOOK, hook_dir / "pre-commit")

        self.run_git(["init", "--quiet"])
        self.run_git(["config", "user.name", "GitMesh Security Test"])
        self.run_git(["config", "user.email", "gitmesh-security-test@example.invalid"])
        self.run_git(["config", "commit.gpgsign", "false"])
        self.run_git(["config", "core.hooksPath", ".git/hooks"])
        self.run_git(["add", "gitmesh-template"])
        baseline = self.run_git(["commit", "--quiet", "-m", "fixture baseline"])
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.run_git(["config", "core.hooksPath", "gitmesh-template/hooks"])

        self.readme = self.template_root / "README.md"
        self.baseline_readme = self.readme.read_bytes()
        self.network_marker = self.repo_root / "unexpected-network-request"
        self.network_guard = self.repo_root / "network-guard.mjs"
        self.network_guard.write_text(
            'import fs from "node:fs";\n'
            "globalThis.fetch = async () => {\n"
            '  fs.writeFileSync(process.env.GITMESH_TEST_NETWORK_MARKER, "called");\n'
            '  throw new Error("network request attempted");\n'
            "};\n"
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_git(self, args, env=None):
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def hook_environment_without_github_token(self):
        env = os.environ.copy()
        env.pop("GITHUB_TOKEN", None)
        env["GITMESH_TEST_NETWORK_MARKER"] = str(self.network_marker)
        env["NODE_OPTIONS"] = f"--import={self.network_guard.as_uri()}"
        return env

    def test_precommit_hook_blocks_staged_credentials_without_exposing_them(self):
        credential = "ghp_" + "Z" * 36
        staged_source_line = f"staged_secret={credential}"
        self.readme.write_text(f"staged source fixture\n{staged_source_line}\n")
        self.run_git(["add", "gitmesh-template/README.md"])

        # The staged blob still contains the credential after the working
        # tree is restored, so a correct hook must inspect the index version.
        self.readme.write_bytes(self.baseline_readme)
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        result = self.run_git(
            ["commit", "-m", "must be blocked"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md (line 2)", output)
        self.assertIn("Remove the value from this staged file", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn(credential, output)
        self.assertNotIn(staged_source_line, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
            "gitmesh-template/README.md",
        )
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_reports_unicode_separator_lines_without_exposing_content(self):
        first_secret = "ghp_" + "U" * 36
        second_secret = "github_pat_" + "V" * 40
        first_line = f"token={first_secret}"
        second_line = f"token={second_secret}"

        for label, line_ending in (
            ("U+2028", "\u2028"),
            ("U+2029", "\u2029"),
        ):
            with self.subTest(line_ending=label):
                source_text = line_ending.join(
                    (
                        "SAFE_UNICODE_HEADER_CONTEXT",
                        first_line,
                        "SAFE_UNICODE_MIDDLE_CONTEXT",
                        second_line,
                        "SAFE_UNICODE_FOOTER_CONTEXT",
                    )
                )
                self.readme.write_bytes(source_text.encode("utf-8"))
                self.run_git(["add", "gitmesh-template/README.md"])

                # Verify the hook reads the staged blob, not the restored file.
                self.readme.write_bytes(self.baseline_readme)
                original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
                result = self.run_git(
                    ["commit", "-m", f"must be blocked for {label}"],
                    env=self.hook_environment_without_github_token(),
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("README.md (lines 2, 4)", output)
                self.assertIn("No GitHub requests were made", output)
                for private_text in (
                    first_secret,
                    second_secret,
                    first_line,
                    second_line,
                    "SAFE_UNICODE_HEADER_CONTEXT",
                    "SAFE_UNICODE_MIDDLE_CONTEXT",
                    "SAFE_UNICODE_FOOTER_CONTEXT",
                    FAKE_GITHUB_TOKEN,
                ):
                    self.assertNotIn(private_text, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_blocks_when_node_is_missing(self):
        credential = "ghp_" + "N" * 36
        source_sentinel = "NODE_MISSING_STAGED_SOURCE_SENTINEL"
        self.readme.write_text(f"staged_secret={credential}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        path_without_node = self.repo_root / "path-without-node"
        path_without_node.mkdir()
        for command in ("git", "dirname"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"required test executable not found: {command}")
            (path_without_node / command).symlink_to(executable)

        env = self.hook_environment_without_github_token()
        env["PATH"] = str(path_without_node)
        result = self.run_git(
            ["commit", "-m", "must be blocked without node"],
            env=env,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node.js 20 or newer is required", output)
        self.assertIn("Install Node.js or make node available on PATH", output)
        self.assertIn("retry the commit", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("command not found", output)
        self.assertNotIn(credential, output)
        self.assertNotIn(source_sentinel, output)
        self.assertNotIn(FAKE_GITHUB_TOKEN, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
            "gitmesh-template/README.md",
        )
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_blocks_when_staged_index_cannot_be_read(self):
        credential = "ghp_" + "I" * 36
        source_sentinel = "UNREADABLE_INDEX_STAGED_SOURCE_SENTINEL"
        diagnostic_sentinel = "PRIVATE_INDEX_DIAGNOSTIC_SENTINEL"
        self.readme.write_text(f"staged_secret={credential}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        hook_dir = self.template_root / "hooks"
        precommit_hook = hook_dir / "pre-commit"
        original_hook = hook_dir / "gitmesh-pre-commit"
        shutil.copy2(precommit_hook, original_hook)
        unreadable_index = self.repo_root / "unreadable-index"
        unreadable_index.write_text(f"invalid index {diagnostic_sentinel}\n")
        precommit_hook.write_text(
            "#!/bin/sh\n"
            'HOOK_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)\n'
            'export GIT_INDEX_FILE="$HOOK_DIR/../../unreadable-index"\n'
            'exec "$HOOK_DIR/gitmesh-pre-commit" "$@"\n'
        )
        precommit_hook.chmod(0o755)

        result = self.run_git(
            ["commit", "-m", "must be blocked when index cannot be read"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not inspect staged allowlisted source files", output)
        self.assertIn("Check that the staged index is readable and not locked", output)
        self.assertIn("stage the intended files again and retry the commit", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn(diagnostic_sentinel, output)
        self.assertNotIn("fatal: index is unreadable", output)
        self.assertNotIn(credential, output)
        self.assertNotIn(source_sentinel, output)
        self.assertNotIn(FAKE_GITHUB_TOKEN, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
            "gitmesh-template/README.md",
        )
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_passes_clean_source_and_ignores_unrelated_files(self):
        self.readme.write_bytes(self.baseline_readme + b"\nclean staged source fixture\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        unstaged_credential = "ghp_" + "X" * 36
        self.readme.write_text(f"unstaged_secret={unstaged_credential}\n")
        clean_result = self.run_git(
            ["commit", "-m", "clean allowlisted source"],
            env=self.hook_environment_without_github_token(),
        )
        clean_output = clean_result.stdout + clean_result.stderr
        self.assertEqual(clean_result.returncode, 0, clean_output)
        self.assertIn("1 staged allowlisted source file", clean_output)
        self.assertNotIn(unstaged_credential, clean_output)
        self.assertFalse(self.network_marker.exists())

        unrelated_credential = "ghp_" + "Y" * 36
        unrelated = self.repo_root / "unrelated-private-file.txt"
        unrelated.write_text(f"unrelated_secret={unrelated_credential}\n")
        self.run_git(["add", "unrelated-private-file.txt"])
        unrelated_result = self.run_git(
            ["commit", "-m", "unrelated file"],
            env=self.hook_environment_without_github_token(),
        )
        unrelated_output = unrelated_result.stdout + unrelated_result.stderr

        self.assertEqual(unrelated_result.returncode, 0, unrelated_output)
        self.assertIn("no allowlisted source files are staged", unrelated_output)
        self.assertNotIn(unrelated_credential, unrelated_output)
        self.assertFalse(self.network_marker.exists())


class HookInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gitmesh-hook-installer-test-")
        self.repo_root = pathlib.Path(self.temp.name)
        self.template_root = self.repo_root / "gitmesh-template"
        self.template_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, self.template_root / name)
        shutil.copy2(HOOK_INSTALLER, self.template_root / HOOK_INSTALLER.name)
        hook_dir = self.template_root / "hooks"
        hook_dir.mkdir()
        shutil.copy2(PRE_COMMIT_HOOK, hook_dir / "pre-commit")

        self.global_config = self.repo_root / "isolated-global.gitconfig"
        self.global_config.write_text("")
        self.env = os.environ.copy()
        self.env.pop("GITHUB_TOKEN", None)
        self.env["GIT_CONFIG_GLOBAL"] = str(self.global_config)
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.run_git(["init", "--quiet"])
        self.run_git(["config", "--local", "user.name", "GitMesh Hook Test"])
        self.run_git(["config", "--local", "user.email", "gitmesh-hook-test@example.invalid"])
        self.run_git(["config", "--local", "commit.gpgsign", "false"])
        self.run_git(["add", "gitmesh-template"])
        baseline = self.run_git(["commit", "--quiet", "-m", "fixture baseline"])
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

    def tearDown(self):
        self.temp.cleanup()

    def run_git_at(self, cwd, args):
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def run_git(self, args):
        return self.run_git_at(self.repo_root, args)

    def run_installer(self, cwd=None, args=(), installer_path=None):
        cwd = cwd or self.repo_root
        installer_path = installer_path or cwd / "gitmesh-template" / HOOK_INSTALLER.name
        return subprocess.run(
            ["node", str(installer_path), *args],
            cwd=cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_hook_setup_uses_local_hooks_path_when_gitmesh_is_repository_root(self):
        standalone_root = self.repo_root / "standalone-gitmesh"
        standalone_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, standalone_root / name)
        installer_path = standalone_root / HOOK_INSTALLER.name
        shutil.copy2(HOOK_INSTALLER, installer_path)
        hook_dir = standalone_root / "hooks"
        hook_dir.mkdir()
        gitmesh_hook = hook_dir / "pre-commit"
        shutil.copy2(PRE_COMMIT_HOOK, gitmesh_hook)
        original_gitmesh_hook = gitmesh_hook.read_bytes()

        initialized = self.run_git_at(standalone_root, ["init", "--quiet"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        for name, value in (
            ("user.name", "GitMesh Standalone Test"),
            ("user.email", "gitmesh-standalone-test@example.invalid"),
            ("commit.gpgsign", "false"),
        ):
            configured = self.run_git_at(
                standalone_root,
                ["config", "--local", name, value],
            )
            self.assertEqual(configured.returncode, 0, configured.stderr)
        self.run_git_at(standalone_root, ["add", "."])
        baseline = self.run_git_at(
            standalone_root,
            ["commit", "--quiet", "-m", "standalone fixture baseline"],
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

        default_hooks_result = self.run_git_at(
            standalone_root,
            ["rev-parse", "--git-path", "hooks"],
        )
        self.assertEqual(default_hooks_result.returncode, 0)
        default_hooks = pathlib.Path(default_hooks_result.stdout.strip())
        if not default_hooks.is_absolute():
            default_hooks = standalone_root / default_hooks
        existing_hook = default_hooks / "pre-commit"
        existing_hook.parent.mkdir(parents=True, exist_ok=True)
        existing_hook.write_text("#!/bin/sh\nexit 0\n")
        existing_hook.chmod(0o755)
        original_existing_hook = existing_hook.read_bytes()

        refused = self.run_installer(
            cwd=standalone_root,
            installer_path=installer_path,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("Custom files already exist", refused.stderr)
        self.assertIn("No Git configuration was changed", refused.stderr)
        self.assertIn(
            "node 'sync-public-source.mjs' --check-staged-credentials",
            refused.stderr,
        )
        self.assertEqual(existing_hook.read_bytes(), original_existing_hook)
        self.assertEqual(
            self.run_git_at(
                standalone_root,
                ["config", "--local", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )

        existing_hook.unlink()
        enabled = self.run_installer(
            cwd=standalone_root,
            installer_path=installer_path,
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn("for this repository only", enabled.stdout)
        self.assertIn("git config --local --unset core.hooksPath", enabled.stdout)
        configured_path = self.run_git_at(
            standalone_root,
            ["config", "--local", "--get", "core.hooksPath"],
        )
        self.assertEqual(configured_path.returncode, 0)
        self.assertEqual(configured_path.stdout.strip(), "hooks")
        self.assertEqual(gitmesh_hook.read_bytes(), original_gitmesh_hook)
        self.assertEqual(self.global_config.read_text(), "")
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )

    def test_hook_setup_enables_only_repository_local_path_when_safe(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("for this repository only", result.stdout)
        self.assertIn("git config --local --unset core.hooksPath", result.stdout)

        configured = self.run_git(["config", "--local", "--get", "core.hooksPath"])
        self.assertEqual(configured.returncode, 0)
        self.assertEqual(configured.stdout.strip(), "gitmesh-template/hooks")
        self.assertEqual(self.global_config.read_text(), "")

        repeated = self.run_installer()
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("already enabled", repeated.stdout)
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).stdout.strip(),
            "gitmesh-template/hooks",
        )

        credential = "ghp_" + "Q" * 36
        readme = self.template_root / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(["commit", "-m", "installer enabled hook"])
        output = commit.stdout + commit.stderr
        self.assertNotEqual(commit.returncode, 0)
        self.assertIn("README.md (line 1)", output)
        self.assertNotIn(credential, output)

    def test_hook_setup_preserves_existing_local_hooks_path(self):
        existing_hooks = self.repo_root / "existing-local-hooks"
        existing_hooks.mkdir()
        existing_hook = existing_hooks / "pre-commit"
        existing_hook.write_text("#!/bin/sh\nprintf 'existing-hook-ran\\n'\n")
        self.run_git(["config", "--local", "core.hooksPath", "existing-local-hooks"])
        result = self.run_installer()
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository-local Git hooks path is already configured", output)
        self.assertIn("No Git configuration was changed", output)
        self.assertIn("--check-staged-credentials", output)
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-local-hooks",
        )
        self.assertEqual(existing_hook.read_text(), "#!/bin/sh\nprintf 'existing-hook-ran\\n'\n")
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_setup_preserves_multiple_local_hooks_paths(self):
        self.run_git(["config", "--local", "--add", "core.hooksPath", "first-hooks"])
        self.run_git(["config", "--local", "--add", "core.hooksPath", "second-hooks"])
        result = self.run_installer()
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository-local Git hooks path is already configured", output)
        self.assertIn("No Git configuration was changed", output)
        paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(paths.returncode, 0)
        self.assertEqual(paths.stdout.splitlines(), ["first-hooks", "second-hooks"])
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_setup_preserves_existing_global_hooks_path(self):
        self.run_git(["config", "--global", "core.hooksPath", "existing-global-hooks"])
        result = self.run_installer()
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configured outside this repository", output)
        self.assertIn("No Git configuration was changed", output)
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )
        self.assertEqual(self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode, 1)

    def test_hook_setup_preserves_existing_default_hooks(self):
        hooks_path = self.run_git(["rev-parse", "--git-path", "hooks"]).stdout.strip()
        default_hooks = self.repo_root / hooks_path
        default_hooks.mkdir(parents=True, exist_ok=True)
        (default_hooks / "pre-commit").write_text("#!/bin/sh\nexit 0\n")

        result = self.run_installer()
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Custom files already exist in Git's default hooks directory", output)
        self.assertIn("No Git configuration was changed", output)
        self.assertEqual(self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode, 1)
        self.assertTrue((default_hooks / "pre-commit").exists())

    def test_hook_setup_enables_only_selected_linked_worktree_when_supported(self):
        self.run_git(["config", "--local", "extensions.worktreeConfig", "true"])
        worktree_root = self.repo_root / "linked-worktree"
        sibling_root = self.repo_root / "sibling-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        added_sibling = self.run_git(["worktree", "add", "--detach", str(sibling_root), "HEAD"])
        self.assertEqual(added_sibling.returncode, 0, added_sibling.stdout + added_sibling.stderr)

        result = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local",),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("for this worktree only", result.stdout)
        self.assertIn("git config --worktree --unset core.hooksPath", result.stdout)
        self.assertEqual(
            self.run_git_at(
                worktree_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).stdout.strip(),
            "gitmesh-template/hooks",
        )
        for sibling in (self.repo_root, sibling_root):
            self.assertEqual(
                self.run_git_at(
                    sibling,
                    ["config", "--worktree", "--get", "core.hooksPath"],
                ).returncode,
                1,
            )
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "extensions.worktreeConfig"]).stdout.strip(),
            "true",
        )
        self.assertEqual(self.global_config.read_text(), "")

        repeated = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local",),
        )
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("already enabled for this worktree", repeated.stdout)

        credential = "ghp_" + "W" * 36
        readme = worktree_root / "gitmesh-template" / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git_at(worktree_root, ["add", "gitmesh-template/README.md"])
        original_head = self.run_git_at(worktree_root, ["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git_at(worktree_root, ["commit", "-m", "linked worktree hook check"])
        output = commit.stdout + commit.stderr
        self.assertNotEqual(commit.returncode, 0, output.replace(credential, "[redacted test credential]"))
        self.assertIn("README.md (line 1)", output)
        self.assertNotIn(credential, output)
        self.assertEqual(
            self.run_git_at(worktree_root, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_setup_refuses_worktree_opt_in_without_worktree_config_support(self):
        nonlinked = self.run_installer(args=("--worktree-local",))
        self.assertNotEqual(nonlinked.returncode, 0)
        self.assertIn("only available in a linked Git worktree", nonlinked.stderr)
        self.assertIn("No Git configuration was changed", nonlinked.stderr)
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )

        worktree_root = self.repo_root / "linked-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        config_path_result = self.run_git_at(
            worktree_root,
            ["rev-parse", "--git-path", "config.worktree"],
        )
        self.assertEqual(config_path_result.returncode, 0)
        config_path = pathlib.Path(config_path_result.stdout.strip())
        if not config_path.is_absolute():
            config_path = worktree_root / config_path
        original_worktree_config = config_path.read_bytes() if config_path.exists() else None

        result = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local",),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires extensions.worktreeConfig=true", result.stderr)
        self.assertIn("No Git configuration was changed", result.stderr)
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )
        self.assertEqual(
            config_path.read_bytes() if config_path.exists() else None,
            original_worktree_config,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_setup_refuses_linked_worktree_without_changing_config(self):
        worktree_root = self.repo_root / "linked-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)

        installer = worktree_root / "gitmesh-template" / HOOK_INSTALLER.name
        result = subprocess.run(
            ["node", str(installer)],
            cwd=worktree_root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("linked Git worktree", output)
        self.assertIn("No Git configuration was changed", output)
        self.assertEqual(self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode, 1)
        worktree_config = subprocess.run(
            ["git", "config", "--local", "--get", "core.hooksPath"],
            cwd=worktree_root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(worktree_config.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
