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
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "gitmesh-ultimate-core.mjs"
SYNC = ROOT / "sync-public-source.mjs"
PRE_COMMIT_HOOK = ROOT / "hooks" / "pre-commit"
PRE_PUSH_HOOK = ROOT / "hooks" / "pre-push"
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
CREDENTIAL_HOOK_TEST_CASES = {
    "github-prefixed-token": (
        ("GitHub personal token", "ghp_" + "A" * 36),
        ("GitHub OAuth token", "gho_" + "B" * 36),
        ("GitHub user token", "ghu_" + "C" * 36),
        ("GitHub server token", "ghs_" + "D" * 36),
        ("GitHub refresh token", "ghr_" + "E" * 36),
    ),
    "github-fine-grained-token": (
        ("GitHub fine-grained token", "github_pat_" + "F" * 40),
    ),
    "gitlab-token": (
        ("GitLab personal access token", "glpat-" + "G" * 24),
    ),
    "npm-token": (
        ("npm token", "npm_" + "H" * 32),
    ),
    "slack-token": (
        ("Slack bot token", "xoxb-" + "I" * 24),
        ("Slack app token", "xoxa-" + "J" * 24),
        ("Slack user token", "xoxp-" + "K" * 24),
        ("Slack refresh token", "xoxr-" + "L" * 24),
        ("Slack service token", "xoxs-" + "M" * 24),
    ),
    "google-api-key": (
        ("Google API key", "AIza" + "N" * 35),
    ),
    "openai-prefixed-key": (
        ("OpenAI project key", "sk-proj-" + "O" * 24),
        ("OpenAI admin key", "sk-admin-" + "P" * 24),
        ("OpenAI service account key", "sk-svcacct-" + "Q" * 24),
    ),
    "openai-legacy-key": (
        ("OpenAI legacy key", "sk-" + "R" * 40),
    ),
    "stripe-secret-key": (
        ("Stripe live secret", "sk_live_" + "S" * 24),
        ("Stripe test secret", "sk_test_" + "T" * 24),
    ),
    "private-key-header": (
        ("unencrypted private key", "-----BEGIN PRIVATE KEY-----"),
        ("encrypted private key", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
        ("RSA private key", "-----BEGIN RSA PRIVATE KEY-----"),
        ("EC private key", "-----BEGIN EC PRIVATE KEY-----"),
        ("DSA private key", "-----BEGIN DSA PRIVATE KEY-----"),
        ("OpenSSH private key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("PGP private key", "-----BEGIN PGP PRIVATE KEY-----"),
    ),
}
CREDENTIAL_HOOK_FAMILY_LABELS = {
    "github-prefixed-token": "GitHub token",
    "github-fine-grained-token": "GitHub fine-grained token",
    "gitlab-token": "GitLab token",
    "npm-token": "npm token",
    "slack-token": "Slack token",
    "google-api-key": "Google API key",
    "openai-prefixed-key": "OpenAI API key",
    "openai-legacy-key": "OpenAI API key",
    "stripe-secret-key": "Stripe secret key",
    "private-key-header": "Private key",
}
CREDENTIAL_HOOK_NEAR_MISS_CASES = {
    "github-prefixed-token": (
        ("below-minimum", "ghp_" + "A" * 29),
        ("invalid-character", "ghp_" + "B" * 15 + "." + "C" * 15),
    ),
    "github-fine-grained-token": (
        ("below-minimum", "github_pat_" + "D" * 29),
        ("invalid-character", "github_pat_" + "E" * 15 + "." + "F" * 15),
    ),
    "gitlab-token": (
        ("below-minimum", "glpat-" + "G" * 19),
        ("invalid-character", "glpat-" + "H" * 10 + "." + "I" * 10),
    ),
    "npm-token": (
        ("below-minimum", "npm_" + "J" * 29),
        ("invalid-character", "npm_" + "K" * 15 + "." + "L" * 15),
    ),
    "slack-token": (
        ("below-minimum", "xoxb-" + "M" * 19),
        ("invalid-character", "xoxb-" + "N" * 10 + "." + "O" * 10),
    ),
    "google-api-key": (
        ("below-minimum", "AIza" + "P" * 34),
        ("invalid-character", "AIza" + "Q" * 17 + "." + "R" * 18),
    ),
    "openai-prefixed-key": (
        ("below-minimum", "sk-proj-" + "S" * 19),
        ("invalid-character", "sk-proj-" + "T" * 10 + "." + "U" * 10),
    ),
    "openai-legacy-key": (
        ("below-minimum", "sk-" + "V" * 39),
        ("invalid-character", "sk-" + "W" * 20 + "." + "X" * 20),
    ),
    "stripe-secret-key": (
        ("below-minimum", "sk_live_" + "Y" * 19),
        ("invalid-character", "sk_test_" + "Z" * 10 + "." + "a" * 10),
    ),
    "private-key-header": (
        ("invalid-character", "-----BEGIN PRIVATE.KEY-----"),
    ),
}


def assert_credential_hook_vectors_cover_scanner_patterns(scanner_pattern_ids, test_cases):
    scanner_ids = set(scanner_pattern_ids)
    test_vector_ids = set(test_cases)
    missing_vectors = sorted(scanner_ids - test_vector_ids)
    stale_vectors = sorted(test_vector_ids - scanner_ids)
    if missing_vectors or stale_vectors:
        raise AssertionError(
            "Add representative synthetic commit-hook values to CREDENTIAL_HOOK_TEST_CASES "
            "for every scanner pattern. "
            f"Missing vectors: {missing_vectors}; stale vector groups: {stale_vectors}."
        )

    empty_vectors = sorted(
        pattern_id for pattern_id in scanner_ids if not test_cases[pattern_id]
    )
    if empty_vectors:
        raise AssertionError(
            "Every scanner credential pattern needs at least one synthetic hook test value. "
            f"Empty vector groups: {empty_vectors}."
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
const malformedJsonAt = process.env.GITMESH_TEST_MALFORMED_JSON_AT;
const malformedJsonBody = process.env.GITMESH_TEST_MALFORMED_JSON_BODY;
const selectedBranch = process.env.GITMESH_TEST_BRANCH ?? "main";
const encodedBranch = encodeURIComponent(selectedBranch);
let targetRefReadCount = 0;
const originalSpawnSync = childProcess.spawnSync.bind(childProcess);
childProcess.spawnSync = (command, ...args) => {
  if (
    command === process.execPath &&
    args[0]?.[0] === "--input-type=module" &&
    args[0]?.includes("--check") &&
    Object.hasOwn(process.env, "GITMESH_TEST_NODE_SYNTAX_DIAGNOSTICS")
  ) {
    return {
      error: undefined,
      status: 1,
      signal: null,
      stdout: "",
      stderr: process.env.GITMESH_TEST_NODE_SYNTAX_DIAGNOSTICS,
      pid: 123,
      output: [],
    };
  }
  if (command === "python3") {
    preflightCalls.push({
      command,
      args: args[0],
      hasGitHubToken: Boolean(args[1]?.env?.GITHUB_TOKEN),
    });
    if (args[0]?.[0] === "-c") {
      const version = process.env.GITMESH_TEST_PREFLIGHT_PYTHON_VERSION ?? "3.13";
      return {
        error: undefined,
        status: 0,
        signal: null,
        stdout: process.env.GITMESH_TEST_PREFLIGHT_VERSION_STDOUT ?? `${version}\n`,
        stderr: process.env.GITMESH_TEST_PREFLIGHT_VERSION_STDERR ?? "",
        pid: 123,
        output: [],
      };
    }
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
    if (mode === "interrupt") {
      return {
        error: undefined,
        status: null,
        signal: "SIGINT",
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
      if (isPath) {
        filesystemReads.push({ method: name, path: resolvedPath });
        const deniedPath = process.env.GITMESH_TEST_PERMISSION_DENIED_PATH;
        if (deniedPath && resolvedPath === path.resolve(deniedPath)) {
          const error = new Error(
            `EACCES: permission denied, open '${resolvedPath}' PRIVATE_PERMISSION_OS_DIAGNOSTIC_SENTINEL`,
          );
          error.code = "EACCES";
          throw error;
        }
      }
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
  if (method === "GET" && url.pathname === base + "/git/ref/heads/" + encodedBranch) {
    targetRefReadCount += 1;
    const movedHeadSha = process.env.GITMESH_TEST_MOVED_HEAD_SHA;
    const secondMovedHeadSha = process.env.GITMESH_TEST_SECOND_MOVED_HEAD_SHA;
    let previewSha = initialCommitSha;
    if (targetRefReadCount > 1 && movedHeadSha) previewSha = movedHeadSha;
    if (targetRefReadCount > 2 && secondMovedHeadSha) previewSha = secondMovedHeadSha;
    if (
      invalidShaStage === "main-ref" ||
      (invalidShaStage === "dry-run-initial-ref" && targetRefReadCount === 1) ||
      (invalidShaStage === "dry-run-first-comparison-ref" && targetRefReadCount === 2)
    ) previewSha = invalidSha;
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
  } else if (method === "PATCH" && url.pathname === base + "/git/refs/heads/" + encodedBranch) {
    data = {
      object: {
        sha: invalidShaStage === "updated-ref" ? invalidSha : body.sha,
      },
    };
  } else {
    throw new Error("Unexpected mocked GitHub request.");
  }
  saveCapture();
  if (malformedJsonAt === method + " " + route) {
    return {
      ok: true,
      status: 200,
      json: async () => JSON.parse(malformedJsonBody),
    };
  }
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
        preflight_python_version=None,
        preflight_version_stdout=None,
        preflight_version_stderr=None,
        moved_head_sha=None,
        second_moved_head_sha=None,
        fail_ref=None,
        invalid_sha_stage=None,
        invalid_sha=None,
        malformed_json_at=None,
        malformed_json_body=None,
        env_overrides=None,
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
            ("GITMESH_TEST_PREFLIGHT_PYTHON_VERSION", preflight_python_version),
            ("GITMESH_TEST_PREFLIGHT_VERSION_STDOUT", preflight_version_stdout),
            ("GITMESH_TEST_PREFLIGHT_VERSION_STDERR", preflight_version_stderr),
            ("GITMESH_TEST_MOVED_HEAD_SHA", moved_head_sha),
            ("GITMESH_TEST_SECOND_MOVED_HEAD_SHA", second_moved_head_sha),
            ("GITMESH_TEST_FAIL_REF", fail_ref),
            ("GITMESH_TEST_INVALID_SHA_STAGE", invalid_sha_stage),
            ("GITMESH_TEST_INVALID_SHA", invalid_sha),
            ("GITMESH_TEST_MALFORMED_JSON_AT", malformed_json_at),
            ("GITMESH_TEST_MALFORMED_JSON_BODY", malformed_json_body),
        ):
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        if env_overrides:
            env.update(env_overrides)
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

    def run_source_git(self, args):
        result = subprocess.run(
            ["git", *args],
            cwd=self.source_root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def initialize_source_history(self):
        self.run_source_git(["init", "--quiet"])
        self.run_source_git(["config", "user.name", "GitMesh History Test"])
        self.run_source_git(["config", "user.email", "gitmesh-history-test@example.invalid"])
        self.run_source_git(["config", "commit.gpgsign", "false"])
        self.run_source_git(["config", "core.hooksPath", str(self.temp_path / "history-hooks")])
        self.run_source_git(["add", *ALLOWED_SOURCE_NAMES])
        self.run_source_git(["commit", "--quiet", "-m", "clean history baseline"])
        return self.run_source_git(["rev-parse", "HEAD"])

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
        result = self.run_sync(preflight_python_version="3.9")
        self.assertEqual(result.returncode, 0, "Mocked source sync did not complete.")
        self.assertNotIn(FAKE_GITHUB_TOKEN, result.stdout + result.stderr)
        self.assertNotIn(FAKE_AUTHORIZATION, result.stdout + result.stderr)
        reported_paths = reported_changed_paths(result.stdout)
        self.assertEqual(set(reported_paths), ALLOWED_GITHUB_PATHS)
        self.assertEqual(len(reported_paths), len(ALLOWED_GITHUB_PATHS))
        capture = json.loads(self.capture.read_text())
        self.assertEqual(len(capture["preflightCalls"]), 2)
        self.assertEqual(
            capture["preflightCalls"][0]["args"],
            [
                "-c",
                "import sys; print('%s.%s' % (sys.version_info[0], sys.version_info[1]))",
            ],
        )
        self.assertEqual(
            capture["preflightCalls"][1]["args"],
            [str(self.source_root / "tests" / "test_security_regressions.py")],
        )
        self.assertFalse(any(call["hasGitHubToken"] for call in capture["preflightCalls"]))
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

    def test_sync_stops_safely_when_object_creation_returns_unreadable_json(self):
        self.set_remote_snapshot()
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nUnreadable JSON sync test marker.\n")

        body_sentinel = "UNTRUSTED_SUCCESS_RESPONSE_BODY_SENTINEL"
        repository_prefix = "/repos/vitalitychems-dot/GitMesh"
        cases = (
            ("/git/blobs", ["/git/blobs"]),
            ("/git/trees", ["/git/blobs", "/git/trees"]),
            ("/git/commits", ["/git/blobs", "/git/trees", "/git/commits"]),
        )
        for route, expected_write_routes in cases:
            with self.subTest(route=route):
                result = self.run_sync(
                    malformed_json_at=f"POST {route}",
                    malformed_json_body=body_sentinel,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"GitHub returned an invalid response during POST {route}", result.stderr)
                self.assertNotIn(body_sentinel, output)
                self.assertNotIn("Synced ", output)
                self.assertNotIn("Commit: ", output)
                self.assertEqual(reported_changed_paths(result.stdout), [])
                self.assert_safe_failure_output(result)
                self.assert_no_source_contents_in_output(output)

                capture = json.loads(self.capture.read_text())
                requests = capture["requests"]
                self.assertTrue(all(request["hasExpectedBearer"] for request in requests))
                write_routes = [
                    request["path"][len(repository_prefix):]
                    for request in requests
                    if request["method"] in ("POST", "PATCH")
                ]
                self.assertEqual(write_routes, expected_write_routes)
                self.assertFalse(any(request["method"] == "PATCH" for request in requests))

    def test_sync_stops_safely_when_contents_response_returns_unreadable_json(self):
        self.set_remote_snapshot()
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nUnreadable contents response test marker.\n")
        body_sentinel = "UNTRUSTED_CONTENT_RESPONSE_BODY_SENTINEL"
        result = self.run_sync(
            malformed_json_at="GET /contents/projects/local-vault/README.md",
            malformed_json_body=body_sentinel,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "GitHub returned an invalid response during GET /contents/projects/local-vault/README.md",
            result.stderr,
        )
        self.assertNotIn(body_sentinel, output)
        self.assertNotIn("Synced ", output)
        self.assertNotIn("Commit: ", output)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(output)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        self.assertTrue(all(request["hasExpectedBearer"] for request in requests))
        self.assertEqual(
            [request["method"] for request in requests],
            ["GET", "GET", "GET"],
        )
        self.assertTrue(requests[-1]["path"].endswith("/contents/projects/local-vault/README.md"))
        self.assertEqual(
            [
                request for request in requests
                if request["method"] in ("POST", "PATCH")
            ],
            [],
        )

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
        self.assertRegex(INITIAL_COMMIT_SHA, r"^[a-f0-9]{40}$")
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

    def test_dry_run_uses_selected_branch_and_encodes_ref_route(self):
        self.set_remote_snapshot()
        branch = "release/2026.10+canary#ops"
        encoded_branch = "release%2F2026.10%2Bcanary%23ops"
        result = self.run_sync(
            args=("--branch", branch, "--dry-run"),
            env_overrides={"GITMESH_TEST_BRANCH": branch},
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"@{branch}", result.stdout)
        self.assertIn("no commit was created", result.stdout)
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        ref_path = (
            "/repos/vitalitychems-dot/GitMesh/git/ref/heads/" +
            encoded_branch
        )
        self.assertEqual(
            sum(request["path"] == ref_path for request in capture["requests"]),
            2,
        )
        self.assertTrue(all(request["method"] == "GET" for request in capture["requests"]))
        self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))
        self.assert_preview_snapshot_matches_content_reads(result.stdout, capture)

    def test_dry_run_retries_consistently_on_selected_branch(self):
        self.set_remote_snapshot()
        branch = "release/2026.10+canary#ops"
        encoded_branch = "release%2F2026.10%2Bcanary%23ops"
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nBranch preview fixture.\n")
        result = self.run_sync(
            args=("--dry-run", "--branch", branch),
            moved_head_sha=MOVED_COMMIT_SHA,
            env_overrides={"GITMESH_TEST_BRANCH": branch},
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"@{branch}", result.stdout)
        self.assertIn(f"compared with commit {MOVED_COMMIT_SHA[:7]}", result.stdout)
        self.assertIn("no GitHub changes were made", result.stdout)
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        ref_path = (
            "/repos/vitalitychems-dot/GitMesh/git/ref/heads/" +
            encoded_branch
        )
        requests = capture["requests"]
        self.assertEqual(sum(request["path"] == ref_path for request in requests), 3)
        content_reads = [
            request for request in requests
            if request["method"] == "GET" and "/contents/" in request["path"]
        ]
        self.assertEqual(len(content_reads), 6)
        self.assertEqual(
            [request["ref"] for request in content_reads],
            [INITIAL_COMMIT_SHA] * 3 + [MOVED_COMMIT_SHA] * 3,
        )
        self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_sync_uses_selected_branch_and_preserves_non_force_update(self):
        self.set_remote_snapshot()
        branch = "release/2026.10+canary#ops"
        encoded_branch = "release%2F2026.10%2Bcanary%23ops"
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nBranch-specific sync fixture.\n")

        result = self.run_sync(
            args=("--branch", branch),
            env_overrides={"GITMESH_TEST_BRANCH": branch},
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"@{branch}", result.stdout)
        self.assertIn("Synced 1 changed allowlisted source file", result.stdout)
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(result.stdout + result.stderr)

        capture = json.loads(self.capture.read_text())
        update = capture["requests"][-1]
        self.assertEqual(
            update["path"],
            "/repos/vitalitychems-dot/GitMesh/git/refs/heads/" + encoded_branch,
        )
        self.assertEqual(update["method"], "PATCH")
        self.assertIs(update["body"]["force"], False)
        self.assertTrue(all(request["hasExpectedBearer"] for request in capture["requests"]))

    def test_invalid_branch_selection_stops_before_github_request(self):
        invalid_branches = (
            "../admin",
            "release/../admin",
            "release//candidate",
            "/release",
            "release/",
            "feature?ref=main",
            "release/.hidden",
            "release/head.lock",
            "branch with spaces",
            "bad\\branch",
            "@",
            "--dry-run",
            "a" * 256,
        )
        for branch in invalid_branches:
            with self.subTest(branch=branch):
                result = self.run_sync(args=("--branch", branch), token_value=None)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--branch requires a valid Git branch name", result.stderr)
                self.assertNotIn(branch, result.stdout + result.stderr)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])

    def test_branch_option_requires_one_valid_name_and_sync_mode(self):
        invalid_argument_sets = (
            ("--branch",),
            ("--branch", "release/candidate", "--branch", "release/other"),
            ("--branch", "release/candidate", "--check-local"),
            ("--dry-run", "--dry-run"),
        )
        for args in invalid_argument_sets:
            with self.subTest(args=args):
                result = self.run_sync(args=args, token_value=None)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage: node ./sync-public-source.mjs", result.stderr)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])

    def test_dry_run_rejects_malformed_initial_and_first_comparison_commit_ids(self):
        self.set_remote_snapshot()
        readme = self.source_root / "README.md"
        source_sentinel = "DRY_RUN_INVALID_HEAD_SOURCE_SENTINEL"
        readme.write_bytes(readme.read_bytes() + f"\n{source_sentinel}\n".encode())

        invalid_commit_ids = (
            ("non-hex", "UNTRUSTED_COMMIT_ID_SENTINEL"),
            ("one hex digit short", "b" * 39),
            ("one hex digit long", "c" * 41),
            ("64 lowercase hex digits", "d" * 64),
            ("uppercase hex", "E" * 40),
        )
        stages = (
            ("dry-run-initial-ref", 1, []),
            ("dry-run-first-comparison-ref", 2, [INITIAL_COMMIT_SHA] * 3),
        )
        for stage, expected_head_reads, expected_content_refs in stages:
            for invalid_kind, invalid_sha in invalid_commit_ids:
                with self.subTest(stage=stage, invalid_kind=invalid_kind):
                    result = self.run_sync(
                        args=("--dry-run",),
                        invalid_sha_stage=stage,
                        invalid_sha=invalid_sha,
                    )
                    output = result.stdout + result.stderr

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("invalid main branch commit", result.stderr)
                    self.assertIn("Rerun the dry run before publishing", result.stderr)
                    self.assertIn("No GitHub changes were made", result.stderr)
                    for preview_success in ("Dry run:", "would be published", "already match"):
                        self.assertNotIn(preview_success, output)
                    self.assertNotIn(invalid_sha, output)
                    self.assertEqual(reported_changed_paths(result.stdout), [])
                    self.assert_safe_failure_output(result)
                    self.assert_no_source_contents_in_output(output)

                    capture = json.loads(self.capture.read_text())
                    requests = capture["requests"]
                    head_reads = [
                        request for request in requests
                        if request["path"] ==
                        "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main"
                    ]
                    content_reads = [
                        request for request in requests
                        if request["method"] == "GET" and "/contents/" in request["path"]
                    ]
                    self.assertEqual(len(head_reads), expected_head_reads)
                    self.assertEqual(
                        [request["ref"] for request in content_reads],
                        expected_content_refs,
                    )
                    self.assertNotIn(invalid_sha, json.dumps(requests))
                    self.assertTrue(all(request["method"] == "GET" for request in requests))

    def test_dry_run_stops_safely_when_branch_ref_returns_unreadable_json(self):
        self.set_remote_snapshot()
        body_sentinel = "UNTRUSTED_BRANCH_REF_RESPONSE_BODY_SENTINEL"
        result = self.run_sync(
            args=("--dry-run",),
            malformed_json_at="GET /git/ref/heads/main",
            malformed_json_body=body_sentinel,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Dry run could not complete a consistent comparison",
            result.stderr,
        )
        self.assertIn(
            "GitHub returned an invalid response during GET /git/ref/heads/main",
            result.stderr,
        )
        self.assertIn("Rerun the dry run before publishing", result.stderr)
        self.assertIn("No GitHub changes were made", result.stderr)
        self.assertNotIn(body_sentinel, output)
        self.assertNotIn("would be published", output)
        self.assertNotIn("already match", output)
        self.assertEqual(reported_changed_paths(result.stdout), [])
        self.assert_safe_failure_output(result)
        self.assert_no_source_contents_in_output(output)

        capture = json.loads(self.capture.read_text())
        requests = capture["requests"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            requests[0]["path"],
            "/repos/vitalitychems-dot/GitMesh/git/ref/heads/main",
        )
        self.assertTrue(requests[0]["hasExpectedBearer"])
        self.assertEqual(requests[0]["method"], "GET")
        self.assertFalse(any("/contents/" in request["path"] for request in requests))
        self.assertFalse(any(request["method"] in ("POST", "PATCH") for request in requests))

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
            "Usage: node ./sync-public-source.mjs [--dry-run] [--branch <name>] | [--check-local | --check-credentials | --check-history-credentials [--since <full-commit-sha>] | --check-staged-credentials | --check-push-credentials | --check-syntax].",
            result.stderr,
        )
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])

    def test_history_credential_check_reports_removed_values_without_leaking(self):
        base_commit = self.initialize_source_history()
        readme = self.source_root / "README.md"
        clean_readme = readme.read_bytes()
        history_token = "ghp_" + "H" * 36
        private_line = f"GITHUB_TOKEN={history_token}"
        readme.write_text(f"SAFE_HISTORY_HEADER\n{private_line}\nSAFE_HISTORY_FOOTER\n")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "temporary credential test fixture"])
        credential_commit = self.run_source_git(["rev-parse", "HEAD"])
        readme.write_bytes(clean_readme)
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "remove temporary test fixture"])
        head_before_scan = self.run_source_git(["rev-parse", "HEAD"])
        expected_args = (
            ("--check-history-credentials",),
            ("--check-history-credentials", "--since", base_commit),
        )

        for args in expected_args:
            with self.subTest(args=args):
                result = self.run_sync(token_value=None, args=args)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(credential_commit, output)
                self.assertIn("README.md (line 2)", output)
                self.assertIn("No GitHub requests were made", output)
                self.assertNotIn(history_token, output)
                self.assertNotIn(private_line, output)
                self.assertNotIn("SAFE_HISTORY_HEADER", output)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(capture["preflightCalls"], [])

        self.assertEqual(self.run_source_git(["rev-parse", "HEAD"]), head_before_scan)
        self.assertEqual(readme.read_bytes(), clean_readme)

    def test_history_credential_check_reports_merge_resolution_credentials_without_leaking(self):
        self.initialize_source_history()
        readme = self.source_root / "README.md"
        base_branch = self.run_source_git(["branch", "--show-current"])

        self.run_source_git(["checkout", "-b", "history-conflict-side"])
        readme.write_text("SAFE_CONFLICT_SIDE_PARENT\n", encoding="utf-8")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "safe side parent"])
        side_parent = self.run_source_git(["rev-parse", "HEAD"])

        self.run_source_git(["checkout", base_branch])
        readme.write_text("SAFE_CONFLICT_MAIN_PARENT\n", encoding="utf-8")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "safe main parent"])
        main_parent = self.run_source_git(["rev-parse", "HEAD"])

        merge = subprocess.run(
            ["git", "merge", "history-conflict-side"],
            cwd=self.source_root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        merge_output = merge.stdout + merge.stderr
        self.assertNotEqual(merge.returncode, 0, merge_output)
        self.assertIn("CONFLICT", merge_output)

        history_token = "ghp_" + "M" * 36
        private_line = f"GITHUB_TOKEN={history_token}"
        merge_source = f"SAFE_MERGE_HEADER\n{private_line}\nSAFE_MERGE_FOOTER\n"
        readme.write_text(merge_source, encoding="utf-8")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(
            ["commit", "--quiet", "-m", "resolve conflict with synthetic credential"]
        )
        merge_commit = self.run_source_git(["rev-parse", "HEAD"])
        merge_parents = self.run_source_git(
            ["rev-list", "--parents", "-n", "1", "HEAD"]
        ).split()
        self.assertEqual(merge_parents[0], merge_commit)
        self.assertEqual(set(merge_parents[1:]), {main_parent, side_parent})

        for parent in merge_parents[1:]:
            parent_source = self.run_source_git(["show", f"{parent}:README.md"])
            self.assertNotIn(history_token, parent_source)
            self.assertNotIn(private_line, parent_source)

        result = self.run_sync(
            token_value=None,
            args=("--check-history-credentials",),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        expected_location = f"{merge_commit} README.md (line 2)"
        self.assertEqual(output.count(expected_location), 1)
        self.assertEqual(output.count("README.md (line "), 1)
        for parent in merge_parents[1:]:
            self.assertNotIn(parent, output)
        for private_text in (
            history_token,
            private_line,
            "SAFE_MERGE_HEADER",
            "SAFE_MERGE_FOOTER",
            "SAFE_CONFLICT_MAIN_PARENT",
            "SAFE_CONFLICT_SIDE_PARENT",
        ):
            self.assertNotIn(private_text, output)
        self.assertIn("No GitHub requests were made", output)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])

    def test_history_credential_check_accepts_a_since_commit_range(self):
        self.initialize_source_history()
        readme = self.source_root / "README.md"
        clean_readme = readme.read_bytes()
        history_token = "ghp_" + "J" * 36
        readme.write_text(f"SAFE_HISTORY_HEADER\nGITHUB_TOKEN={history_token}\n")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "temporary credential test fixture"])
        credential_commit = self.run_source_git(["rev-parse", "HEAD"])
        readme.write_bytes(clean_readme)
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "remove temporary test fixture"])
        head_before_scan = self.run_source_git(["rev-parse", "HEAD"])

        result = self.run_sync(
            token_value=None,
            args=("--check-history-credentials", "--since", credential_commit),
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("History credential check passed", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn(history_token, output)
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])
        self.assertEqual(self.run_source_git(["rev-parse", "HEAD"]), head_before_scan)
        self.assertEqual(readme.read_bytes(), clean_readme)

    def test_history_credential_check_rejects_valid_non_ancestor_since_commit(self):
        self.initialize_source_history()
        base_branch = self.run_source_git(["branch", "--show-current"])
        readme = self.source_root / "README.md"
        history_token = "ghp_" + "N" * 36
        private_line = f"GITHUB_TOKEN={history_token}"
        readme.write_text(
            f"SAFE_HISTORY_HEADER\n{private_line}\nSAFE_HISTORY_FOOTER\n",
            encoding="utf-8",
        )
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "credential on current history"])
        credential_commit = self.run_source_git(["rev-parse", "HEAD"])

        self.run_source_git(["checkout", "-b", "unrelated-history-boundary"])
        readme.write_text("SAFE_UNRELATED_BOUNDARY_CONTENT\n", encoding="utf-8")
        self.run_source_git(["add", "README.md"])
        self.run_source_git(["commit", "--quiet", "-m", "valid non-ancestor boundary"])
        since_commit = self.run_source_git(["rev-parse", "HEAD"])
        self.assertEqual(
            self.run_source_git(["rev-parse", "--verify", f"{since_commit}^{{commit}}"]),
            since_commit,
        )

        self.run_source_git(["checkout", base_branch])
        head_before_scan = self.run_source_git(["rev-parse", "HEAD"])
        self.assertEqual(head_before_scan, credential_commit)
        self.assertNotEqual(since_commit, head_before_scan)
        self.assertEqual(
            self.run_source_git(["merge-base", since_commit, "HEAD"]),
            credential_commit,
        )
        self.assertEqual(self.run_source_git(["rev-list", f"{since_commit}..HEAD"]), "")

        result = self.run_sync(
            token_value=None,
            args=("--check-history-credentials", "--since", since_commit),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "The --since commit must be an ancestor of the current HEAD",
            output,
        )
        self.assertIn("No history was scanned", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("History credential check passed", output)
        self.assertNotIn("Credential-like values were found", output)
        for private_text in (
            history_token,
            private_line,
            "SAFE_HISTORY_HEADER",
            "SAFE_HISTORY_FOOTER",
            "SAFE_UNRELATED_BOUNDARY_CONTENT",
        ):
            self.assertNotIn(private_text, output)
        self.assert_safe_failure_output(result)
        self.assertEqual(self.run_source_git(["rev-parse", "HEAD"]), head_before_scan)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])

    def test_history_credential_check_fails_safely_for_large_history(self):
        self.initialize_source_history()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        wrapper_dir = self.temp_path / "history-git-wrapper"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "if len(sys.argv) > 1 and sys.argv[1] == 'log':\n"
            "    for index in range(501):\n"
            "        print(f'{index + 1:040x}')\n"
            "        print('README.md')\n"
            "    raise SystemExit(0)\n"
            f"os.execv({real_git!r}, [{real_git!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join((str(wrapper_dir), env.get("PATH", "")))
        head_before_scan = self.run_source_git(["rev-parse", "HEAD"])

        result = self.run_sync(
            token_value=None,
            args=("--check-history-credentials",),
            env_overrides={"PATH": env["PATH"]},
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("500-commit limit", output)
        self.assertIn("--since <full-commit-sha>", output)
        self.assertIn("No GitHub requests were made", output)
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(self.run_source_git(["rev-parse", "HEAD"]), head_before_scan)

    def test_history_credential_check_refuses_shallow_repositories(self):
        head_commit = self.initialize_source_history()
        shallow_file = self.source_root / ".git" / "shallow"
        shallow_file.write_text(f"{head_commit}\n", encoding="utf-8")

        result = self.run_sync(token_value=None, args=("--check-history-credentials",))
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete history in a shallow clone", output)
        self.assertIn("Use a full clone", output)
        self.assertIn("No GitHub requests were made", output)
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

    def test_local_source_check_passes_without_token_or_github_requests(self):
        result = self.run_sync(token_value=None, args=("--check-local",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no credential-like values found in 3 allowlisted source files", result.stdout)
        self.assertIn("JavaScript syntax passed for 2 allowlisted JavaScript source files", result.stdout)
        self.assertIn("No GitHub requests were made", result.stdout)
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

    def test_local_source_check_reports_credentials_without_leaking(self):
        readme = self.source_root / "README.md"
        original_content = readme.read_bytes()
        credential = "ghp_" + "L" * 36
        source_line = f"example={credential}"
        try:
            readme.write_text(f"safe configuration\n{source_line}\n")
            result = self.run_sync(token_value=None, args=("--check-local",))
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("credential-like value", result.stderr)
            self.assertIn(
                "Refusing to check local source files containing a credential-like value",
                result.stderr,
            )
            self.assertIn("README.md (line 2)", result.stderr)
            self.assertIn(
                "Rerun the local source check with --check-local after removing the reported value.",
                result.stderr,
            )
            self.assertNotIn("Refusing to sync source files", result.stderr)
            self.assertIn("No GitHub requests were made", result.stderr)
            self.assertNotIn(credential, output)
            self.assertNotIn(source_line, output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
        finally:
            readme.write_bytes(original_content)

    def test_local_source_check_reports_syntax_failure_without_leaking(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        invalid_line = "const INVALID_COMBINED_SYNTAX_SENTINEL = ;"
        invalid_source = f"const SAFE_COMBINED_SYNTAX_CONTEXT = 1;\n{invalid_line}\n"
        try:
            source_path.write_text(invalid_source)
            result = self.run_sync(token_value=None, args=("--check-local",))
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                f"{source_path.name} (line 2, column {invalid_line.index(';') + 1})",
                result.stderr,
            )
            self.assertIn(
                "rerun the combined local source check with --check-local",
                result.stderr,
            )
            self.assertIn("No GitHub requests were made", result.stderr)
            self.assertNotIn(invalid_source, output)
            self.assertNotIn(invalid_line, output)
            self.assertNotIn("INVALID_COMBINED_SYNTAX_SENTINEL", output)
            self.assertNotIn("SyntaxError", output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_local_source_check_reports_both_failure_types_without_leaking(self):
        readme = self.source_root / "README.md"
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_readme = readme.read_bytes()
        original_source = source_path.read_bytes()
        credential = "ghp_" + "M" * 36
        credential_line = f"example={credential}"
        invalid_line = "const INVALID_BOTH_CHECKS_SENTINEL = ;"
        invalid_source = f"const SAFE_BOTH_CHECKS_CONTEXT = 1;\n{invalid_line}\n"
        try:
            readme.write_text(f"safe configuration\n{credential_line}\n")
            source_path.write_text(invalid_source)
            result = self.run_sync(token_value=None, args=("--check-local",))
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Local source check found 2 issues", result.stderr)
            self.assertIn(
                "Refusing to check local source files containing a credential-like value",
                result.stderr,
            )
            self.assertIn(
                "Rerun the local source check with --check-local after removing the reported value.",
                result.stderr,
            )
            self.assertNotIn("Refusing to sync source files", result.stderr)
            self.assertIn("README.md (line 2)", result.stderr)
            self.assertIn(
                f"{source_path.name} (line 2, column {invalid_line.index(';') + 1})",
                result.stderr,
            )
            self.assertNotIn(credential, output)
            self.assertNotIn(credential_line, output)
            self.assertNotIn(invalid_source, output)
            self.assertNotIn(invalid_line, output)
            self.assertNotIn("INVALID_BOTH_CHECKS_SENTINEL", output)
            self.assertNotIn("SyntaxError", output)
            self.assertIn("No GitHub requests were made", result.stderr)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
        finally:
            readme.write_bytes(original_readme)
            source_path.write_bytes(original_source)

    def test_local_javascript_syntax_check_passes_and_rejects_invalid_source_safely(self):
        javascript_sources = [
            source for source in ALLOWED_SOURCE_NAMES if source.endswith(".mjs")
        ]
        expected_reads = Counter(
            (method, str((self.source_root / source).resolve()))
            for source in javascript_sources
            for method in ("lstatSync", "openSync", "readFileSync")
        )

        success = self.run_sync(token_value=None, args=("--check-syntax",))
        self.assertEqual(success.returncode, 0)
        self.assertIn(
            "JavaScript syntax check passed for 2 allowlisted JavaScript source files",
            success.stdout,
        )
        self.assertNotIn("Credential check passed", success.stdout)
        self.assert_safe_failure_output(success)
        success_capture = json.loads(self.capture.read_text())
        self.assertEqual(success_capture["requests"], [])
        self.assertEqual(success_capture["preflightCalls"], [])
        success_reads = Counter(
            (event["method"], event["path"])
            for event in success_capture["filesystemReads"]
        )
        self.assertEqual(success_reads, expected_reads)

        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        invalid_line = "const INVALID_LOCAL_SYNTAX_SENTINEL = ;"
        invalid_source = f"const SAFE_SYNTAX_CONTEXT = 1;\n{invalid_line}\n"
        try:
            source_path.write_text(invalid_source)
            failure = self.run_sync(token_value=None, args=("--check-syntax",))
            output = failure.stdout + failure.stderr

            self.assertNotEqual(failure.returncode, 0)
            self.assertIn(
                f"{source_path.name} (line 2, column {invalid_line.index(';') + 1})",
                failure.stderr,
            )
            self.assertIn(
                "Review and correct this file, save it, then rerun the local syntax check with --check-syntax.",
                failure.stderr,
            )
            self.assertIn("No GitHub requests were made", failure.stderr)
            self.assertNotIn(invalid_source, output)
            self.assertNotIn(invalid_line, output)
            self.assertNotIn("SAFE_SYNTAX_CONTEXT", output)
            self.assertNotIn("INVALID_LOCAL_SYNTAX_SENTINEL", output)
            self.assertNotIn("SyntaxError", output)
            self.assertNotIn("Unexpected token", output)
            self.assertNotIn("[stdin]", output)
            self.assertNotIn("Node.js v", output)
            self.assert_safe_failure_output(failure)

            failure_capture = json.loads(self.capture.read_text())
            self.assertEqual(failure_capture["requests"], [])
            self.assertEqual(failure_capture["preflightCalls"], [])
            failure_reads = Counter(
                (event["method"], event["path"])
                for event in failure_capture["filesystemReads"]
            )
            self.assertEqual(failure_reads, expected_reads)
        finally:
            source_path.write_bytes(original_content)

    def test_local_syntax_check_reports_all_invalid_files_without_leaking(self):
        core_path = self.source_root / "gitmesh-ultimate-core.mjs"
        sync_path = self.source_root / "sync-public-source.mjs"
        fixture_path = self.source_root / "syntax-check-fixture.mjs"
        original_core = core_path.read_bytes()
        original_sync = sync_path.read_bytes()
        core_invalid_line = "const INVALID_CORE_SYNTAX_SENTINEL = ;"
        core_invalid_source = f"const SAFE_CORE_SYNTAX_CONTEXT = 1;\n{core_invalid_line}\n"
        fixture_invalid_line = "const INVALID_FIXTURE_SYNTAX_SENTINEL = ;"
        fixture_invalid_source = (
            "const SAFE_FIXTURE_CONTEXT = 1;\n"
            "const SAFE_FIXTURE_SECOND_LINE = 2;\n"
            f"{fixture_invalid_line}\n"
        )
        fixture_entry = (
            '  {\n'
            '    source: "syntax-check-fixture.mjs",\n'
            '    target: "projects/local-vault/syntax-check-fixture.mjs",\n'
            '  },\n'
        )
        allowlist_header = "const ALLOWED_FILES = [\n"
        sync_text = original_sync.decode("utf-8")
        self.assertIn(allowlist_header, sync_text)
        sync_path.write_text(
            sync_text.replace(allowlist_header, allowlist_header + fixture_entry, 1),
            encoding="utf-8",
        )

        try:
            core_path.write_text(core_invalid_source, encoding="utf-8")
            fixture_path.write_text(fixture_invalid_source, encoding="utf-8")

            result = self.run_sync(token_value=None, args=("--check-syntax",))
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Local JavaScript syntax check found 2 issues in allowlisted JavaScript source files",
                result.stderr,
            )
            self.assertIn(
                f"{core_path.name} (line 2, column {core_invalid_line.index(';') + 1})",
                result.stderr,
            )
            self.assertIn(
                f"{fixture_path.name} (line 3, column {fixture_invalid_line.index(';') + 1})",
                result.stderr,
            )
            self.assertIn(
                "Review and correct this file, save it, then rerun the local syntax check with --check-syntax.",
                result.stderr,
            )
            self.assertIn("No GitHub requests were made", result.stderr)
            for private_text in (
                core_invalid_source,
                core_invalid_line,
                "SAFE_CORE_SYNTAX_CONTEXT",
                fixture_invalid_source,
                fixture_invalid_line,
                "SAFE_FIXTURE_CONTEXT",
                "SAFE_FIXTURE_SECOND_LINE",
                "SyntaxError",
                "Unexpected token",
                "[stdin]",
                "Node.js v",
            ):
                self.assertNotIn(private_text, output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
            javascript_sources = (
                "gitmesh-ultimate-core.mjs",
                "sync-public-source.mjs",
                "syntax-check-fixture.mjs",
            )
            expected_reads = Counter(
                (method, str((self.source_root / source).resolve()))
                for source in javascript_sources
                for method in ("lstatSync", "openSync", "readFileSync")
            )
            observed_reads = Counter(
                (event["method"], event["path"])
                for event in capture["filesystemReads"]
            )
            self.assertEqual(observed_reads, expected_reads)
        finally:
            core_path.write_bytes(original_core)
            sync_path.write_bytes(original_sync)
            fixture_path.unlink(missing_ok=True)

    def test_local_syntax_check_repairs_unavailable_linked_and_oversized_sources(self):
        source_name = "gitmesh-ultimate-core.mjs"
        source_path = self.source_root / source_name
        private_path = self.source_root / "SovereignMeshVault/ledger_matrix/private-record.json"
        original_content = source_path.read_bytes()
        unavailable_guidance = (
            "Review and save the intended file state, then rerun the local syntax check "
            "with --check-syntax."
        )
        linked_guidance = (
            "Save it as a regular file within the size limit, then rerun the local syntax check "
            "with --check-syntax."
        )
        cases = (
            (
                "unavailable",
                "Refusing to check an unavailable JavaScript source file",
                unavailable_guidance,
                (),
                [],
            ),
            (
                "symlink",
                "Refusing to check an invalid, linked, or oversized JavaScript source file",
                linked_guidance,
                ("PRIVATE_RECORD_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "hard link",
                "Refusing to check an invalid, linked, or oversized JavaScript source file",
                linked_guidance,
                ("PRIVATE_RECORD_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "oversized",
                "Refusing to check an invalid, linked, or oversized JavaScript source file",
                linked_guidance,
                ("OVERSIZED_SYNTAX_CHECK_SOURCE_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
        )

        try:
            for case_name, expected_error, expected_guidance, sentinels, expected_reads in cases:
                with self.subTest(source_type=case_name):
                    source_path.unlink(missing_ok=True)
                    if case_name == "symlink":
                        source_path.symlink_to(private_path)
                    elif case_name == "hard link":
                        os.link(private_path, source_path)
                    elif case_name == "oversized":
                        source_path.write_bytes(
                            b"OVERSIZED_SYNTAX_CHECK_SOURCE_SENTINEL" + b"x" * (512 * 1024)
                        )

                    result = self.run_sync(
                        token_value=None,
                        args=("--check-syntax",),
                    )
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)
                    self.assertIn(source_name, result.stderr)
                    self.assertIn(expected_guidance, result.stderr)
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn("--check-credentials", output)
                    self.assertNotIn("rerun sync", output)
                    self.assertNotIn("Refusing to sync", output)
                    for sentinel in sentinels:
                        self.assertNotIn(sentinel, output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
                    observed_reads = [
                        (event["method"], event["path"])
                        for event in capture["filesystemReads"]
                        if event["path"] == str(source_path)
                    ]
                    self.assertEqual(observed_reads, expected_reads)
        finally:
            source_path.unlink(missing_ok=True)
            source_path.write_bytes(original_content)

    def test_local_credential_check_reports_location_without_exposing_value(self):
        source_path = self.source_root / "README.md"
        credential = "ghp_" + "R" * 36
        source_line = f"Example configuration value: {credential}"
        source_path.write_text(source_line + "\n")

        result = self.run_sync(token_value=None, args=("--check-credentials",))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Refusing to check local source files containing a credential-like value",
            result.stderr,
        )
        self.assertIn(f"{source_path.name} (line 1)", result.stderr)
        self.assertIn("Remove the value from this file", result.stderr)
        self.assertIn(
            "Rerun the local credential check with --check-credentials after removing the reported value.",
            result.stderr,
        )
        self.assertNotIn("Refusing to sync source files", result.stderr)
        self.assertIn("No GitHub requests were made", result.stderr)
        self.assertNotIn(credential, result.stdout + result.stderr)
        self.assertNotIn(source_line, result.stdout + result.stderr)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(capture["preflightCalls"], [])

    def test_local_credential_check_repairs_unavailable_linked_and_oversized_sources(self):
        source_name = "gitmesh-ultimate-core.mjs"
        source_path = self.source_root / source_name
        private_path = self.source_root / "SovereignMeshVault/ledger_matrix/private-record.json"
        original_content = source_path.read_bytes()
        local_guidance = (
            "Replace it with a standalone regular file (not a symlink or hard link) no larger than "
            "512 KiB, then rerun the local credential check with --check-credentials."
        )
        cases = (
            (
                "unavailable",
                "Refusing to check an unavailable source file",
                "Restore or recreate the intended file at this path, then rerun the local credential check with --check-credentials.",
                (),
                [],
            ),
            (
                "symlink",
                "Refusing to check an invalid, linked, or oversized source file",
                local_guidance,
                ("PRIVATE_RECORD_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "hard link",
                "Refusing to check an invalid, linked, or oversized source file",
                local_guidance,
                ("PRIVATE_RECORD_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
            (
                "oversized",
                "Refusing to check an invalid, linked, or oversized source file",
                local_guidance,
                ("OVERSIZED_LOCAL_CHECK_SOURCE_SENTINEL",),
                [("lstatSync", str(source_path))],
            ),
        )

        try:
            for case_name, expected_error, expected_guidance, sentinels, expected_reads in cases:
                with self.subTest(source_type=case_name):
                    source_path.unlink(missing_ok=True)
                    if case_name == "symlink":
                        source_path.symlink_to(private_path)
                    elif case_name == "hard link":
                        os.link(private_path, source_path)
                    elif case_name == "oversized":
                        source_path.write_bytes(
                            b"OVERSIZED_LOCAL_CHECK_SOURCE_SENTINEL" + b"x" * (512 * 1024)
                        )

                    result = self.run_sync(
                        token_value=None,
                        args=("--check-credentials",),
                    )
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)
                    self.assertIn(source_name, result.stderr)
                    self.assertIn(expected_guidance, result.stderr)
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn("rerun sync", output)
                    self.assert_safe_failure_output(result)
                    for sentinel in sentinels:
                        self.assertNotIn(sentinel, output)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
                    observed_reads = [
                        (event["method"], event["path"])
                        for event in capture["filesystemReads"]
                        if event["path"] == str(source_path)
                    ]
                    self.assertEqual(observed_reads, expected_reads)
        finally:
            source_path.unlink(missing_ok=True)
            source_path.write_bytes(original_content)

    def test_local_credential_check_reports_all_files_needing_repair(self):
        core_path = self.source_root / "gitmesh-ultimate-core.mjs"
        readme_path = self.source_root / "README.md"
        sync_path = self.source_root / "sync-public-source.mjs"
        private_path = self.source_root / "SovereignMeshVault/ledger_matrix/private-record.json"
        original_core = core_path.read_bytes()
        original_readme = readme_path.read_bytes()
        original_sync = sync_path.read_bytes()
        oversized_sentinel = b"OVERSIZED_AGGREGATE_SOURCE_SENTINEL"
        private_sentinel = "PRIVATE_RECORD_SENTINEL"
        credential = "ghp_" + "K" * 36
        credential_line = f"// temporary credential fixture: {credential}"

        try:
            core_path.write_bytes(oversized_sentinel + b"x" * (512 * 1024))
            readme_path.unlink()
            readme_path.symlink_to(private_path)
            sync_text = original_sync.decode("utf-8").rstrip("\r\n")
            credential_line_number = len(sync_text.splitlines()) + 1
            sync_path.write_text(f"{sync_text}\n{credential_line}\n", encoding="utf-8")

            result = self.run_sync(token_value=None, args=("--check-credentials",))
            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Local credential check could not inspect every allowlisted source file", output)
            self.assertIn(core_path.name, output)
            self.assertIn("512 KiB", output)
            self.assertIn(readme_path.name, output)
            self.assertIn("not a symlink or hard link", output)
            self.assertIn(sync_path.name, output)
            self.assertIn(f"line {credential_line_number}", output)
            self.assertIn("rerun --check-credentials", output)
            self.assertIn("No GitHub requests were made", output)
            self.assertNotIn(credential, output)
            self.assertNotIn(credential_line, output)
            self.assertNotIn(oversized_sentinel.decode(), output)
            self.assertNotIn(private_sentinel, output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
        finally:
            core_path.write_bytes(original_core)
            readme_path.unlink(missing_ok=True)
            readme_path.write_bytes(original_readme)
            sync_path.write_bytes(original_sync)

    def test_local_credential_check_sanitizes_permission_denied_open_failures(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        private_content = b"PRIVATE_UNREADABLE_SOURCE_SENTINEL"

        try:
            source_path.write_bytes(private_content)
            result = self.run_sync(
                token_value=None,
                args=("--check-credentials",),
                env_overrides={
                    "GITMESH_TEST_PERMISSION_DENIED_PATH": str(source_path),
                },
            )
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Local credential check could not inspect every allowlisted source file",
                result.stderr,
            )
            self.assertIn(source_path.name, result.stderr)
            self.assertIn(
                "Restore it as a standalone regular file, save it, then rerun the local credential check with --check-credentials.",
                result.stderr,
            )
            self.assertIn("No GitHub requests were made", result.stderr)
            self.assertNotIn("EACCES", output)
            self.assertNotIn("permission denied", output)
            self.assertNotIn("PRIVATE_PERMISSION_OS_DIAGNOSTIC_SENTINEL", output)
            self.assertNotIn("PRIVATE_UNREADABLE_SOURCE_SENTINEL", output)
            self.assertNotIn(str(source_path), output)
            self.assertNotIn("rerun sync", output)
            self.assert_safe_failure_output(result)

            capture = json.loads(self.capture.read_text())
            self.assertEqual(capture["requests"], [])
            self.assertEqual(capture["preflightCalls"], [])
            source_reads = [
                (event["method"], event["path"])
                for event in capture["filesystemReads"]
                if event["path"] == str(source_path)
            ]
            self.assertEqual(
                source_reads,
                [
                    ("lstatSync", str(source_path)),
                    ("openSync", str(source_path)),
                ],
            )
        finally:
            source_path.write_bytes(original_content)

    def test_local_credential_check_guides_non_text_repair_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        non_text_cases = (
            ("invalid UTF-8", b"\xffLOCAL_INVALID_UTF8_CONTENT_SENTINEL"),
            ("NUL byte", b"\x00LOCAL_NUL_CONTENT_SENTINEL"),
        )

        try:
            for case_name, content in non_text_cases:
                with self.subTest(case=case_name):
                    source_path.write_bytes(content)
                    result = self.run_sync(
                        token_value=None,
                        args=("--check-credentials",),
                    )
                    output = result.stdout + result.stderr

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"Refusing to check a non-text source file: {source_path.name}.",
                        result.stderr,
                    )
                    self.assertIn(
                        "Save the intended source as valid UTF-8 plain text, then rerun the local credential check with --check-credentials.",
                        result.stderr,
                    )
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn("rerun sync", output)
                    self.assertNotIn(content.decode("latin1"), output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

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
        invalid_line = "const INVALID_JS_SOURCE_SENTINEL = ;"
        invalid_source = f"const SAFE_SYNTAX_CONTEXT = 1;\n{invalid_line}\n"
        source_path.write_text(invalid_source)

        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node syntax validation", result.stderr)
        self.assertIn(
            f"{source_path.name} (line 2, column {invalid_line.index(';') + 1})",
            result.stderr,
        )
        self.assertIn(
            "Review and correct this file, save it, then rerun sync. No GitHub requests were made.",
            result.stderr,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(invalid_source, output)
        self.assertNotIn(invalid_line, output)
        self.assertNotIn("SAFE_SYNTAX_CONTEXT", output)
        self.assertNotIn("INVALID_JS_SOURCE_SENTINEL", output)
        self.assertNotIn("SyntaxError", output)
        self.assertNotIn("Unexpected token", output)
        self.assertNotIn("[stdin]", output)
        self.assertNotIn("Node.js v", output)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])

    def test_javascript_syntax_locations_are_accurate_with_tabs_and_crlf_without_leaking_source(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        cases = (
            (
                "tab",
                b"const SAFE_SYNTAX_CONTEXT = 1;\n\tconst TAB_SYNTAX_SOURCE_SENTINEL = ;\n",
                "\tconst TAB_SYNTAX_SOURCE_SENTINEL = ;",
            ),
            (
                "CRLF",
                b"const SAFE_SYNTAX_CONTEXT = 1;\r\nconst CRLF_SYNTAX_SOURCE_SENTINEL = ;\r\n",
                "const CRLF_SYNTAX_SOURCE_SENTINEL = ;",
            ),
        )
        try:
            for case_name, invalid_source, invalid_line in cases:
                with self.subTest(case=case_name):
                    source_path.write_bytes(invalid_source)
                    result = self.run_sync()
                    output = result.stdout + result.stderr

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{source_path.name} (line 2, column {invalid_line.index(';') + 1})",
                        result.stderr,
                    )
                    self.assertIn(
                        "Review and correct this file, save it, then rerun sync. No GitHub requests were made.",
                        result.stderr,
                    )
                    self.assertNotIn(invalid_source.decode(), output)
                    self.assertNotIn(invalid_line, output)
                    self.assertNotIn("TAB_SYNTAX_SOURCE_SENTINEL", output)
                    self.assertNotIn("CRLF_SYNTAX_SOURCE_SENTINEL", output)
                    self.assertNotIn("SyntaxError", output)
                    self.assertNotIn("[stdin]", output)
                    self.assertNotIn("Node.js v", output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_javascript_syntax_columns_follow_utf16_units_after_emoji_and_combining_marks(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        cases = (
            (
                "emoji",
                'const prefix = "😀"; const EMOJI_SYNTAX_SOURCE_SENTINEL = ;',
                "EMOJI_SYNTAX_SOURCE_SENTINEL",
            ),
            (
                "combining accent",
                'const prefix = "e\u0301"; const COMBINING_SYNTAX_SOURCE_SENTINEL = ;',
                "COMBINING_SYNTAX_SOURCE_SENTINEL",
            ),
        )
        try:
            for case_name, invalid_line, source_sentinel in cases:
                with self.subTest(case=case_name):
                    invalid_source = f"const SAFE_SYNTAX_CONTEXT = 1;\n{invalid_line}\n"
                    source_path.write_text(invalid_source, encoding="utf-8")
                    result = self.run_sync()
                    output = result.stdout + result.stderr
                    token_index = invalid_line.rindex(";")
                    utf16_column = (
                        len(invalid_line[:token_index].encode("utf-16-le")) // 2
                    ) + 1

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{source_path.name} (line 2, column {utf16_column})",
                        result.stderr,
                    )
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn(invalid_source, output)
                    self.assertNotIn(invalid_line, output)
                    self.assertNotIn(source_sentinel, output)
                    self.assertNotIn("const prefix", output)
                    self.assertNotIn("SyntaxError", output)
                    self.assertNotIn("[stdin]", output)
                    self.assertNotIn("Node.js v", output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_javascript_syntax_locations_follow_unicode_line_separators_without_leaking_source(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        safe_header = "const SAFE_UNICODE_SEPARATOR_CONTEXT = 1;"
        invalid_line = "const UNICODE_SEPARATOR_SYNTAX_SOURCE_SENTINEL = ;"
        cases = (
            ("U+2028", "\u2028"),
            ("U+2029", "\u2029"),
        )
        try:
            for case_name, separator in cases:
                with self.subTest(separator=case_name):
                    invalid_source = f"{safe_header}{separator}{invalid_line}\n"
                    source_path.write_text(invalid_source, encoding="utf-8")
                    result = self.run_sync()
                    output = result.stdout + result.stderr
                    expected_column = invalid_line.index(";") + 1

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{source_path.name} (line 2, column {expected_column})",
                        result.stderr,
                    )
                    self.assertIn("No GitHub requests were made", result.stderr)
                    self.assertNotIn(invalid_source, output)
                    self.assertNotIn(invalid_line, output)
                    self.assertNotIn(safe_header, output)
                    self.assertNotIn("UNICODE_SEPARATOR_SYNTAX_SOURCE_SENTINEL", output)
                    self.assertNotIn("SyntaxError", output)
                    self.assertNotIn("[stdin]", output)
                    self.assertNotIn("Node.js v", output)
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_syntax_diagnostics_are_sanitized_across_node_formats(self):
        source_path = self.source_root / "gitmesh-ultimate-core.mjs"
        original_content = source_path.read_bytes()
        invalid_line = "const PRIVATE_NODE_FORMAT_SOURCE_SENTINEL = ;"
        invalid_source = f"const SAFE_SYNTAX_CONTEXT = 1;\n{invalid_line}\n"
        column = invalid_line.index(";") + 1
        source_path.write_text(invalid_source)

        cases = (
            (
                "caret-format",
                (
                    "[stdin]:2\n"
                    f"{invalid_line}\n"
                    f"{' ' * (column - 1)}^\n"
                    "SyntaxError: RAW_NODE_DIAGNOSTIC_SENTINEL"
                ),
                f"{source_path.name} (line 2, column {column})",
            ),
            (
                "explicit-column-format",
                (
                    f"[stdin]:2:{column}\n"
                    f"{invalid_line}\n"
                    f"{' ' * (column - 1)}^\n"
                    "SyntaxError: RAW_NODE_DIAGNOSTIC_SENTINEL"
                ),
                f"{source_path.name} (line 2, column {column})",
            ),
            (
                "unrecognized-format",
                (
                    "RAW_UNKNOWN_NODE_FORMAT_SENTINEL\n"
                    f"{invalid_line}\n"
                ),
                source_path.name,
            ),
            (
                "malformed-location",
                (
                    "[stdin]:9007199254740992:999999999999999999999\n"
                    f"{invalid_line}\n"
                    "^\n"
                    "RAW_MALFORMED_NODE_LOCATION_SENTINEL"
                ),
                source_path.name,
            ),
        )
        try:
            for case_name, diagnostics, expected_location in cases:
                with self.subTest(format=case_name):
                    result = self.run_sync(
                        env_overrides={
                            "GITMESH_TEST_NODE_SYNTAX_DIAGNOSTICS": diagnostics,
                        }
                    )
                    output = result.stdout + result.stderr

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_location, result.stderr)
                    self.assertIn(
                        "Review and correct this file, save it, then rerun sync. No GitHub requests were made.",
                        result.stderr,
                    )
                    self.assertNotIn(invalid_source, output)
                    self.assertNotIn(invalid_line, output)
                    self.assertNotIn("PRIVATE_NODE_FORMAT_SOURCE_SENTINEL", output)
                    self.assertNotIn("RAW_NODE_DIAGNOSTIC_SENTINEL", output)
                    self.assertNotIn("RAW_UNKNOWN_NODE_FORMAT_SENTINEL", output)
                    self.assertNotIn("RAW_MALFORMED_NODE_LOCATION_SENTINEL", output)
                    self.assertNotIn("[stdin]", output)
                    self.assertNotIn("SyntaxError", output)
                    self.assertNotIn("Node.js v", output)
                    if case_name in {"unrecognized-format", "malformed-location"}:
                        self.assertNotRegex(
                            result.stderr,
                            r"\(line \d+, column \d+\)",
                        )
                    self.assert_safe_failure_output(result)

                    capture = json.loads(self.capture.read_text())
                    self.assertEqual(capture["requests"], [])
                    self.assertEqual(capture["preflightCalls"], [])
        finally:
            source_path.write_bytes(original_content)

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
                    warning = (
                        "Refusing to sync source files containing a credential-like value:"
                        if mode == "sync"
                        else "Refusing to check local source files containing a credential-like value:"
                    )
                    self.assertEqual(
                        result.stderr.count(warning),
                        1,
                    )
                    if mode == "local check without token":
                        self.assertIn(
                            "Rerun the local credential check with --check-credentials after removing the reported value.",
                            result.stderr,
                        )
                        self.assertNotIn(
                            "Refusing to sync source files containing a credential-like value:",
                            result.stderr,
                        )
                    else:
                        self.assertNotIn("Refusing to check local source files", result.stderr)
                        self.assertNotIn("Rerun the local credential check", result.stderr)
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

    def test_embedded_credentials_report_lines_for_blank_boundary_separators_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        cases = (
            (
                "leading separators",
                "\r\n\u2028\r",
                ("ghp_" + "A" * 36,),
                (),
                "\n",
                (4,),
            ),
            (
                "trailing separators",
                "SAFE_TRAILING_HEADER\r\n",
                ("github_pat_" + "B" * 40,),
                (),
                "\r\n\u2028\u2029\r\r",
                (2,),
            ),
            (
                "repeated separators",
                "SAFE_REPEATED_HEADER\u2028\u2028",
                ("npm_" + "C" * 36, "xoxb-" + "D" * 24, "sk_live_" + "E" * 24),
                ("\r\r", "\u2029\u2029"),
                "",
                (3, 5, 7),
            ),
        )

        try:
            for label, prefix, credentials, separators, suffix, expected_lines in cases:
                credential_lines = tuple(
                    f"token_{index}={credential}"
                    for index, credential in enumerate(credentials, start=1)
                )
                source_text = prefix + credential_lines[0]
                for separator, credential_line in zip(separators, credential_lines[1:]):
                    source_text += separator + credential_line
                source_text += suffix
                source_path.write_bytes(source_text.encode("utf-8"))

                expected_line_label = (
                    f"line {expected_lines[0]}"
                    if len(expected_lines) == 1
                    else f"lines {', '.join(str(line) for line in expected_lines)}"
                )
                for mode, args, token_value in (
                    ("sync", (), FAKE_GITHUB_TOKEN),
                    ("local check without token", ("--check-credentials",), None),
                ):
                    with self.subTest(case=label, mode=mode):
                        result = self.run_sync(args=args, token_value=token_value)
                        output = result.stdout + result.stderr
                        safe_output = output
                        private_texts = [
                            *credentials,
                            *credential_lines,
                            "SAFE_TRAILING_HEADER",
                            "SAFE_REPEATED_HEADER",
                            FAKE_GITHUB_TOKEN,
                        ]
                        for private_text in private_texts:
                            safe_output = safe_output.replace(
                                private_text,
                                "[redacted test content]",
                            )

                        self.assertNotEqual(result.returncode, 0, safe_output)
                        self.assertIn(
                            f"{source_path.name} ({expected_line_label})",
                            result.stderr,
                            safe_output,
                        )
                        self.assertIn("No GitHub requests were made", result.stderr, safe_output)
                        for private_text in private_texts:
                            self.assertFalse(private_text in output, safe_output)
                        self.assert_safe_failure_output(result)

                        capture = json.loads(self.capture.read_text())
                        self.assertEqual(capture["requests"], [])
        finally:
            source_path.write_bytes(original_content)

    def test_embedded_credentials_report_lines_with_bom_before_leading_separators_without_leaking(self):
        source_path = self.source_root / "README.md"
        original_content = source_path.read_bytes()
        credential = "ghp_" + "F" * 36
        credential_line = f"token={credential}"
        source_text = "\ufeff\r\n\u2028\r" + credential_line + "\n"

        try:
            source_path.write_bytes(source_text.encode("utf-8"))

            for mode, args, token_value in (
                ("sync", (), FAKE_GITHUB_TOKEN),
                ("local credential check", ("--check-credentials",), None),
                ("combined local check", ("--check-local",), None),
            ):
                with self.subTest(mode=mode):
                    result = self.run_sync(args=args, token_value=token_value)
                    output = result.stdout + result.stderr
                    safe_output = output.replace(
                        credential,
                        "[redacted test credential]",
                    )

                    self.assertNotEqual(result.returncode, 0, safe_output)
                    self.assertIn("README.md (line 4)", result.stderr, safe_output)
                    self.assertIn("No GitHub requests were made", result.stderr, safe_output)
                    self.assertNotIn(credential, output)
                    self.assertNotIn(credential_line, output)
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
        safe_class_block = re.search(
            r"const SAFE_PREFLIGHT_TEST_CLASSES = new Set\(\[(.*?)\]\);",
            sync_source,
            re.DOTALL,
        )
        self.assertIsNotNone(
            safe_class_block,
            "Could not find the safe preflight test-class allowlist.",
        )
        safe_class_names = set(
            re.findall(r'"([A-Za-z0-9_]+)"', safe_class_block.group(1))
        )
        test_source = pathlib.Path(__file__).read_text()
        test_class_names = set(
            re.findall(r"^class ([A-Za-z0-9_]+)\(", test_source, re.MULTILINE)
        )
        self.assertEqual(safe_class_names, test_class_names)
        test_method_names = re.findall(
            r"^\s+def (test_[A-Za-z0-9_]+)\(",
            test_source,
            re.MULTILINE,
        )
        regression_test_names = set(test_method_names)
        self.assertEqual(
            safe_names,
            regression_test_names,
            "Keep the safe preflight names in sync with all regression tests.",
        )
        eligible_name_counts = Counter(
            name for name in test_method_names if name in safe_names
        )
        duplicate_eligible_names = sorted(
            name for name, count in eligible_name_counts.items() if count > 1
        )
        self.assertEqual(
            duplicate_eligible_names,
            [],
            "Safe preflight summaries identify tests by method name, so eligible names must be unique across test classes.",
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

    def test_outdated_python_version_stops_before_preflight_and_github_without_leaking_output(self):
        source_sentinel = "PYTHON_VERSION_SOURCE_SENTINEL"
        credential_sentinel = "ghp_" + "R" * 36
        version_output = f"{source_sentinel}\n{credential_sentinel}"
        result = self.run_sync(
            preflight_mode="failure",
            preflight_python_version="3.8",
            preflight_version_stderr=version_output,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("The installed Python version is too old.", result.stderr)
        self.assertIn("Detected Python 3.8.", result.stderr)
        self.assertIn(
            "Python 3.9 or newer is required for the security regression preflight.",
            result.stderr,
        )
        self.assertIn(
            "Install or upgrade Python to 3.9 or newer using your operating system's package manager or python.org",
            result.stderr,
        )
        self.assertIn(
            "confirm python3 --version reports 3.9 or newer",
            result.stderr,
        )
        self.assertIn(
            "Run locally from the workspace root: "
            "python3 gitmesh-template/tests/test_security_regressions.py.",
            result.stderr,
        )
        self.assertIn("No GitHub requests were made", result.stderr)
        self.assertNotIn(source_sentinel, output)
        self.assertNotIn(credential_sentinel, output)
        self.assertNotIn(version_output, output)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(len(capture["preflightCalls"]), 1)
        self.assertEqual(capture["preflightCalls"][0]["command"], "python3")
        self.assertEqual(
            capture["preflightCalls"][0]["args"],
            [
                "-c",
                "import sys; print('%s.%s' % (sys.version_info[0], sys.version_info[1]))",
            ],
        )
        self.assertFalse(capture["preflightCalls"][0]["hasGitHubToken"])

    def test_invalid_python_version_output_stops_before_preflight_and_github_without_leaking(self):
        source_sentinel = "PYTHON_VERSION_STDOUT_SOURCE_SENTINEL"
        extra_text_sentinel = "PYTHON_VERSION_EXTRA_TEXT_SENTINEL"
        credential_sentinel = "ghp_" + "S" * 36
        version_stderr = f"PYTHON_VERSION_STDERR_PRIVATE_SENTINEL\n{credential_sentinel}"
        cases = (
            ("empty", ""),
            ("malformed", f"not-a-version {source_sentinel}"),
            ("extra text", f"3.13 {extra_text_sentinel}"),
            ("extra line", f"3.13\n{extra_text_sentinel}"),
        )
        for label, version_stdout in cases:
            with self.subTest(response=label):
                result = self.run_sync(
                    preflight_mode="success",
                    preflight_version_stdout=version_stdout,
                    preflight_version_stderr=version_stderr,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "Could not safely determine the python3 version for the security regression preflight.",
                    result.stderr,
                )
                self.assertIn(
                    "Python 3.9 or newer is required for the security regression preflight.",
                    result.stderr,
                )
                for private_text in (
                    source_sentinel,
                    extra_text_sentinel,
                    credential_sentinel,
                    version_stderr,
                ):
                    self.assertNotIn(private_text, output)
                if version_stdout:
                    self.assertNotIn(version_stdout, output)
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(len(capture["preflightCalls"]), 1)
                self.assertEqual(
                    capture["preflightCalls"][0]["args"],
                    [
                        "-c",
                        "import sys; print('%s.%s' % (sys.version_info[0], sys.version_info[1]))",
                    ],
                )
                self.assertFalse(capture["preflightCalls"][0]["hasGitHubToken"])

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
        expected_rerun_command = (
            "python3 gitmesh-template/tests/test_security_regressions.py \\\n"
            f"  GitHubSyncTests.{safe_test_name} \\\n"
            f"  GitHubSyncTests.{second_safe_test_name}"
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
                "Install or upgrade Python to 3.9 or newer, make python3 available on PATH, then rerun the regression checks and sync",
            ),
        )
        recognized_failure_stderr = None
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
                if preflight_mode == "failure":
                    self.assertIn(
                        "Rerun only the named checks from the workspace root:\n"
                        f"{expected_rerun_command}\nNo GitHub requests were made.",
                        result.stderr,
                    )
                else:
                    self.assertIn(
                        "Run locally from the workspace root: "
                        "python3 gitmesh-template/tests/test_security_regressions.py.",
                        result.stderr,
                    )
                self.assertIn("No GitHub requests were made", result.stderr)
                self.assertNotIn(source_sentinel, result.stdout + result.stderr)
                self.assertNotIn(credential_sentinel, result.stdout + result.stderr)
                self.assertNotIn(unlisted_test_name, result.stdout + result.stderr)
                self.assertNotIn(injected_output, result.stdout + result.stderr)
                if preflight_mode == "failure":
                    for recognized_name in (safe_test_name, second_safe_test_name):
                        self.assertEqual(result.stderr.count(recognized_name), 2)
                    if mode == "publish":
                        recognized_failure_stderr = result.stderr
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(len(capture["preflightCalls"]), 2)
                self.assertEqual(capture["preflightCalls"][0]["command"], "python3")
                self.assertEqual(
                    capture["preflightCalls"][0]["args"][0],
                    "-c",
                )
                self.assertFalse(any(call["hasGitHubToken"] for call in capture["preflightCalls"]))
                self.assertEqual(
                    capture["preflightCalls"][1]["args"],
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

        reported_command_prefix = "Rerun only the named checks from the workspace root:\n"
        self.assertIsNotNone(recognized_failure_stderr)
        command_start = recognized_failure_stderr.index(reported_command_prefix) + len(
            reported_command_prefix
        )
        command_end = recognized_failure_stderr.index(
            "\nNo GitHub requests were made.", command_start
        )
        reported_command = recognized_failure_stderr[command_start:command_end]
        self.assertEqual(reported_command, expected_rerun_command)
        selected_command = reported_command.replace("\\\n", " ").split()
        self.assertEqual(
            selected_command,
            [
                "python3",
                "gitmesh-template/tests/test_security_regressions.py",
                f"GitHubSyncTests.{safe_test_name}",
                f"GitHubSyncTests.{second_safe_test_name}",
            ],
        )
        selected_tests = subprocess.run(
            selected_command,
            cwd=ROOT.parent,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(
            selected_tests.returncode,
            0,
            selected_tests.stdout + selected_tests.stderr,
        )
        selected_run_count = re.search(r"Ran (\d+) tests?", selected_tests.stderr)
        self.assertIsNotNone(selected_run_count, selected_tests.stderr)
        self.assertEqual(int(selected_run_count.group(1)), 2)

        unknown_only_output = (
            f"ERROR: {unlisted_test_name} (__main__.GitHubSyncTests.{unlisted_test_name})\n"
            f"{source_sentinel}\n{credential_sentinel}"
        )
        unallowlisted_class_output = (
            f"FAIL: {safe_test_name} (__main__.UnlistedFixtureTests.{safe_test_name})\n"
            f"{source_sentinel}\n{credential_sentinel}"
        )
        for label, child_output, hidden_name in (
            ("unknown test only", unknown_only_output, unlisted_test_name),
            ("unallowlisted class", unallowlisted_class_output, safe_test_name),
        ):
            with self.subTest(mode=label):
                result = self.run_sync(
                    preflight_mode="failure",
                    preflight_output=child_output,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no safe failing test name was available", result.stderr)
                self.assertIn(
                    "Run locally from the workspace root: "
                    "python3 gitmesh-template/tests/test_security_regressions.py.",
                    result.stderr,
                )
                self.assertNotIn("Rerun only the named checks", result.stderr)
                for unsafe_text in (
                    hidden_name,
                    source_sentinel,
                    credential_sentinel,
                    child_output,
                ):
                    self.assertNotIn(unsafe_text, output)
                self.assert_safe_failure_output(result)
                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])

    def test_many_safe_preflight_failures_use_a_wrapped_copyable_rerun_command(self):
        parent_test_names = (
            "test_authentication_and_permission_errors_give_safe_recovery_guidance",
            "test_branch_conflict_uses_non_force_update_and_stops",
            "test_changed_source_updates_only_the_changed_allowlisted_file",
            "test_credentials_in_multiple_sources_are_all_reported_without_leaking",
            "test_dry_run_lists_only_changed_paths_without_contents_or_writes",
            "test_dry_run_refresh_failure_requests_rerun",
            "test_dry_run_refreshes_once_when_main_advances",
            "test_dry_run_rejects_malformed_initial_and_first_comparison_commit_ids",
            "test_dry_run_stops_after_second_head_advance",
            "test_dry_run_stops_safely_when_refreshed_commit_id_is_invalid",
            "test_dry_run_with_no_changes_reports_no_commit_and_makes_no_writes",
        )
        source_sentinel = "PREFLIGHT_MANY_FAILURE_SOURCE_SENTINEL"
        credential_sentinel = "ghp_" + "R" * 36
        unlisted_test_name = f"test_{credential_sentinel}"
        stdout_output = "\n".join(
            [
                *(
                    f"FAIL: {test_name} (__main__.GitHubSyncTests.{test_name})"
                    for test_name in parent_test_names
                ),
                f"ERROR: {unlisted_test_name} (__main__.GitHubSyncTests.{unlisted_test_name})",
                source_sentinel,
                credential_sentinel,
            ]
        )
        stderr_output = "PREFLIGHT_MANY_FAILURE_PRIVATE_DIAGNOSTIC"
        result = self.run_sync(
            preflight_mode="failure",
            preflight_output=stdout_output,
            preflight_stderr=stderr_output,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        for test_name in parent_test_names:
            self.assertIn(test_name, result.stderr)
        for private_output in (
            unlisted_test_name,
            source_sentinel,
            credential_sentinel,
            stderr_output,
            stdout_output,
            FAKE_GITHUB_TOKEN,
        ):
            self.assertNotIn(private_output, output)
        self.assert_safe_failure_output(result)

        command_prefix = "Rerun only the named checks from the workspace root:\n"
        command_start = result.stderr.index(command_prefix) + len(command_prefix)
        command_end = result.stderr.index("\nNo GitHub requests were made.", command_start)
        reported_command = result.stderr[command_start:command_end]
        command_lines = reported_command.splitlines()
        self.assertGreater(len(command_lines), 2)
        self.assertTrue(all(line.endswith("\\") for line in command_lines[:-1]))
        self.assertFalse(command_lines[-1].endswith("\\"))
        self.assertLessEqual(max(map(len, command_lines)), 100)

        selected_command = reported_command.replace("\\\n", " ").split()
        expected_command = [
            "python3",
            "gitmesh-template/tests/test_security_regressions.py",
            *(f"GitHubSyncTests.{test_name}" for test_name in parent_test_names),
        ]
        self.assertEqual(selected_command, expected_command)
        selected_tests = subprocess.run(
            ["sh", "-c", reported_command],
            cwd=ROOT.parent,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(
            selected_tests.returncode,
            0,
            selected_tests.stdout + selected_tests.stderr,
        )
        selected_run_count = re.search(r"Ran (\d+) tests?", selected_tests.stderr)
        self.assertIsNotNone(selected_run_count, selected_tests.stderr)
        self.assertEqual(int(selected_run_count.group(1)), len(parent_test_names))

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(len(capture["preflightCalls"]), 2)
        self.assertFalse(any(call["hasGitHubToken"] for call in capture["preflightCalls"]))

    def test_security_preflight_multiple_subcases_are_counted_safely(self):
        parent_test_name = "test_sync_publishes_only_the_fixed_source_allowlist"
        first_subcase = "PRIVATE_SUBCASE_DESCRIPTION_ALPHA"
        second_subcase = "PRIVATE_SUBCASE_DESCRIPTION_BETA"
        source_sentinel = "PREFLIGHT_SUBCASE_SOURCE_CONTENT_SENTINEL"
        credential_sentinel = "ghp_" + "V" * 36
        stdout_output = (
            f"FAIL: {parent_test_name} (__main__.GitHubSyncTests.{parent_test_name}) "
            f"(case='{first_subcase}')\n"
            f"ERROR: {parent_test_name} (__main__.GitHubSyncTests.{parent_test_name}) "
            f"(case='{second_subcase}')\n"
            f"{source_sentinel}\n{credential_sentinel}"
        )
        stderr_output = "PREFLIGHT_SUBCASE_PRIVATE_DIAGNOSTIC_SENTINEL"
        result = self.run_sync(
            preflight_mode="failure",
            preflight_output=stdout_output,
            preflight_stderr=stderr_output,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Security regression preflight failed in: "
            f"{parent_test_name} (2 failing subcases)",
            result.stderr,
        )
        command_prefix = "Rerun only the named checks from the workspace root:\n"
        command_start = result.stderr.index(command_prefix) + len(command_prefix)
        command_end = result.stderr.index("\nNo GitHub requests were made.", command_start)
        reported_command = result.stderr[command_start:command_end]
        self.assertEqual(
            reported_command.replace("\\\n", " ").split(),
            [
                "python3",
                "gitmesh-template/tests/test_security_regressions.py",
                f"GitHubSyncTests.{parent_test_name}",
            ],
        )
        for private_output in (
            first_subcase,
            second_subcase,
            source_sentinel,
            credential_sentinel,
            stderr_output,
            stdout_output,
            FAKE_GITHUB_TOKEN,
        ):
            self.assertNotIn(private_output, output)
        self.assert_safe_failure_output(result)

        capture = json.loads(self.capture.read_text())
        self.assertEqual(capture["requests"], [])
        self.assertEqual(len(capture["preflightCalls"]), 2)
        self.assertFalse(any(call["hasGitHubToken"] for call in capture["preflightCalls"]))

    def test_security_preflight_timeout_and_interruption_are_clear_and_private(self):
        stdout_output = (
            "PREFLIGHT_CHILD_STDOUT_SENTINEL\n"
            "PREFLIGHT_SOURCE_CONTENT_SENTINEL\n"
            "ghp_" + "T" * 36
        )
        stderr_output = (
            "PREFLIGHT_CHILD_STDERR_SENTINEL\n"
            "PREFLIGHT_PRIVATE_DIAGNOSTIC_SENTINEL\n"
        )
        cases = (
            ("timeout", "Security regression preflight timed out"),
            ("interrupt", "Python security regression preflight was interrupted"),
        )

        for preflight_mode, expected_summary in cases:
            with self.subTest(preflight_mode=preflight_mode):
                result = self.run_sync(
                    preflight_mode=preflight_mode,
                    preflight_output=stdout_output,
                    preflight_stderr=stderr_output,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn(expected_summary, result.stderr)
                self.assertIn(
                    "Run locally from the workspace root: "
                    "python3 gitmesh-template/tests/test_security_regressions.py.",
                    result.stderr,
                )
                self.assertIn("No GitHub requests were made", result.stderr)
                if preflight_mode == "interrupt":
                    self.assertNotIn("preflight timed out", result.stderr.lower())
                else:
                    self.assertNotIn("preflight was interrupted", result.stderr)
                for private_output in (
                    stdout_output,
                    stderr_output,
                    "PREFLIGHT_CHILD_STDOUT_SENTINEL",
                    "PREFLIGHT_SOURCE_CONTENT_SENTINEL",
                    "PREFLIGHT_CHILD_STDERR_SENTINEL",
                    "PREFLIGHT_PRIVATE_DIAGNOSTIC_SENTINEL",
                    "ghp_" + "T" * 36,
                    FAKE_GITHUB_TOKEN,
                ):
                    self.assertNotIn(private_output, output)
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(len(capture["preflightCalls"]), 2)
                self.assertFalse(
                    any(call["hasGitHubToken"] for call in capture["preflightCalls"])
                )

    def test_security_preflight_output_limit_hides_child_output_and_stops_before_github(self):
        stdout_output = (
            "PREFLIGHT_CHILD_STDOUT_SENTINEL\n"
            "PREFLIGHT_SOURCE_CONTENT_SENTINEL\n"
            "ghp_" + "Q" * 36
        )
        stderr_output = (
            "PREFLIGHT_CHILD_STDERR_SENTINEL\n"
            "PREFLIGHT_PRIVATE_DIAGNOSTIC_SENTINEL\n"
        )
        for args in ((), ("--dry-run",)):
            with self.subTest(args=args):
                result = self.run_sync(
                    args=args,
                    preflight_mode="output-limit",
                    preflight_output=stdout_output,
                    preflight_stderr=stderr_output,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn(
                    "Security regression preflight exceeded its output limit",
                    result.stderr,
                )
                self.assertIn(
                    "Run locally from the workspace root: "
                    "python3 gitmesh-template/tests/test_security_regressions.py.",
                    result.stderr,
                )
                self.assertIn("No GitHub requests were made", result.stderr)
                for private_output in (
                    stdout_output,
                    stderr_output,
                    "PREFLIGHT_CHILD_STDOUT_SENTINEL",
                    "PREFLIGHT_SOURCE_CONTENT_SENTINEL",
                    "PREFLIGHT_CHILD_STDERR_SENTINEL",
                    "PREFLIGHT_PRIVATE_DIAGNOSTIC_SENTINEL",
                    "ghp_" + "Q" * 36,
                    FAKE_GITHUB_TOKEN,
                ):
                    self.assertNotIn(private_output, output)
                self.assert_safe_failure_output(result)

                capture = json.loads(self.capture.read_text())
                self.assertEqual(capture["requests"], [])
                self.assertEqual(len(capture["preflightCalls"]), 2)
                self.assertFalse(
                    any(call["hasGitHubToken"] for call in capture["preflightCalls"])
                )
                self.assertEqual(
                    capture["preflightCalls"][1]["args"],
                    [str(self.source_root / "tests" / "test_security_regressions.py")],
                )

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

    def test_selected_branch_conflict_stops_without_force_update(self):
        self.set_remote_snapshot()
        branch = "release/2026.10+canary#ops"
        encoded_branch = "release%2F2026.10%2Bcanary%23ops"
        readme = self.source_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nConflict fixture.\n")
        result = self.run_sync(
            args=("--branch", branch),
            fail_at="PATCH /git/refs/heads/" + encoded_branch,
            fail_mode="http",
            fail_status=409,
            env_overrides={"GITMESH_TEST_BRANCH": branch},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 409", result.stderr)
        self.assertIn("branch changed while syncing", result.stderr)
        self.assertIn("No force update was attempted.", result.stderr)
        self.assert_safe_failure_output(result)
        capture = json.loads(self.capture.read_text())
        update = capture["requests"][-1]
        self.assertEqual(
            update["path"],
            "/repos/vitalitychems-dot/GitMesh/git/refs/heads/" + encoded_branch,
        )
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
        shutil.copy2(PRE_PUSH_HOOK, hook_dir / "pre-push")

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
            'import childProcess from "node:child_process";\n'
            'import { syncBuiltinESMExports } from "node:module";\n'
            "if (process.env.GITMESH_TEST_GIT_TIMEOUT === \"1\") {\n"
            "  const originalSpawnSync = childProcess.spawnSync.bind(childProcess);\n"
            "  childProcess.spawnSync = (command, ...args) => {\n"
            "    const gitArgs = command === \"git\" && Array.isArray(args[0]) ? args[0] : [];\n"
            "    const timeoutStage = process.env.GITMESH_TEST_GIT_TIMEOUT_STAGE;\n"
            "    const shouldTimeout =\n"
            '      (timeoutStage === "repository-lookup" && gitArgs[0] === "rev-parse" && gitArgs[1] === "--show-toplevel") ||\n'
            '      (timeoutStage === "staged-path-listing" && gitArgs[0] === "diff" && gitArgs[1] === "--cached" && gitArgs[2] === "--name-only") ||\n'
            '      (timeoutStage === "staged-blob-size" && gitArgs[0] === "cat-file" && gitArgs[1] === "-s") ||\n'
            '      (timeoutStage === "staged-blob-content" && gitArgs[0] === "show");\n'
            "    if (shouldTimeout) {\n"
            "      fs.writeFileSync(\n"
            "        process.env.GITMESH_TEST_GIT_TIMEOUT_MARKER,\n"
            "        JSON.stringify({\n"
            "          stage: timeoutStage,\n"
            "          command: gitArgs[0],\n"
            "          timeoutMs: args[1]?.timeout,\n"
            "          hasGitHubToken: Boolean(args[1]?.env?.GITHUB_TOKEN),\n"
            "        }),\n"
            "      );\n"
            "      return {\n"
            '        error: { code: "ETIMEDOUT", message: "PRIVATE_GIT_TIMEOUT_DIAGNOSTIC" },\n'
            "        status: null,\n"
            '        signal: "SIGTERM",\n'
            '        stdout: Buffer.from("PRIVATE_STAGED_TIMEOUT_CONTENT"),\n'
            '        stderr: Buffer.from("PRIVATE_GIT_TIMEOUT_STDERR"),\n'
            "        pid: 123,\n"
            "        output: [],\n"
            "      };\n"
            "    }\n"
            "    return originalSpawnSync(command, ...args);\n"
            "  };\n"
            "  syncBuiltinESMExports();\n"
            "}\n"
            "globalThis.fetch = async () => {\n"
            '  fs.writeFileSync(process.env.GITMESH_TEST_NETWORK_MARKER, "called");\n'
            '  throw new Error("network request attempted");\n'
            "};\n"
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_git(self, args, env=None):
        return self.run_git_at(self.repo_root, args, env=env)

    def run_git_at(self, cwd, args, env=None):
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
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

    def configure_push_remote(self, enable_check=True):
        remote = self.repo_root / "push-remote.git"
        result = self.run_git(["init", "--bare", "--quiet", str(remote)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_git(["remote", "add", "origin", str(remote)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if enable_check:
            result = self.run_git(
                ["config", "--local", "gitmesh.prePushCredentialCheck", "true"]
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return remote

    def test_pre_push_hook_blocks_outgoing_credentials_without_exposing_them(self):
        remote = self.configure_push_remote()
        credential = "ghp_" + "Q" * 36
        self.readme.write_text(f"safe source\nstaged_secret={credential}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(
            ["commit", "--no-verify", "-m", "commit that skipped credential check"]
        )
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)

        pushed_commit = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        hook_env = self.hook_environment_without_github_token()
        hook_env["GITHUB_TOKEN"] = FAKE_GITHUB_TOKEN
        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=hook_env,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Credential-like values were found in outgoing GitMesh source changes", output)
        self.assertIn("README.md (line 2)", output)
        self.assertIn("Push blocked", output)
        self.assertNotIn(credential, output)
        self.assertNotIn("safe source", output)
        self.assertNotIn(pushed_commit, output)
        self.assertNotIn(FAKE_GITHUB_TOKEN, output)
        self.assertNotIn("network request attempted", output)
        self.assertFalse(self.network_marker.exists())
        remote_ref = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "--verify", "refs/heads/main"]
        )
        self.assertNotEqual(remote_ref.returncode, 0)

    def test_pre_push_hook_reports_multiple_files_in_stable_order(self):
        remote = self.configure_push_remote()
        outgoing_sources = [
            (
                self.template_root / "README.md",
                "gitmesh-template/README.md",
                "README_TOKEN",
                "ghp_" + "A" * 36,
                ["SAFE_README_HEADER"],
                2,
            ),
            (
                self.template_root / "gitmesh-ultimate-core.mjs",
                "gitmesh-template/gitmesh-ultimate-core.mjs",
                "// CONSOLE_TOKEN",
                "github_pat_" + "B" * 40,
                ["// SAFE_CONSOLE_HEADER", "// SAFE_CONSOLE_CONTEXT"],
                3,
            ),
            (
                self.template_root / "sync-public-source.mjs",
                "gitmesh-template/sync-public-source.mjs",
                "// SYNC_TOKEN",
                "glpat-" + "C" * 24,
                [
                    "// SAFE_SYNC_HEADER",
                    "// SAFE_SYNC_CONTEXT_ONE",
                    "// SAFE_SYNC_CONTEXT_TWO",
                ],
                4,
            ),
        ]
        expected_locations = [
            f"{file_path.name} (line {line_number})"
            for file_path, _git_path, _name, _credential, _context, line_number
            in outgoing_sources
        ]
        original_contents = {
            file_path: file_path.read_bytes()
            for file_path, *_ in outgoing_sources
        }
        private_texts = []
        # The report order is repository-relative path order, even when staging is reversed.
        for file_path, git_path, variable_name, credential, safe_context, _line_number in reversed(outgoing_sources):
            source_line = f"{variable_name}={credential}"
            file_path.write_text(
                "\n".join([*safe_context, source_line, "SAFE_SOURCE_FOOTER"]) + "\n",
                encoding="utf-8",
            )
            staged = self.run_git(["add", git_path])
            self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
            private_texts.extend([credential, source_line, *safe_context, "SAFE_SOURCE_FOOTER"])

        # Keep the working-tree scanner executable; the outgoing scan reads committed blobs.
        for file_path, original_content in original_contents.items():
            file_path.write_bytes(original_content)

        commit = self.run_git(
            ["commit", "--no-verify", "-m", "create outgoing multi-file credential findings"]
        )
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)
        pushed_commit = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        hook_env = self.hook_environment_without_github_token()
        hook_env["GITHUB_TOKEN"] = FAKE_GITHUB_TOKEN
        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=hook_env,
        )
        output = result.stdout + result.stderr
        safe_output = output
        for private_text in [*private_texts, FAKE_GITHUB_TOKEN]:
            safe_output = safe_output.replace(private_text, "[redacted test content]")

        self.assertNotEqual(result.returncode, 0, safe_output)
        self.assertIn(
            "Credential-like values were found in outgoing GitMesh source changes:",
            output,
            safe_output,
        )
        self.assertIn("; ".join(expected_locations), output, safe_output)
        self.assertIn("Push blocked", output, safe_output)
        self.assertIn("No GitHub requests were made", output, safe_output)
        for private_text in private_texts:
            self.assertNotIn(private_text, output, safe_output)
        self.assertNotIn(FAKE_GITHUB_TOKEN, output, safe_output)
        self.assertNotIn(pushed_commit, output, safe_output)
        self.assertNotIn("network request attempted", output, safe_output)
        self.assertFalse(self.network_marker.exists())
        remote_ref = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "--verify", "refs/heads/main"]
        )
        self.assertNotEqual(remote_ref.returncode, 0)

    def test_pre_push_hook_allows_clean_outgoing_commits_without_github_access(self):
        remote = self.configure_push_remote()
        self.readme.write_text(self.baseline_readme.decode() + "\nClean outgoing change.\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(["commit", "-m", "clean outgoing source change"])
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)
        local_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Pre-push credential check passed", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("network request attempted", output)
        self.assertFalse(self.network_marker.exists())
        remote_head = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "refs/heads/main"]
        ).stdout.strip()
        self.assertEqual(remote_head, local_head)

    def test_pre_push_hook_blocks_credentials_pushed_to_existing_branch(self):
        remote = self.configure_push_remote()
        seed = self.run_git(
            ["push", "--no-verify", "origin", "HEAD:refs/heads/main"]
        )
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        baseline_head = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "refs/heads/main"]
        ).stdout.strip()
        self.assertEqual(
            baseline_head,
            self.run_git(["rev-parse", "HEAD"]).stdout.strip(),
        )

        credential = "ghp_" + "S" * 36
        private_context = "PRIVATE_EXISTING_BRANCH_SOURCE_SENTINEL"
        credential_line = f"staged_secret={credential}"
        self.readme.write_text(
            f"{private_context}\n{credential_line}\n",
            encoding="utf-8",
        )
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(
            ["commit", "--no-verify", "-m", "commit secret after existing remote tip"]
        )
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)

        pushed_commit = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Credential-like values were found in outgoing GitMesh source changes", output)
        self.assertIn("README.md (line 2)", output)
        self.assertIn("Push blocked", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn(credential, output)
        self.assertNotIn(credential_line, output)
        self.assertNotIn(private_context, output)
        self.assertNotIn(pushed_commit, output)
        self.assertNotIn("network request attempted", output)
        self.assertFalse(self.network_marker.exists())
        remote_head = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "refs/heads/main"]
        ).stdout.strip()
        self.assertEqual(remote_head, baseline_head)

    def test_pre_push_hook_allows_clean_update_to_existing_branch(self):
        remote = self.configure_push_remote()
        seed = self.run_git(
            ["push", "--no-verify", "origin", "HEAD:refs/heads/main"]
        )
        self.assertEqual(seed.returncode, 0, seed.stdout + seed.stderr)
        baseline_head = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "refs/heads/main"]
        ).stdout.strip()

        self.readme.write_text(
            self.baseline_readme.decode("utf-8") + "\nClean update to existing branch.\n",
            encoding="utf-8",
        )
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(["commit", "-m", "clean update to existing remote branch"])
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)
        local_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Pre-push credential check passed", output)
        self.assertIn("scanned 1 outgoing commits", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("network request attempted", output)
        self.assertFalse(self.network_marker.exists())
        remote_head = self.run_git(
            ["--git-dir", str(remote), "rev-parse", "refs/heads/main"]
        ).stdout.strip()
        self.assertNotEqual(remote_head, baseline_head)
        self.assertEqual(remote_head, local_head)

    def test_pre_push_hook_is_opt_in_by_default(self):
        remote = self.configure_push_remote(enable_check=False)
        credential = "ghp_" + "M" * 36
        self.readme.write_text(f"source={credential}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        commit = self.run_git(["commit", "--no-verify", "-m", "pre-push check remains optional"])
        self.assertEqual(commit.returncode, 0, commit.stdout + commit.stderr)

        result = self.run_git(
            ["push", "origin", "HEAD:refs/heads/main"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertNotIn("Credential-like values were found", output)
        self.assertNotIn("Pre-push credential check", output)
        self.assertNotIn(credential, output)
        self.assertFalse(self.network_marker.exists())

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
        self.assertIn("README.md (line 2: GitHub token)", output)
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

    def test_precommit_hook_blocks_staged_javascript_syntax_errors_from_index(self):
        source = self.template_root / "gitmesh-ultimate-core.mjs"
        clean_worktree_source = source.read_bytes()
        staged_source = (
            b"export const cleanSyntax = true;\n"
            b"const stagedSyntaxSentinel = ; // STAGED_SYNTAX_SOURCE_SENTINEL\n"
        )
        source.write_bytes(staged_source)
        self.run_git(["add", "gitmesh-template/gitmesh-ultimate-core.mjs"])

        # Keep the working-tree copy syntactically clean while the index still
        # contains the invalid version that would be included in the commit.
        source.write_bytes(clean_worktree_source)
        self.assertEqual(source.read_bytes(), clean_worktree_source)
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        result = self.run_git(
            ["commit", "-m", "must block staged JavaScript syntax errors"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Refusing to commit staged JavaScript that fails Node syntax validation:",
            output,
        )
        self.assertIn("gitmesh-ultimate-core.mjs", output)
        self.assertRegex(output, r"\(line 2, column \d+\)")
        self.assertIn("stage the fix, and retry the commit", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("STAGED_SYNTAX_SOURCE_SENTINEL", output)
        self.assertNotIn("const stagedSyntaxSentinel = ;", output)
        self.assertNotIn("[stdin]", output)
        self.assertNotIn("SyntaxError", output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(source.read_bytes(), clean_worktree_source)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
            "gitmesh-template/gitmesh-ultimate-core.mjs",
        )
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_reports_all_staged_source_repair_issues(self):
        readme = self.readme
        core_source = self.template_root / "gitmesh-ultimate-core.mjs"
        sync_source = self.template_root / "sync-public-source.mjs"
        original_contents = {
            readme: readme.read_bytes(),
            core_source: core_source.read_bytes(),
            sync_source: sync_source.read_bytes(),
        }
        credential = "ghp_" + "R" * 36
        credential_line = f"staged_secret={credential}"
        syntax_sentinel = "PRIVATE_MULTI_FILE_SYNTAX_SENTINEL"
        oversized_sentinel = b"PRIVATE_MULTI_FILE_OVERSIZED_SENTINEL"
        staged_contents = {
            readme: f"SAFE_README_CONTEXT\n{credential_line}\n".encode("utf-8"),
            core_source: (
                "export const stagedRepair = true;\n"
                f"const stagedRepairBroken = ; // {syntax_sentinel}\n"
            ).encode("utf-8"),
            sync_source: oversized_sentinel + b"\n" + b"x" * (2 * 1024 * 1024),
        }
        git_paths = [
            "gitmesh-template/README.md",
            "gitmesh-template/gitmesh-ultimate-core.mjs",
            "gitmesh-template/sync-public-source.mjs",
        ]
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        try:
            for file_path, content in staged_contents.items():
                file_path.write_bytes(content)
            added = self.run_git(["add", *git_paths])
            self.assertEqual(added.returncode, 0, added.stdout + added.stderr)

            # The hook must inspect all three staged blobs, even though the
            # working tree is restored before the commit is attempted.
            for file_path, content in original_contents.items():
                file_path.write_bytes(content)

            result = self.run_git(
                ["commit", "-m", "report every staged source repair issue"],
                env=self.hook_environment_without_github_token(),
            )
            output = result.stdout + result.stderr

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Refusing to commit: these staged allowlisted source files need repair",
                output,
            )
            self.assertIn("README.md (line 2: GitHub token)", output)
            self.assertIn("Remove the value from this staged file", output)
            self.assertIn("gitmesh-ultimate-core.mjs", output)
            self.assertRegex(output, r"\(line 2, column \d+\)")
            self.assertIn("stage the fix, and retry the commit", output)
            self.assertIn(
                "Refusing to check an oversized staged source file: sync-public-source.mjs",
                output,
            )
            self.assertIn("Save a smaller intended version no larger than 512 KiB", output)
            self.assertIn(
                'from the repository root run "git add gitmesh-template/sync-public-source.mjs" and retry the commit',
                output,
            )
            self.assertIn("No GitHub requests were made", output)
            for private_text in (
                credential,
                credential_line,
                syntax_sentinel,
                "const stagedRepairBroken = ;",
                oversized_sentinel.decode("utf-8"),
                "SyntaxError",
                "[stdin]",
                "network request attempted",
                FAKE_GITHUB_TOKEN,
            ):
                self.assertNotIn(private_text, output)
            self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
            self.assertEqual(
                self.run_git(["diff", "--cached", "--name-only"]).stdout.strip().splitlines(),
                git_paths,
            )
            for file_path, content in original_contents.items():
                self.assertEqual(file_path.read_bytes(), content)
            self.assertFalse(self.network_marker.exists())
        finally:
            for file_path, content in original_contents.items():
                file_path.write_bytes(content)

    def test_precommit_hook_passes_clean_staged_javascript(self):
        source = self.template_root / "gitmesh-ultimate-core.mjs"
        source.write_bytes(
            source.read_bytes() + b"\n// Clean staged syntax regression fixture.\n"
        )
        self.run_git(["add", "gitmesh-template/gitmesh-ultimate-core.mjs"])
        result = self.run_git(
            ["commit", "-m", "allow clean staged JavaScript"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertIn(
            "JavaScript syntax passed for 1 staged allowlisted JavaScript source file",
            output,
        )
        self.assertIn("No GitHub requests were made", output)
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_blocks_every_supported_credential_pattern(self):
        credential_cases = [
            (pattern_id, label, credential)
            for pattern_id, pattern_cases in CREDENTIAL_HOOK_TEST_CASES.items()
            for label, credential in pattern_cases
        ]
        hook_env = self.hook_environment_without_github_token()
        self.assertNotIn("GITHUB_TOKEN", hook_env)

        for pattern_id, label, credential in credential_cases:
            with self.subTest(credential_family=pattern_id, token_variant=label):
                source_line = f"staged_credential_{label.replace(' ', '_')}={credential}"
                self.readme.write_text(f"safe source context\n{source_line}\n")
                self.run_git(["add", "gitmesh-template/README.md"])

                # Restore the worktree so this commit verifies the staged blob.
                self.readme.write_bytes(self.baseline_readme)
                original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
                result = self.run_git(
                    ["commit", "-m", "each credential family must be blocked"],
                    env=hook_env,
                )
                output = result.stdout + result.stderr
                safe_output = output.replace(credential, "[redacted test credential]")

                self.assertNotEqual(result.returncode, 0, safe_output)
                self.assertIn(
                    f"README.md (line 2: {CREDENTIAL_HOOK_FAMILY_LABELS[pattern_id]})",
                    output,
                )
                self.assertIn("No GitHub requests were made", output)
                self.assertFalse(credential in output, safe_output)
                self.assertFalse(source_line in output, safe_output)
                self.assertFalse("safe source context" in output, safe_output)
                self.assertNotIn(FAKE_GITHUB_TOKEN, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_allows_near_miss_credential_strings_without_network(self):
        hook_env = self.hook_environment_without_github_token()
        self.assertNotIn("GITHUB_TOKEN", hook_env)

        for pattern_id, near_miss_cases in CREDENTIAL_HOOK_NEAR_MISS_CASES.items():
            for case_kind, near_miss in near_miss_cases:
                with self.subTest(pattern=pattern_id, case=case_kind):
                    source_line = f"near_miss_{pattern_id.replace('-', '_')}={near_miss}"
                    self.readme.write_text(f"safe source context\n{source_line}\n")
                    staged = self.run_git(["add", "gitmesh-template/README.md"])
                    self.assertEqual(staged.returncode, 0, staged.stderr)
                    result = self.run_git(
                        ["commit", "-m", f"allow harmless {pattern_id} near miss"],
                        env=hook_env,
                    )
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0, output)
                    self.assertIn("Credential check passed:", output)
                    self.assertIn("No GitHub requests were made", output)
                    self.assertNotIn("Credential-like values were found", output)
                    self.assertNotIn(FAKE_GITHUB_TOKEN, output)
                    self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_vectors_cover_every_scanner_pattern(self):
        scanner_source = SYNC.read_text(encoding="utf-8")
        pattern_block = re.search(
            r"const EMBEDDED_CREDENTIAL_PATTERNS = \[(.*?)\n\];",
            scanner_source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(
            pattern_block,
            "Keep scanner formats in an explicit registry so hook-test coverage can be checked.",
        )
        pattern_block_text = pattern_block.group(1)
        scanner_pattern_ids = re.findall(
            r'\bid\s*:\s*"([a-z0-9-]+)"',
            pattern_block_text,
        )
        scanner_pattern_families = re.findall(
            r'\bfamily\s*:\s*"([^"]+)"',
            pattern_block_text,
        )
        scanner_pattern_count = len(re.findall(r"\bpattern\s*:", pattern_block_text))

        self.assertEqual(
            len(scanner_pattern_ids),
            scanner_pattern_count,
            "Every scanner pattern needs an ID before it can be paired with a hook test vector.",
        )
        self.assertEqual(
            len(scanner_pattern_ids),
            len(set(scanner_pattern_ids)),
            "Scanner credential pattern IDs must be unique.",
        )
        scanner_ids = set(scanner_pattern_ids)
        assert_credential_hook_vectors_cover_scanner_patterns(
            scanner_pattern_ids,
            CREDENTIAL_HOOK_TEST_CASES,
        )
        self.assertEqual(
            scanner_pattern_ids,
            list(CREDENTIAL_HOOK_FAMILY_LABELS),
            "Every scanner pattern needs a stable, safe family label in registry order.",
        )
        self.assertEqual(
            scanner_pattern_families,
            list(CREDENTIAL_HOOK_FAMILY_LABELS.values()),
            "Keep user-facing family labels aligned with the scanner pattern registry.",
        )
        near_miss_ids = set(CREDENTIAL_HOOK_NEAR_MISS_CASES)
        missing_near_misses = sorted(scanner_ids - near_miss_ids)
        stale_near_misses = sorted(near_miss_ids - scanner_ids)
        self.assertFalse(
            missing_near_misses or stale_near_misses,
            "Add near-miss cases for every scanner pattern. "
            f"Missing cases: {missing_near_misses}; stale cases: {stale_near_misses}.",
        )
        for pattern_id in scanner_ids:
            case_kinds = {
                case_kind
                for case_kind, _value in CREDENTIAL_HOOK_NEAR_MISS_CASES[pattern_id]
            }
            expected_case_kinds = (
                {"invalid-character"}
                if pattern_id == "private-key-header"
                else {"below-minimum", "invalid-character"}
            )
            self.assertEqual(
                case_kinds,
                expected_case_kinds,
                f"Near-miss cases for {pattern_id} must cover {sorted(expected_case_kinds)}.",
            )

    def test_precommit_hook_vector_coverage_reports_missing_pattern_id(self):
        missing_pattern_id = "github-prefixed-token"
        simulated_test_cases = dict(CREDENTIAL_HOOK_TEST_CASES)
        del simulated_test_cases[missing_pattern_id]

        with self.assertRaises(AssertionError) as error:
            assert_credential_hook_vectors_cover_scanner_patterns(
                CREDENTIAL_HOOK_FAMILY_LABELS,
                simulated_test_cases,
            )

        diagnostic = str(error.exception)
        self.assertIn(
            "Add representative synthetic commit-hook values to CREDENTIAL_HOOK_TEST_CASES",
            diagnostic,
        )
        self.assertIn(f"Missing vectors: ['{missing_pattern_id}']", diagnostic)
        for pattern_cases in CREDENTIAL_HOOK_TEST_CASES.values():
            for _label, credential in pattern_cases:
                self.assertNotIn(credential, diagnostic)

    def test_precommit_hook_rejects_non_text_staged_files_without_leaking_contents(self):
        non_text_cases = (
            ("invalid UTF-8", b"\xffINVALID_UTF8_STAGED_CONTENT_SENTINEL"),
            ("NUL byte", b"\x00NUL_STAGED_CONTENT_SENTINEL"),
        )

        for case_name, content in non_text_cases:
            with self.subTest(case=case_name):
                self.readme.write_bytes(content)
                self.run_git(["add", "gitmesh-template/README.md"])

                # Ensure validation reads the staged blob rather than the working tree.
                self.readme.write_bytes(self.baseline_readme)
                original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
                result = self.run_git(
                    ["commit", "-m", f"must be blocked for {case_name}"],
                    env=self.hook_environment_without_github_token(),
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("non-text staged source file: README.md", output)
                self.assertIn("Save it as UTF-8 text and stage it again", output)
                self.assertIn("No GitHub requests were made", output)
                self.assertNotIn(str(self.readme), output)
                self.assertNotIn(content.decode("latin1"), output)
                self.assertNotIn("network request attempted", output)
                self.assertNotIn(FAKE_GITHUB_TOKEN, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_accepts_staged_source_at_exact_size_limit(self):
        exact_size = 512 * 1024
        self.readme.write_bytes(b"x" * exact_size)
        added = self.run_git(["add", "gitmesh-template/README.md"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)

        result = self.run_git(
            ["commit", "-m", "accept staged source at exact size limit"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Credential check passed", output)
        self.assertIn("1 staged allowlisted source file", output)
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn("network request attempted", output)
        stored_size = self.run_git(
            ["cat-file", "-s", "HEAD:gitmesh-template/README.md"],
        )
        self.assertEqual(stored_size.returncode, 0, stored_size.stderr)
        self.assertEqual(stored_size.stdout.strip(), str(exact_size))
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_blocks_oversized_staged_source_with_safe_repair_steps(self):
        limit_plus_one = 512 * 1024 + 1
        oversized_sentinel = b"OVERSIZED_STAGED_SOURCE_SENTINEL"
        oversized_content = oversized_sentinel + b"x" * (limit_plus_one - len(oversized_sentinel))
        self.assertEqual(len(oversized_content), limit_plus_one)
        self.readme.write_bytes(oversized_content)
        self.run_git(["add", "gitmesh-template/README.md"])

        # The staged blob remains oversized even though the working tree is repaired.
        self.readme.write_bytes(self.baseline_readme)
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        result = self.run_git(
            ["commit", "-m", "must be blocked for oversized staged source"],
            env=self.hook_environment_without_github_token(),
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to check an oversized staged source file: README.md", output)
        self.assertIn("Save a smaller intended version no larger than 512 KiB", output)
        self.assertIn(
            'from the repository root run "git add gitmesh-template/README.md" and retry the commit',
            output,
        )
        self.assertIn("No GitHub requests were made", output)
        self.assertNotIn(oversized_sentinel.decode(), output)
        self.assertNotIn(str(self.readme), output)
        self.assertNotIn(FAKE_GITHUB_TOKEN, output)
        self.assertNotIn("network request attempted", output)
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
                self.assertIn(
                    "README.md (line 2: GitHub token; line 4: GitHub fine-grained token)",
                    output,
                )
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

    def test_precommit_hook_reports_blank_boundary_separator_lines_without_exposing_content(self):
        cases = (
            (
                "leading separators",
                "\r\n\u2028\r",
                ("ghp_" + "A" * 36,),
                (),
                "\n",
                ((4, "GitHub token"),),
            ),
            (
                "trailing separators",
                "SAFE_TRAILING_HEADER\r\n",
                ("github_pat_" + "B" * 40,),
                (),
                "\r\n\u2028\u2029\r\r",
                ((2, "GitHub fine-grained token"),),
            ),
            (
                "repeated separators",
                "SAFE_REPEATED_HEADER\u2028\u2028",
                ("npm_" + "C" * 36, "xoxb-" + "D" * 24, "sk_live_" + "E" * 24),
                ("\r\r", "\u2029\u2029"),
                "",
                (
                    (3, "npm token"),
                    (5, "Slack token"),
                    (7, "Stripe secret key"),
                ),
            ),
        )
        hook_env = self.hook_environment_without_github_token()
        self.assertNotIn("GITHUB_TOKEN", hook_env)

        for label, prefix, credentials, separators, suffix, expected_locations in cases:
            with self.subTest(case=label):
                credential_lines = tuple(
                    f"token_{index}={credential}"
                    for index, credential in enumerate(credentials, start=1)
                )
                source_text = prefix + credential_lines[0]
                for separator, credential_line in zip(separators, credential_lines[1:]):
                    source_text += separator + credential_line
                source_text += suffix

                reset = self.run_git(["reset", "--hard", "HEAD"])
                self.assertEqual(reset.returncode, 0, reset.stdout + reset.stderr)
                self.readme.write_bytes(source_text.encode("utf-8"))
                staged = self.run_git(["add", "gitmesh-template/README.md"])
                self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)

                # The hook must inspect the staged content after the worktree is restored.
                self.readme.write_bytes(self.baseline_readme)
                original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
                result = self.run_git(
                    ["commit", "-m", f"must block blank-boundary case: {label}"],
                    env=hook_env,
                )
                output = result.stdout + result.stderr
                safe_output = output
                private_texts = [
                    *credentials,
                    *credential_lines,
                    "SAFE_TRAILING_HEADER",
                    "SAFE_REPEATED_HEADER",
                    FAKE_GITHUB_TOKEN,
                ]
                for private_text in private_texts:
                    safe_output = safe_output.replace(
                        private_text,
                        "[redacted test content]",
                    )

                expected_location_label = "; ".join(
                    f"line {line}: {family}"
                    for line, family in expected_locations
                )
                self.assertNotEqual(result.returncode, 0, safe_output)
                self.assertIn(
                    f"README.md ({expected_location_label})",
                    output,
                    safe_output,
                )
                self.assertIn("No GitHub requests were made", output, safe_output)
                for private_text in private_texts:
                    self.assertFalse(private_text in output, safe_output)
                self.assertEqual(
                    self.run_git(["rev-parse", "HEAD"]).stdout.strip(),
                    original_head,
                )
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_reports_credentials_from_every_staged_source_file(self):
        staged_sources = [
            (
                self.template_root / "README.md",
                "gitmesh-template/README.md",
                "README_TOKEN",
                "ghp_" + "A" * 36,
                "GitHub token",
                ["SAFE_README_HEADER"],
                2,
            ),
            (
                self.template_root / "gitmesh-ultimate-core.mjs",
                "gitmesh-template/gitmesh-ultimate-core.mjs",
                "CONSOLE_TOKEN",
                "github_pat_" + "B" * 40,
                "GitHub fine-grained token",
                ["SAFE_CONSOLE_HEADER", "SAFE_CONSOLE_CONTEXT"],
                3,
            ),
            (
                self.template_root / "sync-public-source.mjs",
                "gitmesh-template/sync-public-source.mjs",
                "SYNC_TOKEN",
                "glpat-" + "C" * 24,
                "GitLab token",
                ["SAFE_SYNC_HEADER", "SAFE_SYNC_CONTEXT_ONE", "SAFE_SYNC_CONTEXT_TWO"],
                4,
            ),
        ]
        original_contents = {
            file_path: file_path.read_bytes()
            for file_path, *_ in staged_sources
        }
        private_texts = []
        expected_locations = [
            f"{file_path.name} (line {line_number}: {family})"
            for file_path, _git_path, _variable_name, _credential, family, _safe_context, line_number
            in staged_sources
        ]
        # Diagnostics are documented in repository-relative path order, not staging order.
        for file_path, git_path, variable_name, credential, _family, safe_context, _line_number in reversed(staged_sources):
            source_line = f"{variable_name}={credential}"
            staged_text = "\n".join([*safe_context, source_line, "SAFE_SOURCE_FOOTER"]) + "\n"
            file_path.write_bytes(staged_text.encode("utf-8"))
            self.run_git(["add", git_path])
            private_texts.extend([credential, source_line, *safe_context, "SAFE_SOURCE_FOOTER"])

        # The hook must inspect each staged blob, not the restored working tree.
        for file_path, original_content in original_contents.items():
            file_path.write_bytes(original_content)

        hook_env = self.hook_environment_without_github_token()
        self.assertNotIn("GITHUB_TOKEN", hook_env)
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        result = self.run_git(
            ["commit", "-m", "all staged source findings must be reported"],
            env=hook_env,
        )
        output = result.stdout + result.stderr
        safe_output = output
        for private_text in [*private_texts, FAKE_GITHUB_TOKEN]:
            safe_output = safe_output.replace(private_text, "[redacted test content]")

        self.assertNotEqual(result.returncode, 0, safe_output)
        self.assertIn(
            "Refusing to commit staged source files containing a credential-like value:",
            output,
            safe_output,
        )
        self.assertIn("; ".join(expected_locations), output, safe_output)
        self.assertIn("Remove the values from these staged files", output, safe_output)
        self.assertIn("No GitHub requests were made", output, safe_output)
        for private_text in private_texts:
            self.assertFalse(private_text in output, safe_output)
        self.assertFalse(FAKE_GITHUB_TOKEN in output, safe_output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip().splitlines(),
            sorted(git_path for _, git_path, *_ in staged_sources),
        )
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_reports_every_credential_in_linked_worktree(self):
        enabled_worktree_config = self.run_git(
            ["config", "--local", "extensions.worktreeConfig", "true"]
        )
        self.assertEqual(
            enabled_worktree_config.returncode,
            0,
            enabled_worktree_config.stdout + enabled_worktree_config.stderr,
        )
        worktree_root = self.repo_root / "multi-file-credential-worktree"
        added = self.run_git(
            ["worktree", "add", "--detach", str(worktree_root), "HEAD"]
        )
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        configured_hooks = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "core.hooksPath", "gitmesh-template/hooks"],
        )
        self.assertEqual(
            configured_hooks.returncode,
            0,
            configured_hooks.stdout + configured_hooks.stderr,
        )

        linked_template_root = worktree_root / "gitmesh-template"
        staged_sources = [
            (
                linked_template_root / "README.md",
                "gitmesh-template/README.md",
                "README_TOKEN",
                "ghp_" + "A" * 36,
                "GitHub token",
                ["SAFE_README_HEADER"],
                2,
            ),
            (
                linked_template_root / "gitmesh-ultimate-core.mjs",
                "gitmesh-template/gitmesh-ultimate-core.mjs",
                "CONSOLE_TOKEN",
                "github_pat_" + "B" * 40,
                "GitHub fine-grained token",
                ["SAFE_CONSOLE_HEADER", "SAFE_CONSOLE_CONTEXT"],
                3,
            ),
            (
                linked_template_root / "sync-public-source.mjs",
                "gitmesh-template/sync-public-source.mjs",
                "SYNC_TOKEN",
                "glpat-" + "C" * 24,
                "GitLab token",
                ["SAFE_SYNC_HEADER", "SAFE_SYNC_CONTEXT_ONE", "SAFE_SYNC_CONTEXT_TWO"],
                4,
            ),
        ]
        original_contents = {
            file_path: file_path.read_bytes()
            for file_path, *_ in staged_sources
        }
        private_texts = []
        expected_locations = []
        for file_path, git_path, variable_name, credential, family, safe_context, line_number in staged_sources:
            source_line = f"{variable_name}={credential}"
            staged_text = "\n".join([*safe_context, source_line, "SAFE_SOURCE_FOOTER"]) + "\n"
            file_path.write_bytes(staged_text.encode("utf-8"))
            staged = self.run_git_at(worktree_root, ["add", git_path])
            self.assertEqual(staged.returncode, 0, staged.stdout + staged.stderr)
            private_texts.extend([credential, source_line, *safe_context, "SAFE_SOURCE_FOOTER"])
            expected_locations.append(f"{file_path.name} (line {line_number}: {family})")

        # The linked-worktree hook must inspect the staged blobs, not restored files.
        for file_path, original_content in original_contents.items():
            file_path.write_bytes(original_content)

        hook_env = self.hook_environment_without_github_token()
        self.assertNotIn("GITHUB_TOKEN", hook_env)
        original_head = self.run_git_at(worktree_root, ["rev-parse", "HEAD"]).stdout.strip()
        result = subprocess.run(
            ["git", "commit", "-m", "report all linked-worktree source findings"],
            cwd=worktree_root,
            env=hook_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        safe_output = output
        for private_text in [*private_texts, FAKE_GITHUB_TOKEN]:
            safe_output = safe_output.replace(private_text, "[redacted test content]")

        self.assertNotEqual(result.returncode, 0, safe_output)
        self.assertIn(
            "Refusing to commit staged source files containing a credential-like value:",
            output,
            safe_output,
        )
        for location in expected_locations:
            self.assertIn(location, output, safe_output)
        self.assertIn("Remove the values from these staged files", output, safe_output)
        self.assertIn("No GitHub requests were made", output, safe_output)
        for private_text in private_texts:
            self.assertFalse(private_text in output, safe_output)
        self.assertFalse(FAKE_GITHUB_TOKEN in output, safe_output)
        self.assertEqual(
            self.run_git_at(worktree_root, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(
            self.run_git_at(
                worktree_root,
                ["diff", "--cached", "--name-only"],
            ).stdout.strip().splitlines(),
            sorted(git_path for _, git_path, *_ in staged_sources),
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

    def test_precommit_hook_blocks_when_node_is_too_old_without_leaking_output(self):
        credential = "ghp_" + "D" * 36
        staged_source_line = f"staged_secret={credential}"
        source_sentinel = "OLD_NODE_STAGED_SOURCE_SENTINEL"
        self.readme.write_text(f"{staged_source_line}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        path_with_old_node = self.repo_root / "path-with-old-node"
        path_with_old_node.mkdir()
        for command in ("git", "dirname"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"required test executable not found: {command}")
            (path_with_old_node / command).symlink_to(executable)
        execution_marker = self.repo_root / "old-node-was-used-for-scan"
        node_shim = path_with_old_node / "node"
        node_shim.write_text(
            "#!/bin/sh\n"
            'if [ "${1-}" = "--version" ]; then\n'
            "  printf '%s\\n' 'v18.19.0'\n"
            "  printf '%s\\n' 'NODE_VERSION_STDERR_SENTINEL' >&2\n"
            "  exit 0\n"
            "fi\n"
            'printf "%s\\n" "scanner unexpectedly launched" > "$GITMESH_TEST_NODE_EXECUTION_MARKER"\n'
            'printf "%s\\n" "NODE_RUNTIME_OUTPUT_SENTINEL" >&2\n'
            "exit 1\n"
        )
        node_shim.chmod(0o755)

        env = self.hook_environment_without_github_token()
        env["PATH"] = str(path_with_old_node)
        env["GITMESH_TEST_NODE_EXECUTION_MARKER"] = str(execution_marker)
        result = self.run_git(
            ["commit", "-m", "must be blocked with old node"],
            env=env,
        )
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detected Node.js major version 18", output)
        self.assertIn("Node.js 20 or newer is required", output)
        self.assertIn("Upgrade Node.js to 20 or newer", output)
        self.assertIn("ensure node --version reports v20 or newer", output)
        self.assertIn("No staged content was inspected", output)
        self.assertIn("No GitHub requests were made", output)
        for private_text in (
            "v18.19.0",
            "NODE_VERSION_STDERR_SENTINEL",
            "NODE_RUNTIME_OUTPUT_SENTINEL",
            staged_source_line,
            source_sentinel,
            credential,
            FAKE_GITHUB_TOKEN,
        ):
            self.assertNotIn(private_text, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(
            self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
            "gitmesh-template/README.md",
        )
        self.assertFalse(execution_marker.exists())
        self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_blocks_when_node_version_output_is_empty_or_malformed(self):
        credential = "ghp_" + "P" * 36
        staged_source_line = f"staged_secret={credential}"
        source_sentinel = "INVALID_NODE_STAGED_SOURCE_SENTINEL"
        self.readme.write_text(f"{staged_source_line}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        path_with_invalid_node = self.repo_root / "path-with-invalid-node-version"
        path_with_invalid_node.mkdir()
        for command in ("git", "dirname"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"required test executable not found: {command}")
            (path_with_invalid_node / command).symlink_to(executable)

        execution_marker = self.repo_root / "invalid-node-version-scanner-was-used"
        node_shim = path_with_invalid_node / "node"
        node_shim.write_text(
            "#!/bin/sh\n"
            'if [ "${1-}" = "--version" ]; then\n'
            '  printf "%s" "${GITMESH_TEST_NODE_VERSION_STDOUT-}"\n'
            '  printf "%s\\n" "${GITMESH_TEST_NODE_VERSION_STDERR-}" >&2\n'
            "  exit 0\n"
            "fi\n"
            'printf "%s\\n" "NODE_VERSION_SCANNER_LAUNCH_SENTINEL" > "$GITMESH_TEST_NODE_EXECUTION_MARKER"\n'
            'printf "%s\\n" "NODE_VERSION_SCANNER_OUTPUT_SENTINEL" >&2\n'
            "exit 1\n"
        )
        node_shim.chmod(0o755)

        cases = (
            ("empty", ""),
            ("malformed", "NODE_VERSION_STDOUT_SENTINEL"),
            ("version with trailing text", "v20.0.0 NODE_VERSION_TRAILING_TEXT_SENTINEL"),
        )
        version_stderr = "NODE_VERSION_STDERR_SENTINEL"
        for label, version_output in cases:
            with self.subTest(output=label):
                env = self.hook_environment_without_github_token()
                env["PATH"] = str(path_with_invalid_node)
                env["GITMESH_TEST_NODE_EXECUTION_MARKER"] = str(execution_marker)
                env["GITMESH_TEST_NODE_VERSION_STDOUT"] = version_output
                env["GITMESH_TEST_NODE_VERSION_STDERR"] = version_stderr
                result = self.run_git(
                    ["commit", "-m", "must be blocked by an unverifiable Node version"],
                    env=env,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("could not verify the Node.js version", output)
                self.assertIn("Node.js 20 or newer is required", output)
                self.assertIn("Install or upgrade Node.js to 20 or newer", output)
                self.assertIn("ensure node --version reports v20 or newer", output)
                self.assertIn("retry the commit", output)
                self.assertIn("No staged content was inspected", output)
                self.assertIn("No GitHub requests were made", output)
                private_output = (
                    version_stderr,
                    "NODE_VERSION_STDOUT_SENTINEL",
                    "NODE_VERSION_TRAILING_TEXT_SENTINEL",
                    "NODE_VERSION_SCANNER_LAUNCH_SENTINEL",
                    "NODE_VERSION_SCANNER_OUTPUT_SENTINEL",
                    staged_source_line,
                    source_sentinel,
                    credential,
                    FAKE_GITHUB_TOKEN,
                )
                for private_text in private_output:
                    self.assertNotIn(private_text, output)
                if version_output:
                    self.assertNotIn(version_output, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(execution_marker.exists())
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_reports_staged_git_timeout_safely_without_github_token(self):
        credential = "ghp_" + "T" * 36
        staged_source_line = f"staged_secret={credential}"
        source_sentinel = "STAGED_GIT_TIMEOUT_SOURCE_SENTINEL"
        self.readme.write_text(f"{staged_source_line}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        timeout_cases = (
            ("repository-lookup", "repository lookup", "rev-parse"),
            ("staged-path-listing", "staged path listing", "diff"),
            ("staged-blob-size", "staged blob reading", "cat-file"),
            ("staged-blob-content", "staged blob reading", "show"),
        )
        for timeout_stage, display_stage, expected_command in timeout_cases:
            with self.subTest(timeout_stage=timeout_stage):
                timeout_marker = self.repo_root / f"staged-git-timeout-{timeout_stage}.json"
                env = self.hook_environment_without_github_token()
                env["GITMESH_TEST_GIT_TIMEOUT"] = "1"
                env["GITMESH_TEST_GIT_TIMEOUT_STAGE"] = timeout_stage
                env["GITMESH_TEST_GIT_TIMEOUT_MARKER"] = str(timeout_marker)
                self.assertNotIn("GITHUB_TOKEN", env)
                result = self.run_git(
                    ["commit", "-m", "must be blocked when staged git times out"],
                    env=env,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"Git timed out during {display_stage} while checking staged source files",
                    output,
                )
                self.assertIn("Check whether another Git process is stuck", output)
                self.assertIn("whether the repository is responsive", output)
                self.assertIn("then retry the commit", output)
                self.assertIn("staged source check failed closed", output)
                self.assertIn("No GitHub requests were made", output)
                self.assertNotIn("Check that the staged index is readable", output)
                for private_text in (
                    credential,
                    staged_source_line,
                    source_sentinel,
                    "PRIVATE_GIT_TIMEOUT_DIAGNOSTIC",
                    "PRIVATE_GIT_TIMEOUT_STDERR",
                    "PRIVATE_STAGED_TIMEOUT_CONTENT",
                    FAKE_GITHUB_TOKEN,
                    "rev-parse",
                    "--show-toplevel",
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-ext-diff",
                    "--no-textconv",
                    "-z",
                    "--diff-filter=ACMRT",
                    "cat-file",
                    "-s",
                    "show",
                    ":0:gitmesh-template/README.md",
                    "gitmesh-template/README.md",
                ):
                    self.assertNotIn(private_text, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertTrue(timeout_marker.exists())
                timeout_capture = json.loads(timeout_marker.read_text())
                self.assertEqual(timeout_capture["stage"], timeout_stage)
                self.assertEqual(timeout_capture["command"], expected_command)
                self.assertEqual(timeout_capture["timeoutMs"], 15_000)
                self.assertFalse(timeout_capture["hasGitHubToken"])
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_accepts_bounded_staged_git_timeout_override(self):
        credential = "ghp_" + "R" * 36
        staged_source_line = f"staged_secret={credential}"
        source_sentinel = "CUSTOM_TIMEOUT_STAGED_SOURCE_SENTINEL"
        self.readme.write_text(f"{staged_source_line}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        valid_settings = (("1000", 1_000), ("30000", 30_000), ("120000", 120_000))
        for setting, expected_timeout in valid_settings:
            with self.subTest(timeout_ms=setting):
                timeout_marker = self.repo_root / f"valid-staged-git-timeout-{setting}.json"
                env = self.hook_environment_without_github_token()
                env["GITMESH_STAGED_SCAN_TIMEOUT_MS"] = setting
                env["GITMESH_TEST_GIT_TIMEOUT"] = "1"
                env["GITMESH_TEST_GIT_TIMEOUT_STAGE"] = "repository-lookup"
                env["GITMESH_TEST_GIT_TIMEOUT_MARKER"] = str(timeout_marker)
                result = self.run_git(
                    ["commit", "-m", "must block when the staged scan times out"],
                    env=env,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Git timed out during repository lookup", output)
                self.assertIn("The staged source check failed closed", output)
                self.assertIn("No GitHub requests were made", output)
                for private_text in (
                    credential,
                    staged_source_line,
                    source_sentinel,
                    "PRIVATE_GIT_TIMEOUT_DIAGNOSTIC",
                    "PRIVATE_GIT_TIMEOUT_STDERR",
                    "PRIVATE_STAGED_TIMEOUT_CONTENT",
                    FAKE_GITHUB_TOKEN,
                ):
                    self.assertNotIn(private_text, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertTrue(timeout_marker.exists())
                timeout_capture = json.loads(timeout_marker.read_text())
                self.assertEqual(timeout_capture["stage"], "repository-lookup")
                self.assertEqual(timeout_capture["command"], "rev-parse")
                self.assertEqual(timeout_capture["timeoutMs"], expected_timeout)
                self.assertFalse(timeout_capture["hasGitHubToken"])
                self.assertFalse(self.network_marker.exists())

    def test_precommit_hook_rejects_invalid_staged_git_timeout_settings(self):
        credential = "ghp_" + "S" * 36
        staged_source_line = f"staged_secret={credential}"
        source_sentinel = "INVALID_TIMEOUT_STAGED_SOURCE_SENTINEL"
        self.readme.write_text(f"{staged_source_line}\n{source_sentinel}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()

        invalid_settings = (
            "",
            "0",
            "999",
            "120001",
            "-1",
            "1.5",
            "1e6",
            "UNSAFE_TIMEOUT_SETTING_SENTINEL",
            "9" * 100,
        )
        for index, setting in enumerate(invalid_settings):
            with self.subTest(timeout_setting=setting or "<empty>"):
                timeout_marker = self.repo_root / f"invalid-staged-git-timeout-{index}.json"
                env = self.hook_environment_without_github_token()
                env["GITMESH_STAGED_SCAN_TIMEOUT_MS"] = setting
                env["GITMESH_TEST_GIT_TIMEOUT"] = "1"
                env["GITMESH_TEST_GIT_TIMEOUT_STAGE"] = "repository-lookup"
                env["GITMESH_TEST_GIT_TIMEOUT_MARKER"] = str(timeout_marker)
                result = self.run_git(
                    ["commit", "-m", "must block with invalid staged scan timeout"],
                    env=env,
                )
                output = result.stdout + result.stderr

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "GITMESH_STAGED_SCAN_TIMEOUT_MS must be a whole number from "
                    "1000 to 120000 milliseconds",
                    output,
                )
                self.assertIn("The staged source check failed closed", output)
                self.assertIn("No GitHub requests were made", output)
                self.assertNotIn("UNSAFE_TIMEOUT_SETTING_SENTINEL", output)
                self.assertNotIn(staged_source_line, output)
                self.assertNotIn(source_sentinel, output)
                self.assertNotIn(credential, output)
                self.assertNotIn(FAKE_GITHUB_TOKEN, output)
                self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
                self.assertEqual(
                    self.run_git(["diff", "--cached", "--name-only"]).stdout.strip(),
                    "gitmesh-template/README.md",
                )
                self.assertFalse(timeout_marker.exists())
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
        shutil.copy2(PRE_PUSH_HOOK, hook_dir / "pre-push")

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

    def run_installer(self, cwd=None, args=(), installer_path=None, env=None):
        cwd = cwd or self.repo_root
        installer_path = installer_path or cwd / "gitmesh-template" / HOOK_INSTALLER.name
        return subprocess.run(
            ["node", str(installer_path), *args],
            cwd=cwd,
            env=self.env if env is None else env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def make_executable_hook(self, hook_path, contents):
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(contents)
        hook_path.chmod(0o755)
        return hook_path.read_bytes()

    def git_config_snapshot(self, cwd):
        git_dir_result = self.run_git_at(cwd, ["rev-parse", "--absolute-git-dir"])
        common_dir_result = self.run_git_at(cwd, ["rev-parse", "--git-common-dir"])
        self.assertEqual(git_dir_result.returncode, 0, git_dir_result.stderr)
        self.assertEqual(common_dir_result.returncode, 0, common_dir_result.stderr)
        git_dir = pathlib.Path(git_dir_result.stdout.strip())
        common_dir = pathlib.Path(common_dir_result.stdout.strip())
        if not git_dir.is_absolute():
            git_dir = cwd / git_dir
        if not common_dir.is_absolute():
            common_dir = cwd / common_dir
        paths = (common_dir / "config", git_dir / "config.worktree", self.global_config)
        snapshot = {}
        for config_path in paths:
            try:
                metadata = config_path.stat()
                snapshot[str(config_path)] = (
                    metadata.st_mtime_ns,
                    metadata.st_size,
                    config_path.read_bytes(),
                )
            except FileNotFoundError:
                snapshot[str(config_path)] = None
        return snapshot

    def test_hook_status_reports_repository_local_setup_without_writing_config(self):
        self.run_git(["config", "--local", "core.hooksPath", "gitmesh-template/hooks"])
        self.run_git(["config", "--local", "gitmesh.prePushCredentialCheck", "false"])
        before = self.git_config_snapshot(self.repo_root)
        status = self.run_installer(args=("--status",))
        output = status.stdout + status.stderr

        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: active", output)
        self.assertIn("Scope: repository-local", output)
        self.assertIn(
            "To disable this GitMesh setup, run: git config --local --unset core.hooksPath '^gitmesh-template/hooks$'",
            output,
        )
        self.assertIn("GitMesh outgoing push credential scan: disabled", output)
        self.assertIn(
            "To enable it for this repository, run: git config --local gitmesh.prePushCredentialCheck true",
            output,
        )
        self.assertEqual(self.git_config_snapshot(self.repo_root), before)

    def test_hook_status_reports_enabled_push_scan_without_writing_config(self):
        configured_hooks_path = self.run_git(
            ["config", "--local", "core.hooksPath", "gitmesh-template/hooks"]
        )
        self.assertEqual(configured_hooks_path.returncode, 0, configured_hooks_path.stderr)
        configured_push_scan = self.run_git(
            ["config", "--local", "gitmesh.prePushCredentialCheck", "true"]
        )
        self.assertEqual(configured_push_scan.returncode, 0, configured_push_scan.stderr)
        before = self.git_config_snapshot(self.repo_root)

        status = self.run_installer(args=("--status",))
        output = status.stdout + status.stderr

        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: active", output)
        self.assertIn("GitMesh outgoing push credential scan: enabled", output)
        self.assertNotIn("To enable it for this repository", output)
        self.assertEqual(self.git_config_snapshot(self.repo_root), before)

    def test_hook_status_scope_fallback_identifies_repository_and_worktree_settings(self):
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        fake_git_directory = self.repo_root / "legacy-git-bin"
        fake_git_directory.mkdir()
        fake_git = fake_git_directory / "git"
        fake_git.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "config" ] && [ "$2" = "--show-scope" ]; then\n'
            '  : > "$GITMESH_SCOPE_FALLBACK_MARKER"\n'
            "  printf '%s\\n' 'option --show-scope is unavailable' >&2\n"
            "  exit 129\n"
            "fi\n"
            'exec "$GITMESH_TEST_REAL_GIT" "$@"\n'
        )
        fake_git.chmod(0o755)
        legacy_git_env = self.env.copy()
        legacy_git_env["PATH"] = (
            str(fake_git_directory) + os.pathsep + legacy_git_env["PATH"]
        )
        legacy_git_env["GITMESH_TEST_REAL_GIT"] = str(real_git)
        scope_fallback_marker = self.repo_root / "scope-fallback-was-used"
        legacy_git_env["GITMESH_SCOPE_FALLBACK_MARKER"] = str(scope_fallback_marker)

        configured_local = self.run_git(
            ["config", "--local", "core.hooksPath", "gitmesh-template/hooks"]
        )
        self.assertEqual(configured_local.returncode, 0, configured_local.stderr)
        repository_config_before = self.git_config_snapshot(self.repo_root)
        repository_status = self.run_installer(
            args=("--status",),
            env=legacy_git_env,
        )
        repository_output = repository_status.stdout + repository_status.stderr
        self.assertEqual(repository_status.returncode, 0, repository_output)
        self.assertTrue(scope_fallback_marker.is_file())
        self.assertIn("GitMesh pre-commit check: active", repository_output)
        self.assertIn("Scope: repository-local", repository_output)
        self.assertIn(
            "To disable this GitMesh setup, run: git config --local --unset core.hooksPath '^gitmesh-template/hooks$'",
            repository_output,
        )
        self.assertEqual(
            self.git_config_snapshot(self.repo_root),
            repository_config_before,
        )
        scope_fallback_marker.unlink()

        configured_extension = self.run_git(
            ["config", "--local", "extensions.worktreeConfig", "true"]
        )
        self.assertEqual(configured_extension.returncode, 0, configured_extension.stderr)
        worktree_root = self.repo_root / "legacy-git-scope-worktree"
        added = self.run_git(
            ["worktree", "add", "--detach", str(worktree_root), "HEAD"]
        )
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        configured_worktree = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "core.hooksPath", "gitmesh-template/hooks"],
        )
        self.assertEqual(configured_worktree.returncode, 0, configured_worktree.stderr)
        worktree_config_before = self.git_config_snapshot(worktree_root)
        repository_config_before_worktree_status = self.git_config_snapshot(self.repo_root)

        worktree_status = self.run_installer(
            cwd=worktree_root,
            args=("--status",),
            env=legacy_git_env,
        )
        worktree_output = worktree_status.stdout + worktree_status.stderr
        self.assertEqual(worktree_status.returncode, 0, worktree_output)
        self.assertTrue(scope_fallback_marker.is_file())
        self.assertIn("GitMesh pre-commit check: active", worktree_output)
        self.assertIn("Scope: worktree-local", worktree_output)
        self.assertIn(
            "To disable this GitMesh setup, run: git config --worktree --unset core.hooksPath '^gitmesh-template/hooks$'",
            worktree_output,
        )
        self.assertEqual(
            self.git_config_snapshot(worktree_root),
            worktree_config_before,
        )
        self.assertEqual(
            self.git_config_snapshot(self.repo_root),
            repository_config_before_worktree_status,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_status_reports_inherited_repository_local_setup_as_shared(self):
        worktree_root = self.repo_root / "status-inherited-linked-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        configured = self.run_git(
            ["config", "--local", "core.hooksPath", "gitmesh-template/hooks"]
        )
        self.assertEqual(configured.returncode, 0, configured.stderr)
        worktree_config_before = self.git_config_snapshot(worktree_root)
        repository_config_before = self.git_config_snapshot(self.repo_root)

        status = self.run_installer(
            cwd=worktree_root,
            args=("--status",),
        )
        output = status.stdout + status.stderr
        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: active", output)
        self.assertIn(
            "Scope: shared (repository-local across linked worktrees)",
            output,
        )
        self.assertIn(
            "To disable this GitMesh setup, run: git config --local --unset core.hooksPath '^gitmesh-template/hooks$'",
            output,
        )
        self.assertNotIn("git config --worktree --unset core.hooksPath", output)
        self.assertEqual(
            self.git_config_snapshot(worktree_root),
            worktree_config_before,
        )
        self.assertEqual(
            self.git_config_snapshot(self.repo_root),
            repository_config_before,
        )
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).stdout.strip(),
            "gitmesh-template/hooks",
        )

    def test_hook_status_reports_shared_setup_without_writing_config(self):
        shared_hooks = self.template_root / "hooks"
        self.run_git(["config", "--global", "core.hooksPath", str(shared_hooks)])
        before = self.git_config_snapshot(self.repo_root)
        status = self.run_installer(args=("--status",))
        output = status.stdout + status.stderr

        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: active", output)
        self.assertIn("Scope: shared (global)", output)
        self.assertIn("git config --global --unset core.hooksPath", output)
        self.assertEqual(self.git_config_snapshot(self.repo_root), before)

    def test_hook_status_reports_inactive_setup_without_writing_config(self):
        before = self.git_config_snapshot(self.repo_root)
        status = self.run_installer(args=("--status",))
        output = status.stdout + status.stderr

        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: inactive", output)
        self.assertIn("Scope: inactive", output)
        self.assertIn("GitMesh outgoing push credential scan: disabled", output)
        self.assertIn(
            "To enable it for this repository, run: git config --local gitmesh.prePushCredentialCheck true",
            output,
        )
        self.assertIn("No GitMesh-specific disable command is needed", output)
        self.assertEqual(self.git_config_snapshot(self.repo_root), before)

    def test_hook_status_reports_manual_hook_integration_without_writing_config(self):
        hook_path = self.repo_root / "manual-hooks" / "pre-commit"
        self.make_executable_hook(
            hook_path,
            "#!/bin/sh\n"
            "node 'gitmesh-template/sync-public-source.mjs' --check-staged-credentials\n",
        )
        self.run_git(["config", "--local", "core.hooksPath", "manual-hooks"])
        before = self.git_config_snapshot(self.repo_root)
        status = self.run_installer(args=("--status",))
        output = status.stdout + status.stderr

        self.assertEqual(status.returncode, 0, output)
        self.assertIn("GitMesh pre-commit check: active", output)
        self.assertIn("Scope: repository-local", output)
        self.assertIn("GitMesh check found in the existing hook", output)
        self.assertIn("remove its command", output)
        self.assertNotIn("git config --local --unset core.hooksPath", output)
        self.assertEqual(self.git_config_snapshot(self.repo_root), before)

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

    def test_hook_setup_uses_standalone_hooks_path_only_for_selected_worktree(self):
        standalone_root = self.repo_root / "standalone-gitmesh-worktree"
        standalone_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, standalone_root / name)
        installer_path = standalone_root / HOOK_INSTALLER.name
        shutil.copy2(HOOK_INSTALLER, installer_path)
        standalone_hooks = standalone_root / "hooks"
        standalone_hooks.mkdir()
        shutil.copy2(PRE_COMMIT_HOOK, standalone_hooks / "pre-commit")

        initialized = self.run_git_at(standalone_root, ["init", "--quiet"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        for name, value in (
            ("user.name", "GitMesh Standalone Worktree Test"),
            ("user.email", "gitmesh-standalone-worktree-test@example.invalid"),
            ("commit.gpgsign", "false"),
        ):
            configured = self.run_git_at(standalone_root, ["config", "--local", name, value])
            self.assertEqual(configured.returncode, 0, configured.stderr)
        self.run_git_at(standalone_root, ["add", "."])
        baseline = self.run_git_at(
            standalone_root,
            ["commit", "--quiet", "-m", "standalone worktree fixture baseline"],
        )
        self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)

        extension = self.run_git_at(
            standalone_root,
            ["config", "--local", "extensions.worktreeConfig", "true"],
        )
        self.assertEqual(extension.returncode, 0, extension.stderr)
        selected_worktree = self.repo_root / "standalone-selected-worktree"
        sibling_worktree = self.repo_root / "standalone-sibling-worktree"
        selected_added = self.run_git_at(
            standalone_root,
            ["worktree", "add", "--detach", str(selected_worktree), "HEAD"],
        )
        self.assertEqual(selected_added.returncode, 0, selected_added.stdout + selected_added.stderr)
        sibling_added = self.run_git_at(
            standalone_root,
            ["worktree", "add", "--detach", str(sibling_worktree), "HEAD"],
        )
        self.assertEqual(sibling_added.returncode, 0, sibling_added.stdout + sibling_added.stderr)

        enabled = self.run_installer(
            cwd=selected_worktree,
            args=("--worktree-local",),
            installer_path=selected_worktree / HOOK_INSTALLER.name,
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        selected_path = self.run_git_at(
            selected_worktree,
            ["config", "--worktree", "--get", "core.hooksPath"],
        )
        self.assertEqual(selected_path.returncode, 0)
        self.assertEqual(selected_path.stdout.strip(), "hooks")
        before_status = self.git_config_snapshot(selected_worktree)
        status = self.run_installer(
            cwd=selected_worktree,
            args=("--status",),
            installer_path=selected_worktree / HOOK_INSTALLER.name,
        )
        status_output = status.stdout + status.stderr
        self.assertEqual(status.returncode, 0, status_output)
        self.assertIn("GitMesh pre-commit check: active", status_output)
        self.assertIn("Scope: worktree-local", status_output)
        self.assertIn(
            "To disable this GitMesh setup, run: git config --worktree --unset core.hooksPath '^hooks$'",
            status_output,
        )
        self.assertEqual(self.git_config_snapshot(selected_worktree), before_status)

        moved_worktree = self.repo_root / "standalone-moved-selected-worktree"
        moved = self.run_git_at(
            standalone_root,
            ["worktree", "move", str(selected_worktree), str(moved_worktree)],
        )
        self.assertEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertFalse(selected_worktree.exists())
        self.assertTrue(moved_worktree.is_dir())
        selected_worktree = moved_worktree
        self.assertEqual(
            pathlib.Path(
                self.run_git_at(selected_worktree, ["rev-parse", "--show-toplevel"]).stdout.strip()
            ),
            selected_worktree,
        )
        moved_configured_path = self.run_git_at(
            selected_worktree,
            ["config", "--worktree", "--get", "core.hooksPath"],
        )
        self.assertEqual(moved_configured_path.returncode, 0, moved_configured_path.stderr)
        self.assertEqual(moved_configured_path.stdout.strip(), "hooks")
        self.assertTrue((selected_worktree / "hooks" / "pre-commit").is_file())

        for untouched in (standalone_root, sibling_worktree):
            self.assertEqual(
                self.run_git_at(
                    untouched,
                    ["config", "--worktree", "--get", "core.hooksPath"],
                ).returncode,
                1,
            )
        self.assertEqual(
            self.run_git_at(
                standalone_root,
                ["config", "--local", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(
            self.run_git_at(
                standalone_root,
                ["config", "--local", "--get", "extensions.worktreeConfig"],
            ).stdout.strip(),
            "true",
        )
        self.assertEqual(self.global_config.read_text(), "")

        credential = "ghp_" + "N" * 36
        readme = selected_worktree / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git_at(selected_worktree, ["add", "README.md"])
        original_head = self.run_git_at(selected_worktree, ["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git_at(
            selected_worktree,
            ["commit", "-m", "standalone worktree credential check"],
        )
        output = commit.stdout + commit.stderr
        self.assertNotEqual(
            commit.returncode,
            0,
            output.replace(credential, "[redacted test credential]"),
        )
        self.assertIn("README.md (line 1: GitHub token)", output)
        self.assertNotIn(credential, output)
        self.assertEqual(
            self.run_git_at(selected_worktree, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(
            self.run_git_at(
                sibling_worktree,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(
            self.run_git_at(
                standalone_root,
                ["config", "--local", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_standalone_root_worktree_setup_refuses_without_worktree_config_support(self):
        standalone_root = self.repo_root / "standalone-no-worktree-config"
        standalone_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, standalone_root / name)
        installer_path = standalone_root / HOOK_INSTALLER.name
        shutil.copy2(HOOK_INSTALLER, installer_path)
        hooks_directory = standalone_root / "hooks"
        hooks_directory.mkdir()
        standalone_hook = hooks_directory / "pre-commit"
        shutil.copy2(PRE_COMMIT_HOOK, standalone_hook)
        original_hook = standalone_hook.read_bytes()

        initialized = self.run_git_at(standalone_root, ["init", "--quiet"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        for name, value in (
            ("user.name", "GitMesh Standalone Unsupported Test"),
            ("user.email", "gitmesh-standalone-unsupported-test@example.invalid"),
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
            ["commit", "--quiet", "-m", "standalone unsupported fixture baseline"],
        )
        self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)

        selected_worktree = self.repo_root / "standalone-no-config-selected"
        sibling_worktree = self.repo_root / "standalone-no-config-sibling"
        selected_added = self.run_git_at(
            standalone_root,
            ["worktree", "add", "--detach", str(selected_worktree), "HEAD"],
        )
        self.assertEqual(selected_added.returncode, 0, selected_added.stdout + selected_added.stderr)
        sibling_added = self.run_git_at(
            standalone_root,
            ["worktree", "add", "--detach", str(sibling_worktree), "HEAD"],
        )
        self.assertEqual(sibling_added.returncode, 0, sibling_added.stdout + sibling_added.stderr)

        selected_hook = selected_worktree / "hooks" / "pre-commit"
        sibling_hook = sibling_worktree / "hooks" / "pre-commit"
        self.assertEqual(selected_hook.read_bytes(), original_hook)
        self.assertEqual(sibling_hook.read_bytes(), original_hook)
        config_before = {
            str(root): self.git_config_snapshot(root)
            for root in (standalone_root, selected_worktree, sibling_worktree)
        }

        result = self.run_installer(
            cwd=selected_worktree,
            args=("--worktree-local",),
            installer_path=selected_worktree / HOOK_INSTALLER.name,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires extensions.worktreeConfig=true", output)
        self.assertIn("The setting is not enabled", output)
        self.assertIn("No Git configuration was changed", output)
        self.assertEqual(
            self.run_git_at(
                standalone_root,
                ["config", "--local", "--get", "extensions.worktreeConfig"],
            ).returncode,
            1,
        )
        for root in (standalone_root, selected_worktree, sibling_worktree):
            hook_path = self.run_git_at(root, ["config", "--get-all", "core.hooksPath"])
            self.assertEqual(hook_path.returncode, 1, hook_path.stdout + hook_path.stderr)
            self.assertEqual(
                self.git_config_snapshot(root),
                config_before[str(root)],
            )
        self.assertEqual(selected_hook.read_bytes(), original_hook)
        self.assertEqual(sibling_hook.read_bytes(), original_hook)
        self.assertEqual(standalone_hook.read_bytes(), original_hook)
        self.assertEqual(self.global_config.read_bytes(), b"")

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
        self.assertIn("README.md (line 1: GitHub token)", output)
        self.assertNotIn(credential, output)

    def test_chain_existing_hooks_run_first_and_preserve_configuration(self):
        existing_hooks = self.repo_root / "existing-local-hooks"
        pre_commit = existing_hooks / "pre-commit"
        post_commit = existing_hooks / "post-commit"
        post_commit_marker = self.repo_root / "existing-post-commit-marker"
        original_pre_commit = self.make_executable_hook(
            pre_commit,
            "#!/bin/sh\nprintf 'existing-pre-commit-ran\\n'\n",
        )
        original_post_commit = self.make_executable_hook(
            post_commit,
            "#!/bin/sh\n"
            f"printf '%s\\n' 'existing-post-commit-ran' > {shlex.quote(str(post_commit_marker))}\n",
        )
        self.run_git(["config", "--global", "core.hooksPath", "existing-global-hooks"])
        self.run_git(["config", "--local", "--add", "core.hooksPath", "existing-local-hooks"])

        enabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn("existing pre-commit hook, if present, runs first, then GitMesh", enabled.stdout)
        self.assertIn("No global or sibling-worktree settings were changed", enabled.stdout)
        disable_command_text = (
            "node 'gitmesh-template/install-pre-commit-hook.mjs' --disable-chain"
        )
        self.assertIn(disable_command_text, enabled.stdout)
        before_status = self.git_config_snapshot(self.repo_root)
        status = self.run_installer(args=("--status",))
        status_output = status.stdout + status.stderr
        self.assertEqual(status.returncode, 0, status_output)
        self.assertIn("GitMesh pre-commit check: active", status_output)
        self.assertIn("Scope: repository-local", status_output)
        self.assertIn(disable_command_text, status_output)
        self.assertEqual(self.git_config_snapshot(self.repo_root), before_status)

        local_paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(local_paths.returncode, 0)
        path_values = local_paths.stdout.splitlines()
        self.assertEqual(path_values[0], "existing-local-hooks")
        self.assertEqual(len(path_values), 2)
        dispatch_directory = pathlib.Path(path_values[1])
        self.assertTrue(dispatch_directory.is_dir())
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)
        self.assertEqual(post_commit.read_bytes(), original_post_commit)

        unrelated = self.repo_root / "unrelated-chain-test.txt"
        unrelated.write_text("Both hooks should pass.\n")
        self.run_git(["add", unrelated.name])
        commit = self.run_git(["commit", "-m", "chained hooks pass"])
        output = commit.stdout + commit.stderr
        self.assertEqual(commit.returncode, 0, output)
        existing_index = output.index("existing-pre-commit-ran")
        gitmesh_index = output.index("Credential check passed: no allowlisted source files are staged.")
        self.assertLess(existing_index, gitmesh_index)
        self.assertTrue(post_commit_marker.exists())
        self.assertEqual(post_commit.read_bytes(), original_post_commit)
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )
        # Existing installations may still have the original marker-only format.
        (dispatch_directory / ".gitmesh-dispatch").write_text(
            "GitMesh hook dispatcher v1\n"
        )
        disable_command = enabled.stdout.split("To disable it, run: ", 1)[1].strip()
        disabled = subprocess.run(
            shlex.split(disable_command),
            cwd=self.repo_root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(disabled.returncode, 0, disabled.stdout + disabled.stderr)
        self.assertFalse(dispatch_directory.exists())
        restored_paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(restored_paths.stdout.splitlines(), ["existing-local-hooks"])
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)
        self.assertEqual(post_commit.read_bytes(), original_post_commit)
        reenabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(reenabled.returncode, 0, reenabled.stdout + reenabled.stderr)
        reenabled_paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(len(reenabled_paths.stdout.splitlines()), 2)
        self.assertTrue(dispatch_directory.is_dir())

    def test_chain_existing_hooks_survive_paths_with_spaces_apostrophes_and_regex_characters(self):
        repo_root = self.repo_root / "repo with spaces ' [regex]+(root)$"
        repo_root.mkdir()
        template_root = repo_root / "gitmesh-template"
        template_root.mkdir()
        for name in ALLOWED_SOURCE_NAMES:
            shutil.copy2(ROOT / name, template_root / name)
        installer_path = template_root / HOOK_INSTALLER.name
        shutil.copy2(HOOK_INSTALLER, installer_path)
        hooks_root = template_root / "hooks"
        hooks_root.mkdir()
        shutil.copy2(PRE_COMMIT_HOOK, hooks_root / "pre-commit")
        shutil.copy2(PRE_PUSH_HOOK, hooks_root / "pre-push")

        initialized = self.run_git_at(repo_root, ["init", "--quiet"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        for name, value in (
            ("user.name", "GitMesh Quoted Path Test"),
            ("user.email", "gitmesh-quoted-path-test@example.invalid"),
            ("commit.gpgsign", "false"),
        ):
            configured = self.run_git_at(repo_root, ["config", "--local", name, value])
            self.assertEqual(configured.returncode, 0, configured.stderr)
        self.run_git_at(repo_root, ["add", "gitmesh-template"])
        baseline = self.run_git_at(repo_root, ["commit", "--quiet", "-m", "quoted path baseline"])
        self.assertEqual(baseline.returncode, 0, baseline.stdout + baseline.stderr)

        previous_hooks_value = "previous hooks ' [first]+$"
        existing_hooks_value = "existing hooks ' [a-z]+(current)$"
        existing_hooks = repo_root / existing_hooks_value
        marker = repo_root / "hook ran ' [marker]+.txt"
        original_hook = self.make_executable_hook(
            existing_hooks / "pre-commit",
            "#!/bin/sh\n"
            "printf 'existing hook invoked\\n'\n"
            "printf 'existing hook invoked\\n' >> "
            f"{shlex.quote(str(marker))}\n",
        )
        self.run_git_at(
            repo_root,
            ["config", "--local", "--add", "core.hooksPath", previous_hooks_value],
        )
        self.run_git_at(
            repo_root,
            ["config", "--local", "--add", "core.hooksPath", existing_hooks_value],
        )
        original_global_config = self.global_config.read_bytes()

        enabled = self.run_installer(
            cwd=repo_root,
            args=("--chain-existing",),
            installer_path=installer_path,
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn(
            "node 'gitmesh-template/install-pre-commit-hook.mjs' --disable-chain",
            enabled.stdout,
        )
        configured_paths = self.run_git_at(
            repo_root,
            ["config", "--local", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(configured_paths.returncode, 0, configured_paths.stderr)
        path_values = configured_paths.stdout.splitlines()
        self.assertEqual(path_values[:2], [previous_hooks_value, existing_hooks_value])
        self.assertEqual(len(path_values), 3)
        dispatch_directory = pathlib.Path(path_values[-1])
        self.assertTrue(dispatch_directory.is_dir())
        self.assertIn(" [regex]+(root)$", str(dispatch_directory))
        self.assertEqual((existing_hooks / "pre-commit").read_bytes(), original_hook)

        first_file = repo_root / "first ordinary file.txt"
        first_file.write_text("Commit through the quoted dispatcher.\n")
        self.run_git_at(repo_root, ["add", first_file.name])
        first_commit = self.run_git_at(repo_root, ["commit", "-m", "first quoted path commit"])
        first_output = first_commit.stdout + first_commit.stderr
        self.assertEqual(first_commit.returncode, 0, first_output)
        self.assertLess(
            first_output.index("existing hook invoked"),
            first_output.index("Credential check passed: no allowlisted source files are staged."),
        )
        self.assertEqual(marker.read_text().splitlines(), ["existing hook invoked"])
        self.assertEqual((existing_hooks / "pre-commit").read_bytes(), original_hook)

        before_status = self.git_config_snapshot(repo_root)
        status = self.run_installer(
            cwd=repo_root,
            args=("--status",),
            installer_path=installer_path,
        )
        status_output = status.stdout + status.stderr
        self.assertEqual(status.returncode, 0, status_output)
        self.assertIn(
            "node 'gitmesh-template/install-pre-commit-hook.mjs' --disable-chain",
            status_output,
        )
        self.assertEqual(self.git_config_snapshot(repo_root), before_status)

        disable_command = enabled.stdout.split("To disable it, run: ", 1)[1].strip()
        disabled = subprocess.run(
            shlex.split(disable_command),
            cwd=repo_root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(disabled.returncode, 0, disabled.stdout + disabled.stderr)
        self.assertFalse(dispatch_directory.exists())
        remaining_paths = self.run_git_at(
            repo_root,
            ["config", "--local", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(
            remaining_paths.stdout.splitlines(),
            [previous_hooks_value, existing_hooks_value],
        )
        self.assertEqual((existing_hooks / "pre-commit").read_bytes(), original_hook)
        self.assertEqual(self.global_config.read_bytes(), original_global_config)

        reenabled = self.run_installer(
            cwd=repo_root,
            args=("--chain-existing",),
            installer_path=installer_path,
        )
        self.assertEqual(reenabled.returncode, 0, reenabled.stdout + reenabled.stderr)
        reenabled_paths = self.run_git_at(
            repo_root,
            ["config", "--local", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(reenabled_paths.returncode, 0, reenabled_paths.stderr)
        self.assertEqual(
            reenabled_paths.stdout.splitlines()[:2],
            [previous_hooks_value, existing_hooks_value],
        )
        self.assertEqual(len(reenabled_paths.stdout.splitlines()), 3)
        reinstalled_again = self.run_installer(
            cwd=repo_root,
            args=("--chain-existing",),
            installer_path=installer_path,
        )
        self.assertEqual(
            reinstalled_again.returncode,
            0,
            reinstalled_again.stdout + reinstalled_again.stderr,
        )
        self.assertIn("already enabled", reinstalled_again.stdout)
        self.assertEqual(
            self.run_git_at(
                repo_root,
                ["config", "--local", "--get-all", "core.hooksPath"],
            ).stdout.splitlines(),
            reenabled_paths.stdout.splitlines(),
        )

        second_file = repo_root / "second ordinary file.txt"
        second_file.write_text("Reinstallation kept the hook working.\n")
        self.run_git_at(repo_root, ["add", second_file.name])
        second_commit = self.run_git_at(
            repo_root,
            ["commit", "-m", "reinstalled quoted path commit"],
        )
        second_output = second_commit.stdout + second_commit.stderr
        self.assertEqual(second_commit.returncode, 0, second_output)
        self.assertEqual(
            marker.read_text().splitlines(),
            ["existing hook invoked", "existing hook invoked"],
        )
        self.assertEqual((existing_hooks / "pre-commit").read_bytes(), original_hook)
        self.assertEqual(self.global_config.read_bytes(), original_global_config)

    def test_disable_chain_refuses_unmarked_or_unexpected_dispatcher_files(self):
        self.run_git(["config", "--global", "core.hooksPath", "existing-global-hooks"])
        self.run_git(["config", "--local", "--add", "core.hooksPath", "existing-local-hooks"])
        enabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        local_paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(local_paths.returncode, 0, local_paths.stderr)
        original_values = local_paths.stdout.splitlines()
        self.assertEqual(original_values[0], "existing-local-hooks")
        self.assertEqual(len(original_values), 2)
        dispatch_directory = pathlib.Path(original_values[-1])
        marker = dispatch_directory / ".gitmesh-dispatch"
        marker_contents = marker.read_text()

        unexpected_file = dispatch_directory / "unexpected-hook"
        unexpected_file.write_text("UNEXPECTED_DISPATCHER_FILE_SENTINEL\n")
        refused_extra = self.run_installer(args=("--disable-chain",))
        output_extra = refused_extra.stdout + refused_extra.stderr
        self.assertNotEqual(refused_extra.returncode, 0)
        self.assertIn("marker or file set is missing or unexpected", output_extra)
        self.assertIn("no Git configuration or files were changed", output_extra)
        self.assertTrue(dispatch_directory.is_dir())
        self.assertEqual(
            self.run_git(["config", "--local", "--get-all", "core.hooksPath"]).stdout.splitlines(),
            original_values,
        )
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )

        unexpected_file.unlink()
        marker.write_text("UNTRUSTED_DISPATCHER_MARKER_SENTINEL\n")
        refused_unmarked = self.run_installer(args=("--disable-chain",))
        output_unmarked = refused_unmarked.stdout + refused_unmarked.stderr
        self.assertNotEqual(refused_unmarked.returncode, 0)
        self.assertIn("marker or file set is missing or unexpected", output_unmarked)
        self.assertIn("no Git configuration or files were changed", output_unmarked)
        self.assertTrue(dispatch_directory.is_dir())
        self.assertEqual(
            self.run_git(["config", "--local", "--get-all", "core.hooksPath"]).stdout.splitlines(),
            original_values,
        )
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )

        marker.write_text(marker_contents)
        pre_commit_dispatcher = dispatch_directory / "pre-commit"
        pre_commit_dispatcher.write_text(
            pre_commit_dispatcher.read_text() + "# TAMPERED_DISPATCHER_SENTINEL\n"
        )
        refused_tampered = self.run_installer(args=("--disable-chain",))
        output_tampered = refused_tampered.stdout + refused_tampered.stderr
        self.assertNotEqual(refused_tampered.returncode, 0)
        self.assertIn("marker or file set is missing or unexpected", output_tampered)
        self.assertIn("no Git configuration or files were changed", output_tampered)
        self.assertTrue(dispatch_directory.is_dir())
        self.assertEqual(
            self.run_git(["config", "--local", "--get-all", "core.hooksPath"]).stdout.splitlines(),
            original_values,
        )
        self.assertEqual(
            self.run_git(["config", "--global", "--get", "core.hooksPath"]).stdout.strip(),
            "existing-global-hooks",
        )

    def test_chain_existing_pre_push_replays_ref_input_to_gitmesh_after_existing_hook(self):
        existing_hooks = self.repo_root / "existing-push-hooks"
        ref_input_marker = self.repo_root / "existing-pre-push-ref-input"
        pre_push = existing_hooks / "pre-push"
        original_pre_push = self.make_executable_hook(
            pre_push,
            "#!/bin/sh\n"
            f"cat > {shlex.quote(str(ref_input_marker))}\n"
            "printf 'existing-pre-push-ran\\n'\n",
        )
        self.run_git(["config", "--local", "--add", "core.hooksPath", "existing-push-hooks"])
        enabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        hook_paths = self.run_git(["config", "--local", "--get-all", "core.hooksPath"])
        self.assertEqual(hook_paths.returncode, 0, hook_paths.stderr)
        dispatch_directory = pathlib.Path(hook_paths.stdout.splitlines()[-1])
        legacy_pre_push = dispatch_directory / "pre-push"
        legacy_pre_push.write_text(
            "#!/bin/sh\n"
            "# GitMesh hook dispatcher v1\n"
            f"exec {shlex.quote(str(pre_push))} \"$@\"\n"
        )
        legacy_pre_push.chmod(0o755)
        (dispatch_directory / ".gitmesh-dispatch").write_text(
            "GitMesh hook dispatcher v1\n"
        )
        upgraded = self.run_installer(args=("--chain-existing",))
        self.assertEqual(upgraded.returncode, 0, upgraded.stdout + upgraded.stderr)
        self.assertIn("Updated the existing GitMesh dispatcher", upgraded.stdout)
        self.run_git(
            ["config", "--local", "gitmesh.prePushCredentialCheck", "true"]
        )
        remote = self.repo_root / "pre-push-remote.git"
        remote_init = self.run_git(["init", "--bare", "--quiet", str(remote)])
        self.assertEqual(remote_init.returncode, 0, remote_init.stdout + remote_init.stderr)
        self.run_git(["remote", "add", "origin", str(remote)])

        push = self.run_git(["push", "origin", "HEAD:refs/heads/main"])
        output = push.stdout + push.stderr

        self.assertEqual(push.returncode, 0, output)
        self.assertIn("existing-pre-push-ran", output)
        self.assertIn("Pre-push credential check passed: scanned", output)
        self.assertIn("allowlisted source revisions", output)
        self.assertLess(
            output.index("existing-pre-push-ran"),
            output.index("Pre-push credential check passed"),
        )
        self.assertTrue(ref_input_marker.exists())
        self.assertIn("refs/heads/main", ref_input_marker.read_text())
        self.assertEqual(pre_push.read_bytes(), original_pre_push)

    def test_chain_existing_hook_failure_stops_before_gitmesh(self):
        existing_hooks = self.repo_root / "failing-local-hooks"
        pre_commit = existing_hooks / "pre-commit"
        original_pre_commit = self.make_executable_hook(
            pre_commit,
            "#!/bin/sh\nprintf 'existing-pre-commit-failed\\n'\nexit 7\n",
        )
        self.run_git(["config", "--local", "--add", "core.hooksPath", "failing-local-hooks"])
        enabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)

        credential = "ghp_" + "Z" * 36
        readme = self.template_root / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git(["commit", "-m", "existing hook must block"])
        output = commit.stdout + commit.stderr

        self.assertNotEqual(commit.returncode, 0)
        self.assertIn("existing-pre-commit-failed", output)
        self.assertNotIn("Refusing to commit staged source files", output)
        self.assertNotIn("README.md (line 1)", output)
        self.assertNotIn(credential, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)

    def test_chain_existing_gitmesh_failure_happens_after_existing_hook(self):
        existing_hooks = self.repo_root / "passing-local-hooks"
        pre_commit = existing_hooks / "pre-commit"
        original_pre_commit = self.make_executable_hook(
            pre_commit,
            "#!/bin/sh\nprintf 'existing-pre-commit-ran\\n'\n",
        )
        self.run_git(["config", "--local", "--add", "core.hooksPath", "passing-local-hooks"])
        enabled = self.run_installer(args=("--chain-existing",))
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)

        credential = "ghp_" + "R" * 36
        readme = self.template_root / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git(["add", "gitmesh-template/README.md"])
        original_head = self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git(["commit", "-m", "GitMesh credential check must block"])
        output = commit.stdout + commit.stderr

        self.assertNotEqual(commit.returncode, 0)
        self.assertIn("existing-pre-commit-ran", output)
        self.assertIn("Refusing to commit staged source files containing a credential-like value", output)
        self.assertLess(
            output.index("existing-pre-commit-ran"),
            output.index("Refusing to commit staged source files"),
        )
        self.assertNotIn(credential, output)
        self.assertEqual(self.run_git(["rev-parse", "HEAD"]).stdout.strip(), original_head)
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)

    def test_chain_existing_worktree_scope_does_not_change_sibling_settings(self):
        self.run_git(["config", "--local", "extensions.worktreeConfig", "true"])
        worktree_root = self.repo_root / "chain-worktree"
        sibling_root = self.repo_root / "chain-sibling-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        added_sibling = self.run_git(["worktree", "add", "--detach", str(sibling_root), "HEAD"])
        self.assertEqual(added_sibling.returncode, 0, added_sibling.stdout + added_sibling.stderr)

        hooks_path_result = self.run_git(["rev-parse", "--git-path", "hooks"])
        self.assertEqual(hooks_path_result.returncode, 0)
        hooks_directory = pathlib.Path(hooks_path_result.stdout.strip())
        if not hooks_directory.is_absolute():
            hooks_directory = self.repo_root / hooks_directory
        pre_commit = hooks_directory / "pre-commit"
        original_pre_commit = self.make_executable_hook(
            pre_commit,
            "#!/bin/sh\nprintf 'shared-existing-pre-commit-ran\\n'\n",
        )

        unscoped = self.run_installer(
            cwd=worktree_root,
            args=("--chain-existing",),
        )
        self.assertNotEqual(unscoped.returncode, 0)
        self.assertIn("linked Git worktree", unscoped.stderr)
        self.assertIn("No Git configuration was changed", unscoped.stderr)
        self.assertEqual(
            self.run_git_at(worktree_root, ["config", "--worktree", "--get", "core.hooksPath"]).returncode,
            1,
        )

        enabled = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local", "--chain-existing"),
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn("this worktree only", enabled.stdout)
        self.assertIn(
            "node 'gitmesh-template/install-pre-commit-hook.mjs' "
            "--worktree-local --disable-chain",
            enabled.stdout,
        )
        worktree_path = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "--get", "core.hooksPath"],
        )
        self.assertEqual(worktree_path.returncode, 0)
        dispatch_directory = pathlib.Path(worktree_path.stdout.strip())
        self.assertTrue(dispatch_directory.is_dir())
        self.assertEqual(
            self.run_git_at(sibling_root, ["config", "--worktree", "--get", "core.hooksPath"]).returncode,
            1,
        )
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )

        readme = worktree_root / "gitmesh-template" / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nWorktree-local chained hook test.\n")
        self.run_git_at(worktree_root, ["add", "gitmesh-template/README.md"])
        commit = self.run_git_at(
            worktree_root,
            ["commit", "-m", "worktree-local hooks run in order"],
        )
        output = commit.stdout + commit.stderr
        self.assertEqual(commit.returncode, 0, output)
        self.assertLess(
            output.index("shared-existing-pre-commit-ran"),
            output.index("Credential check passed:"),
        )
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)
        self.assertEqual(self.global_config.read_text(), "")
        self.assertEqual(
            self.run_git_at(sibling_root, ["config", "--worktree", "--get", "core.hooksPath"]).returncode,
            1,
        )

        disable_command = enabled.stdout.split("To disable it, run: ", 1)[1].strip()
        disabled = subprocess.run(
            shlex.split(disable_command),
            cwd=worktree_root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(disabled.returncode, 0, disabled.stdout + disabled.stderr)
        self.assertIn("removed the verified dispatcher directory", disabled.stdout)
        self.assertFalse(dispatch_directory.exists())
        self.assertEqual(
            self.run_git_at(
                worktree_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(
            self.run_git_at(
                sibling_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(
            self.run_git(
                ["config", "--local", "--get", "core.hooksPath"]
            ).returncode,
            1,
        )
        self.assertEqual(self.global_config.read_text(), "")
        self.assertEqual(pre_commit.read_bytes(), original_pre_commit)

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
        self.assertIn("README.md (line 1: GitHub token)", output)
        self.assertNotIn(credential, output)
        self.assertEqual(
            self.run_git_at(worktree_root, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_hook_setup_keeps_selected_worktree_check_after_move(self):
        self.run_git(["config", "--local", "extensions.worktreeConfig", "true"])
        worktree_root = self.repo_root / "movable-linked-worktree"
        moved_root = self.repo_root / "moved-linked-worktree"
        sibling_root = self.repo_root / "move-test-sibling-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        added_sibling = self.run_git(["worktree", "add", "--detach", str(sibling_root), "HEAD"])
        self.assertEqual(added_sibling.returncode, 0, added_sibling.stdout + added_sibling.stderr)

        enabled = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local",),
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertEqual(
            self.run_git_at(
                worktree_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).stdout.strip(),
            "gitmesh-template/hooks",
        )
        for untouched in (self.repo_root, sibling_root):
            self.assertEqual(
                self.run_git_at(
                    untouched,
                    ["config", "--worktree", "--get", "core.hooksPath"],
                ).returncode,
                1,
            )

        moved = self.run_git(["worktree", "move", str(worktree_root), str(moved_root)])
        self.assertEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertFalse(worktree_root.exists())
        self.assertTrue(moved_root.is_dir())
        self.assertEqual(
            pathlib.Path(
                self.run_git_at(moved_root, ["rev-parse", "--show-toplevel"]).stdout.strip()
            ),
            moved_root,
        )
        self.assertEqual(
            self.run_git_at(
                moved_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).stdout.strip(),
            "gitmesh-template/hooks",
        )
        self.assertEqual(
            self.run_git_at(
                sibling_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )

        credential = "ghp_" + "V" * 36
        readme = moved_root / "gitmesh-template" / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git_at(moved_root, ["add", "gitmesh-template/README.md"])
        original_head = self.run_git_at(moved_root, ["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git_at(
            moved_root,
            ["commit", "-m", "moved worktree hook check"],
        )
        output = commit.stdout + commit.stderr
        self.assertNotEqual(
            commit.returncode,
            0,
            output.replace(credential, "[redacted test credential]"),
        )
        self.assertIn("README.md (line 1: GitHub token)", output)
        self.assertNotIn(credential, output)
        self.assertEqual(
            self.run_git_at(moved_root, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(
            self.run_git_at(
                sibling_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).returncode,
            1,
        )
        self.assertEqual(
            self.run_git(["config", "--local", "--get", "core.hooksPath"]).returncode,
            1,
        )
        self.assertEqual(self.global_config.read_text(), "")

    def test_chain_existing_custom_hook_stays_active_after_worktree_move(self):
        self.run_git(["config", "--local", "extensions.worktreeConfig", "true"])
        worktree_root = self.repo_root / "chain-movable-linked-worktree"
        moved_root = self.repo_root / "chain-moved-linked-worktree"
        sibling_root = self.repo_root / "chain-move-sibling-worktree"
        added = self.run_git(["worktree", "add", "--detach", str(worktree_root), "HEAD"])
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        added_sibling = self.run_git(["worktree", "add", "--detach", str(sibling_root), "HEAD"])
        self.assertEqual(added_sibling.returncode, 0, added_sibling.stdout + added_sibling.stderr)

        custom_hooks_value = "selected-worktree-custom-hooks"
        pre_commit = worktree_root / custom_hooks_value / "pre-commit"
        original_pre_commit = self.make_executable_hook(
            pre_commit,
            "#!/bin/sh\nprintf 'custom-pre-commit-ran\\n'\n",
        )
        configured_custom_path = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "core.hooksPath", custom_hooks_value],
        )
        self.assertEqual(configured_custom_path.returncode, 0, configured_custom_path.stderr)
        sibling_hooks_value = "sibling-custom-hooks"
        sibling_pre_commit = sibling_root / sibling_hooks_value / "pre-commit"
        original_sibling_pre_commit = self.make_executable_hook(
            sibling_pre_commit,
            "#!/bin/sh\nprintf 'sibling-pre-commit-ran\\n'\n",
        )
        configured_sibling_path = self.run_git_at(
            sibling_root,
            ["config", "--worktree", "core.hooksPath", sibling_hooks_value],
        )
        self.assertEqual(
            configured_sibling_path.returncode,
            0,
            configured_sibling_path.stderr,
        )
        sibling_config_before = self.git_config_snapshot(sibling_root)
        self.assertEqual(
            self.run_git_at(sibling_root, ["config", "--worktree", "--get", "core.hooksPath"]).stdout.strip(),
            sibling_hooks_value,
        )

        enabled = self.run_installer(
            cwd=worktree_root,
            args=("--worktree-local", "--chain-existing"),
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn("this worktree only", enabled.stdout)
        selected_path = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "--get", "core.hooksPath"],
        )
        self.assertEqual(selected_path.returncode, 0, selected_path.stderr)
        dispatch_directory = pathlib.Path(selected_path.stdout.strip())
        self.assertTrue(dispatch_directory.is_dir())
        selected_paths = self.run_git_at(
            worktree_root,
            ["config", "--worktree", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(selected_paths.returncode, 0, selected_paths.stderr)
        self.assertEqual(
            selected_paths.stdout.splitlines(),
            [custom_hooks_value, str(dispatch_directory)],
        )
        self.assertEqual(
            self.run_git_at(
                sibling_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).stdout.strip(),
            sibling_hooks_value,
        )
        self.assertEqual(
            self.run_git(
                ["config", "--local", "--get", "core.hooksPath"]
            ).returncode,
            1,
        )
        self.assertEqual(
            self.git_config_snapshot(sibling_root),
            sibling_config_before,
        )

        moved = self.run_git(["worktree", "move", str(worktree_root), str(moved_root)])
        self.assertEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertFalse(worktree_root.exists())
        self.assertTrue(moved_root.is_dir())
        self.assertTrue(dispatch_directory.is_dir())
        moved_pre_commit = moved_root / custom_hooks_value / "pre-commit"
        self.assertTrue(moved_pre_commit.is_file())
        self.assertEqual(
            pathlib.Path(
                self.run_git_at(moved_root, ["rev-parse", "--show-toplevel"]).stdout.strip()
            ),
            moved_root,
        )
        self.assertEqual(
            pathlib.Path(
                self.run_git_at(
                    moved_root,
                    ["config", "--worktree", "--get", "core.hooksPath"],
                ).stdout.strip()
            ),
            dispatch_directory,
        )
        paths_before_rerun = self.run_git_at(
            moved_root,
            ["config", "--worktree", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(paths_before_rerun.returncode, 0, paths_before_rerun.stderr)
        self.assertEqual(
            paths_before_rerun.stdout.splitlines(),
            [custom_hooks_value, str(dispatch_directory)],
        )
        selected_config_before_rerun = self.git_config_snapshot(moved_root)
        repository_config_before_rerun = self.git_config_snapshot(self.repo_root)
        sibling_config_before_rerun = self.git_config_snapshot(sibling_root)

        rerun = self.run_installer(
            cwd=moved_root,
            args=("--worktree-local", "--chain-existing"),
        )
        rerun_output = rerun.stdout + rerun.stderr
        self.assertEqual(rerun.returncode, 0, rerun_output)
        self.assertIn(
            "The GitMesh dispatcher is already enabled for this worktree.",
            rerun_output,
        )
        paths_after_rerun = self.run_git_at(
            moved_root,
            ["config", "--worktree", "--get-all", "core.hooksPath"],
        )
        self.assertEqual(paths_after_rerun.returncode, 0, paths_after_rerun.stderr)
        self.assertEqual(
            paths_after_rerun.stdout.splitlines(),
            [custom_hooks_value, str(dispatch_directory)],
        )
        self.assertEqual(
            paths_after_rerun.stdout.splitlines().count(str(dispatch_directory)),
            1,
        )
        self.assertEqual(
            self.git_config_snapshot(moved_root),
            selected_config_before_rerun,
        )
        self.assertEqual(
            self.git_config_snapshot(self.repo_root),
            repository_config_before_rerun,
        )
        self.assertEqual(
            self.git_config_snapshot(sibling_root),
            sibling_config_before_rerun,
        )

        credential = "ghp_" + "M" * 36
        readme = moved_root / "gitmesh-template" / "README.md"
        readme.write_text(f"staged_secret={credential}\n")
        self.run_git_at(moved_root, ["add", "gitmesh-template/README.md"])
        original_head = self.run_git_at(moved_root, ["rev-parse", "HEAD"]).stdout.strip()
        commit = self.run_git_at(
            moved_root,
            ["commit", "-m", "moved worktree chained hook check"],
        )
        output = commit.stdout + commit.stderr
        self.assertNotEqual(
            commit.returncode,
            0,
            output.replace(credential, "[redacted test credential]"),
        )
        self.assertIn("custom-pre-commit-ran", output)
        self.assertIn("README.md (line 1: GitHub token)", output)
        self.assertIn(
            "Refusing to commit staged source files containing a credential-like value",
            output,
        )
        self.assertLess(
            output.index("custom-pre-commit-ran"),
            output.index("Refusing to commit staged source files containing a credential-like value"),
        )
        self.assertNotIn(credential, output)
        self.assertEqual(
            self.run_git_at(moved_root, ["rev-parse", "HEAD"]).stdout.strip(),
            original_head,
        )
        self.assertEqual(moved_pre_commit.read_bytes(), original_pre_commit)
        self.assertEqual(
            self.git_config_snapshot(sibling_root),
            sibling_config_before,
        )
        self.assertEqual(
            self.run_git_at(
                sibling_root,
                ["config", "--worktree", "--get", "core.hooksPath"],
            ).stdout.strip(),
            sibling_hooks_value,
        )

        sibling_file = sibling_root / "sibling ordinary file.txt"
        sibling_file.write_text("The sibling keeps its original hook behavior.\n")
        self.run_git_at(sibling_root, ["add", sibling_file.name])
        sibling_commit = self.run_git_at(
            sibling_root,
            ["commit", "-m", "sibling worktree keeps original hooks"],
        )
        sibling_output = sibling_commit.stdout + sibling_commit.stderr
        self.assertEqual(sibling_commit.returncode, 0, sibling_output)
        self.assertIn("sibling-pre-commit-ran", sibling_output)
        self.assertNotIn("custom-pre-commit-ran", sibling_output)
        self.assertNotIn("Credential check passed:", sibling_output)
        self.assertEqual(sibling_pre_commit.read_bytes(), original_sibling_pre_commit)
        self.assertEqual(moved_pre_commit.read_bytes(), original_pre_commit)
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
