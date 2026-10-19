import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";
import { changeSigil, setupOrAuthenticate } from "../gitmesh-ultimate-core.mjs";

const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
const temporaryDirectories = [];

function makeAuthPath() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sigil-test-"));
  temporaryDirectories.push(directory);
  return path.join(directory, "active_sigil.hash");
}

function getPrompt(values) {
  return async () => {
    assert.ok(values.length, "the flow requested more input than expected");
    return values.shift();
  };
}

function fingerprint(sigil) {
  return crypto.createHash("sha256").update(sigil, "utf8").digest("hex");
}

function verifier(sigil, salt) {
  return crypto.scryptSync(sigil, salt, 64, SCRYPT_OPTIONS).toString("hex");
}

function loadAuth(authFile) {
  return JSON.parse(fs.readFileSync(authFile, "utf8"));
}

function assertNoPlaintextSigil(authFile, ...sigils) {
  const stored = fs.readFileSync(authFile, "utf8");
  for (const sigil of sigils) assert.equal(stored.includes(sigil), false);
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("first-time setup stores only a verifier for the active sigil", async () => {
  const authFile = makeAuthPath();
  const sigil = "initial-admin-sigil-2026";
  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([sigil, sigil]),
    log: () => {},
  });

  assert.equal(session.currentSigil, sigil);
  assert.equal(session.auth.version, 2);
  assert.equal(session.auth.generation, 0);
  assert.deepEqual(session.auth.usedSigilHashes, []);
  assert.equal(session.auth.verifier, verifier(sigil, session.auth.salt));
  assertNoPlaintextSigil(authFile, sigil);
});

test("a version-1 credential migrates on successful sign-in and consumes the old sigil", async () => {
  const authFile = makeAuthPath();
  const oldSigil = "legacy-passphrase-2024";
  const salt = "a".repeat(32);
  fs.writeFileSync(authFile, JSON.stringify({
    version: 1,
    salt,
    verifier: verifier(oldSigil, salt),
  }));
  const output = [];

  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([oldSigil]),
    promptTextFn: getPrompt(["SAVED"]),
    log: (message) => output.push(message),
  });
  const migrated = loadAuth(authFile);

  assert.equal(migrated.version, 2);
  assert.equal(migrated.generation, 1);
  assert.deepEqual(migrated.usedSigilHashes, [fingerprint(oldSigil)]);
  assert.equal(migrated.verifier, verifier(session.currentSigil, migrated.salt));
  assert.ok(output.some((message) => message.includes(session.currentSigil)));
  assertNoPlaintextSigil(authFile, oldSigil, session.currentSigil);
  await assert.rejects(
    setupOrAuthenticate({ authFile, promptLineFn: getPrompt([oldSigil]), log: () => {} }),
    /Access denied/,
  );
});

test("successful rotation invalidates the prior sigil and records it as consumed", async () => {
  const authFile = makeAuthPath();
  const oldSigil = "first-active-sigil-2026";
  await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([oldSigil, oldSigil]),
    log: () => {},
  });
  const output = [];

  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([oldSigil]),
    promptTextFn: getPrompt(["SAVED"]),
    log: (message) => output.push(message),
  });
  const rotated = loadAuth(authFile);

  assert.equal(rotated.version, 2);
  assert.equal(rotated.generation, 1);
  assert.deepEqual(rotated.usedSigilHashes, [fingerprint(oldSigil)]);
  assert.equal(rotated.verifier, verifier(session.currentSigil, rotated.salt));
  assert.ok(output.some((message) => message.includes(session.currentSigil)));
  assertNoPlaintextSigil(authFile, oldSigil, session.currentSigil);
  await assert.rejects(
    setupOrAuthenticate({ authFile, promptLineFn: getPrompt([oldSigil]), log: () => {} }),
    /Access denied/,
  );
});

test("cancelling rotation leaves the active sigil and credential file unchanged", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "still-active-sigil-2026";
  await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil, activeSigil]),
    log: () => {},
  });
  const before = fs.readFileSync(authFile);

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([activeSigil]),
      promptTextFn: getPrompt(["CANCEL"]),
      log: () => {},
    }),
    /Rotation cancelled/,
  );
  assert.deepEqual(fs.readFileSync(authFile), before);

  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil]),
    promptTextFn: getPrompt(["SAVED"]),
    log: () => {},
  });
  assert.notEqual(session.currentSigil, activeSigil);
});

test("manual changes store the replacement privately and reject previously used sigils", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "manual-current-sigil-2026";
  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil, activeSigil]),
    log: () => {},
  });
  const replacement = "manual-replacement-sigil-2026";

  await changeSigil(session, {
    authFile,
    promptLineFn: getPrompt([replacement, replacement]),
    log: () => {},
  });
  const changed = loadAuth(authFile);
  assert.equal(session.currentSigil, replacement);
  assert.deepEqual(changed.usedSigilHashes, [fingerprint(activeSigil)]);
  assert.equal(changed.verifier, verifier(replacement, changed.salt));
  assertNoPlaintextSigil(authFile, activeSigil, replacement);

  const beforeRejectedChange = fs.readFileSync(authFile);
  await assert.rejects(
    changeSigil(session, {
      authFile,
      promptLineFn: getPrompt([activeSigil, activeSigil]),
      log: () => {},
    }),
    /Choose a sigil that has never been used before/,
  );
  assert.deepEqual(fs.readFileSync(authFile), beforeRejectedChange);
  await assert.rejects(
    setupOrAuthenticate({ authFile, promptLineFn: getPrompt([activeSigil]), log: () => {} }),
    /Access denied/,
  );
});
