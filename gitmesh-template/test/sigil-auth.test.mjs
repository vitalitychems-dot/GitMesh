import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";
import { changeSigil, saveAuth, setupOrAuthenticate } from "../../projects/local-vault/gitmesh-ultimate-core.mjs";

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

function failCredentialRename(auth, authFile, options = {}) {
  return saveAuth(auth, authFile, {
    ...options,
    renameSync() {
      throw new Error("forced credential-save failure");
    },
    linkSync() {
      throw new Error("forced credential-save failure");
    },
  });
}

function failCredentialWriteAfterPartialFile(auth, authFile) {
  return saveAuth(auth, authFile, {
    writeFileSync(temporaryPath, contents, options) {
      fs.writeFileSync(temporaryPath, contents.slice(0, 12), options);
      throw new Error("forced partial credential-write failure");
    },
  });
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

test("failed first-time setup does not report success or leave credential files behind", async () => {
  const authFile = makeAuthPath();
  const output = [];
  const sigil = "initial-admin-sigil-2026";

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([sigil, sigil]),
      saveAuthFn: failCredentialRename,
      log: (message) => output.push(message),
    }),
    /forced credential-save failure/,
  );

  assert.equal(output.some((message) => message.includes("Admin sigil verifier saved locally.")), false);
  assert.equal(fs.existsSync(authFile), false);
  assert.deepEqual(fs.readdirSync(path.dirname(authFile)), []);
});

test("simultaneous first-time setup allows only one sigil to become active", async () => {
  const authFile = makeAuthPath();
  const sigils = ["first-admin-sigil-2026", "second-admin-sigil-2026"];
  const outputs = [[], []];
  let promptsStarted = 0;
  let releasePrompts;
  const bothSetupsReadMissingCredential = new Promise((resolve) => {
    releasePrompts = resolve;
  });

  const attempts = sigils.map((sigil, index) => {
    let promptCount = 0;
    return setupOrAuthenticate({
      authFile,
      promptLineFn: async () => {
        promptCount += 1;
        if (promptCount === 1) {
          promptsStarted += 1;
          if (promptsStarted === 2) releasePrompts();
          await bothSetupsReadMissingCredential;
        }
        return sigil;
      },
      log: (message) => outputs[index].push(message),
    });
  });

  const results = await Promise.allSettled(attempts);
  const successfulIndex = results.findIndex((result) => result.status === "fulfilled");
  const rejectedIndex = results.findIndex((result) => result.status === "rejected");

  assert.notEqual(successfulIndex, -1, "one setup should create the credential");
  assert.notEqual(rejectedIndex, -1, "the competing setup should be rejected");
  assert.notEqual(successfulIndex, rejectedIndex);
  assert.match(results[rejectedIndex].reason.message, /set up by another process/);
  assert.equal(outputs[successfulIndex].some((message) => message.includes("Admin sigil verifier saved locally.")), true);
  assert.equal(outputs[rejectedIndex].some((message) => message.includes("Admin sigil verifier saved locally.")), false);

  const savedAuth = loadAuth(authFile);
  const successfulSession = results[successfulIndex].value;
  assert.equal(savedAuth.verifier, verifier(successfulSession.currentSigil, savedAuth.salt));
  assertNoPlaintextSigil(authFile, ...sigils);
});

test("authentication rejects malformed consumed-sigil hashes before prompting or rewriting credentials", async () => {
  const authFile = makeAuthPath();
  const currentSigil = "current-admin-sigil-2026";
  fs.writeFileSync(authFile, JSON.stringify({
    version: 2,
    salt: "a".repeat(32),
    verifier: verifier(currentSigil, "a".repeat(32)),
    generation: 1,
    usedSigilHashes: ["not-a-valid-sha256-hash"],
  }));
  const before = fs.readFileSync(authFile);
  let promptCount = 0;

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: async () => {
        promptCount += 1;
        throw new Error("Authentication must reject the credential file before prompting.");
      },
      log: () => {},
    }),
    /local credential file is invalid/,
  );

  assert.equal(promptCount, 0);
  assert.deepEqual(fs.readFileSync(authFile), before);
});

test("authentication rejects duplicate consumed-sigil hashes before prompting or rewriting credentials", async () => {
  const authFile = makeAuthPath();
  const currentSigil = "current-admin-sigil-2026";
  const consumedHash = fingerprint("previously-consumed-sigil-2025");
  fs.writeFileSync(authFile, JSON.stringify({
    version: 2,
    salt: "b".repeat(32),
    verifier: verifier(currentSigil, "b".repeat(32)),
    generation: 2,
    usedSigilHashes: [consumedHash, consumedHash],
  }));
  const before = fs.readFileSync(authFile);
  let promptCount = 0;

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: async () => {
        promptCount += 1;
        throw new Error("Authentication must reject the credential file before prompting.");
      },
      log: () => {},
    }),
    /local credential file is invalid/,
  );

  assert.equal(promptCount, 0);
  assert.deepEqual(fs.readFileSync(authFile), before);
});

test("authentication rejects an active sigil already marked as consumed without rotating or rewriting credentials", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "active-but-consumed-sigil-2026";
  const salt = "c".repeat(32);
  fs.writeFileSync(authFile, JSON.stringify({
    version: 2,
    salt,
    verifier: verifier(activeSigil, salt),
    generation: 3,
    usedSigilHashes: [fingerprint(activeSigil)],
  }));
  const before = fs.readFileSync(authFile);
  let authenticationPromptCount = 0;
  let replacementConfirmationCount = 0;

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: async () => {
        authenticationPromptCount += 1;
        return activeSigil;
      },
      promptTextFn: async () => {
        replacementConfirmationCount += 1;
        return "SAVED";
      },
      log: () => {},
    }),
    /local credential history is inconsistent; access was not granted/,
  );

  assert.equal(authenticationPromptCount, 1);
  assert.equal(replacementConfirmationCount, 0, "the replacement sigil must not be offered for confirmation");
  assert.deepEqual(fs.readFileSync(authFile), before, "the inconsistent credential must not be rewritten");
});

test("authentication rejects unsafe and negative generation counters before prompting or rewriting credentials", async () => {
  for (const generation of [Number.MAX_SAFE_INTEGER + 1, -1]) {
    const authFile = makeAuthPath();
    const salt = "e".repeat(32);
    fs.writeFileSync(authFile, JSON.stringify({
      version: 2,
      salt,
      verifier: verifier("current-admin-sigil-2026", salt),
      generation,
      usedSigilHashes: [],
    }));
    const before = fs.readFileSync(authFile);
    let promptCount = 0;

    await assert.rejects(
      setupOrAuthenticate({
        authFile,
        promptLineFn: async () => {
          promptCount += 1;
          throw new Error("Authentication must reject the credential file before prompting.");
        },
        log: () => {},
      }),
      /local credential file is invalid/,
      `generation ${generation} should be rejected`,
    );

    assert.equal(promptCount, 0, `generation ${generation} must not reach the sign-in prompt`);
    assert.deepEqual(fs.readFileSync(authFile), before, `generation ${generation} must not rewrite credentials`);
  }
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

test("authentication rotates a version-2 credential into the maximum safe generation", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "penultimate-generation-active-sigil-2026";
  const salt = "d".repeat(32);
  fs.writeFileSync(authFile, JSON.stringify({
    version: 2,
    salt,
    verifier: verifier(activeSigil, salt),
    generation: Number.MAX_SAFE_INTEGER - 1,
    usedSigilHashes: [],
  }));
  const output = [];

  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil]),
    promptTextFn: getPrompt(["SAVED"]),
    log: (message) => output.push(message),
  });
  const rotated = loadAuth(authFile);

  assert.equal(session.auth.generation, Number.MAX_SAFE_INTEGER);
  assert.equal(rotated.generation, Number.MAX_SAFE_INTEGER);
  assert.deepEqual(rotated.usedSigilHashes, [fingerprint(activeSigil)]);
  assert.equal(rotated.verifier, verifier(session.currentSigil, rotated.salt));
  assert.ok(output.some((message) => message.includes(session.currentSigil)));
  assertNoPlaintextSigil(authFile, activeSigil, session.currentSigil);
});

test("authentication rejects rotation at the maximum safe generation without prompting or rewriting credentials", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "maximum-generation-active-sigil-2026";
  const salt = "c".repeat(32);
  fs.writeFileSync(authFile, JSON.stringify({
    version: 2,
    salt,
    verifier: verifier(activeSigil, salt),
    generation: Number.MAX_SAFE_INTEGER,
    usedSigilHashes: [],
  }));
  const before = fs.readFileSync(authFile);
  let replacementPromptCount = 0;

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([activeSigil]),
      promptTextFn: async () => {
        replacementPromptCount += 1;
        throw new Error("Rotation confirmation must not be requested.");
      },
      log: () => {},
    }),
    /sigil generation limit has been reached/,
  );

  assert.equal(replacementPromptCount, 0);
  assert.deepEqual(fs.readFileSync(authFile), before);
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

test("failed automatic rotation keeps the previously saved sigil active", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "rotation-persistence-current-2026";
  await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil, activeSigil]),
    log: () => {},
  });
  const before = fs.readFileSync(authFile);
  const priorAuth = loadAuth(authFile);
  const output = [];

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([activeSigil]),
      promptTextFn: getPrompt(["SAVED"]),
      saveAuthFn: failCredentialRename,
      log: (message) => output.push(message),
    }),
    /forced credential-save failure/,
  );

  assert.equal(output.some((message) => message.includes("Sigil rotated.")), false);
  assert.deepEqual(fs.readFileSync(authFile), before);
  assert.deepEqual(fs.readdirSync(path.dirname(authFile)), [path.basename(authFile)]);
  assert.equal(loadAuth(authFile).verifier, verifier(activeSigil, priorAuth.salt));
  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt(["not-the-active-sigil-2026"]),
      log: () => {},
    }),
    /Access denied/,
  );
});

test("partial credential write failure preserves the active sigil and removes the temporary file", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "partial-write-current-sigil-2026";
  await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil, activeSigil]),
    log: () => {},
  });
  const before = fs.readFileSync(authFile);
  const priorAuth = loadAuth(authFile);

  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([activeSigil]),
      promptTextFn: getPrompt(["SAVED"]),
      saveAuthFn: failCredentialWriteAfterPartialFile,
      log: () => {},
    }),
    /forced partial credential-write failure/,
  );

  assert.deepEqual(fs.readFileSync(authFile), before);
  assert.deepEqual(fs.readdirSync(path.dirname(authFile)), [path.basename(authFile)]);
  assert.equal(loadAuth(authFile).verifier, verifier(activeSigil, priorAuth.salt));

  const authenticatedSession = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil]),
    promptTextFn: getPrompt(["SAVED"]),
    log: () => {},
  });
  assert.notEqual(authenticatedSession.currentSigil, activeSigil);
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

test("failed manual change keeps the session and saved sigil unchanged", async () => {
  const authFile = makeAuthPath();
  const activeSigil = "manual-persistence-current-2026";
  const session = await setupOrAuthenticate({
    authFile,
    promptLineFn: getPrompt([activeSigil, activeSigil]),
    log: () => {},
  });
  const before = fs.readFileSync(authFile);
  const priorAuth = session.auth;
  const replacement = "manual-persistence-replacement-2026";
  const output = [];

  await assert.rejects(
    changeSigil(session, {
      authFile,
      promptLineFn: getPrompt([replacement, replacement]),
      saveAuthFn: failCredentialRename,
      log: (message) => output.push(message),
    }),
    /forced credential-save failure/,
  );

  assert.equal(session.currentSigil, activeSigil);
  assert.equal(session.auth, priorAuth);
  assert.equal(output.some((message) => message.includes("Admin sigil updated.")), false);
  assert.deepEqual(fs.readFileSync(authFile), before);
  assert.deepEqual(fs.readdirSync(path.dirname(authFile)), [path.basename(authFile)]);
  assert.equal(loadAuth(authFile).verifier, verifier(activeSigil, priorAuth.salt));
  await assert.rejects(
    setupOrAuthenticate({
      authFile,
      promptLineFn: getPrompt([replacement]),
      log: () => {},
    }),
    /Access denied/,
  );
});
