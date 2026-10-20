import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  decryptBundleFile,
  decryptBundleBuffer,
  encryptBundleFile,
  encryptBundleBuffer,
  validateBundlePassphrase,
} from "../bundle-crypto.mjs";

const passphrase = "correct horse battery staple";

test("encrypted GitMesh bundle round-trips without exposing plaintext", () => {
  const plaintext = Buffer.from("git bundle contents with private records");
  const encrypted = encryptBundleBuffer(plaintext, passphrase);

  assert.equal(encrypted.subarray(0, 4).toString("ascii"), "GMBX");
  assert.equal(encrypted.includes(plaintext), false);
  assert.deepEqual(decryptBundleBuffer(encrypted, passphrase), plaintext);
});

test("encrypted bundle rejects a wrong passphrase and modified ciphertext", () => {
  const encrypted = encryptBundleBuffer(Buffer.from("sensitive bundle bytes"), passphrase);
  assert.throws(
    () => decryptBundleBuffer(encrypted, "a different passphrase with enough chars"),
    /authentication failed/i,
  );

  const modified = Buffer.from(encrypted);
  modified[40] ^= 0x01;
  assert.throws(() => decryptBundleBuffer(modified, passphrase), /authentication failed/i);
});

test("encrypted bundle format rejects legacy plaintext and weak passphrases", () => {
  assert.throws(() => decryptBundleBuffer(Buffer.from("legacy git bundle"), passphrase), /invalid size/i);
  assert.throws(() => validateBundlePassphrase("too short"), /16 to 256 characters/i);
  assert.throws(() => encryptBundleBuffer(Buffer.from("data"), "too short"), /16 to 256 characters/i);
});

test("file encryption streams bounded data and removes partial plaintext after authentication failure", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-bundle-crypto-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const source = path.join(directory, "source.bundle");
  const encryptedPath = path.join(directory, "source.bundle.enc");
  const decryptedPath = path.join(directory, "decrypted.bundle");
  const damagedPath = path.join(directory, "damaged.bundle.enc");
  const rejectedPath = path.join(directory, "rejected.bundle");
  const content = Buffer.from("private git bundle contents");

  fs.writeFileSync(source, content, { mode: 0o600 });
  encryptBundleFile(source, encryptedPath, passphrase);
  decryptBundleFile(encryptedPath, decryptedPath, passphrase);
  assert.deepEqual(fs.readFileSync(decryptedPath), content);
  assert.equal(fs.readFileSync(encryptedPath).includes(content), false);

  const damaged = fs.readFileSync(encryptedPath);
  damaged[40] ^= 0x01;
  fs.writeFileSync(damagedPath, damaged, { mode: 0o600 });
  assert.throws(
    () => decryptBundleFile(damagedPath, rejectedPath, passphrase),
    /authentication failed/i,
  );
  assert.equal(fs.existsSync(rejectedPath), false);
});
