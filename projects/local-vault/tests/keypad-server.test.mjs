import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createKeypadServer } from "../keypad-server.mjs";

function request(port, route, { method = "GET", body, cookie, origin } = {}) {
  return new Promise((resolve, reject) => {
    const serialized = body === undefined ? undefined : JSON.stringify(body);
    const headers = {};
    if (serialized !== undefined) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(serialized);
    }
    if (cookie) headers.Cookie = cookie;
    if (origin) headers.Origin = origin;
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: route,
      method,
      headers,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, json, text });
      });
    });
    req.on("error", reject);
    if (serialized !== undefined) req.write(serialized);
    req.end();
  });
}

function codesFor(value, keys) {
  const lookup = new Map(keys.map(({ label, token }) => [label, token]));
  return [...value].map((character) => {
    const token = lookup.get(character);
    assert.ok(token, `The keypad must include the character ${character}.`);
    return token;
  });
}

test("local keypad uses per-session opaque codes and only activates a replacement after save confirmation", async (t) => {
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-keypad-"));
  const authFile = path.join(tempDirectory, "active_sigil.hash");
  const localRecords = [];
  let exportCalls = 0;
  let encryptedImportCalls = 0;
  const server = createKeypadServer({
    authFile,
    records: () => localRecords,
    addRecord: (targetNode, objectiveScope) => {
      const record = {
        id: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
        targetNode,
        objectiveScope,
      };
      localRecords.push(record);
      return record;
    },
    makeBundle: (passphrase) => {
      exportCalls += 1;
      assert.equal(passphrase, "bundle-passphrase-16");
      return "mesh_snapshot_test.bundle.enc";
    },
    inboundBundles: () => ["known.bundle", "encrypted.bundle.enc"],
    importExistingBundle: (filename) => {
      assert.equal(filename, "known.bundle");
      return { imported: 2, duplicates: 1 };
    },
    importEncryptedExistingBundle: (filename, passphrase) => {
      encryptedImportCalls += 1;
      assert.equal(filename, "encrypted.bundle.enc");
      assert.equal(passphrase, "bundle-passphrase-16");
      return { imported: 1, duplicates: 0 };
    },
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  });

  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;
  const stateResponse = await request(port, "/api/state");
  assert.equal(stateResponse.json.setupRequired, true);

  const rejectedOrigin = await request(port, "/api/auth/start", {
    method: "POST",
    body: { challengeId: "invalid", first: [] },
    origin: "http://attacker.example",
  });
  assert.equal(rejectedOrigin.status, 403);

  const firstChallenge = (await request(port, "/api/keymap")).json;
  const originalSigil = "Start-GitMesh_2026";
  const setup = await request(port, "/api/auth/start", {
    method: "POST",
    origin,
    body: {
      challengeId: firstChallenge.id,
      first: codesFor(originalSigil, firstChallenge.keys),
      confirmation: codesFor(originalSigil, firstChallenge.keys),
    },
  });
  assert.equal(setup.status, 200);
  assert.equal(setup.json.state, "authenticated");
  assert.equal(JSON.stringify(setup.json).includes(originalSigil), false);
  assert.ok(fs.existsSync(authFile));
  assert.equal(fs.readFileSync(authFile, "utf8").includes(originalSigil), false);

  const setupCookie = setup.headers["set-cookie"][0].split(";")[0];
  assert.match(setup.headers["set-cookie"][0], /HttpOnly/);
  assert.match(setup.headers["set-cookie"][0], /SameSite=Strict/);
  const records = await request(port, "/api/records", { cookie: setupCookie });
  assert.equal(records.status, 200);
  assert.deepEqual(records.json.records, []);
  const unauthenticatedRecords = await request(port, "/api/records");
  assert.equal(unauthenticatedRecords.status, 401);

  const createdRecord = await request(port, "/api/records", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { targetNode: "<mesh-node>", objectiveScope: "local test" },
  });
  assert.equal(createdRecord.status, 201);
  assert.equal(createdRecord.json.record.targetNode, "<mesh-node>");
  const listedRecords = await request(port, "/api/records", { cookie: setupCookie });
  assert.equal(listedRecords.json.records.length, 1);
  assert.equal(listedRecords.json.records[0].objectiveScope, "local test");

  const rejectedExport = await request(port, "/api/export", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { passphrase: "short" },
  });
  assert.equal(rejectedExport.status, 400);
  assert.equal(exportCalls, 0);
  const exported = await request(port, "/api/export", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { passphrase: "bundle-passphrase-16" },
  });
  assert.equal(exported.status, 200);
  assert.equal(exportCalls, 1);
  assert.equal(exported.json.filename, "mesh_snapshot_test.bundle.enc");
  assert.equal(exported.text.includes("bundle-passphrase-16"), false);
  const inbound = await request(port, "/api/inbound", { cookie: setupCookie });
  assert.deepEqual(inbound.json.bundles, ["known.bundle", "encrypted.bundle.enc"]);
  const unconfirmedLegacyImport = await request(port, "/api/import", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { filename: "known.bundle" },
  });
  assert.equal(unconfirmedLegacyImport.status, 400);
  const imported = await request(port, "/api/import", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { filename: "known.bundle", allowUnencrypted: true },
  });
  assert.deepEqual(imported.json, { imported: 2, duplicates: 1 });
  const rejectedEncryptedImport = await request(port, "/api/import", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { filename: "encrypted.bundle.enc", passphrase: "short" },
  });
  assert.equal(rejectedEncryptedImport.status, 400);
  assert.equal(encryptedImportCalls, 0);
  const encryptedImport = await request(port, "/api/import", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { filename: "encrypted.bundle.enc", passphrase: "bundle-passphrase-16" },
  });
  assert.deepEqual(encryptedImport.json, { imported: 1, duplicates: 0 });
  assert.equal(encryptedImportCalls, 1);
  const rejectedBundle = await request(port, "/api/import", {
    method: "POST",
    origin,
    cookie: setupCookie,
    body: { filename: "../outside.bundle" },
  });
  assert.equal(rejectedBundle.status, 400);

  const beforeRotation = (await request(port, "/api/keymap")).json;
  assert.notEqual(
    beforeRotation.keys.find((key) => key.label === "a").token,
    firstChallenge.keys.find((key) => key.label === "a").token,
  );
  const cancelledAttempt = await request(port, "/api/auth/start", {
    method: "POST",
    origin,
    body: {
      challengeId: beforeRotation.id,
      first: codesFor(originalSigil, beforeRotation.keys),
    },
  });
  assert.equal(cancelledAttempt.json.state, "save-new-sigil");
  assert.notEqual(cancelledAttempt.json.nextSigil, originalSigil);
  assert.match(cancelledAttempt.json.nextSigil, /^gm-\d+-[A-Za-z0-9_-]+$/);

  const cancelled = await request(port, "/api/auth/confirm", {
    method: "POST",
    origin,
    body: { attemptId: cancelledAttempt.json.attemptId, saved: false },
  });
  assert.equal(cancelled.status, 200);
  assert.equal(cancelled.json.state, "cancelled");

  const retryChallenge = (await request(port, "/api/keymap")).json;
  const retry = await request(port, "/api/auth/start", {
    method: "POST",
    origin,
    body: {
      challengeId: retryChallenge.id,
      first: codesFor(originalSigil, retryChallenge.keys),
    },
  });
  assert.equal(retry.status, 200);
  const replacementSigil = retry.json.nextSigil;

  const confirmed = await request(port, "/api/auth/confirm", {
    method: "POST",
    origin,
    body: { attemptId: retry.json.attemptId, saved: true },
  });
  assert.equal(confirmed.status, 200);
  assert.equal(confirmed.json.state, "authenticated");
  const newCookie = confirmed.headers["set-cookie"][0].split(";")[0];
  const pageReload = await request(port, "/", { cookie: newCookie });
  assert.equal(pageReload.status, 200);
  assert.match(pageReload.headers["set-cookie"][0], /Max-Age=0/);
  assert.equal((await request(port, "/api/records", { cookie: newCookie })).status, 401);

  const oldSigilChallenge = (await request(port, "/api/keymap")).json;
  const oldSigilAttempt = await request(port, "/api/auth/start", {
    method: "POST",
    origin,
    body: {
      challengeId: oldSigilChallenge.id,
      first: codesFor(originalSigil, oldSigilChallenge.keys),
    },
  });
  assert.equal(oldSigilAttempt.status, 401);

  const replacementChallenge = (await request(port, "/api/keymap")).json;
  const replacementAttempt = await request(port, "/api/auth/start", {
    method: "POST",
    origin,
    body: {
      challengeId: replacementChallenge.id,
      first: codesFor(replacementSigil, replacementChallenge.keys),
    },
  });
  assert.equal(replacementAttempt.status, 200);
  assert.equal(replacementAttempt.json.state, "save-new-sigil");
  assert.notEqual(replacementAttempt.json.nextSigil, replacementSigil);
  await request(port, "/api/auth/confirm", {
    method: "POST",
    origin,
    body: { attemptId: replacementAttempt.json.attemptId, saved: false },
  });
});
