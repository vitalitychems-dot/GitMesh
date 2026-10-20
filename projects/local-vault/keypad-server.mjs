import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_ENCRYPTED_BUNDLE_BYTES, validateBundlePassphrase } from "./bundle-crypto.mjs";
import {
  addLocalRecord,
  ensureVault,
  exportBundle,
  importEncryptedBundle,
  importBundle,
  listInboundBundles,
  listLocalRecords,
  setupOrAuthenticate,
} from "./gitmesh-ultimate-core.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VAULT = path.join(ROOT, "SovereignMeshVault");
const AUTH_FILE = path.join(VAULT, "active_sigil.hash");
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const SYLLABLES = [
  "ka", "zu", "re", "vo", "mi", "sha", "te", "lu",
  "no", "qi", "dra", "fen", "xo", "bae", "ri", "thu",
];
const BODY_LIMIT = 8 * 1024;
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const SESSION_TTL_MS = 15 * 60 * 1000;
const FAILURE_WINDOW_MS = 5 * 60 * 1000;
const FAILURE_LIMIT = 5;
const LOCAL_HOST = "127.0.0.1";

function randomId(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function makeSessionMap() {
  const words = new Set();
  while (words.size < ALPHABET.length) {
    const word = Array.from({ length: 3 }, () =>
      SYLLABLES[crypto.randomInt(SYLLABLES.length)]
    ).join("-");
    words.add(word);
  }

  const shuffled = [...words];
  for (let i = shuffled.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }

  const keys = [];
  const tokenToCharacter = new Map();
  ALPHABET.split("").forEach((character, index) => {
    const token = randomId(18);
    tokenToCharacter.set(token, character);
    keys.push({ label: character, token, glyph: shuffled[index] });
  });
  return { keys, tokenToCharacter };
}

function decodeKeys(tokens, challenge) {
  if (!Array.isArray(tokens) || tokens.length < 1 || tokens.length > 256) {
    throw new Error("Enter a sigil using the on-screen keys.");
  }
  let decoded = "";
  for (const token of tokens) {
    if (typeof token !== "string" || token.length > 64) {
      throw new Error("The keypad session expired. Reload the page and try again.");
    }
    const character = challenge.tokenToCharacter.get(token);
    if (!character) {
      throw new Error("The keypad session expired. Reload the page and try again.");
    }
    decoded += character;
  }
  return decoded;
}

function setHeaders(response, requestId, contentType = "application/json; charset=utf-8") {
  response.setHeader("Content-Type", contentType);
  response.setHeader("Cache-Control", "no-store, max-age=0");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  response.setHeader("X-Request-ID", requestId);
}

function sendJson(response, requestId, status, payload) {
  setHeaders(response, requestId);
  response.writeHead(status);
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let oversized = false;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT && !oversized) {
        oversized = true;
        reject(Object.assign(new Error("Request too large."), { statusCode: 413 }));
        return;
      }
      if (!oversized) chunks.push(chunk);
    });
    request.on("end", () => {
      if (oversized) return;
      if (size === 0) return reject(Object.assign(new Error("Request body required."), { statusCode: 400 }));
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) {
        return reject(Object.assign(new Error("JSON content type required."), { statusCode: 415 }));
      }
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error();
        resolve(body);
      } catch {
        reject(Object.assign(new Error("Invalid request body."), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function isLoopback(request) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(request.socket.remoteAddress);
}

function hasSameOrigin(request) {
  const origin = request.headers.origin;
  if (typeof origin !== "string") return false;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "http:" &&
      parsed.hostname === "127.0.0.1" &&
      parsed.port === String(request.socket.localPort);
  } catch {
    return false;
  }
}

function requestCookie(request, name) {
  const prefix = `${name}=`;
  const cookies = (request.headers.cookie ?? "").split(";");
  for (const cookie of cookies) {
    const trimmed = cookie.trim();
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  return "";
}

function validateRecordInput(body) {
  if (typeof body.targetNode !== "string" ||
      body.targetNode.length < 1 ||
      body.targetNode.length > 120 ||
      typeof body.objectiveScope !== "string" ||
      body.objectiveScope.length < 1 ||
      body.objectiveScope.length > 1000) {
    throw new Error("Enter a node name and purpose within the displayed limits.");
  }
}

function validateBundleName(name) {
  if (typeof name !== "string" ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.bundle(?:\.enc)?$/.test(name)) {
    throw new Error("Choose a listed bundle.");
  }
}

export function createKeypadServer({
  authFile = AUTH_FILE,
  vaultReady = ensureVault,
  records = listLocalRecords,
  addRecord = addLocalRecord,
  makeBundle = exportBundle,
  inboundBundles = listInboundBundles,
  importExistingBundle = importBundle,
  importEncryptedExistingBundle = importEncryptedBundle,
} = {}) {
  const challenges = new Map();
  const pendingLogins = new Map();
  const sessions = new Map();
  const failedAttempts = [];

  function prune(now = Date.now()) {
    for (const [id, challenge] of challenges) {
      if (challenge.expiresAt <= now) challenges.delete(id);
    }
    for (const [id, attempt] of pendingLogins) {
      if (attempt.expiresAt <= now) {
        attempt.cancel?.();
        pendingLogins.delete(id);
      }
    }
    for (const [id, session] of sessions) {
      if (session.expiresAt <= now) sessions.delete(id);
    }
    while (failedAttempts.length && failedAttempts[0] <= now - FAILURE_WINDOW_MS) {
      failedAttempts.shift();
    }
  }

  function newChallenge() {
    prune();
    while (challenges.size >= 16) challenges.delete(challenges.keys().next().value);
    const id = randomId();
    const mapping = makeSessionMap();
    const challenge = {
      ...mapping,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    };
    challenges.set(id, challenge);
    return { id, keys: challenge.keys };
  }

  function consumeChallenge(id) {
    prune();
    const challenge = challenges.get(id);
    challenges.delete(id);
    if (!challenge || challenge.expiresAt <= Date.now()) {
      throw new Error("The keypad session expired. Reload the page and try again.");
    }
    return challenge;
  }

  function currentSession(request) {
    prune();
    const id = requestCookie(request, "gitmesh_session");
    const session = sessions.get(id);
    if (!session) return null;
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    return { id, ...session };
  }

  function establishSession(response, requestId) {
    const id = randomId(32);
    prune();
    while (sessions.size >= 8) sessions.delete(sessions.keys().next().value);
    sessions.set(id, { expiresAt: Date.now() + SESSION_TTL_MS });
    setHeaders(response, requestId);
    response.setHeader("Set-Cookie", `gitmesh_session=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`);
  }

  async function handle(request, response) {
    const requestId = randomId(12);
    setHeaders(response, requestId);

    if (!isLoopback(request)) {
      return sendJson(response, requestId, 403, { error: "This app accepts local connections only." });
    }
    if (typeof request.url !== "string" || request.url.length > 2048) {
      return sendJson(response, requestId, 414, { error: "Request path is too long." });
    }

    const url = new URL(request.url ?? "/", `http://127.0.0.1:${request.socket.localPort}`);
    const route = `${request.method} ${url.pathname}`;

    if (route === "GET /" || route === "GET /rotating-keypad.html") {
      const previousSessionId = requestCookie(request, "gitmesh_session");
      sessions.delete(previousSessionId);
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.setHeader("Set-Cookie", "gitmesh_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
      return response.end(fs.readFileSync(path.join(ROOT, "rotating-keypad.html")));
    }
    if (route === "GET /rotating-keypad.css") {
      response.setHeader("Content-Type", "text/css; charset=utf-8");
      return response.end(fs.readFileSync(path.join(ROOT, "rotating-keypad.css")));
    }
    if (route === "GET /rotating-keypad.js") {
      response.setHeader("Content-Type", "text/javascript; charset=utf-8");
      return response.end(fs.readFileSync(path.join(ROOT, "rotating-keypad.js")));
    }
    if (route === "GET /favicon.ico") {
      response.writeHead(204);
      return response.end();
    }
    if (route === "GET /health") {
      return sendJson(response, requestId, 200, { ok: true, localOnly: true });
    }
    if (route === "GET /api/state") {
      return sendJson(response, requestId, 200, {
        setupRequired: !fs.existsSync(authFile),
      });
    }
    if (route === "GET /api/keymap") {
      return sendJson(response, requestId, 200, {
        ...newChallenge(),
      });
    }

    if (request.method === "POST" && !hasSameOrigin(request)) {
      return sendJson(response, requestId, 403, { error: "Request origin was not accepted." });
    }

    if (route === "POST /api/auth/start") {
      prune();
      if (failedAttempts.length >= FAILURE_LIMIT) {
        return sendJson(response, requestId, 429, { error: "Too many attempts. Wait five minutes before trying again." });
      }
      if (pendingLogins.size >= 8) {
        return sendJson(response, requestId, 429, { error: "A sign-in is already waiting for confirmation. Cancel it or wait for it to expire." });
      }
      const body = await readJson(request);
      const challenge = consumeChallenge(body.challengeId);
      const first = decodeKeys(body.first, challenge);
      const setupRequired = !fs.existsSync(authFile);

      if (!setupRequired) {
        const nextSigilReady = new Promise((resolve, reject) => {
          const attemptId = randomId();
          let resolveConfirmation;
          const confirmation = new Promise((resolveConfirmationPromise) => {
            resolveConfirmation = resolveConfirmationPromise;
          });

          let nextSigil = "";
          let resolveReady;
          let rejectReady;
          const ready = new Promise((resolveReadyPromise, rejectReadyPromise) => {
            resolveReady = resolveReadyPromise;
            rejectReady = rejectReadyPromise;
          });
          const promptFlow = setupOrAuthenticate({
            authFile,
            promptLineFn: async () => first,
            promptTextFn: async () => confirmation,
            log: (message) => {
              const match = message.match(/\b(gm-\d+-[A-Za-z0-9_-]+)\b/);
              if (match && !nextSigil) {
                nextSigil = match[1];
                resolveReady();
              }
            },
          });

          const attempt = {
            id: attemptId,
            expiresAt: Date.now() + CHALLENGE_TTL_MS,
            nextSigil: "",
            promptFlow,
            cancel: () => resolveConfirmation("CANCEL"),
            resolveConfirmation,
          };
          pendingLogins.set(attemptId, attempt);
          promptFlow.then(
            () => {},
            (error) => rejectReady(error),
          );
          const timeout = setTimeout(() => resolveConfirmation("CANCEL"), CHALLENGE_TTL_MS);
          timeout.unref?.();
          ready.then(
            () => {
              attempt.nextSigil = nextSigil;
              resolve({ attemptId, nextSigil });
            },
            (error) => {
              clearTimeout(timeout);
              pendingLogins.delete(attemptId);
              reject(error);
            },
          );
        });

        try {
          const offer = await nextSigilReady;
          return sendJson(response, requestId, 200, { state: "save-new-sigil", ...offer });
        } catch {
          failedAttempts.push(Date.now());
          return sendJson(response, requestId, 401, { error: "Sign-in failed. The current sigil remains unchanged." });
        }
      }

      const confirmation = decodeKeys(body.confirmation, challenge);
      if (first.length < 12 || first !== confirmation) {
        return sendJson(response, requestId, 400, { error: "The two initial sigils must match and contain at least 12 characters." });
      }
      try {
        await setupOrAuthenticate({
          authFile,
          promptLineFn: async () => first,
          log: () => {},
        });
        failedAttempts.length = 0;
        establishSession(response, requestId);
        return sendJson(response, requestId, 200, { state: "authenticated", initialSetup: true });
      } catch {
        return sendJson(response, requestId, 400, { error: "Initial setup could not be saved. No sigil was activated." });
      }
    }

    if (route === "POST /api/auth/confirm") {
      const body = await readJson(request);
      if (typeof body.attemptId !== "string" || typeof body.saved !== "boolean") {
        return sendJson(response, requestId, 400, { error: "Invalid confirmation." });
      }
      const attempt = pendingLogins.get(body.attemptId);
      if (!attempt || attempt.expiresAt <= Date.now()) {
        pendingLogins.delete(body.attemptId);
        return sendJson(response, requestId, 410, { error: "This sign-in expired. The current sigil remains valid." });
      }
      attempt.resolveConfirmation(body.saved ? "SAVED" : "CANCEL");
      try {
        await attempt.promptFlow;
        pendingLogins.delete(attempt.id);
        if (!body.saved) {
          return sendJson(response, requestId, 200, { state: "cancelled" });
        }
        failedAttempts.length = 0;
        establishSession(response, requestId);
        return sendJson(response, requestId, 200, {
          state: "authenticated",
          initialSetup: false,
        });
      } catch {
        pendingLogins.delete(attempt.id);
        if (!body.saved) return sendJson(response, requestId, 200, { state: "cancelled" });
        failedAttempts.push(Date.now());
        return sendJson(response, requestId, 400, { error: "The sigil was not rotated and access was not granted." });
      }
    }

    const knownProtectedRoute = [
      "POST /api/auth/logout",
      "GET /api/records",
      "POST /api/records",
      "POST /api/export",
      "GET /api/inbound",
      "POST /api/import",
    ].includes(route) ||
      (request.method === "GET" && url.pathname.startsWith("/api/export/"));
    if (!knownProtectedRoute) {
      return sendJson(response, requestId, 404, { error: "Not found." });
    }

    const session = currentSession(request);
    if (!session) return sendJson(response, requestId, 401, { error: "Sign in again to open the local vault." });

    if (route === "POST /api/auth/logout") {
      sessions.delete(session.id);
      response.setHeader("Set-Cookie", "gitmesh_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
      return sendJson(response, requestId, 200, { state: "signed-out" });
    }
    if (route === "GET /api/records") {
      const localRecords = records();
      return sendJson(response, requestId, 200, {
        records: localRecords.map(({ id, createdAt, targetNode, objectiveScope }) => ({
          id,
          createdAt,
          targetNode,
          objectiveScope,
        })),
      });
    }
    if (route === "POST /api/records") {
      const body = await readJson(request);
      validateRecordInput(body);
      try {
        const record = addRecord(body.targetNode, body.objectiveScope);
        return sendJson(response, requestId, 201, {
          record: {
            id: record.id,
            createdAt: record.createdAt,
            targetNode: record.targetNode,
            objectiveScope: record.objectiveScope,
          },
        });
      } catch {
        return sendJson(response, requestId, 400, { error: "The record was not saved. Check the fields and vault state." });
      }
    }
    if (route === "POST /api/export") {
      const body = await readJson(request);
      try {
        validateBundlePassphrase(body.passphrase);
        const filename = makeBundle(body.passphrase);
        validateBundleName(filename);
        if (!filename.endsWith(".bundle.enc")) throw new Error("Bundle export must be encrypted.");
        return sendJson(response, requestId, 200, { filename, download: `/api/export/${encodeURIComponent(filename)}` });
      } catch {
        return sendJson(response, requestId, 400, { error: "Encrypted bundle export failed. Check the passphrase and vault state." });
      }
    }
    if (route === "GET /api/inbound") {
      return sendJson(response, requestId, 200, { bundles: inboundBundles() });
    }
    if (route === "POST /api/import") {
      const body = await readJson(request);
      validateBundleName(body.filename);
      try {
        let result;
        if (body.filename.endsWith(".bundle.enc")) {
          validateBundlePassphrase(body.passphrase);
          result = importEncryptedExistingBundle(body.filename, body.passphrase);
        } else {
          if (body.allowUnencrypted !== true) {
            return sendJson(response, requestId, 400, {
              error: "This older bundle is unencrypted. Confirm explicitly before importing it.",
            });
          }
          result = importExistingBundle(body.filename);
        }
        return sendJson(response, requestId, 200, result);
      } catch {
        return sendJson(response, requestId, 400, {
          error: body.filename.endsWith(".bundle.enc")
            ? "Bundle authentication or validation failed. No records were imported."
            : "Import failed. No invalid records were added.",
        });
      }
    }
    if (request.method === "GET" && url.pathname.startsWith("/api/export/")) {
      const filename = decodeURIComponent(url.pathname.slice("/api/export/".length));
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.bundle\.enc$/.test(filename)) {
        return sendJson(response, requestId, 400, { error: "Invalid bundle name." });
      }
      const bundlePath = path.join(VAULT, "bundles_outbound", filename);
      try {
        const info = fs.lstatSync(bundlePath);
        if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > MAX_ENCRYPTED_BUNDLE_BYTES) {
          return sendJson(response, requestId, 404, { error: "Bundle not found." });
        }
        response.setHeader("Content-Type", "application/octet-stream");
        response.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Content-Length", info.size);
        return fs.createReadStream(bundlePath).pipe(response);
      } catch {
        return sendJson(response, requestId, 404, { error: "Bundle not found." });
      }
    }

    return sendJson(response, requestId, 404, { error: "Not found." });
  }

  const server = http.createServer((request, response) => {
    handle(request, response).catch((error) => {
      const requestId = response.getHeader("X-Request-ID") ?? randomId(12);
      if (!response.headersSent) {
        const status = Number.isInteger(error?.statusCode) ? error.statusCode : 400;
        sendJson(response, requestId, status, { error: status === 413 ? "Request is too large." : "The request could not be completed." });
      } else {
        response.destroy();
      }
      if (!response.destroyed) {
        console.error(JSON.stringify({
          event: "local_keypad_request_failed",
          requestId,
          method: request.method,
          route: request.url?.split("?")[0] ?? "/",
          errorType: error?.name ?? "Error",
        }));
      }
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

export function listenLocalOnly(server, port, onReady) {
  return server.listen(port, LOCAL_HOST, onReady);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    ensureVault();
    const port = Number(process.env.GITMESH_LOCAL_PORT || 8782);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      throw new Error("GITMESH_LOCAL_PORT must be an integer between 1024 and 65535.");
    }
    const server = createKeypadServer();
    // Keep the HTTP app on loopback; iPhone access must use an SSH port-forward.
    listenLocalOnly(server, port, () => {
      console.log(`GitMesh local keypad listening at http://127.0.0.1:${port}`);
    });
  } catch {
    console.error("GitMesh local keypad could not start.");
    process.exitCode = 1;
  }
}
