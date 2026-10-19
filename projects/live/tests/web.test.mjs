import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import express from "express";
import { createApp } from "../live.mjs";
import { createRateLimit, isGithubOwner } from "../admin-auth.mjs";
import { CLERK_PROXY_PATH, clerkProxyMiddleware } from "../clerk-proxy.mjs";

const github = (overrides = {}) => ({
  provider: "oauth_github", externalId: "42", verification: { status: "verified" }, ...overrides,
});
const user = (account = github()) => ({ externalAccounts: [account] });

async function serve(t, handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}

async function appFor(t, { account = user(), lookupError = false } = {}) {
  const app = await createApp({
    authMiddleware: (_req, _res, next) => next(),
    readAuth: (req) => ({ userId: req.headers["x-test-user"] }),
    getUser: async () => { if (lookupError) throw new Error("private diagnostic must not escape"); return account; },
    ownerId: "42", ownerLogin: "test-owner", serveFrontend: false,
  });
  return serve(t, app);
}

test("only a verified GitHub external ID grants administration", () => {
  assert.equal(isGithubOwner(user(), "42"), true);
  for (const account of [
    github({ externalId: "43", username: "test-owner" }),
    github({ provider: "oauth_google" }),
    github({ verification: { status: "unverified" } }),
    github({ verification: null }),
    github({ externalId: undefined }),
  ]) assert.equal(isGithubOwner(user(account), "42"), false);
  assert.equal(isGithubOwner({ publicMetadata: { role: "admin" }, username: "test-owner", externalAccounts: [] }, "42"), false);
  assert.equal(isGithubOwner(user(), ""), false);
  assert.equal(isGithubOwner(user(), "42anything"), false);
});

test("anonymous callers cannot get admin details, even with client role hints", async (t) => {
  const base = await appFor(t);
  const response = await fetch(`${base}/api/admin/status?role=admin`, { headers: { "x-role": "admin" } });
  assert.equal(response.status, 401);
  const body = await response.text();
  assert.doesNotMatch(body, /nodeVersion|uptimeSeconds|private diagnostic/);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const session = await (await fetch(`${base}/api/session`)).json();
  assert.deepEqual(session, { authenticated: false, admin: false, owner: "test-owner" });
});

test("signed-in non-owner is denied, not promoted on first signup", async (t) => {
  const base = await appFor(t, { account: user(github({ externalId: "43" })) });
  const headers = { "x-test-user": "ordinary-user" };
  assert.equal((await fetch(`${base}/api/admin/status`, { headers })).status, 403);
  const session = await (await fetch(`${base}/api/session`, { headers })).json();
  assert.equal(session.authenticated, true);
  assert.equal(session.admin, false);
});

test("verified owner can load real web service status without vault access", async (t) => {
  const base = await appFor(t);
  const response = await fetch(`${base}/api/admin/status`, { headers: { "x-test-user": "owner" } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.identity.role, "admin");
  assert.equal(body.security.vaultHosted, false);
  assert.equal(body.service.nodeVersion, process.version);
  assert.equal(typeof body.service.uptimeSeconds, "number");
  assert.equal((await fetch(`${base}/api/vault`)).status, 404);
  assert.equal((await fetch(`${base}/SovereignMeshVault/active_sigil.hash`)).status, 404);
  assert.equal((await fetch(`${base}/health`)).status, 200);
});

test("provider failure fails closed with a generic error", async (t) => {
  const base = await appFor(t, { lookupError: true });
  const response = await fetch(`${base}/api/admin/status`, { headers: { "x-test-user": "owner" } });
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /diagnostic|Error:|stack|owner/);
});

test("removing a verified GitHub connection revokes access on the next request", async (t) => {
  const account = user();
  const base = await appFor(t, { account });
  const headers = { "x-test-user": "owner" };
  assert.equal((await fetch(`${base}/api/admin/status`, { headers })).status, 200);
  account.externalAccounts.length = 0;
  assert.equal((await fetch(`${base}/api/admin/status`, { headers })).status, 403);
});

test("sensitive routes rate-limit spoofed forwarded IPs and recover after expiry", async (t) => {
  let now = 1000;
  const app = express();
  app.use(createRateLimit({ limit: 2, windowMs: 1000, clock: () => now }));
  app.get("/", (_req, res) => res.json({ ok: true }));
  const base = await serve(t, app);
  assert.equal((await fetch(base)).status, 200);
  assert.equal((await fetch(base)).status, 200);
  const blocked = await fetch(base, { headers: { "x-forwarded-for": "spoofed-ip" } });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get("retry-after"), "1");
  now += 1001;
  assert.equal((await fetch(base)).status, 200);
});

test("Clerk production proxy forwards the mounted path and buffers chunked responses", async (t) => {
  const upstream = await serve(t, (req, res) => {
    assert.equal(req.url, "/v1/environment?check=1");
    assert.equal(req.headers["clerk-secret-key"], "fake-test-key");
    assert.match(req.headers["clerk-proxy-url"], new RegExp(`${CLERK_PROXY_PATH}$`));
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"ok":');
    res.end("true}");
  });
  const app = express();
  app.use(CLERK_PROXY_PATH, clerkProxyMiddleware({ production: true, secretKey: "fake-test-key", target: upstream }));
  const base = await serve(t, app);
  const response = await fetch(`${base}${CLERK_PROXY_PATH}/v1/environment?check=1`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(response.headers.get("transfer-encoding"), null);
  assert.equal(response.headers.get("content-length"), "11");
});

test("production proxy returns a generic error when its upstream is unavailable", async (t) => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const target = `http://127.0.0.1:${server.address().port}`;
  await new Promise((resolve) => server.close(resolve));
  const app = express();
  app.use(CLERK_PROXY_PATH, clerkProxyMiddleware({ production: true, secretKey: "fake-test-key", target }));
  const base = await serve(t, app);
  const response = await fetch(`${base}${CLERK_PROXY_PATH}/v1/environment`);
  assert.equal(response.status, 502);
  assert.equal(await response.text(), "");
});

test("oversized chunked proxy responses fail safely rather than hanging", async (t) => {
  const upstream = await serve(t, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(Buffer.alloc(4 * 1024 * 1024 + 1, "x"));
  });
  const app = express();
  app.use(CLERK_PROXY_PATH, clerkProxyMiddleware({ production: true, secretKey: "fake-test-key", target: upstream }));
  const base = await serve(t, app);
  const response = await fetch(`${base}${CLERK_PROXY_PATH}/v1/environment`, { signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 502);
  assert.equal(await response.text(), "");
});

test("production serves built sign-in callbacks and assets but not repository files", async (t) => {
  const app = await createApp({
    production: true, serveFrontend: true,
    authMiddleware: (_req, _res, next) => next(),
    readAuth: () => ({ userId: null }), ownerId: "42",
  });
  const base = await serve(t, app);
  for (const path of ["/", "/sign-in", "/sign-in/sso-callback", "/sign-up/sso-callback", "/admin"]) {
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /<div id="root"><\/div>/);
    const asset = html.match(/src="([^"]+\.js)"/)?.[1];
    assert.ok(asset?.startsWith("/assets/"));
    assert.equal((await fetch(`${base}${asset}`)).status, 200);
  }
  for (const path of ["/.env", "/.git/config", "/SovereignMeshVault/active_sigil.hash", "/projects/local-vault/keypad-server.mjs"]) {
    assert.equal((await fetch(`${base}${path}`)).status, 404);
  }
  assert.equal((await fetch(`${base}/api/admin/status`)).status, 401);
});
