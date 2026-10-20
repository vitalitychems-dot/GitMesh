import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import pg from "pg";
import { AuthStore } from "../auth-store.mjs";
import { PrivateAuth, digest, validSigil } from "../private-auth.mjs";
import { createApp, createWebServer } from "../live.mjs";

const initial = "test-only-initial-key-never-use";
const databaseTest = (name, fn) => test(name, { skip: !process.env.DATABASE_URL || process.env.NODE_ENV === "production" }, fn);

async function fixture(t, { seeded = true } = {}) {
  // Every test gets a disposable, randomly named DEVELOPMENT-only schema.
  const schema = `gm_test_${randomBytes(8).toString("hex")}`;
  assert.match(schema, /^gm_test_[a-f0-9]+$/);
  const setup = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
  await setup.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 4, options: `-c search_path=${schema}` });
  t.after(async () => { await pool.end(); await setup.query(`DROP SCHEMA ${schema} CASCADE`); await setup.end(); });
  await pool.query(await readFile(new URL("../schema.sql", import.meta.url), "utf8"));
  const auth = new PrivateAuth(new AuthStore(pool));
  await auth.initialize(seeded ? initial : "");
  return { auth, pool };
}
async function serve(t, app) {
  const server = createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const post = (base, path, body, cookie) => fetch(base + path, {
  method: "POST", headers: { Origin: base, "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) },
  body: JSON.stringify(body),
});

test("web server applies bounded request, header, keep-alive and socket limits", () => {
  const server = createWebServer((_request, response) => response.end());
  assert.equal(server.requestTimeout, 15000);
  assert.equal(server.headersTimeout, 10000);
  assert.equal(server.keepAliveTimeout, 5000);
  assert.equal(server.maxHeadersCount, 100);
  assert.equal(server.maxRequestsPerSocket, 100);
  server.close();
});

test("key validation rejects unsafe types, short values and control characters", () => {
  assert.equal(validSigil(initial), true);
  for (const value of [undefined, {}, "short", "x".repeat(257), initial + "\n"]) assert.equal(validSigil(value), false);
});

databaseTest("unconfigured web access does not create a default administrator", async (t) => {
  const { auth } = await fixture(t, { seeded: false });
  assert.equal(await auth.configured(), false);
  await assert.rejects(auth.begin(initial), { publicStatus: 503 });
});
databaseTest("keys are hashed and a replacement grants no access before save confirmation", async (t) => {
  const { auth, pool } = await fixture(t);
  const offer = await auth.begin(initial);
  assert.notEqual(offer.nextSigil, initial);
  assert.equal(await auth.session(offer.pendingToken), false);
  const dump = JSON.stringify((await pool.query("SELECT * FROM gm_web_admin UNION ALL SELECT true, generation, salt, verifier FROM gm_web_pending")).rows);
  assert.ok(!dump.includes(initial));
  assert.ok(!dump.includes(offer.nextSigil));
  const pending = (await pool.query("SELECT token_hash FROM gm_web_pending")).rows[0];
  assert.equal(pending.token_hash, digest(offer.pendingToken));
  assert.ok(!JSON.stringify(pending).includes(offer.pendingToken));
});
databaseTest("rotation invalidates the old key, saves the new verifier and survives a service restart", async (t) => {
  const { auth, pool } = await fixture(t);
  const offer = await auth.begin(initial);
  const session = await auth.confirm(offer.pendingToken);
  assert.equal(await auth.session(session), true);
  await assert.rejects(auth.begin(initial), { publicStatus: 401 });
  const restarted = new PrivateAuth(new AuthStore(pool));
  await restarted.initialize(initial); // Initial secret may never reset an existing state.
  await assert.rejects(restarted.begin(initial), { publicStatus: 401 });
  const next = await restarted.begin(offer.nextSigil);
  assert.notEqual(next.nextSigil, offer.nextSigil);
  await restarted.confirm(next.pendingToken);
  assert.equal(await auth.session(session), false, "a new sign-in revokes old sessions");
});
databaseTest("cancellation and expired offers leave the active key valid", async (t) => {
  const { auth, pool } = await fixture(t);
  const first = await auth.begin(initial);
  await auth.cancel(first.pendingToken);
  await assert.rejects(auth.confirm(first.pendingToken), { publicStatus: 409 });
  const second = await auth.begin(initial);
  await pool.query("UPDATE gm_web_pending SET expires_at = now() - interval '1 second'");
  await assert.rejects(auth.confirm(second.pendingToken), { publicStatus: 409 });
  await auth.begin(initial);
});
databaseTest("competing sign-ins across service instances cannot consume one generation twice", async (t) => {
  const { auth, pool } = await fixture(t);
  const other = new PrivateAuth(new AuthStore(pool));
  const [a, b] = await Promise.all([auth.begin(initial), other.begin(initial)]);
  const outcomes = await Promise.allSettled([auth.confirm(a.pendingToken), other.confirm(b.pendingToken)]);
  assert.equal(outcomes.filter((x) => x.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((x) => x.status === "rejected").length, 1);
  assert.equal((await pool.query("SELECT generation FROM gm_web_admin")).rows[0].generation, 2);
  assert.equal((await pool.query("SELECT count(*) FROM gm_web_sessions")).rows[0].count, "1");
});
databaseTest("database-wide failed-login throttling survives new service instances", async (t) => {
  const { auth, pool } = await fixture(t);
  for (let i = 0; i < 8; i++) await assert.rejects(auth.begin("test-only-wrong-key-is-long"), { publicStatus: 401 });
  const other = new PrivateAuth(new AuthStore(pool));
  await assert.rejects(other.begin(initial), { publicStatus: 429 });
});
databaseTest("HTTP login enforces origin, save confirmation, cookie sessions and logout", async (t) => {
  const { auth } = await fixture(t);
  const base = await serve(t, await createApp({ auth, serveFrontend: false }));
  assert.equal((await fetch(`${base}/api/admin/status`)).status, 401);
  assert.equal((await fetch(`${base}/api/admin/login`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://other.invalid" }, body: JSON.stringify({ sigil: initial }) })).status, 403);
  const bad = await post(base, "/api/admin/login", { sigil: initial, role: "admin" });
  assert.equal(bad.status, 400);
  const response = await post(base, "/api/admin/login", { sigil: initial });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const offer = await response.json();
  assert.ok(validSigil(offer.nextSigil));
  const pendingCookie = response.headers.getSetCookie().find((x) => x.startsWith("gm_pending="));
  assert.match(pendingCookie, /HttpOnly/);
  assert.match(pendingCookie, /SameSite=Strict/);
  assert.equal((await fetch(`${base}/api/admin/status`, { headers: { Cookie: pendingCookie.split(";")[0] } })).status, 401);
  assert.equal((await post(base, "/api/admin/confirm", { saved: false, offerId: offer.offerId }, pendingCookie.split(";")[0])).status, 400);
  assert.equal((await post(base, "/api/admin/confirm", { saved: true, offerId: "0".repeat(64) }, pendingCookie.split(";")[0])).status, 409, "a stale tab must not consume a different tab's unsaved replacement");
  const confirmed = await post(base, "/api/admin/confirm", { saved: true, offerId: offer.offerId }, pendingCookie.split(";")[0]);
  assert.equal(confirmed.status, 200);
  const sessionCookie = confirmed.headers.getSetCookie().find((x) => x.startsWith("gm_admin=")).split(";")[0];
  const status = await fetch(`${base}/api/admin/status`, { headers: { Cookie: sessionCookie } });
  assert.equal(status.status, 200);
  const data = await status.json();
  assert.equal(data.security.socialLogin, false);
  assert.equal(data.mesh.transport, "not_connected");
  assert.equal((await post(base, "/api/admin/logout", {}, sessionCookie)).status, 200);
  assert.equal((await fetch(`${base}/api/admin/status`, { headers: { Cookie: sessionCookie } })).status, 401);
});
databaseTest("production cookies are Secure and private files are not served", async (t) => {
  const { auth } = await fixture(t);
  const base = await serve(t, await createApp({ production: true, auth }));
  for (const path of ["/", "/sign-in", "/admin", "/sign-up"]) assert.equal((await fetch(base + path)).status, 200);
  for (const path of ["/.env", "/.git/config", "/projects/live/schema.sql", "/SovereignMeshVault/active_sigil.hash", "/api/__clerk"]) {
    assert.equal((await fetch(base + path)).status, 404);
  }
  assert.equal((await post(base, "/api/admin/login", { sigil: initial })).status, 403, "production must refuse plaintext administration");
  const response = await fetch(base + "/api/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: `https://${new URL(base).host}`, "x-forwarded-proto": "https" },
    body: JSON.stringify({ sigil: initial }),
  });
  assert.match(response.headers.getSetCookie().join(";"), /Secure/);
  assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
});
databaseTest("a missing active row cannot silently reset consumed-key history", async (t) => {
  const { auth, pool } = await fixture(t);
  await pool.query("DELETE FROM gm_web_admin");
  await assert.rejects(auth.initialize(initial), /Incomplete authentication state/);
  assert.equal((await pool.query("SELECT count(*) FROM gm_web_admin")).rows[0].count, "0");
});
test("auth database failures return no private diagnostic detail", async (t) => {
  const auth = { configured: async () => { throw new Error("PRIVATE_DATABASE_SECRET_SENTINEL"); }, session: async () => false };
  const base = await serve(t, await createApp({ auth, serveFrontend: false }));
  const response = await fetch(`${base}/api/session`);
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /PRIVATE|SECRET|stack|Error:/);
});
test("approved context is available only to an administrator and stays manual, compact, and secret-free", async (t) => {
  const auth = {
    configured: async () => true,
    session: async (value) => value === "approved-test-session",
  };
  const base = await serve(t, await createApp({ auth, serveFrontend: false }));
  const anonymous = await fetch(`${base}/api/admin/context-pack`);
  assert.equal(anonymous.status, 401);

  const response = await fetch(`${base}/api/admin/context-pack`, {
    headers: { Cookie: "gm_admin=approved-test-session" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const pack = await response.json();
  assert.equal(pack.format, "gitmesh-approved-context-v1");
  assert.equal(pack.delivery, "manual-copy-only");
  assert.equal(pack.transport, "not_connected");
  assert.match(pack.markdown, /\[IDENTITY\]/);
  assert.match(pack.markdown, /\[STATUS\]/);
  assert.match(pack.markdown, /\[FLOW\]/);
  assert.match(pack.markdown, /\[BOUNDARIES\]/);
  assert.match(pack.markdown, /\[PRIVACY\]/);
  assert.match(pack.markdown, /\[DELIVERY\]/);
  assert.ok(Buffer.byteLength(pack.markdown, "utf8") <= 2000);
  assert.doesNotMatch(pack.markdown, /gh[pousr]_[A-Za-z0-9]{20,}/);
  assert.doesNotMatch(pack.markdown, /PRIVATE_DATABASE_SECRET_SENTINEL|test-only-initial-key-never-use/);
  assert.match(pack.markdown, /Never share GitHub tokens, web admin keys, offline sigils, credentials/);
  assert.match(pack.markdown, /No agent automatically receives it/);
});
test("admin UI offers an explicit manual context handoff and reports copy status accessibly", async () => {
  const app = await readFile(new URL("../client/App.jsx", import.meta.url), "utf8");
  assert.match(app, /Manual agent handoff/);
  assert.match(app, /Copy approved context/);
  assert.match(app, /No agent is connected to this app/);
  assert.match(app, /aria-live="polite"/);
  assert.match(app, /nothing was sent automatically/);
});
test("web sign-in distinguishes the active web key from the offline vault sigil", async () => {
  const app = await readFile(new URL("../client/App.jsx", import.meta.url), "utf8");
  assert.match(app, /Separate web admin key/);
  assert.match(app, /not your offline vault sigil/);
  assert.match(app, /latest web key you saved/);
  assert.match(app, /initial setup Secret does not reset an existing key/);
  assert.match(app, /key replaced by a confirmed rotation/);
});
test("the private client has no third-party identity, external fonts or browser credential storage", async () => {
  const files = ["App.jsx", "styles.css", "main.jsx", "index.html"];
  for (const file of files) {
    const text = await readFile(new URL(`../client/${file}`, import.meta.url), "utf8");
    assert.doesNotMatch(text, /clerk|google|github|https?:\/\/|localStorage|sessionStorage|dangerouslySetInnerHTML/i, file);
  }
});
