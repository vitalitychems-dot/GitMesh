import express from "express";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRateLimit } from "./admin-auth.mjs";
import { PrivateAuth, digest } from "./private-auth.mjs";
import { AuthStore, createAuthPool } from "./auth-store.mjs";
import { APPROVED_CONTEXT_PACK } from "./approved-context.mjs";

function cookie(req, name) {
  const parts = (req.headers.cookie || "").split(";").map((part) => part.trim());
  const values = parts.filter((part) => part.startsWith(`${name}=`));
  return values.length === 1 ? values[0].slice(name.length + 1) : undefined;
}
function cookieOptions(req, maxAge) {
  return { httpOnly: true, sameSite: "strict", path: "/api", maxAge,
    secure: req.app.locals.production || req.headers["x-forwarded-proto"]?.split(",")[0].trim() === "https" };
}
function sameOrigin(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  const protocol = req.headers["x-forwarded-proto"]?.split(",")[0].trim() || req.protocol;
  if (req.app.locals.production && protocol !== "https") return res.status(403).json({ error: "Use HTTPS for private administration." });
  try {
    const origin = new URL(req.headers.origin);
    if (!["http:", "https:"].includes(origin.protocol) || origin.protocol !== `${protocol}:` || origin.host !== host) throw new Error();
  } catch { return res.status(403).json({ error: "Cross-site requests are not allowed." }); }
  if (!req.is("application/json")) return res.status(415).json({ error: "Use a JSON request." });
  next();
}
function exactBody(req, fields) {
  return req.body && !Array.isArray(req.body) && typeof req.body === "object" &&
    Object.keys(req.body).length === fields.length && fields.every((name) => Object.hasOwn(req.body, name));
}
function matchingOffer(req) {
  const pending = cookie(req, "gm_pending");
  return /^[A-Za-z0-9_-]{43}$/.test(pending || "") &&
    typeof req.body.offerId === "string" && /^[a-f0-9]{64}$/.test(req.body.offerId) &&
    digest(pending) === req.body.offerId;
}

export async function createApp({ production = process.env.NODE_ENV === "production", auth, serveFrontend = true } = {}) {
  if (!auth) {
    auth = new PrivateAuth(new AuthStore(createAuthPool()));
    await auth.initialize();
  }
  const app = express();
  app.locals.production = production;
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    req.requestId = randomUUID();
    res.set({
      "X-Request-ID": req.requestId, "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Content-Security-Policy": `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'${production ? "" : " ws: wss:"}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self' https://replit.com https://*.replit.dev`,
      "Cache-Control": "no-store",
    });
    // No request/access logging: keys, cookies, IPs, accounts and URLs are not logged.
    next();
  });
  app.get("/health", async (_req, res) => {
    await auth.configured(); // Also checks that the auth database is reachable.
    res.json({ status: "ok", service: "gitmesh-web" });
  });
  app.use("/api", createRateLimit());
  app.use("/api", sameOrigin);
  app.use(express.json({ limit: "2kb" }));
  app.get("/api/session", async (req, res) => {
    const admin = await auth.session(cookie(req, "gm_admin"));
    res.json({ authenticated: admin, admin, configured: await auth.configured() });
  });
  app.post("/api/admin/login", async (req, res) => {
    if (!exactBody(req, ["sigil"])) return res.status(400).json({ error: "Provide only your admin key." });
    const offer = await auth.begin(req.body.sigil);
    res.cookie("gm_pending", offer.pendingToken, cookieOptions(req, 5 * 60000));
    res.json({ state: "save-new-sigil", nextSigil: offer.nextSigil, offerId: digest(offer.pendingToken) });
  });
  app.post("/api/admin/confirm", async (req, res) => {
    if (!exactBody(req, ["saved", "offerId"]) || req.body.saved !== true) return res.status(400).json({ error: "Save the new key and confirm before continuing." });
    if (!matchingOffer(req)) return res.status(409).json({ error: "This offer expired or a different tab started sign-in. Use your latest saved key." });
    const session = await auth.confirm(cookie(req, "gm_pending"));
    res.cookie("gm_admin", session, cookieOptions(req, 2 * 60 * 60000));
    res.clearCookie("gm_pending", cookieOptions(req, undefined));
    res.json({ authenticated: true, admin: true });
  });
  app.post("/api/admin/cancel", async (req, res) => {
    if (!exactBody(req, ["offerId"])) return res.status(400).json({ error: "Unexpected request fields." });
    if (!matchingOffer(req)) return res.status(410).json({ error: "This offer is no longer current. No key was consumed by this cancellation." });
    await auth.cancel(cookie(req, "gm_pending"));
    res.clearCookie("gm_pending", cookieOptions(req, undefined));
    res.json({ cancelled: true });
  });
  app.post("/api/admin/logout", async (req, res) => {
    if (!exactBody(req, [])) return res.status(400).json({ error: "Unexpected request fields." });
    await auth.logout(cookie(req, "gm_admin"));
    res.clearCookie("gm_admin", cookieOptions(req, undefined));
    res.json({ signedOut: true });
  });
  app.get("/api/admin/status", async (req, res) => {
    if (!await auth.session(cookie(req, "gm_admin"))) return res.status(401).json({ error: "Sign in to continue." });
    res.json({
      identity: { role: "admin" },
      service: { name: "GitMesh private node", uptimeSeconds: Math.floor(process.uptime()), nodeVersion: process.version },
      security: { vaultHosted: false, auth: "Rotating GitMesh admin key", socialLogin: false },
      mesh: { transport: "not_connected" },
    });
  });
  app.get("/api/admin/context-pack", async (req, res) => {
    if (!await auth.session(cookie(req, "gm_admin"))) return res.status(401).json({ error: "Sign in to continue." });
    res.json({
      format: "gitmesh-approved-context-v1",
      delivery: "manual-copy-only",
      transport: "not_connected",
      markdown: APPROVED_CONTEXT_PACK,
    });
  });
  app.use("/api", (_req, res) => res.status(404).json({ error: "Endpoint not found." }));
  if (serveFrontend) {
    if (production) {
      const root = fileURLToPath(new URL("../../generated-artifacts/public/", import.meta.url));
      app.use(express.static(root, { index: false, dotfiles: "deny" }));
      app.get(["/", "/admin", "/sign-in", "/sign-up"], (_req, res) => res.sendFile(`${root}/index.html`));
    } else {
      const { createServer: createVite } = await import("vite");
      const vite = await createVite({ configFile: fileURLToPath(new URL("./vite.config.mjs", import.meta.url)), server: { middlewareMode: true } });
      app.use(vite.middlewares);
    }
  }
  app.use((_req, res) => res.status(404).json({ error: "Not found." }));
  app.use((error, req, res, _next) => {
    const status = error.publicStatus || (error.status === 413 ? 413 : error.type === "entity.parse.failed" ? 400 : 503);
    if (status >= 500) console.error(JSON.stringify({ event: "request_failed", requestId: req.requestId, status }));
    if (status === 429) res.set("Retry-After", "60");
    if (!res.headersSent) res.status(status).json({ error: error.publicStatus ? error.message :
      status === 413 ? "Request too large." : status === 400 ? "Invalid JSON request." : "The private service is temporarily unavailable. Please try again." });
  });
  return app;
}

export function createWebServer(app) {
  const server = createServer(app);
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 100;
  server.maxRequestsPerSocket = 100;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const app = await createApp();
    const server = createWebServer(app);
    server.on("error", () => {
      console.error(JSON.stringify({ event: "server_start_failed" }));
      process.exit(1);
    });
    server.listen(Number(process.env.PORT || 5000), "0.0.0.0", () => console.log(JSON.stringify({ event: "server_started", service: "gitmesh-web" })));
  } catch {
    console.error(JSON.stringify({ event: "startup_failed", message: "Private authentication is unavailable. Check database and initial-key configuration." }));
    process.exit(1);
  }
}
