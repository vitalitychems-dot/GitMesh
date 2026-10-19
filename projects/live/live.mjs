import express from "express";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { clerkMiddleware, clerkClient, getAuth } from "@clerk/express";
import { publishableKeyFromHost } from "@clerk/shared/keys";
import { CLERK_PROXY_PATH, clerkProxyMiddleware, getClerkProxyHost } from "./clerk-proxy.mjs";
import { isGithubOwner, createRateLimit } from "./admin-auth.mjs";

export async function createApp({
  production = process.env.NODE_ENV === "production",
  authMiddleware,
  readAuth = getAuth,
  getUser = (id) => clerkClient.users.getUser(id),
  ownerId = process.env.GITMESH_ADMIN_GITHUB_ID,
  ownerLogin = process.env.GITMESH_ADMIN_GITHUB_LOGIN || "repository owner",
  serveFrontend = true,
} = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    req.requestId = randomUUID();
    res.set({
      "X-Request-ID": req.requestId,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Content-Security-Policy": "frame-ancestors 'self' https://replit.com https://*.replit.dev",
    });
    if (req.path.startsWith("/api/")) {
      res.set("Cache-Control", "no-store");
      const started = Date.now();
      res.on("finish", () => {
        // No URL queries, headers, account identifiers or request bodies.
        if (!req.path.startsWith(CLERK_PROXY_PATH)) console.log(JSON.stringify({
          event: "api_request", requestId: req.requestId, status: res.statusCode, durationMs: Date.now() - started,
        }));
      });
    }
    next();
  });
  app.get("/health", (_req, res) => res.json({ status: "ok", service: "gitmesh-web" }));
  app.use("/api", createRateLimit());
  // The Clerk proxy must stream bytes before body parsing/auth middleware.
  app.use(CLERK_PROXY_PATH, clerkProxyMiddleware());
  app.use(express.json({ limit: "8kb" }));
  app.use(authMiddleware || clerkMiddleware((req) => ({
    publishableKey: publishableKeyFromHost(
      getClerkProxyHost(req) ?? "",
      process.env.CLERK_PUBLISHABLE_KEY,
    ),
  })));

  async function identity(req) {
    const { userId } = readAuth(req);
    if (!userId) return { authenticated: false, admin: false };
    // A time-bounded provider lookup, with no credential/user cache, means
    // removing the GitHub connection revokes admin on the next request.
    let timer;
    try {
      const user = await Promise.race([
        getUser(userId),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("identity unavailable")), 8000); }),
      ]);
      return { authenticated: true, admin: isGithubOwner(user, ownerId) };
    } finally { clearTimeout(timer); }
  }

  app.get("/api/session", async (req, res) => {
    const state = await identity(req);
    res.json({ ...state, owner: ownerLogin });
  });
  app.get("/api/admin/status", async (req, res) => {
    const state = await identity(req);
    if (!state.authenticated) return res.status(401).json({ error: "Sign in to continue." });
    if (!state.admin) return res.status(403).json({ error: "Only the configured GitHub owner can access web administration." });
    return res.json({
      identity: { github: ownerLogin, role: "admin" },
      service: { name: "GitMesh web", uptimeSeconds: Math.floor(process.uptime()), nodeVersion: process.version },
      security: { vaultHosted: false, auth: "GitHub via Clerk" },
      repository: { url: "https://github.com/vitalitychems-dot/GitMesh", branch: "main" },
    });
  });
  app.use("/api", (_req, res) => res.status(404).json({ error: "Endpoint not found." }));

  if (serveFrontend) {
    if (production) {
      const root = fileURLToPath(new URL("../../generated-artifacts/public/", import.meta.url));
      app.use(express.static(root, { index: false, dotfiles: "deny" }));
      app.get(["/", "/admin", "/sign-in", "/sign-in/*path", "/sign-up", "/sign-up/*path"], (_req, res) => {
        res.set("Cache-Control", "no-cache").sendFile(`${root}/index.html`);
      });
    } else {
      const { createServer: createVite } = await import("vite");
      const vite = await createVite({
        configFile: fileURLToPath(new URL("./vite.config.mjs", import.meta.url)),
        server: { middlewareMode: true },
      });
      app.use(vite.middlewares);
    }
  }
  app.use((_req, res) => res.status(404).json({ error: "Not found." }));
  app.use((error, req, res, _next) => {
    const status = error?.status === 413 ? 413 : 503;
    console.error(JSON.stringify({ event: "request_failed", requestId: req.requestId, status }));
    if (!res.headersSent) res.status(status).json({ error: status === 413 ? "Request too large." : "This service is temporarily unavailable. Please try again." });
  });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  for (const key of ["CLERK_SECRET_KEY", "CLERK_PUBLISHABLE_KEY", "GITMESH_ADMIN_GITHUB_ID"]) {
    if (!process.env[key]) throw new Error(`Required server configuration missing: ${key}`);
  }
  const app = await createApp();
  const server = createServer(app);
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  server.listen(Number(process.env.PORT || 5000), "0.0.0.0", () => {
    console.log(JSON.stringify({ event: "server_started", service: "gitmesh-web", port: Number(process.env.PORT || 5000) }));
  });
}
