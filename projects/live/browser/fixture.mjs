import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import express from "express";
import pg from "pg";
import { PrivateAuth } from "../private-auth.mjs";
import { AuthStore } from "../auth-store.mjs";
import { createApp } from "../live.mjs";

export async function disposableAuthFixture() {
  if (process.env.GITMESH_BROWSER_TESTS !== "development" ||
      process.env.REPLIT_DEPLOYMENT === "1" || process.env.NODE_ENV === "production" ||
      !process.env.DATABASE_URL ||
      (process.env.REPLIT_ENVIRONMENT && !process.env.REPLIT_DEV_DOMAIN)) {
    throw new Error("Browser tests require an explicitly selected development database/runtime. Set GITMESH_BROWSER_TESTS=development; never run against production.");
  }
  const schema = `gm_browser_${randomBytes(12).toString("hex")}`;
  const initial = `gm-browser-test-${randomBytes(32).toString("hex")}`;
  const setup = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1, connectionTimeoutMillis: 5000 });
  let pool;
  let server;
  let created = false;
  async function close() {
    if (server?.listening) {
      await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
    }
    if (pool) await pool.end();
    try {
      if (created) await setup.query(`DROP SCHEMA ${schema} CASCADE`);
    } finally { await setup.end(); }
  }
  try {
    await setup.query(`CREATE SCHEMA ${schema}`);
    created = true;
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      max: 4,
      options: `-c search_path=${schema}`,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
    });
    await pool.query(await readFile(new URL("../schema.sql", import.meta.url), "utf8"));
    const auth = new PrivateAuth(new AuthStore(pool));
    await auth.initialize(initial); // Generated test key, never the real bootstrap Secret.
    const authApp = await createApp({ production: false, auth, serveFrontend: false });
    const app = express();
    app.use((req, res, next) => {
      if (req.path.startsWith("/api/") || req.path === "/health") return authApp(req, res, next);
      next();
    });
    const frontend = fileURLToPath(new URL("../../../generated-artifacts/public/", import.meta.url));
    app.use(express.static(frontend, { index: false }));
    app.get(["/", "/admin", "/sign-in", "/sign-up"], (_req, res) => res.sendFile(`${frontend}/index.html`));
    server = createServer(app);
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    return { initial, pool, baseURL: `http://127.0.0.1:${server.address().port}`, close };
  } catch {
    await close();
    throw new Error("Disposable development browser-auth fixture could not be created. No production or real-admin fallback is allowed.");
  }
}
