// Development/task-merge reconciliation ONLY. Never call from build or startup.
import { readFile } from "node:fs/promises";
import { createAuthPool } from "../projects/live/auth-store.mjs";
if (process.env.NODE_ENV === "production" || process.env.REPLIT_DEPLOYMENT === "1" || !process.env.REPLIT_DEV_DOMAIN) {
  throw new Error("Development schema setup cannot run in production. Use Replit Publish.");
}
const pool = createAuthPool();
try {
  await pool.query(await readFile(new URL("../projects/live/schema.sql", import.meta.url), "utf8"));
  console.log("Development web-auth schema ready.");
} finally { await pool.end(); }
