import pg from "pg";

export function createAuthPool() {
  if (!process.env.DATABASE_URL) throw new Error("Web authentication database is not configured.");
  const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    max: 4,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    query_timeout: 6000,
    idleTimeoutMillis: 30000,
  });
  pool.on("error", () => console.error(JSON.stringify({ event: "auth_database_unavailable" })));
  return pool;
}

export class AuthStore {
  constructor(pool) { this.pool = pool; }
  async transaction(work) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const value = await work(client);
      await client.query("COMMIT");
      return value;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  async active() {
    return (await this.pool.query("SELECT generation, salt, verifier FROM gm_web_admin WHERE singleton = true")).rows[0] || null;
  }
  async initialize(record) {
    return this.transaction(async (client) => {
      const history = await client.query("SELECT 1 FROM gm_web_used_keys LIMIT 1");
      const existing = await client.query("SELECT 1 FROM gm_web_admin WHERE singleton = true");
      if (history.rowCount && !existing.rowCount) throw new Error("Incomplete authentication state requires manual recovery.");
      const inserted = await client.query(
        "INSERT INTO gm_web_admin (singleton, generation, salt, verifier) VALUES (true, 1, $1, $2) ON CONFLICT DO NOTHING RETURNING singleton",
        [record.salt, record.verifier],
      );
      if (inserted.rowCount) await client.query("INSERT INTO gm_web_used_keys (digest) VALUES ($1) ON CONFLICT DO NOTHING", [record.digest]);
    });
  }
  async attemptAllowed() {
    const result = await this.pool.query(`
      INSERT INTO gm_web_auth_limit (singleton, window_start, attempts) VALUES (true, now(), 1)
      ON CONFLICT (singleton) DO UPDATE SET
        attempts = CASE WHEN gm_web_auth_limit.window_start < now() - interval '1 minute' THEN 1 ELSE gm_web_auth_limit.attempts + 1 END,
        window_start = CASE WHEN gm_web_auth_limit.window_start < now() - interval '1 minute' THEN now() ELSE gm_web_auth_limit.window_start END
      RETURNING attempts
    `);
    return result.rows[0].attempts <= 8;
  }
  async knownKey(digest) {
    return (await this.pool.query("SELECT 1 FROM gm_web_used_keys WHERE digest = $1", [digest])).rowCount > 0;
  }
  async pending(record) {
    await this.pool.query("DELETE FROM gm_web_pending WHERE expires_at <= now()");
    await this.pool.query("DELETE FROM gm_web_sessions WHERE expires_at <= now()");
    const result = await this.pool.query(`
      INSERT INTO gm_web_pending (token_hash, generation, salt, verifier, key_digest, expires_at)
      SELECT $1, $2, $3, $4, $5, now() + interval '5 minutes'
      FROM gm_web_admin WHERE singleton = true AND generation = $2
      RETURNING token_hash
    `, [record.tokenHash, record.generation, record.salt, record.verifier, record.digest]);
    return result.rowCount === 1;
  }
  async confirm(tokenHash, sessionHash) {
    return this.transaction(async (client) => {
      // Serialize on the single active generation before looking up an offer.
      const active = (await client.query("SELECT generation FROM gm_web_admin WHERE singleton = true FOR UPDATE")).rows[0];
      const pending = (await client.query(
        "SELECT * FROM gm_web_pending WHERE token_hash = $1 AND expires_at > now() FOR UPDATE", [tokenHash],
      )).rows[0];
      if (!active || !pending || pending.generation !== active.generation) return false;
      const unique = await client.query("INSERT INTO gm_web_used_keys (digest) VALUES ($1) ON CONFLICT DO NOTHING RETURNING digest", [pending.key_digest]);
      if (!unique.rowCount) return false;
      await client.query("UPDATE gm_web_admin SET generation = generation + 1, salt = $1, verifier = $2 WHERE singleton = true", [pending.salt, pending.verifier]);
      // Completing a new sign-in revokes earlier sessions and competing offers.
      await client.query("DELETE FROM gm_web_pending");
      await client.query("DELETE FROM gm_web_sessions");
      await client.query("INSERT INTO gm_web_sessions (token_hash, expires_at) VALUES ($1, now() + interval '2 hours')", [sessionHash]);
      return true;
    });
  }
  async session(tokenHash) {
    return (await this.pool.query("SELECT 1 FROM gm_web_sessions WHERE token_hash = $1 AND expires_at > now()", [tokenHash])).rowCount === 1;
  }
  async cancel(tokenHash) {
    await this.pool.query("DELETE FROM gm_web_pending WHERE token_hash = $1", [tokenHash]);
  }
  async logout(tokenHash) {
    await this.pool.query("DELETE FROM gm_web_sessions WHERE token_hash = $1", [tokenHash]);
  }
}
