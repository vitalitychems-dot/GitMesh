-- Development schema source. Replit Publish applies the schema diff to production.
-- The application never creates or migrates production tables at startup.
CREATE TABLE IF NOT EXISTS gm_web_admin (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  generation integer NOT NULL CHECK (generation > 0),
  salt text NOT NULL,
  verifier text NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_web_used_keys (
  digest text PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS gm_web_pending (
  token_hash text PRIMARY KEY,
  generation integer NOT NULL,
  salt text NOT NULL,
  verifier text NOT NULL,
  key_digest text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_web_sessions (
  token_hash text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_web_auth_limit (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  window_start timestamptz NOT NULL,
  attempts integer NOT NULL
);
