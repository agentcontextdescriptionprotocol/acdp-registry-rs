-- JWT revocation list (SEC-01). Postgres mirror of SQLite migration 006.
CREATE TABLE IF NOT EXISTS issued_tokens (
    jti        TEXT PRIMARY KEY,
    agent_did  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    -- false = active (recorded at issue time), true = revoked.
    revoked    BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_exp ON issued_tokens(expires_at);
