CREATE TABLE IF NOT EXISTS auth_challenges (
    nonce      TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_exp ON auth_challenges(expires_at);
