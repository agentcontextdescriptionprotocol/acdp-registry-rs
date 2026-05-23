-- Auth challenge nonces (TTL ≤ 5 minutes).
--
-- `agent_id` is required and non-empty: the token-issue path asserts that
-- the agent presenting the challenge is the same agent the challenge was
-- issued for. An empty value is treated as a missing record.
CREATE TABLE IF NOT EXISTS auth_challenges (
    nonce      TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_exp ON auth_challenges(expires_at);
