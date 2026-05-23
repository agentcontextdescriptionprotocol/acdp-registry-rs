-- JWT revocation list (SEC-01).
--
-- A row exists for every token the registry has been asked to revoke. The
-- signer rejects bearer tokens whose `jti` matches a row here and whose
-- `expires_at` has not yet elapsed (expired tokens are harmless and the
-- eviction task drops them). Storing `agent_did` alongside lets the
-- revocation endpoint enforce that an agent may only revoke their own
-- tokens.
CREATE TABLE IF NOT EXISTS issued_tokens (
    jti        TEXT PRIMARY KEY,
    agent_did  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    -- 0 = active (recorded at issue time), 1 = revoked.
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_issued_tokens_exp ON issued_tokens(expires_at);
