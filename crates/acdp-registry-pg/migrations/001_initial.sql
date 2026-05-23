-- Postgres schema. Mirror of SQLite migrations 001 + 002 + 003,
-- using native array / JSONB / FTS where available.

CREATE TABLE IF NOT EXISTS contexts (
    ctx_id          TEXT PRIMARY KEY,
    lineage_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    contributors    TEXT[] NOT NULL DEFAULT '{}',
    origin_registry TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    visibility      TEXT NOT NULL,
    context_type    TEXT NOT NULL,
    version         INTEGER NOT NULL,
    supersedes      TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    summary         TEXT,
    domain          TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    content_hash    TEXT NOT NULL,
    body_json       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ctx_lineage ON contexts(lineage_id);
CREATE INDEX IF NOT EXISTS idx_ctx_agent   ON contexts(agent_id);
CREATE INDEX IF NOT EXISTS idx_ctx_status  ON contexts(status);
CREATE INDEX IF NOT EXISTS idx_ctx_type    ON contexts(context_type);
CREATE INDEX IF NOT EXISTS idx_ctx_created ON contexts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ctx_tags    ON contexts USING gin(tags);

CREATE TABLE IF NOT EXISTS lineages (
    lineage_id        TEXT PRIMARY KEY,
    first_version_ctx TEXT NOT NULL REFERENCES contexts(ctx_id),
    latest_ctx        TEXT NOT NULL REFERENCES contexts(ctx_id)
);

CREATE TABLE IF NOT EXISTS context_audience (
    ctx_id    TEXT NOT NULL REFERENCES contexts(ctx_id) ON DELETE CASCADE,
    agent_did TEXT NOT NULL,
    PRIMARY KEY (ctx_id, agent_did)
);
CREATE INDEX IF NOT EXISTS idx_audience_agent ON context_audience(agent_did);

CREATE TABLE IF NOT EXISTS idempotency_records (
    agent_id      TEXT NOT NULL,
    key           TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    response_json JSONB NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE INDEX IF NOT EXISTS idx_idem_expires ON idempotency_records(expires_at);
