-- SQLite schema for acdp-registry-rs.
--
-- TEXT[] and JSONB don't exist in SQLite, so array/object fields are stored
-- as JSON strings. The application is responsible for round-tripping them.

CREATE TABLE IF NOT EXISTS contexts (
    ctx_id          TEXT PRIMARY KEY,
    lineage_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    contributors    TEXT NOT NULL DEFAULT '[]',    -- JSON array of strings
    origin_registry TEXT NOT NULL,
    created_at      TEXT NOT NULL,                  -- ISO 8601
    status          TEXT NOT NULL DEFAULT 'active',
    visibility      TEXT NOT NULL,
    context_type    TEXT NOT NULL,
    version         INTEGER NOT NULL,
    supersedes      TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    summary         TEXT,
    domain          TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',    -- JSON array of strings
    expires_at      TEXT,
    content_hash    TEXT NOT NULL,
    body_json       TEXT NOT NULL                  -- canonical Body JSON
);

CREATE INDEX IF NOT EXISTS idx_ctx_lineage ON contexts(lineage_id);
CREATE INDEX IF NOT EXISTS idx_ctx_agent   ON contexts(agent_id);
CREATE INDEX IF NOT EXISTS idx_ctx_status  ON contexts(status);
CREATE INDEX IF NOT EXISTS idx_ctx_type    ON contexts(context_type);
CREATE INDEX IF NOT EXISTS idx_ctx_created ON contexts(created_at DESC);

-- Lineage head index: tracks (first version, latest version) per lineage.
CREATE TABLE IF NOT EXISTS lineages (
    lineage_id        TEXT PRIMARY KEY,
    first_version_ctx TEXT NOT NULL,
    latest_ctx        TEXT NOT NULL,
    FOREIGN KEY (first_version_ctx) REFERENCES contexts(ctx_id),
    FOREIGN KEY (latest_ctx) REFERENCES contexts(ctx_id)
);

-- Restricted-visibility audience.
CREATE TABLE IF NOT EXISTS context_audience (
    ctx_id    TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    PRIMARY KEY (ctx_id, agent_did),
    FOREIGN KEY (ctx_id) REFERENCES contexts(ctx_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audience_agent ON context_audience(agent_did);

-- Idempotency cache (RFC-ACDP-0003 §6).
CREATE TABLE IF NOT EXISTS idempotency_records (
    agent_id     TEXT NOT NULL,
    key          TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    response_json TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE INDEX IF NOT EXISTS idx_idem_expires ON idempotency_records(expires_at);
