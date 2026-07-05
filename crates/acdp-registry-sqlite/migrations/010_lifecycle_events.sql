-- Lifecycle events & retraction (RFC-ACDP-0013, ACDP 0.3.0).
--
-- One row per accepted lifecycle event, in registry acceptance order
-- (`seq`). The array served as `registry_state.lifecycle_events` is this
-- table ordered by `seq` per ctx_id — append-only by construction: rows
-- are never updated, reordered, or deleted (§4.1).
--
-- `occurred_at` and `signature` are SIGNED members of the event preimage
-- (§5), so both are stored as the exact text/JSON the strict event parser
-- accepted (canonical millisecond RFC 3339 for `occurred_at`); the
-- application must be able to re-serve them byte-identically.
--
-- `event_id` uniqueness is scoped per context (§4: "unique within the
-- context's lifecycle_events array"); a byte-identical resubmission is an
-- idempotent retry, a divergent one a schema_violation (§6).
--
-- Tenant scoping mirrors `contexts.tenant_id` (migration 007): the value
-- is copied from the owning context row at insert time.
CREATE TABLE IF NOT EXISTS lifecycle_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ctx_id      TEXT NOT NULL REFERENCES contexts(ctx_id),
    event_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    occurred_at TEXT NOT NULL,                 -- canonical ms RFC 3339 (signed member)
    actor       TEXT NOT NULL,
    reason      TEXT,
    signature   TEXT,                          -- JSON signature object (signed envelope)
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    UNIQUE (ctx_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_events_ctx ON lifecycle_events(ctx_id, seq);

-- Denormalized retraction-state flag (RFC-ACDP-0013 §7.1), maintained
-- atomically by `commit_lifecycle_event` in the SAME transaction as the
-- event append. The stored `status` column keeps tracking supersession
-- ONLY; the served status is projected at read time with the §7.2
-- precedence (retracted > superseded > expired > active). The flag exists
-- so search/list queries can project `retracted` without joining the
-- events table per row; `lifecycle_events` (ordered by seq) remains the
-- source of truth.
ALTER TABLE contexts ADD COLUMN retracted INTEGER NOT NULL DEFAULT 0;
