-- Lifecycle events & retraction (RFC-ACDP-0013, ACDP 0.3.0).
--
-- Mirrors crates/acdp-registry-sqlite/migrations/010_lifecycle_events.sql;
-- see that file for the design rationale (append-only per-ctx event log,
-- signed-member byte preservation, per-context event_id uniqueness,
-- tenant scoping copied from the owning context row).
--
-- `occurred_at` is deliberately TEXT, not TIMESTAMPTZ: it is a SIGNED
-- member of the event preimage (§5) and must round-trip byte-identically
-- in the canonical millisecond RFC 3339 form the strict parser accepted —
-- a timestamp column would normalize it.
CREATE TABLE IF NOT EXISTS lifecycle_events (
    seq         BIGSERIAL PRIMARY KEY,
    ctx_id      TEXT NOT NULL REFERENCES contexts(ctx_id),
    event_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor       TEXT NOT NULL,
    reason      TEXT,
    signature   JSONB,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    UNIQUE (ctx_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_events_ctx ON lifecycle_events(ctx_id, seq);

-- Denormalized retraction-state flag (§7.1), maintained atomically by
-- `commit_lifecycle_event` in the SAME transaction as the event append.
-- Stored `status` keeps tracking supersession ONLY; the served status is
-- projected at read time with the §7.2 precedence.
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS retracted BOOLEAN NOT NULL DEFAULT FALSE;
