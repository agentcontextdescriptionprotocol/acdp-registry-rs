-- Plan §5: persist per-issuer revocation-poll cursors so a registry
-- restart doesn't refetch the entire upstream feed from cursor=0.
-- Strict-greater-than pagination on the upstream feed keeps a full
-- refetch correct, but on a busy federation the chattiness wastes
-- bandwidth and log volume on every restart.
--
-- Schema notes:
--   * `issuer` is the `iss` claim of the upstream issuer, which doubles
--     as the lookup key here. PK ensures one row per upstream peer.
--   * `cursor_ms` mirrors the wire-level `next_cursor` (unix-ms). i64
--     in app code, INTEGER (signed 64-bit) in SQLite.
--   * `updated_at` is operator-friendly diagnostics — surfaces "how
--     stale is the cursor" without grepping logs. RFC3339 to match the
--     rest of this DB.

CREATE TABLE IF NOT EXISTS auth_revocation_poll_cursors (
    issuer     TEXT    NOT NULL PRIMARY KEY,
    cursor_ms  INTEGER NOT NULL,
    updated_at TEXT    NOT NULL
);
