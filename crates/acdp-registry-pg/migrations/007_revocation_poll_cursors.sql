-- Plan §5: persist per-issuer revocation-poll cursors so a registry
-- restart doesn't refetch the entire upstream feed from cursor=0.
-- See sqlite/008_revocation_poll_cursors.sql for the design rationale.

CREATE TABLE IF NOT EXISTS auth_revocation_poll_cursors (
    issuer     TEXT        NOT NULL PRIMARY KEY,
    cursor_ms  BIGINT      NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
