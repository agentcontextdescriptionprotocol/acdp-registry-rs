-- Idempotency lookup is on the publish hot path; the existing TEXT
-- expires_at column forced a DateTime::parse_from_rfc3339() per
-- lookup. Add an integer epoch-millis column, backfill, and let the
-- Rust code switch to reading the int form.
--
-- The TEXT column stays in place for one release in case operators
-- need to roll the binary back; a future migration will drop it.
ALTER TABLE idempotency_records ADD COLUMN expires_at_ms INTEGER;

-- Backfill from existing TEXT timestamps. SQLite's strftime('%s', ...)
-- truncates to seconds, so re-introduce the millisecond fraction by
-- pulling the three digits after the dot (if any). Rows without a
-- fractional component get .000 (correct: the wall clock recorded
-- whole-second precision in that case).
UPDATE idempotency_records
SET expires_at_ms = CAST(
    (CAST(strftime('%s', expires_at) AS INTEGER) * 1000)
    + (CASE
         WHEN instr(expires_at, '.') > 0
         THEN CAST(substr(expires_at, instr(expires_at, '.') + 1, 3) AS INTEGER)
         ELSE 0
       END)
    AS INTEGER)
WHERE expires_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS idx_idem_expires_ms ON idempotency_records(expires_at_ms);
