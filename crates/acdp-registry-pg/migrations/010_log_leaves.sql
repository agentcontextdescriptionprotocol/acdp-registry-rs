-- Registry transparency log (RFC-ACDP-0012, ACDP 0.3.0).
--
-- Mirrors crates/acdp-registry-sqlite/migrations/011_log_leaves.sql; see
-- that file for the full design rationale (same-transaction §7.1 append
-- atomicity, dense 0-based acceptance-order leaf_index, exact JCS leaf
-- bytes in leaf_json so the §5.1 hash is byte-exactly reproducible, one
-- leaf per ctx_id).
--
-- Postgres note: unlike SQLite's BEGIN IMMEDIATE (which serializes every
-- writer), concurrent publish transactions here could race the dense
-- leaf_index assignment. `commit_publish` therefore takes
-- pg_advisory_xact_lock on a log-append key before assigning the index —
-- appends serialize on the lock, everything else in the publish stays
-- concurrent.
CREATE TABLE IF NOT EXISTS log_leaves (
    leaf_index BIGINT PRIMARY KEY,                           -- dense, 0-based (§5.3)
    ctx_id     TEXT NOT NULL UNIQUE REFERENCES contexts(ctx_id),
    leaf_json  TEXT NOT NULL,                                -- exact JCS-canonical leaf bytes (§4)
    leaf_hash  TEXT NOT NULL                                 -- "sha256:<hex>" of SHA-256(0x00 || leaf_json) (§5.1)
);
