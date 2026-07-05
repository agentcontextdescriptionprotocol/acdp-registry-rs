-- Registry transparency log (RFC-ACDP-0012, ACDP 0.3.0).
--
-- One row per accepted publish while `[log]` is enabled — the leaf of the
-- per-registry, append-only RFC 6962-style Merkle tree. Appended by
-- `commit_publish` in the SAME transaction as the context row and its
-- RFC-ACDP-0010 receipt (§7.1: the body, its receipt, and its leaf commit
-- together, or none does — a context under the log profile never exists
-- without its leaf, mirroring the receipts no-degraded-mode rule).
--
-- `leaf_index` is the dense, 0-based acceptance-order position (§5.3):
-- assigned as COUNT(*) inside the commit transaction (`BEGIN IMMEDIATE`
-- serializes writers), never reused, reordered, or deleted. Rows are
-- immutable and the table is append-only, forever.
--
-- `leaf_json` stores the EXACT JCS-canonical leaf bytes (RFC 8785 output,
-- valid UTF-8 JSON): the §5.1 leaf hash is SHA-256(0x00 || leaf_json), so
-- persisting the canonical bytes makes every leaf reproducible byte-exactly
-- without trusting any serializer to round-trip. `leaf_hash` is the
-- repository-wide wire form "sha256:" + lowercase_hex of that digest — the
-- ordered leaf_hash column alone determines every root, inclusion path,
-- and consistency path (§5.2, §8.3).
--
-- Exactly one leaf per ctx_id (§4: bodies are immutable, a publish event
-- happens once) — enforced by the UNIQUE constraint.
CREATE TABLE IF NOT EXISTS log_leaves (
    leaf_index INTEGER PRIMARY KEY,                          -- dense, 0-based (§5.3)
    ctx_id     TEXT NOT NULL UNIQUE REFERENCES contexts(ctx_id),
    leaf_json  TEXT NOT NULL,                                -- exact JCS-canonical leaf bytes (§4)
    leaf_hash  TEXT NOT NULL                                 -- "sha256:<hex>" of SHA-256(0x00 || leaf_json) (§5.1)
);
