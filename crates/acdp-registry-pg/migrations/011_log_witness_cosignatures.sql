-- Witness cosignature aggregation (RFC-ACDP-0015 §6.1, ACDP 0.4.0).
--
-- Mirrors crates/acdp-registry-sqlite/migrations/012_log_witness_cosignatures.sql;
-- see that file for the full design rationale (verified-only storage, the
-- wrong-root drop, persisted-not-cached, newest-wins per-tuple upsert, and
-- that `witness_signatures` lives outside every signed object).
CREATE TABLE IF NOT EXISTS log_witness_cosignatures (
    log_id           TEXT   NOT NULL,   -- "<registry_did>/log/<instance>" (§6)
    tree_size        BIGINT NOT NULL,   -- witnessed_checkpoint.tree_size
    root_hash        TEXT   NOT NULL,   -- witnessed_checkpoint.root_hash ("sha256:<hex>")
    witness_did      TEXT   NOT NULL,   -- cosignature.witness_id (the witness's own DID)
    witnessed_at     TEXT   NOT NULL,   -- cosignature.witnessed_at (canonical ms RFC 3339 UTC)
    cosignature_json TEXT   NOT NULL,   -- exact verified §4 cosignature wire bytes (served verbatim)
    stored_at        TEXT   NOT NULL,   -- when this registry verified + stored it
    PRIMARY KEY (log_id, tree_size, root_hash, witness_did)
);

CREATE INDEX IF NOT EXISTS idx_witness_cosig_tuple
    ON log_witness_cosignatures (log_id, tree_size, root_hash);
