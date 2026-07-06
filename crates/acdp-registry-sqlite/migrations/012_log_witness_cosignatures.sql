-- Witness cosignature aggregation (RFC-ACDP-0015 §6.1, ACDP 0.4.0).
--
-- A registry advertising `acdp-registry-transparency-log` MAY collect
-- witness cosignatures of its checkpoints and serve them alongside the
-- checkpoint as the reserved top-level `witness_signatures` member
-- (RFC-ACDP-0015 §6.1). This table holds ONLY cosignatures the registry
-- has itself VERIFIED before storing (aggregator: acdp-registry-core::
-- witness): the witness DID is resolved via the SSRF-guarded did:web
-- resolver, the witness signature is recomputed and checked under the
-- witness DID's assertionMethod key, and the cosignature's
-- `witnessed_checkpoint` MUST match this registry's own root at that
-- tree_size. A witness cosigning a DIFFERENT root (a fork, or a lie) is
-- logged and dropped — it never reaches this table, so the aggregator can
-- never serve a bogus cosignature (RFC-ACDP-0015 §6.1).
--
-- Persisted (not merely cached) so the collected witness quorum survives a
-- restart and the checkpoint handler serves it with a single indexed read
-- — never a blocking network fetch in the request path. The poller refills
-- it on its own cadence.
--
-- Keyed by (log_id, tree_size, root_hash, witness_did): at most one
-- cosignature per witness per exact checkpoint tuple. Cosignatures are
-- ephemeral, per-observation evidence (RFC-ACDP-0015 §4) — a fresh
-- re-observation at the same tuple carries a newer `witnessed_at` and
-- UPSERTs the row (newest wins). `witness_signatures` lives OUTSIDE every
-- signed object (§6.1): storing/serving it never touches a body, receipt,
-- checkpoint, or leaf preimage.
CREATE TABLE IF NOT EXISTS log_witness_cosignatures (
    log_id           TEXT    NOT NULL,   -- "<registry_did>/log/<instance>" (§6)
    tree_size        INTEGER NOT NULL,   -- witnessed_checkpoint.tree_size
    root_hash        TEXT    NOT NULL,   -- witnessed_checkpoint.root_hash ("sha256:<hex>")
    witness_did      TEXT    NOT NULL,   -- cosignature.witness_id (the witness's own DID)
    witnessed_at     TEXT    NOT NULL,   -- cosignature.witnessed_at (canonical ms RFC 3339 UTC)
    cosignature_json TEXT    NOT NULL,   -- exact verified §4 cosignature wire bytes (served verbatim)
    stored_at        TEXT    NOT NULL,   -- when this registry verified + stored it
    PRIMARY KEY (log_id, tree_size, root_hash, witness_did)
);

-- The checkpoint handler reads by the exact tuple it is serving.
CREATE INDEX IF NOT EXISTS idx_witness_cosig_tuple
    ON log_witness_cosignatures (log_id, tree_size, root_hash);
