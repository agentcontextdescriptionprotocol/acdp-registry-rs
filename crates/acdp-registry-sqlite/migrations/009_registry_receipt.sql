-- Registry receipts (RFC-ACDP-0010, ACDP 0.2.0 workstream A).
--
-- Mirrors crates/acdp-registry-pg/migrations/008_registry_receipt.sql; see
-- that file for the design rationale (same-INSERT atomicity, no backfill).
-- Stored as the receipt's JSON text; NULL for pre-receipts contexts.
ALTER TABLE contexts ADD COLUMN registry_receipt TEXT;
