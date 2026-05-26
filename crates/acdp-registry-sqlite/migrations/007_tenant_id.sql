-- Tenancy foundation (closes audit gap §6 registry side).
--
-- Mirrors crates/acdp-registry-pg/migrations/006_tenant_id.sql.
-- See that file for the design rationale.
--
-- Existing rows backfill to 'default'; new writes can opt into a
-- non-default tenant via the X-Tenant-Id header at the publish
-- handler. Reads filter on tenant_id when the request carries
-- X-Tenant-Id; requests without the header continue to see all rows.

ALTER TABLE contexts ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_ctx_tenant ON contexts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ctx_tenant_created ON contexts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ctx_tenant_lineage ON contexts(tenant_id, lineage_id);
