-- Tenancy foundation (closes audit gap §6 registry side).
--
-- Adds a `tenant_id` column to `contexts` with a default of 'default'
-- so existing rows backfill into a single virtual tenant. New writes
-- can opt into a non-default tenant via the `X-Tenant-Id` request
-- header at the publish handler (see acdp-registry-core handlers).
--
-- Reads filter on tenant_id when the request carries X-Tenant-Id;
-- requests without the header continue to see all rows (backward
-- compatible). Tightening into auth-bound enforcement (JWT claim or
-- mandatory header from a trusted proxy) is follow-up work; this
-- migration is the schema foundation that lets that work land
-- without another DB migration.

ALTER TABLE contexts
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_ctx_tenant ON contexts(tenant_id);

-- Composite indexes for the common (tenant, X) filters added in the
-- handler layer. Cheap on Postgres; lets the planner skip a seqscan
-- when both filters are applied.
CREATE INDEX IF NOT EXISTS idx_ctx_tenant_created ON contexts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ctx_tenant_lineage ON contexts(tenant_id, lineage_id);
