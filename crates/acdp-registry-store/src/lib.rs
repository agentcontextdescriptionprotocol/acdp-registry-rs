//! Extension trait layered on top of [`acdp::registry::RegistryStore`].
//!
//! Adds operations the HTTP layer needs but that aren't part of the
//! protocol-level store contract — paginated listing, a backend health
//! check, and migration runner.

pub mod log;

use acdp::error::AcdpError;
use acdp::registry::RegistryStore;
use acdp::types::body::FullContext;
use acdp::types::lifecycle::LifecycleEvent;
use acdp::types::primitives::AgentDid;
use async_trait::async_trait;

pub use log::{build_leaf_record, LogEntryRecord};

/// Cursor-keyed page returned by [`ExtendedRegistryStore::list_contexts`].
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Extension trait for the registry HTTP layer.
///
/// Methods are `async` because real backends (Postgres, SQLite) sit
/// behind `sqlx` and need awaiting. The synchronous `RegistryStore`
/// methods inherited from `acdp` are run via `spawn_blocking` inside
/// implementations.
#[async_trait]
pub trait ExtendedRegistryStore: RegistryStore + Send + Sync {
    /// Paginated listing for admin / debug. Visibility follows the same
    /// RFC-ACDP-0008 §4.5 retrieval-style predicate `retrieve` and `search`
    /// already enforce: `restricted`/`private` bodies require `requester` to
    /// be the producer or a named audience member. The `public` arm is
    /// gated by `anonymous_public_reads`, mirroring `RegistryStore::search`'s
    /// third parameter of the same name — when `requester` is `None` and
    /// `anonymous_public_reads` is `false`, the page is empty; when `true`,
    /// public bodies are returned exactly as before. A non-`None` requester's
    /// results are unaffected by this flag either way.
    ///
    /// `GET /admin/contexts` requires an `auth.admin_tokens` bearer; the
    /// admin caller is authenticated but unnamed (`requester = None`), so it
    /// reaches the §4.5 **public arm only** — restricted and private bodies
    /// are never disclosed to it. The tenant filter below applies when a
    /// tenant is asserted; otherwise the listing spans tenants.
    ///
    /// `tenant` (plan §7): when `Some`, the backend MUST filter rows
    /// at the storage layer so the returned page contains only that
    /// tenant's contexts. This eliminates the "short pages" wart of
    /// the prior post-query filter — a caller asking for `?limit=20`
    /// against a mixed-tenant registry now receives `min(20, available)`
    /// rows for their tenant, not `min(20, available_across_all_tenants)`
    /// reduced by an in-Rust retain.
    ///
    /// `None` preserves V0 behavior (no tenant filter). Implementations
    /// SHOULD pair this with a composite `(tenant_id, created_at)`
    /// index so the WHERE clause stays selective on busy registries —
    /// `idx_ctx_tenant_created` from migration 006/007 (PG/SQLite) is
    /// already in place.
    async fn list_contexts(
        &self,
        limit: u32,
        cursor: Option<&str>,
        requester: Option<&AgentDid>,
        tenant: Option<&str>,
        anonymous_public_reads: bool,
    ) -> Result<Page<FullContext>, AcdpError>;

    /// Storage backend health check. `Ok(())` on success.
    async fn health(&self) -> Result<(), AcdpError>;

    /// Count of currently-stored idempotency records (including not-yet-evicted
    /// expired ones). Surfaced by the admin status endpoint for operational
    /// visibility. The default returns `None` ("not tracked") so backends
    /// without an idempotency table stay compatible; SQL backends override.
    async fn count_idempotency_records(&self) -> Result<Option<u64>, AcdpError> {
        Ok(None)
    }

    /// Run pending migrations. Called at server startup.
    async fn migrate(&self) -> Result<(), AcdpError>;

    /// Tenant-aware lookup: returns the `tenant_id` recorded for a
    /// ctx_id, or `None` if the row doesn't exist. The default
    /// implementation returns `Some("default")` so backends that
    /// haven't migrated to tenant tagging yet still satisfy the
    /// trait without claiming a wrong answer. Production backends
    /// override.
    async fn tenant_of_ctx(&self, _ctx_id: &str) -> Result<Option<String>, AcdpError> {
        Ok(Some("default".into()))
    }

    /// Stamp the tenant_id for a ctx_id. Called by the publish handler
    /// AFTER the protocol-level publish succeeds (the protocol
    /// `RegistryStore::upsert_context` doesn't carry tenancy). When the
    /// requested tenant is `"default"`, this is a no-op since the
    /// migration's default is already `'default'`. Returns Ok on
    /// success; the default impl returns Ok so untenanted backends
    /// stay compatible.
    async fn set_tenant_of_ctx(&self, _ctx_id: &str, _tenant_id: &str) -> Result<(), AcdpError> {
        Ok(())
    }

    /// A context's lifecycle events (RFC-ACDP-0013 §4.1), in registry
    /// acceptance order — the exact array served as
    /// `registry_state.lifecycle_events`. Empty when the context has no
    /// events (or does not exist; callers resolve existence separately).
    ///
    /// The default reads through the protocol-level
    /// [`RegistryStore::get`] projection so backends that already
    /// populate `registry_state.lifecycle_events` (the SQL stores, the
    /// SDK `InMemoryStore`) need no override; a backend with a cheaper
    /// direct query may override.
    async fn lifecycle_events_of_ctx(
        &self,
        ctx_id: &str,
    ) -> Result<Vec<LifecycleEvent>, AcdpError> {
        let ctx = self.get(&acdp::types::primitives::CtxId(ctx_id.to_string()))?;
        Ok(ctx
            .and_then(|c| c.registry_state.lifecycle_events)
            .unwrap_or_default())
    }

    // ── Transparency log reads (ACDP 0.3, RFC-ACDP-0012) ──────────────
    //
    // Leaves are APPENDED only inside `RegistryStore::commit_publish`
    // (same transaction as the context row + receipt, §7.1 — there is
    // deliberately no standalone append API). These are the read
    // projections the `/log/*` endpoints need. Defaults return
    // `NotImplemented` so backends without a `log_leaves` table stay
    // compatible; a deployment MUST NOT enable `[log]` against such a
    // backend (startup validation enforces this for the memory backend).

    /// Current tree size — the number of appended leaves (§5.2).
    async fn log_tree_size(&self) -> Result<u64, AcdpError> {
        Err(AcdpError::NotImplemented(
            "this backend does not implement the transparency log (RFC-ACDP-0012)".into(),
        ))
    }

    /// The first `up_to` §5.1 leaf hashes as raw 32-byte digests, in
    /// leaf-index order — the sole input to every root / inclusion-path /
    /// consistency-path computation (§5.2, §8.3). Errors if the stored
    /// log is not dense over `[0, up_to)`.
    async fn log_leaf_hashes(&self, up_to: u64) -> Result<Vec<[u8; 32]>, AcdpError> {
        let _ = up_to;
        Err(AcdpError::NotImplemented(
            "this backend does not implement the transparency log (RFC-ACDP-0012)".into(),
        ))
    }

    /// The leaf for `ctx_id`, if logged (§8.2 inclusion mode — the
    /// consumer surface). Callers apply retrieval visibility (§8.2 /
    /// RFC-ACDP-0008 §4.5) BEFORE disclosing anything about the result.
    async fn log_leaf_by_ctx(&self, ctx_id: &str) -> Result<Option<LogEntryRecord>, AcdpError> {
        let _ = ctx_id;
        Err(AcdpError::NotImplemented(
            "this backend does not implement the transparency log (RFC-ACDP-0012)".into(),
        ))
    }

    /// The leaf at `leaf_index`, if present (§8.2 inclusion mode — the
    /// auditor surface; hash-only data needs no visibility gate, but the
    /// `leaf` echo does).
    async fn log_leaf_by_index(
        &self,
        leaf_index: u64,
    ) -> Result<Option<LogEntryRecord>, AcdpError> {
        let _ = leaf_index;
        Err(AcdpError::NotImplemented(
            "this backend does not implement the transparency log (RFC-ACDP-0012)".into(),
        ))
    }

    /// Leaves `[start, end)` in leaf-index order (§8.3).
    async fn log_entries(&self, start: u64, end: u64) -> Result<Vec<LogEntryRecord>, AcdpError> {
        let _ = (start, end);
        Err(AcdpError::NotImplemented(
            "this backend does not implement the transparency log (RFC-ACDP-0012)".into(),
        ))
    }

    // ── Witness cosignature aggregation (ACDP 0.4, RFC-ACDP-0015 §6.1) ─
    //
    // The registry MAY collect witness cosignatures of its checkpoints and
    // serve them alongside the checkpoint as the reserved
    // `witness_signatures` member. Only VERIFIED cosignatures are ever
    // stored: the aggregator (`acdp-registry-core::witness`) resolves the
    // witness DID and checks each cosignature's signature AND that its
    // `witnessed_checkpoint` matches this registry's own root at that
    // `tree_size` before calling `upsert_witness_cosignature`. The table
    // is keyed by `(log_id, tree_size, root_hash, witness_did)` so at most
    // one (freshest) cosignature per witness per exact checkpoint tuple is
    // retained; the checkpoint handler reads back by the exact tuple it is
    // serving, so a cosignature can never be mis-attached to a different
    // root.

    /// Insert (or refresh) one VERIFIED witness cosignature for the
    /// checkpoint tuple `(log_id, tree_size, root_hash)`. `cosignature_json`
    /// is the exact wire bytes of the §4 cosignature object (served back
    /// verbatim); `witnessed_at` is its canonical RFC 3339 UTC timestamp,
    /// stored for freshness/newest-wins on re-observation. Upserts on the
    /// `(log_id, tree_size, root_hash, witness_did)` key.
    ///
    /// The default errors: witness aggregation requires a durable backend
    /// with the `log_witness_cosignatures` table (SQLite / Postgres).
    async fn upsert_witness_cosignature(
        &self,
        log_id: &str,
        tree_size: u64,
        root_hash: &str,
        witness_did: &str,
        witnessed_at: &str,
        cosignature_json: &str,
    ) -> Result<(), AcdpError> {
        let _ = (
            log_id,
            tree_size,
            root_hash,
            witness_did,
            witnessed_at,
            cosignature_json,
        );
        Err(AcdpError::NotImplemented(
            "this backend does not implement witness cosignature aggregation (RFC-ACDP-0015)"
                .into(),
        ))
    }

    /// The verified cosignatures stored for the exact checkpoint tuple
    /// `(log_id, tree_size, root_hash)`, as raw §4 wire values, ordered by
    /// `witness_did` for a stable response. Empty when none — the default
    /// returns empty so a backend without the table simply serves a bare
    /// checkpoint (aggregation is optional; RFC-ACDP-0015 §6.1, §11).
    async fn witness_cosignatures_for(
        &self,
        log_id: &str,
        tree_size: u64,
        root_hash: &str,
    ) -> Result<Vec<serde_json::Value>, AcdpError> {
        let _ = (log_id, tree_size, root_hash);
        Ok(Vec::new())
    }

    /// Batch tenant lookup. Returns a map of `ctx_id → tenant_id`.
    /// Used by handlers that filter result sets (search / lineage /
    /// list) — one round-trip beats N. Default impl falls back to N
    /// single-row queries via [`Self::tenant_of_ctx`] so untenanted
    /// backends remain compatible.
    async fn tenants_of_ctxs(
        &self,
        ctx_ids: &[&str],
    ) -> Result<std::collections::HashMap<String, String>, AcdpError> {
        let mut out = std::collections::HashMap::with_capacity(ctx_ids.len());
        for id in ctx_ids {
            if let Some(t) = self.tenant_of_ctx(id).await? {
                out.insert((*id).to_string(), t);
            }
        }
        Ok(out)
    }
}
