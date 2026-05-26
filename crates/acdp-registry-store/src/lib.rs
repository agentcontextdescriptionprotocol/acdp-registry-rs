//! Extension trait layered on top of [`acdp::registry::RegistryStore`].
//!
//! Adds operations the HTTP layer needs but that aren't part of the
//! protocol-level store contract — paginated listing, a backend health
//! check, and migration runner.

use acdp::error::AcdpError;
use acdp::registry::RegistryStore;
use acdp::types::body::FullContext;
use acdp::types::primitives::AgentDid;
use async_trait::async_trait;

/// Cursor-keyed page returned by [`ExtendedRegistryStore::list`].
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
    /// Paginated listing for admin / debug. Visibility rules apply: if
    /// `requester` is `None`, only public bodies are returned.
    async fn list_contexts(
        &self,
        limit: u32,
        cursor: Option<&str>,
        requester: Option<&AgentDid>,
    ) -> Result<Page<FullContext>, AcdpError>;

    /// Storage backend health check. `Ok(())` on success.
    async fn health(&self) -> Result<(), AcdpError>;

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
}
