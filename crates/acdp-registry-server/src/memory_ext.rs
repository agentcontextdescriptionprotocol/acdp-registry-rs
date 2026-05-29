//! Thin `ExtendedRegistryStore` wrapper around [`acdp::registry::InMemoryStore`].
//!
//! Enabled by the `storage-memory` feature. Intended for ephemeral
//! demos and tests where Postgres / SQLite would be overkill — every
//! restart loses state.
//!
//! `list_contexts` is unimplemented because `acdp::registry::InMemoryStore`
//! deliberately does not expose its internal map. The `/admin/contexts`
//! endpoint (compile-gated by `playground`) returns a 500 against this
//! backend; choose `storage-sqlite` if you need it.

use acdp::error::AcdpError;
use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
use acdp::registry::{IdempotencyRecord, InMemoryStore};
use acdp::types::body::{Body, FullContext};
use acdp::types::primitives::{AgentDid, ContentHash, CtxId, LineageId};
use acdp::types::publish::PublishResponse;
use acdp::types::search::{SearchParams, SearchResponse};
use acdp_registry_store::{ExtendedRegistryStore, Page};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Adapter that delegates the protocol store to `acdp::registry::InMemoryStore`
/// while implementing the registry's extension trait.
#[derive(Default)]
pub struct MemoryStore {
    inner: InMemoryStore,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RegistryStore for MemoryStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        self.inner.put(body)
    }
    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        self.inner.get(ctx_id)
    }
    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.inner.lineage(lineage_id)
    }
    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        self.inner.current(lineage_id)
    }
    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
        self.inner.mark_superseded(ctx_id)
    }
    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError> {
        self.inner.first_version_ctx_id(lineage_id)
    }
    fn idempotency_lookup(
        &self,
        agent_id: &AgentDid,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        self.inner.idempotency_lookup(agent_id, key)
    }
    fn idempotency_record(
        &self,
        agent_id: &AgentDid,
        key: &str,
        hash: &ContentHash,
        response: &PublishResponse,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AcdpError> {
        self.inner
            .idempotency_record(agent_id, key, hash, response, expires_at)
    }
    fn idempotency_evict_expired(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        self.inner.idempotency_evict_expired(now)
    }
    fn commit_publish(&self, commit: PublishCommit<'_>) -> Result<PublishCommitOutcome, AcdpError> {
        self.inner.commit_publish(commit)
    }
    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError> {
        self.inner.search(params, requester, anonymous_public_reads)
    }
}

#[async_trait]
impl ExtendedRegistryStore for MemoryStore {
    async fn migrate(&self) -> Result<(), AcdpError> {
        Ok(())
    }
    async fn health(&self) -> Result<(), AcdpError> {
        Ok(())
    }
    async fn list_contexts(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
        _requester: Option<&AgentDid>,
        _tenant: Option<&str>,
    ) -> Result<Page<FullContext>, AcdpError> {
        // The protocol-library InMemoryStore deliberately doesn't expose
        // its internal map; admin listing isn't supported on this backend.
        Err(AcdpError::RegistryInternal(
            "list_contexts is not supported by the memory backend; use SQLite or Postgres".into(),
        ))
    }
}
