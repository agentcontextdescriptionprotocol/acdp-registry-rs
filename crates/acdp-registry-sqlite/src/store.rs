//! SQLite implementation of `acdp::registry::RegistryStore` +
//! `acdp_registry_store::ExtendedRegistryStore`.

use std::path::Path;
use std::str::FromStr;

use acdp::error::AcdpError;
use acdp::pagination::try_paginate_rows;
use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
use acdp::registry::{IdempotencyRecord, ValidatedPublish};
use acdp::types::body::{Body, FullContext, RegistryState};
use acdp::types::primitives::{AgentDid, ContentHash, CtxId, LineageId, Status, Visibility};
use acdp::types::publish::PublishResponse;
use acdp::types::search::{SearchParams, SearchResponse, SearchResult};
use acdp_registry_store::{ExtendedRegistryStore, Page};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// SQLite store. Held by `RegistryServer` and used by the HTTP layer.
#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Open or create a SQLite database at `path`.
    pub async fn connect(path: &Path, max_connections: u32) -> Result<Self, AcdpError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| AcdpError::RegistryInternal(format!("mkdir: {e}")))?;
            }
        }
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|e| AcdpError::RegistryInternal(format!("sqlite uri: {e}")))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(opts)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("sqlite connect: {e}")))?;
        Ok(Self { pool })
    }

    /// In-memory store, primarily for tests.
    ///
    /// sqlx's pool defaults to `min_connections = 0` and a finite idle
    /// timeout — both of which let the single underlying `:memory:`
    /// connection get reaped between calls, after which the next query
    /// opens a brand-new empty database. Pin the pool to keep the same
    /// connection alive for the lifetime of the store.
    pub async fn connect_in_memory() -> Result<Self, AcdpError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("sqlite mem: {e}")))?;
        Ok(Self { pool })
    }

    fn block_on<F: std::future::Future<Output = T>, T>(&self, fut: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }

    /// Borrow the underlying connection pool. Used by the server binary to
    /// hand the same pool to `SqliteChallengeStore` / `SqliteRevocationStore`
    /// instead of standing up a parallel pool — and to drop the previous
    /// `InMemoryChallengeStore` wiring that left migration 003's table
    /// orphaned (BUG-06).
    pub fn pool(&self) -> &sqlx::SqlitePool {
        &self.pool
    }
}

// ── ExtendedRegistryStore ────────────────────────────────────────────────────

#[async_trait]
impl ExtendedRegistryStore for SqliteStore {
    async fn migrate(&self) -> Result<(), AcdpError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("migrate: {e}")))?;
        Ok(())
    }

    async fn health(&self) -> Result<(), AcdpError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| AcdpError::RegistryInternal(format!("health: {e}")))
    }

    async fn count_idempotency_records(&self) -> Result<Option<u64>, AcdpError> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM idempotency_records")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("count_idempotency: {e}")))?;
        Ok(Some(n.max(0) as u64))
    }

    async fn tenant_of_ctx(&self, ctx_id: &str) -> Result<Option<String>, AcdpError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT tenant_id FROM contexts WHERE ctx_id = ?1")
                .bind(ctx_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tenant_of_ctx: {e}")))?;
        Ok(row.map(|(t,)| t))
    }

    async fn set_tenant_of_ctx(&self, ctx_id: &str, tenant_id: &str) -> Result<(), AcdpError> {
        if tenant_id == "default" {
            return Ok(());
        }
        sqlx::query("UPDATE contexts SET tenant_id = ?1 WHERE ctx_id = ?2")
            .bind(tenant_id)
            .bind(ctx_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("set_tenant_of_ctx: {e}")))?;
        Ok(())
    }

    async fn tenants_of_ctxs(
        &self,
        ctx_ids: &[&str],
    ) -> Result<std::collections::HashMap<String, String>, AcdpError> {
        if ctx_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // SQLite lacks array binding — build an `IN (?,?,?,…)` clause
        // with one placeholder per id, then bind each id. Placeholder
        // count is bounded by the caller's page size (default 200).
        let placeholders = std::iter::repeat_n("?", ctx_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT ctx_id, tenant_id FROM contexts WHERE ctx_id IN ({placeholders})");
        let mut q = sqlx::query_as::<_, (String, String)>(&sql);
        for id in ctx_ids {
            q = q.bind(*id);
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("tenants_of_ctxs: {e}")))?;
        Ok(rows.into_iter().collect())
    }

    async fn list_contexts(
        &self,
        limit: u32,
        cursor: Option<&str>,
        requester: Option<&AgentDid>,
        tenant: Option<&str>,
    ) -> Result<Page<FullContext>, AcdpError> {
        let limit = limit.clamp(1, 200) as i64;
        let anchor = cursor.map(decode_cursor).transpose()?.flatten();
        let mut sql =
            String::from("SELECT body_json, status, registry_receipt FROM contexts WHERE 1=1");
        // Plan §7: push the tenant filter into SQL so a busy
        // mixed-tenant registry doesn't return short pages caused by a
        // post-query retain. The `idx_ctx_tenant_created` index lets
        // this stay selective.
        if tenant.is_some() {
            sql.push_str(" AND tenant_id = ?");
        }
        if anchor.is_some() {
            // RFC3339 strings compare lexicographically when the timezone is UTC,
            // so we can do the keyset compare directly on the stored TEXT column
            // without losing sub-second precision. The ctx_id tiebreaker keeps
            // pagination stable when two contexts share a created_at.
            sql.push_str(" AND (created_at < ? OR (created_at = ? AND ctx_id > ?))");
        }
        sql.push_str(" ORDER BY created_at DESC, ctx_id ASC LIMIT ?");

        let mut q = sqlx::query(&sql);
        if let Some(t) = tenant {
            q = q.bind(t);
        }
        if let Some((anchor_ts, anchor_ctx)) = anchor.as_ref() {
            let anchor_rfc = anchor_ts.to_rfc3339();
            q = q.bind(anchor_rfc.clone()).bind(anchor_rfc).bind(anchor_ctx);
        }
        q = q.bind(limit + 1);

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("list: {e}")))?;

        // BUG-01 / BUG (#13): the "more rows?" signal comes from the raw
        // DB row count (the SQL `LIMIT limit+1` sentinel), and
        // `next_cursor` anchors on the last row *scanned*, not the last
        // item kept by the `visible_to` filter. Both invariants (and
        // their regression tests) are owned by
        // `acdp::pagination::try_paginate_rows`.
        let page = try_paginate_rows(
            rows,
            limit as usize,
            |r| row_to_context(&r),
            |ctx| visible_to(ctx, requester),
            |ctx| {
                encode_cursor(
                    ctx.body.created_at.timestamp_millis(),
                    ctx.body.ctx_id.as_str(),
                )
            },
        )?;
        Ok(Page {
            items: page.items,
            next_cursor: page.next_cursor,
        })
    }
}

fn visible_to(ctx: &FullContext, requester: Option<&AgentDid>) -> bool {
    match ctx.body.visibility {
        Visibility::Public => true,
        Visibility::Restricted | Visibility::Private => match requester {
            None => false,
            Some(r) => {
                r == &ctx.body.agent_id
                    || ctx
                        .body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
    }
}

// ── RegistryStore (sync, drives async sqlx via block_on) ─────────────────────

impl RegistryStore for SqliteStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        self.block_on(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx begin: {e}")))?;
            insert_body(&mut tx, &body, Status::Active, None, None).await?;
            tx.commit()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx commit: {e}")))?;
            Ok(())
        })
    }

    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        self.block_on(async {
            let row = sqlx::query(
                "SELECT body_json, status, registry_receipt FROM contexts WHERE ctx_id = ?",
            )
            .bind(ctx_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            let Some(row) = row else {
                return Ok(None);
            };
            let ctx = row_to_context(&row)?;
            Ok(Some(project_context(ctx, Utc::now())))
        })
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.block_on(async {
            let rows = sqlx::query(
                "SELECT body_json, status, registry_receipt FROM contexts \
                 WHERE lineage_id = ? \
                 ORDER BY version ASC, created_at ASC",
            )
            .bind(lineage_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            let now = Utc::now();
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                out.push(project_context(row_to_context(&r)?, now));
            }
            Ok(out)
        })
    }

    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        let all = self.lineage(lineage_id)?;
        for ctx in all.into_iter().rev() {
            if !matches!(ctx.registry_state.status, Status::Superseded) {
                return Ok(Some(ctx));
            }
        }
        Ok(None)
    }

    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
        self.block_on(async {
            sqlx::query("UPDATE contexts SET status = 'superseded' WHERE ctx_id = ?")
                .bind(ctx_id.as_str())
                .execute(&self.pool)
                .await
                .map(|_| ())
                .map_err(map_sqlx_err)
        })
    }

    fn first_version_ctx_id(&self, lineage_id: &LineageId) -> Result<Option<CtxId>, AcdpError> {
        self.block_on(async {
            let row = sqlx::query(
                "SELECT ctx_id FROM contexts WHERE lineage_id = ? \
                 ORDER BY version ASC, created_at ASC LIMIT 1",
            )
            .bind(lineage_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            Ok(row
                .and_then(|r| r.try_get::<String, _>("ctx_id").ok())
                .map(CtxId))
        })
    }

    fn idempotency_lookup(
        &self,
        agent_id: &AgentDid,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, AcdpError> {
        // Background task `evict_idempotency` keeps the table bounded so we
        // don't burn a DELETE on every read. Reads epoch-ms directly to
        // skip the per-call RFC 3339 parse.
        self.block_on(async {
            let row = sqlx::query(
                "SELECT content_hash, response_json, expires_at_ms \
                 FROM idempotency_records WHERE agent_id = ? AND key = ?",
            )
            .bind(agent_id.as_str())
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            let Some(row) = row else {
                return Ok(None);
            };
            let content_hash: String = row.try_get("content_hash").map_err(map_sqlx_err)?;
            let response_json: String = row.try_get("response_json").map_err(map_sqlx_err)?;
            let expires_ms: i64 = row.try_get("expires_at_ms").map_err(map_sqlx_err)?;
            let response: PublishResponse = serde_json::from_str(&response_json)
                .map_err(|e| AcdpError::RegistryInternal(format!("decode response: {e}")))?;
            let expires_at =
                DateTime::<Utc>::from_timestamp_millis(expires_ms).ok_or_else(|| {
                    AcdpError::RegistryInternal(format!("expires_at_ms out of range: {expires_ms}"))
                })?;
            Ok(Some(IdempotencyRecord {
                content_hash: ContentHash(content_hash),
                response,
                expires_at,
            }))
        })
    }

    fn idempotency_record(
        &self,
        agent_id: &AgentDid,
        key: &str,
        hash: &ContentHash,
        response: &PublishResponse,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AcdpError> {
        let response_json = serde_json::to_string(response)
            .map_err(|e| AcdpError::RegistryInternal(format!("encode response: {e}")))?;
        let expires_ms = expires_at.timestamp_millis();
        // The TEXT `expires_at` column is kept populated for one release
        // (rollback safety); both columns carry the same moment.
        let expires_rfc = expires_at.to_rfc3339();
        self.block_on(async {
            sqlx::query(
                "INSERT INTO idempotency_records (agent_id, key, content_hash, response_json, expires_at, expires_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(agent_id, key) DO UPDATE SET \
                   content_hash = excluded.content_hash, \
                   response_json = excluded.response_json, \
                   expires_at = excluded.expires_at, \
                   expires_at_ms = excluded.expires_at_ms",
            )
            .bind(agent_id.as_str())
            .bind(key)
            .bind(hash.0.as_str())
            .bind(response_json)
            .bind(expires_rfc)
            .bind(expires_ms)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_sqlx_err)
        })
    }

    fn idempotency_evict_expired(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        self.block_on(self.idempotency_evict_inner(now))
    }

    fn commit_publish(&self, commit: PublishCommit<'_>) -> Result<PublishCommitOutcome, AcdpError> {
        let PublishCommit {
            req,
            authority,
            idempotency,
            tenant,
            receipt_minter,
        } = commit;
        let now = Utc::now();
        let req = req.clone();
        let authority = authority.to_string();
        let tenant = tenant.map(|t| t.to_string());
        let idem = idempotency.map(|i| (i.key.to_string(), i.ttl));

        self.block_on(async move {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx begin: {e}")))?;

            // 1. Idempotency replay / collision.
            if let Some((key, _ttl)) = &idem {
                // Evict an expired record for this key first so the claim in
                // step 7 (ON CONFLICT DO NOTHING) does not collide with a stale
                // row after its TTL has lapsed.
                sqlx::query(
                    "DELETE FROM idempotency_records \
                     WHERE agent_id = ? AND key = ? AND expires_at_ms <= ?",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .bind(now.timestamp_millis())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                let row = sqlx::query(
                    "SELECT content_hash, response_json, expires_at_ms \
                     FROM idempotency_records WHERE agent_id = ? AND key = ?",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                if let Some(row) = row {
                    let prior_hash: String = row.try_get("content_hash").map_err(map_sqlx_err)?;
                    let response_json: String =
                        row.try_get("response_json").map_err(map_sqlx_err)?;
                    let exp_ms: i64 = row.try_get("expires_at_ms").map_err(map_sqlx_err)?;
                    let expires_at = DateTime::<Utc>::from_timestamp_millis(exp_ms).ok_or_else(
                        || {
                            AcdpError::RegistryInternal(format!(
                                "expires_at_ms out of range: {exp_ms}"
                            ))
                        },
                    )?;
                    if expires_at > now {
                        if prior_hash == req.content_hash.0 {
                            let response: PublishResponse = serde_json::from_str(&response_json)
                                .map_err(|e| {
                                    AcdpError::RegistryInternal(format!("decode response: {e}"))
                                })?;
                            tx.rollback().await.ok();
                            return Ok(PublishCommitOutcome::IdempotentReplay(response));
                        } else {
                            return Err(AcdpError::DuplicatePublish(format!(
                                "Idempotency-Key '{}' was previously used by '{}' \
                                 with a different content_hash",
                                key, req.agent_id
                            )));
                        }
                    }
                }
            }

            // 2. Supersession coherence checks (mirrors InMemoryStore).
            let first_v1 = if let Some(prev) = &req.supersedes {
                let row = sqlx::query(
                    "SELECT lineage_id, version, status, agent_id, contributors, tenant_id \
                     FROM contexts WHERE ctx_id = ?",
                )
                .bind(prev.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                let Some(row) = row else {
                    // Identical message/shape to the not-owner and wrong-tenant
                    // rejections below, so a caller cannot distinguish "absent"
                    // from "exists but not yours / another tenant's" (no
                    // existence oracle). Matches the reference InMemoryStore.
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp::error::SupersessionReason::NotFound,
                        message: format!("supersedes target '{prev}' not found in this registry"),
                    });
                };
                let prev_lineage: String = row.try_get("lineage_id").map_err(map_sqlx_err)?;
                let prev_version: i64 = row.try_get("version").map_err(map_sqlx_err)?;
                let prev_status: String = row.try_get("status").map_err(map_sqlx_err)?;
                let prev_agent: String = row.try_get("agent_id").map_err(map_sqlx_err)?;
                // contributors is stored as a JSON-encoded array of DIDs.
                let prev_contributors: Vec<String> = row
                    .try_get::<String, _>("contributors")
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let prev_tenant: String = row.try_get("tenant_id").map_err(map_sqlx_err)?;
                // P0 (tenant continuity): a successor must live in the same
                // tenant as its predecessor. Even with the owner check below
                // (agent→tenant is normally 1:1), an agent whose binding changed
                // could otherwise stitch a v2 into a lineage owned by a different
                // tenant. Same NotFound shape — no cross-tenant existence oracle.
                // Only enforced when the publish carries an authoritative tenant
                // (production tenant-scoped path); when `None` the tenant is not
                // threaded here (untenanted, or the playground post-hoc stamp),
                // so there is nothing to compare against.
                if let Some(req_tenant) = tenant.as_deref() {
                    if prev_tenant != req_tenant {
                        return Err(AcdpError::SupersededTarget {
                            reason: acdp::error::SupersessionReason::NotFound,
                            message: format!(
                                "supersedes target '{prev}' not found in this registry"
                            ),
                        });
                    }
                }
                // P0 (producer-continuity): only the predecessor's producer or a
                // declared contributor may publish a successor in its lineage.
                // Signature verification only proves the *requester* signed their
                // own request — it does not bind `supersedes` to the predecessor's
                // owner. Without this, any signer could flip another producer's
                // context to `superseded` and re-point `current(lineage)` — a
                // lineage takeover (RFC-ACDP-0001 §5.9). This mirrors
                // `InMemoryStore::commit_publish`; the registry backends had
                // dropped the check. A non-owner gets the same NotFound shape as
                // a genuinely-absent target so it learns neither that the
                // predecessor exists nor its version/superseded status.
                let is_owner = prev_agent == req.agent_id.as_str()
                    || prev_contributors.iter().any(|c| c == req.agent_id.as_str());
                if !is_owner {
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp::error::SupersessionReason::NotFound,
                        message: format!("supersedes target '{prev}' not found in this registry"),
                    });
                }

                if let Some(declared) = &req.lineage_id {
                    if declared.as_str() != prev_lineage.as_str() {
                        return Err(AcdpError::SupersededTarget {
                            reason: acdp::error::SupersessionReason::LineageMismatch,
                            message: format!(
                                "declared lineage_id '{declared}' ≠ predecessor's '{prev_lineage}'"
                            ),
                        });
                    }
                }
                if req.version as i64 != prev_version + 1 {
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp::error::SupersessionReason::VersionMismatch,
                        message: format!(
                            "version {} ≠ predecessor.version + 1 ({})",
                            req.version,
                            prev_version + 1
                        ),
                    });
                }
                if prev_status == "superseded" {
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp::error::SupersessionReason::AlreadySuperseded,
                        message: format!(
                            "supersedes target '{prev}' has already been superseded"
                        ),
                    });
                }
                // First-version ctx_id derivation.
                let first_row = sqlx::query(
                    "SELECT ctx_id FROM contexts WHERE lineage_id = ? \
                     ORDER BY version ASC, created_at ASC LIMIT 1",
                )
                .bind(&prev_lineage)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                first_row.and_then(|r| r.try_get::<String, _>("ctx_id").ok()).map(CtxId)
            } else {
                None
            };

            // 3. Identifier assignment via the protocol library.
            let validated = ValidatedPublish {
                recomputed_hash: req.content_hash.clone(),
            };
            let (ctx_id, lineage_id) = acdp::registry::assign_identifiers(
                &authority,
                &req.supersedes,
                first_v1.as_ref(),
                &validated,
            )?;

            // 4. Build the stored Body via the SDK's single
            // materialization point (`from_publish_request` ms-truncates
            // `created_at` and starts with empty extensions, exactly as
            // the hand-rolled copy did).
            let created_at = acdp::time::trunc_ms(now);
            let body = Body::from_publish_request(
                &req,
                ctx_id.clone(),
                lineage_id.clone(),
                authority.clone(),
                created_at,
            );

            // 4.5. Mint the registry receipt (RFC-ACDP-0010 §7) inside the
            // transaction, against the fully-assigned body. The receipt is
            // written by the SAME INSERT as the context row below, so a
            // context can never be observed without its receipt — minting
            // failure aborts the whole publish (tx drop = rollback).
            let receipt: Option<serde_json::Value> = match receipt_minter {
                Some(mint) => Some(mint(&body)?),
                None => None,
            };

            // 5. Insert the new body.
            insert_body(
                &mut tx,
                &body,
                Status::Active,
                tenant.as_deref(),
                receipt.as_ref(),
            )
            .await?;

            // 6. Mark predecessor superseded.
            if let Some(prev) = &req.supersedes {
                sqlx::query("UPDATE contexts SET status = 'superseded' WHERE ctx_id = ?")
                    .bind(prev.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_err)?;
            }

            let response = PublishResponse {
                ctx_id,
                lineage_id,
                version: req.version,
                created_at,
                status: Status::Active,
                registry_receipt: receipt,
            };

            // 7. Record idempotency — this INSERT is the concurrency gate
            // (P0 #5). `ctx_id` is random per request, so two concurrent
            // first-publishes of the same (agent_id, key) would otherwise each
            // INSERT a distinct context. The `ON CONFLICT DO NOTHING` makes the
            // racers serialize on the PK: the loser inserts 0 rows, so we roll
            // back its context insert and replay the winner instead of
            // persisting a second context.
            if let Some((key, ttl)) = &idem {
                let expires_at = now + *ttl;
                let response_json = serde_json::to_string(&response)
                    .map_err(|e| AcdpError::RegistryInternal(format!("encode response: {e}")))?;
                let inserted = sqlx::query(
                    "INSERT INTO idempotency_records (agent_id, key, content_hash, response_json, expires_at, expires_at_ms) \
                     VALUES (?, ?, ?, ?, ?, ?) \
                     ON CONFLICT(agent_id, key) DO NOTHING",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .bind(req.content_hash.0.as_str())
                .bind(response_json)
                .bind(expires_at.to_rfc3339())
                .bind(expires_at.timestamp_millis())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?
                .rows_affected();

                if inserted == 0 {
                    // A concurrent publish won the key. Discard our context
                    // insert and replay the winner's record (or reject as a
                    // duplicate when the content_hash differs).
                    tx.rollback().await.ok();
                    let row = sqlx::query(
                        "SELECT content_hash, response_json \
                         FROM idempotency_records WHERE agent_id = ? AND key = ?",
                    )
                    .bind(req.agent_id.as_str())
                    .bind(key.as_str())
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_err)?;
                    let Some(row) = row else {
                        return Err(AcdpError::RegistryInternal(
                            "idempotency key claimed by a concurrent publish but its record \
                             could not be read back"
                                .into(),
                        ));
                    };
                    let prior_hash: String = row.try_get("content_hash").map_err(map_sqlx_err)?;
                    if prior_hash != req.content_hash.0 {
                        return Err(AcdpError::DuplicatePublish(format!(
                            "Idempotency-Key '{}' was previously used by '{}' \
                             with a different content_hash",
                            key, req.agent_id
                        )));
                    }
                    let response_json: String =
                        row.try_get("response_json").map_err(map_sqlx_err)?;
                    let winner: PublishResponse = serde_json::from_str(&response_json)
                        .map_err(|e| AcdpError::RegistryInternal(format!("decode response: {e}")))?;
                    return Ok(PublishCommitOutcome::IdempotentReplay(winner));
                }
            }

            tx.commit()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx commit: {e}")))?;
            Ok(PublishCommitOutcome::Inserted(response))
        })
    }

    fn search(
        &self,
        params: &SearchParams,
        requester: Option<&AgentDid>,
        anonymous_public_reads: bool,
    ) -> Result<SearchResponse, AcdpError> {
        self.block_on(async {
            // Boundary parse of all RFC 3339 filters.
            let created_after = parse_opt_rfc3339(&params.created_after)?;
            let created_before = parse_opt_rfc3339(&params.created_before)?;
            let expires_after = parse_opt_rfc3339(&params.expires_after)?;
            let expires_before = parse_opt_rfc3339(&params.expires_before)?;
            let dp_start_after = parse_opt_rfc3339(&params.data_period_start_after)?;
            let dp_end_before = parse_opt_rfc3339(&params.data_period_end_before)?;

            let mut sql = String::from("SELECT body_json, status FROM contexts WHERE 1=1");
            let mut binds: Vec<String> = Vec::new();

            if let Some(q) = &params.q {
                sql.push_str(
                    " AND ctx_id IN (SELECT ctx_id FROM contexts_fts WHERE contexts_fts MATCH ?)",
                );
                binds.push(fts5_escape(q));
            }
            if let Some(d) = &params.domain {
                sql.push_str(" AND domain = ?");
                binds.push(d.clone());
            }
            if let Some(a) = &params.agent_id {
                sql.push_str(" AND agent_id = ?");
                binds.push(a.clone());
            }
            if let Some(t) = &params.context_type {
                sql.push_str(" AND context_type = ?");
                binds.push(t.clone());
            }
            if let Some(s) = &params.schema_uri {
                sql.push_str(" AND json_extract(body_json, '$.schema_uri') = ?");
                binds.push(s.clone());
            }
            if let Some(after) = created_after {
                sql.push_str(" AND created_at >= ?");
                binds.push(after.to_rfc3339());
            }
            if let Some(before) = created_before {
                sql.push_str(" AND created_at <= ?");
                binds.push(before.to_rfc3339());
            }
            if let Some(after) = expires_after {
                sql.push_str(" AND expires_at IS NOT NULL AND expires_at >= ?");
                binds.push(after.to_rfc3339());
            }
            if let Some(before) = expires_before {
                sql.push_str(" AND expires_at IS NOT NULL AND expires_at <= ?");
                binds.push(before.to_rfc3339());
            }
            if let Some(after) = dp_start_after {
                sql.push_str(" AND json_extract(body_json, '$.data_period.start') >= ?");
                binds.push(after.to_rfc3339());
            }
            if let Some(before) = dp_end_before {
                sql.push_str(" AND json_extract(body_json, '$.data_period.end') <= ?");
                binds.push(before.to_rfc3339());
            }

            // BUG-02: bind the cursor and LIMIT as part of the SQL query so
            // pagination doesn't fetch the entire matching set into Rust
            // and discard it. The +1 sentinel lets us tell whether another
            // page exists. The visibility filter that runs in Rust below
            // can still drop a few rows, so the returned page size may be
            // slightly under `limit`; this is the same trade-off
            // `list_contexts` accepts.
            let cursor_anchor = params
                .cursor
                .as_deref()
                .map(decode_cursor)
                .transpose()?
                .flatten();
            if let Some((anchor_ts, anchor_id)) = cursor_anchor.as_ref() {
                sql.push_str(" AND (created_at < ? OR (created_at = ? AND ctx_id > ?))");
                let anchor_rfc = anchor_ts.to_rfc3339();
                binds.push(anchor_rfc.clone());
                binds.push(anchor_rfc);
                binds.push(anchor_id.clone());
            }
            let limit = params.limit.unwrap_or(50).min(100) as usize;
            sql.push_str(" ORDER BY created_at DESC, ctx_id ASC LIMIT ?");

            let mut q = sqlx::query(&sql);
            for b in &binds {
                q = q.bind(b);
            }
            q = q.bind((limit as i64) + 1);
            let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

            let now = Utc::now();
            let want_status = params.status.as_deref().unwrap_or("active");

            // REG-P2-8: the `limit + 1` sentinel and the "anchor the next
            // cursor on the last RAW scanned row, not the last visible
            // match" rule (a page whose rows are all dropped by the
            // disclosure / status / tag / derived_from filters must not
            // stop pagination early) are owned by `acdp::pagination`.
            let page = try_paginate_rows(
                rows,
                limit,
                |row| -> Result<FullContext, AcdpError> {
                    let body_json: String = row.try_get("body_json").map_err(map_sqlx_err)?;
                    let status: String = row.try_get("status").map_err(map_sqlx_err)?;
                    let body: Body = serde_json::from_str(&body_json)
                        .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
                    // Receipts aren't projected into SearchResult rows, so the
                    // search SELECT deliberately skips the column.
                    let mut ctx = full_context(body, parse_status(&status), None);
                    ctx.registry_state.status =
                        project_status_inline(&ctx.registry_state.status, ctx.body.expires_at, now);
                    Ok(ctx)
                },
                |ctx| {
                    // Search disclosure (RFC-ACDP-0008 §4.5) + status.
                    if !can_surface_in_search(ctx, requester, anonymous_public_reads) {
                        return false;
                    }
                    if ctx.registry_state.status.as_str() != want_status {
                        return false;
                    }
                    // tag filter — kept post-SQL because we store as JSON.
                    if let Some(t) = &params.tags {
                        let want: Vec<&str> = t
                            .split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();
                        let body_tags = ctx.body.tags.as_deref().unwrap_or(&[]);
                        if !want.iter().all(|w| body_tags.iter().any(|bt| bt == w)) {
                            return false;
                        }
                    }
                    // derived_from filter — also post-SQL.
                    params
                        .derived_from
                        .as_ref()
                        .is_none_or(|df| ctx.body.derived_from.iter().any(|c| c.as_str() == df))
                },
                |ctx| {
                    encode_cursor(
                        ctx.body.created_at.timestamp_millis(),
                        ctx.body.ctx_id.as_str(),
                    )
                },
            )?;
            let (matches, next_cursor) = (page.items, page.next_cursor);

            let projected: Vec<SearchResult> = matches
                .iter()
                .map(|ctx| SearchResult {
                    ctx_id: ctx.body.ctx_id.clone(),
                    lineage_id: ctx.body.lineage_id.clone(),
                    agent_id: ctx.body.agent_id.clone(),
                    title: ctx.body.title.clone(),
                    summary: ctx.body.summary.clone(),
                    context_type: ctx.body.context_type.clone(),
                    domain: ctx.body.domain.clone(),
                    created_at: ctx.body.created_at,
                    status: ctx.registry_state.status.clone(),
                    visibility: Some(ctx.body.visibility.clone()),
                })
                .collect();

            // DESIGN-05: total_estimate was previously the matches count of
            // the current page, which is always ≤ limit and misleads any
            // client trying to render "showing N of M". Returning `None`
            // is honest until a separate COUNT(*) query is added.
            Ok(SearchResponse {
                matches: projected,
                total_estimate: None,
                next_cursor,
            })
        })
    }
}

impl SqliteStore {
    async fn idempotency_evict_inner(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        sqlx::query("DELETE FROM idempotency_records WHERE expires_at_ms <= ?")
            .bind(now.timestamp_millis())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_sqlx_err)
    }

    /// Public wrapper for the background eviction task spawned by the
    /// server binary. Inline RFC3339 -> ms cleanup is not on the critical
    /// path of any HTTP handler.
    pub async fn evict_idempotency(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        self.idempotency_evict_inner(now).await
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn insert_body<'c>(
    tx: &mut sqlx::Transaction<'c, sqlx::Sqlite>,
    body: &Body,
    status: Status,
    tenant: Option<&str>,
    receipt: Option<&serde_json::Value>,
) -> Result<(), AcdpError> {
    let body_json = serde_json::to_string(body)
        .map_err(|e| AcdpError::RegistryInternal(format!("encode body: {e}")))?;
    let contributors = serde_json::to_string(&body.contributors)
        .map_err(|e| AcdpError::RegistryInternal(format!("encode contribs: {e}")))?;
    let tags = serde_json::to_string(body.tags.as_deref().unwrap_or(&[]))
        .map_err(|e| AcdpError::RegistryInternal(format!("encode tags: {e}")))?;
    let visibility = match body.visibility {
        Visibility::Public => "public",
        Visibility::Restricted => "restricted",
        Visibility::Private => "private",
    };
    let context_type = context_type_str(&body.context_type);

    // P0 (#3): write tenant_id in the SAME INSERT as the context row so the
    // tenancy is atomic with the row. The previous design committed the row
    // with the column default ('default') and stamped the real tenant in a
    // separate, non-transactional UPDATE — a crash/error in between stranded
    // the context in the 'default' (untenanted) bucket permanently.
    let tenant_id = tenant.unwrap_or("default");
    // RFC-ACDP-0010 §7: the receipt rides the SAME INSERT as the context row,
    // so receipt-and-context atomicity is structural, not transactional
    // bookkeeping a refactor could break.
    let receipt_json = receipt
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| AcdpError::RegistryInternal(format!("encode receipt: {e}")))?;
    sqlx::query(
        "INSERT INTO contexts (\
            ctx_id, lineage_id, agent_id, contributors, origin_registry, \
            created_at, status, visibility, context_type, version, supersedes, \
            title, description, summary, domain, tags, expires_at, content_hash, body_json, \
            tenant_id, registry_receipt\
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(body.ctx_id.as_str())
    .bind(body.lineage_id.as_str())
    .bind(body.agent_id.as_str())
    .bind(contributors)
    .bind(&body.origin_registry)
    .bind(body.created_at.to_rfc3339())
    .bind(status.as_str())
    .bind(visibility)
    .bind(context_type)
    .bind(body.version as i64)
    .bind(body.supersedes.as_ref().map(|c| c.as_str().to_string()))
    .bind(&body.title)
    .bind(body.description.clone())
    .bind(body.summary.clone())
    .bind(body.domain.clone())
    .bind(tags)
    .bind(body.expires_at.map(|t| t.to_rfc3339()))
    .bind(body.content_hash.0.as_str())
    .bind(body_json)
    .bind(tenant_id)
    .bind(receipt_json)
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    // Lineage head bookkeeping.
    sqlx::query(
        "INSERT INTO lineages (lineage_id, first_version_ctx, latest_ctx) \
         VALUES (?, ?, ?) \
         ON CONFLICT(lineage_id) DO UPDATE SET latest_ctx = excluded.latest_ctx",
    )
    .bind(body.lineage_id.as_str())
    .bind(body.ctx_id.as_str())
    .bind(body.ctx_id.as_str())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    Ok(())
}

fn full_context(body: Body, status: Status, receipt: Option<serde_json::Value>) -> FullContext {
    FullContext {
        body,
        registry_state: RegistryState {
            status,
            extensions: Default::default(),
        },
        registry_receipt: receipt,
        extensions: Default::default(),
    }
}

/// Decode one `body_json, status, registry_receipt` row into a
/// [`FullContext`]. The receipt column is TEXT (JSON) and nullable —
/// `None` for contexts published before receipts were enabled.
fn row_to_context(r: &sqlx::sqlite::SqliteRow) -> Result<FullContext, AcdpError> {
    let body_json: String = r.try_get("body_json").map_err(map_sqlx_err)?;
    let status: String = r.try_get("status").map_err(map_sqlx_err)?;
    let receipt_raw: Option<String> = r.try_get("registry_receipt").map_err(map_sqlx_err)?;
    let body: Body = serde_json::from_str(&body_json)
        .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
    let receipt = receipt_raw
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| AcdpError::RegistryInternal(format!("decode receipt: {e}")))?;
    Ok(full_context(body, parse_status(&status), receipt))
}

/// DESIGN-04: typed accessor for the wire-form of `ContextType`. The prior
/// implementation went through `serde_json::to_value(...).as_str()`, which
/// silently produced an empty string for any future multi-field variant.
/// Matching directly on the enum also avoids an allocation per insert.
fn context_type_str(t: &acdp::types::primitives::ContextType) -> String {
    use acdp::types::primitives::ContextType;
    match t {
        ContextType::DataSnapshot => "data_snapshot".into(),
        ContextType::Analysis => "analysis".into(),
        ContextType::Prediction => "prediction".into(),
        ContextType::Alert => "alert".into(),
        ContextType::Custom(s) => s.clone(),
    }
}

fn parse_status(s: &str) -> Status {
    match s {
        "active" => Status::Active,
        "superseded" => Status::Superseded,
        "expired" => Status::Expired,
        other => Status::Other(other.to_string()),
    }
}

fn project_status_inline(
    stored: &Status,
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Status {
    match stored {
        Status::Active => match expires_at {
            Some(exp) if exp <= now => Status::Expired,
            _ => Status::Active,
        },
        other => other.clone(),
    }
}

fn project_context(mut ctx: FullContext, now: DateTime<Utc>) -> FullContext {
    ctx.registry_state.status =
        project_status_inline(&ctx.registry_state.status, ctx.body.expires_at, now);
    ctx
}

fn can_surface_in_search(
    ctx: &FullContext,
    requester: Option<&AgentDid>,
    anonymous_public_reads: bool,
) -> bool {
    match ctx.body.visibility {
        Visibility::Public => anonymous_public_reads || requester.is_some(),
        Visibility::Restricted => match requester {
            None => false,
            Some(r) => {
                r == &ctx.body.agent_id
                    || ctx
                        .body
                        .audience
                        .as_deref()
                        .is_some_and(|a| a.iter().any(|d| d == r))
            }
        },
        Visibility::Private => requester == Some(&ctx.body.agent_id),
    }
}

fn parse_opt_rfc3339(s: &Option<String>) -> Result<Option<DateTime<Utc>>, AcdpError> {
    let Some(raw) = s.as_deref() else {
        return Ok(None);
    };
    let dt = DateTime::parse_from_rfc3339(raw)
        .map_err(|e| AcdpError::SchemaViolation(format!("malformed datetime '{raw}': {e}")))?;
    Ok(Some(dt.with_timezone(&Utc)))
}

/// FTS5 input sanitization.
///
/// Tokenizes the input on Unicode whitespace, quotes each token as an
/// FTS5 string literal, and joins with implicit AND (the default FTS5
/// operator). That makes `q=foo bar` match documents containing BOTH
/// `foo` and `bar` — the same semantics Postgres `plainto_tsquery`
/// already gives us, so the two backends agree on result sets for the
/// same query.
///
/// Per-token quoting neutralizes FTS5 operator syntax (`NOT`, `AND`,
/// `OR`, `NEAR`, column filters, `^`, `+`, `-`, `(`, `)`); embedded
/// `"` characters are doubled per FTS5 string-literal rules.
fn fts5_escape(q: &str) -> String {
    let tokens: Vec<String> = q
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    if tokens.is_empty() {
        // FTS5 rejects a bare empty expression; synthesize a token that
        // can't appear in any indexed document so the query returns no
        // rows. The handler still applies non-FTS filters.
        "\"__acdp_empty_query__\"".into()
    } else {
        tokens.join(" ")
    }
}

const CURSOR_TTL_SECS: i64 = 3600;

fn encode_cursor(created_at_ms: i64, ctx_id: &str) -> String {
    let mint_ms = Utc::now().timestamp_millis();
    B64.encode(format!("{mint_ms}:{created_at_ms}:{ctx_id}"))
}

fn decode_cursor(s: &str) -> Result<Option<(DateTime<Utc>, String)>, AcdpError> {
    let bytes = B64
        .decode(s)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not valid base64".into()))?;
    let decoded = String::from_utf8(bytes)
        .map_err(|_| AcdpError::InvalidCursor("cursor is not utf-8".into()))?;
    let mut parts = decoded.splitn(3, ':');
    let mint = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing mint".into()))?;
    let anchor = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing anchor".into()))?;
    let ctx_id = parts
        .next()
        .ok_or_else(|| AcdpError::InvalidCursor("cursor missing ctx_id".into()))?;
    let mint_ms: i64 = mint
        .parse()
        .map_err(|_| AcdpError::InvalidCursor("cursor mint not int".into()))?;
    let anchor_ms: i64 = anchor
        .parse()
        .map_err(|_| AcdpError::InvalidCursor("cursor anchor not int".into()))?;
    let now = Utc::now().timestamp_millis();
    if now.saturating_sub(mint_ms) > CURSOR_TTL_SECS * 1000 {
        return Err(AcdpError::CursorExpired);
    }
    let anchor_ts = DateTime::<Utc>::from_timestamp_millis(anchor_ms)
        .ok_or_else(|| AcdpError::InvalidCursor("cursor anchor out of range".into()))?;
    Ok(Some((anchor_ts, ctx_id.to_string())))
}

fn map_sqlx_err(e: sqlx::Error) -> AcdpError {
    AcdpError::RegistryInternal(format!("sqlite: {e}"))
}

#[cfg(test)]
mod tests {
    use super::fts5_escape;
    use base64::Engine as _;

    #[test]
    fn fts5_escape_single_token() {
        assert_eq!(fts5_escape("hello"), "\"hello\"");
    }

    #[test]
    fn fts5_escape_handles_numeric_and_unicode_tokens() {
        // Numeric-only and multi-byte tokens must still be quoted (not dropped,
        // not treated as operators) so they participate in the AND query.
        assert_eq!(super::fts5_escape("2024 report"), "\"2024\" \"report\"");
        assert_eq!(super::fts5_escape("café"), "\"café\"");
        // A column-filter injection attempt (`title:`) is neutralized by quoting.
        assert_eq!(super::fts5_escape("title:secret"), "\"title:secret\"");
    }

    // ── pagination cursor (encode/decode) ────────────────────────────

    #[test]
    fn cursor_round_trips_anchor_and_ctx_id() {
        use super::{decode_cursor, encode_cursor};
        let anchor_ms = 1_700_000_123_456_i64;
        let cur = encode_cursor(anchor_ms, "acdp://reg/ctx-1");
        let (ts, ctx_id) = decode_cursor(&cur)
            .expect("decode ok")
            .expect("cursor present");
        assert_eq!(ts.timestamp_millis(), anchor_ms);
        assert_eq!(ctx_id, "acdp://reg/ctx-1");
    }

    #[test]
    fn cursor_rejects_malformed_input() {
        use super::decode_cursor;
        use acdp::error::AcdpError;
        // Not base64.
        assert!(matches!(
            decode_cursor("!!!not-base64!!!"),
            Err(AcdpError::InvalidCursor(_))
        ));
        // Valid base64 but missing the ctx_id field.
        let truncated = super::B64.encode("123:456");
        assert!(matches!(
            decode_cursor(&truncated),
            Err(AcdpError::InvalidCursor(_))
        ));
    }

    #[test]
    fn expired_cursor_is_rejected() {
        use super::{decode_cursor, B64, CURSOR_TTL_SECS};
        use acdp::error::AcdpError;
        // Craft a cursor minted just past the TTL window.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let stale_mint = now_ms - (CURSOR_TTL_SECS * 1000 + 5_000);
        let raw = B64.encode(format!("{stale_mint}:{now_ms}:acdp://reg/ctx-1"));
        assert!(
            matches!(decode_cursor(&raw), Err(AcdpError::CursorExpired)),
            "a cursor older than the TTL must be rejected so stale pages can't be replayed"
        );
    }

    #[test]
    fn fts5_escape_tokens_anded() {
        // Implicit AND between quoted tokens is FTS5's default operator.
        assert_eq!(fts5_escape("hello world"), "\"hello\" \"world\"");
    }

    #[test]
    fn fts5_escape_doubles_embedded_quotes() {
        assert_eq!(fts5_escape("foo\"bar"), "\"foo\"\"bar\"");
    }

    #[test]
    fn fts5_escape_quotes_operator_keywords() {
        // `NOT`, `AND`, `OR`, `NEAR` are FTS5 operators; quoting them
        // turns them into literal token searches instead of letting a
        // caller inject operator syntax.
        assert_eq!(fts5_escape("NOT hack"), "\"NOT\" \"hack\"");
    }

    #[test]
    fn fts5_escape_empty_yields_sentinel() {
        assert_eq!(fts5_escape("   "), "\"__acdp_empty_query__\"");
        assert_eq!(fts5_escape(""), "\"__acdp_empty_query__\"");
    }

    /// P0 #5: two concurrent publishes sharing one Idempotency-Key must yield
    /// exactly ONE persisted context. `ctx_id` is random per request, so before
    /// the claim-gate (ON CONFLICT DO NOTHING + rollback-and-replay) both racers
    /// would INSERT distinct contexts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_publish_same_idempotency_key_creates_one_context() {
        use crate::SqliteStore;
        use acdp::crypto::SigningKey;
        use acdp::producer::Producer;
        use acdp::registry::store::{
            PendingIdempotencyCommit, PublishCommit, PublishCommitOutcome, RegistryStore,
        };
        use acdp::types::primitives::{AgentDid, ContextType, Visibility};
        use acdp_registry_store::ExtendedRegistryStore;
        use std::sync::Arc;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 4).await.unwrap();
        store.migrate().await.unwrap();
        let store = Arc::new(store);

        let p = Producer::new(
            SigningKey::from_bytes(&[9u8; 32]),
            AgentDid::new("did:web:agents.test:race".to_string()),
            "did:web:agents.test:race#key-1".to_string(),
        );
        let req = p
            .publish_request()
            .title("race")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let spawn = |store: Arc<SqliteStore>, req: acdp::types::publish::PublishRequest| {
            tokio::task::spawn_blocking(move || {
                store.commit_publish(PublishCommit {
                    req: &req,
                    authority: "reg.test",
                    idempotency: Some(PendingIdempotencyCommit {
                        key: "race-key",
                        ttl: chrono::Duration::hours(1),
                    }),
                    tenant: None,
                    receipt_minter: None,
                })
            })
        };

        let h1 = spawn(store.clone(), req.clone());
        let h2 = spawn(store.clone(), req.clone());
        let (r1, r2) = tokio::join!(h1, h2);
        let r1 = r1.unwrap().expect("publish 1 ok");
        let r2 = r2.unwrap().expect("publish 2 ok");

        let ctx_id = |o: &PublishCommitOutcome| match o {
            PublishCommitOutcome::Inserted(r) | PublishCommitOutcome::IdempotentReplay(r) => {
                r.ctx_id.as_str().to_string()
            }
        };
        assert_eq!(
            ctx_id(&r1),
            ctx_id(&r2),
            "both racers must resolve to the same ctx_id"
        );
        let inserted = [&r1, &r2]
            .iter()
            .filter(|o| matches!(o, PublishCommitOutcome::Inserted(_)))
            .count();
        assert_eq!(
            inserted, 1,
            "exactly one publish inserts; the other replays"
        );

        let page = store.list_contexts(100, None, None, None).await.unwrap();
        assert_eq!(
            page.items.len(),
            1,
            "exactly one context row must exist after a concurrent idempotent publish"
        );
    }

    /// P0 #3: a tenant-scoped publish must write `tenant_id` in the same
    /// transaction as the context row (no separate stamping UPDATE that a
    /// crash could leave stranded in the 'default' bucket).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commit_publish_writes_tenant_atomically() {
        use crate::SqliteStore;
        use acdp::crypto::SigningKey;
        use acdp::producer::Producer;
        use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
        use acdp::types::primitives::{AgentDid, ContextType, Visibility};
        use acdp_registry_store::ExtendedRegistryStore;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 2).await.unwrap();
        store.migrate().await.unwrap();

        let p = Producer::new(
            SigningKey::from_bytes(&[11u8; 32]),
            AgentDid::new("did:web:agents.test:tenant".to_string()),
            "did:web:agents.test:tenant#key-1".to_string(),
        );
        let req = p
            .publish_request()
            .title("scoped")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let req2 = req.clone();
        let store2 = store.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            store2.commit_publish(PublishCommit {
                req: &req2,
                authority: "reg.test",
                idempotency: None,
                tenant: Some("tenant-x"),
                receipt_minter: None,
            })
        })
        .await
        .unwrap()
        .unwrap();
        let ctx_id = match &outcome {
            PublishCommitOutcome::Inserted(r) | PublishCommitOutcome::IdempotentReplay(r) => {
                r.ctx_id.as_str().to_string()
            }
        };

        let tenant = store.tenant_of_ctx(&ctx_id).await.unwrap();
        assert_eq!(
            tenant.as_deref(),
            Some("tenant-x"),
            "tenant_id must be persisted atomically with the context row"
        );
    }

    /// Supersession-ownership plan (tenant dimension): a successor must live in
    /// the same tenant as its predecessor. A v2 committed under a different
    /// tenant than v1 is rejected (NotFound shape); same-tenant succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commit_publish_rejects_cross_tenant_supersession() {
        use crate::SqliteStore;
        use acdp::crypto::SigningKey;
        use acdp::error::{AcdpError, SupersessionReason};
        use acdp::producer::Producer;
        use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
        use acdp::types::primitives::{AgentDid, ContextType, CtxId, Visibility};
        use acdp_registry_store::ExtendedRegistryStore;
        use std::sync::Arc;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 2).await.unwrap();
        store.migrate().await.unwrap();
        let store = Arc::new(store);

        let p = Producer::new(
            SigningKey::from_bytes(&[13u8; 32]),
            AgentDid::new("did:web:agents.test:rebind".to_string()),
            "did:web:agents.test:rebind#key-1".to_string(),
        );

        // v1 committed under tenant-a.
        let v1 = p
            .publish_request()
            .title("v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let s = store.clone();
        let v1r = v1.clone();
        let v1_resp = tokio::task::spawn_blocking(move || {
            s.commit_publish(PublishCommit {
                req: &v1r,
                authority: "reg.test",
                idempotency: None,
                tenant: Some("tenant-a"),
                receipt_minter: None,
            })
        })
        .await
        .unwrap()
        .unwrap();
        let v1_ctx = match v1_resp {
            PublishCommitOutcome::Inserted(r) | PublishCommitOutcome::IdempotentReplay(r) => {
                r.ctx_id
            }
        };
        let v1_body = store
            .get(&CtxId(v1_ctx.as_str().to_string()))
            .unwrap()
            .unwrap()
            .body;

        // v2 superseding v1 but committed under tenant-b → rejected.
        let v2 = p
            .supersede_body(&v1_body)
            .title("v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let s = store.clone();
        let v2c = v2.clone();
        let cross = tokio::task::spawn_blocking(move || {
            s.commit_publish(PublishCommit {
                req: &v2c,
                authority: "reg.test",
                idempotency: None,
                tenant: Some("tenant-b"),
                receipt_minter: None,
            })
        })
        .await
        .unwrap();
        assert!(
            matches!(
                cross,
                Err(AcdpError::SupersededTarget {
                    reason: SupersessionReason::NotFound,
                    ..
                })
            ),
            "cross-tenant supersession must be rejected (NotFound), got {cross:?}"
        );

        // v2 under the same tenant (tenant-a) → succeeds.
        let s = store.clone();
        let ok = tokio::task::spawn_blocking(move || {
            s.commit_publish(PublishCommit {
                req: &v2,
                authority: "reg.test",
                idempotency: None,
                tenant: Some("tenant-a"),
                receipt_minter: None,
            })
        })
        .await
        .unwrap();
        assert!(
            ok.is_ok(),
            "same-tenant supersession must succeed, got {ok:?}"
        );
    }

    /// RFC-ACDP-0010 §7 crash-consistency: a failing receipt minter must
    /// abort the WHOLE publish — no context row, no idempotency record. A
    /// crash between "insert context" and "mint receipt" is structurally
    /// unobservable because both ride one INSERT in one transaction; this
    /// test pins the only seam left (the minter erroring mid-transaction).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receipt_minter_failure_aborts_the_whole_publish() {
        use crate::SqliteStore;
        use acdp::crypto::SigningKey;
        use acdp::producer::Producer;
        use acdp::registry::store::{PendingIdempotencyCommit, PublishCommit, RegistryStore};
        use acdp::types::primitives::{AgentDid, ContextType, Visibility};
        use acdp_registry_store::ExtendedRegistryStore;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 2).await.unwrap();
        store.migrate().await.unwrap();

        let p = Producer::new(
            SigningKey::from_bytes(&[21u8; 32]),
            AgentDid::new("did:web:agents.test:mintfail".to_string()),
            "did:web:agents.test:mintfail#key-1".to_string(),
        );
        let req = p
            .publish_request()
            .title("doomed")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();

        let s = store.clone();
        let failing_minter = |_: &acdp::types::body::Body| {
            Err(acdp::error::AcdpError::RegistryInternal(
                "simulated KMS outage".into(),
            ))
        };
        let outcome = tokio::task::spawn_blocking(move || {
            s.commit_publish(PublishCommit {
                req: &req,
                authority: "reg.test",
                idempotency: Some(PendingIdempotencyCommit {
                    key: "mintfail-key",
                    ttl: chrono::Duration::hours(1),
                }),
                tenant: None,
                receipt_minter: Some(&failing_minter),
            })
        })
        .await
        .unwrap();
        assert!(outcome.is_err(), "minting failure must fail the publish");

        let page = store.list_contexts(100, None, None, None).await.unwrap();
        assert!(
            page.items.is_empty(),
            "no context row may survive a failed receipt mint"
        );
        assert_eq!(
            store.count_idempotency_records().await.unwrap(),
            Some(0),
            "no idempotency record may survive a failed receipt mint"
        );
    }

    /// Receipts persist atomically with the row and round-trip on every
    /// read path: the publish response, `get`, and `lineage`. Receipt
    /// fields minted from the assigned body equal the row's identifiers
    /// byte-for-byte, and every version in a receipts-era lineage carries
    /// exactly one receipt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receipt_round_trips_through_publish_get_and_lineage() {
        use crate::SqliteStore;
        use acdp::crypto::SigningKey;
        use acdp::producer::Producer;
        use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
        use acdp::types::primitives::{AgentDid, ContextType, Visibility};
        use acdp_registry_store::ExtendedRegistryStore;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 2).await.unwrap();
        store.migrate().await.unwrap();

        let p = Producer::new(
            SigningKey::from_bytes(&[22u8; 32]),
            AgentDid::new("did:web:agents.test:rcpt".to_string()),
            "did:web:agents.test:rcpt#key-1".to_string(),
        );
        // Minter mirroring the shape acdp's ReceiptSigner emits, built
        // from the body the store hands back — so equality below proves
        // the store invoked it against the FINAL assigned identifiers.
        let minter = |body: &acdp::types::body::Body| {
            Ok(serde_json::json!({
                "ctx_id": body.ctx_id.as_str(),
                "lineage_id": body.lineage_id.as_str(),
                "origin_registry": body.origin_registry,
                "content_hash": body.content_hash.0,
            }))
        };

        let publish = |req: acdp::types::publish::PublishRequest| {
            let s = store.clone();
            tokio::task::spawn_blocking(move || {
                s.commit_publish(PublishCommit {
                    req: &req,
                    authority: "reg.test",
                    idempotency: None,
                    tenant: None,
                    receipt_minter: Some(&minter),
                })
            })
        };

        let v1 = p
            .publish_request()
            .title("rcpt-v1")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let r1 = match publish(v1).await.unwrap().unwrap() {
            PublishCommitOutcome::Inserted(r) => r,
            other => panic!("expected Inserted, got {other:?}"),
        };
        let receipt = r1
            .registry_receipt
            .clone()
            .expect("publish response carries the minted receipt");
        assert_eq!(receipt["ctx_id"], r1.ctx_id.as_str());
        assert_eq!(receipt["lineage_id"], r1.lineage_id.as_str());

        // get() surfaces the same stored receipt.
        let s = store.clone();
        let ctx_id = r1.ctx_id.clone();
        let fetched = tokio::task::spawn_blocking(move || s.get(&ctx_id))
            .await
            .unwrap()
            .unwrap()
            .expect("context exists");
        assert_eq!(fetched.registry_receipt, Some(receipt));

        // v2 supersession also mints; the whole lineage is receipt-complete.
        let v2 = p
            .supersede(r1.ctx_id.clone())
            .version(2)
            .title("rcpt-v2")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        publish(v2).await.unwrap().unwrap();

        let s = store.clone();
        let lid = r1.lineage_id.clone();
        let chain = tokio::task::spawn_blocking(move || s.lineage(&lid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chain.len(), 2);
        for ctx in &chain {
            let rcpt = ctx
                .registry_receipt
                .as_ref()
                .expect("every receipts-era context carries exactly one receipt");
            assert_eq!(rcpt["ctx_id"], ctx.body.ctx_id.as_str());
            assert_eq!(rcpt["lineage_id"], ctx.body.lineage_id.as_str());
        }
    }
}
