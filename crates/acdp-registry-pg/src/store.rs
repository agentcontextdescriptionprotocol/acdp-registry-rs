//! Postgres implementation of `RegistryStore` + `ExtendedRegistryStore`.

use acdp::error::AcdpError;
use acdp::pagination::try_paginate_rows;
use acdp::registry::store::{PublishCommit, PublishCommitOutcome, RegistryStore};
use acdp::registry::{IdempotencyRecord, LifecycleCommitOutcome, ValidatedPublish};
use acdp::types::body::{Body, FullContext, RegistryState};
use acdp::types::lifecycle::{retraction_state, LifecycleEvent, LifecycleEventType};
use acdp::types::primitives::{AgentDid, ContentHash, CtxId, LineageId, Status, Visibility};
use acdp::types::publish::PublishResponse;
use acdp::types::search::{SearchParams, SearchResponse, SearchResult};
use acdp_registry_store::{ExtendedRegistryStore, LogEntryRecord, Page};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
    /// RFC-ACDP-0012: when true, `commit_publish` appends a transparency-
    /// log leaf in the SAME transaction as the context row + receipt
    /// (§7.1 — no degraded mode). Enabled via
    /// [`Self::with_transparency_log`] when `[log]` is configured.
    log_enabled: bool,
}

/// `pg_advisory_xact_lock` key serializing transparency-log appends so
/// the dense, 0-based `leaf_index` assignment (RFC-ACDP-0012 §5.3) never
/// races under READ COMMITTED. Held to end-of-transaction; publishes
/// without the log never take it.
const LOG_APPEND_LOCK_KEY: i64 = 0x00AC_D900_0012;

impl PgStore {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, AcdpError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect(url)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("pg connect: {e}")))?;
        Ok(Self {
            pool,
            log_enabled: false,
        })
    }

    /// Enable the RFC-ACDP-0012 transparency log: every subsequent
    /// `commit_publish` appends a §4 leaf atomically with the context
    /// row and its receipt (§7.1), and refuses to publish at all when no
    /// receipt is minted — the log profile's prerequisite is the
    /// receipts profile (§11), and there is no degraded mode.
    pub fn with_transparency_log(mut self) -> Self {
        self.log_enabled = true;
        self
    }

    fn block_on<F: std::future::Future<Output = T>, T>(&self, fut: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }

    /// Borrow the underlying connection pool. Used by the server binary
    /// for crash-safe `PgChallengeStore` / `PgRevocationStore` wiring
    /// (BUG-06). The previous code held an `InMemoryChallengeStore` even
    /// in the Postgres build, which broke handshakes across replicas.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

#[async_trait]
impl ExtendedRegistryStore for PgStore {
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
            sqlx::query_as("SELECT tenant_id FROM contexts WHERE ctx_id = $1")
                .bind(ctx_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tenant_of_ctx: {e}")))?;
        Ok(row.map(|(t,)| t))
    }

    async fn set_tenant_of_ctx(&self, ctx_id: &str, tenant_id: &str) -> Result<(), AcdpError> {
        if tenant_id == "default" {
            // The migration default IS 'default'; skip the write so
            // we don't clobber rows another writer hasn't tagged.
            return Ok(());
        }
        sqlx::query("UPDATE contexts SET tenant_id = $1 WHERE ctx_id = $2")
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
        // Postgres-native batch: ANY($1::text[]) takes the whole list
        // as a single bound parameter — beats N round-trips.
        let owned: Vec<String> = ctx_ids.iter().map(|s| (*s).to_string()).collect();
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT ctx_id, tenant_id FROM contexts WHERE ctx_id = ANY($1)")
                .bind(&owned)
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

        // BUG-03: bind the LIMIT instead of concatenating it. The value
        // is range-clamped above so there is no injection risk today, but
        // the inline pattern was contrary to every other query in this
        // file and is fragile if the clamp is ever loosened.
        let mut q = String::from(
            "SELECT body_json, status, registry_receipt, retracted FROM contexts WHERE 1=1",
        );
        let mut next_pos = 1usize;
        // Plan §7: SQL-level tenant filter — see sqlite/list_contexts
        // and store/lib.rs for rationale. The composite
        // `idx_ctx_tenant_created` index from migration 006_tenant_id
        // covers the (tenant_id, created_at) order this query uses.
        if tenant.is_some() {
            q.push_str(&format!(" AND tenant_id = ${}", next_pos));
            next_pos += 1;
        }
        if anchor.is_some() {
            q.push_str(&format!(
                " AND (created_at < ${a} OR (created_at = ${a} AND ctx_id > ${b}))",
                a = next_pos,
                b = next_pos + 1
            ));
            next_pos += 2;
        }
        q.push_str(&format!(
            " ORDER BY created_at DESC, ctx_id ASC LIMIT ${}",
            next_pos
        ));

        let mut query = sqlx::query(&q);
        if let Some(t) = tenant {
            query = query.bind(t);
        }
        if let Some((anchor_ts, anchor_ctx)) = anchor.as_ref() {
            query = query.bind(*anchor_ts).bind(anchor_ctx);
        }
        query = query.bind(limit + 1);
        let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

        // BUG-01 / BUG (#13): the "more rows?" signal comes from the raw
        // DB row count (`limit + 1` sentinel), and `next_cursor` anchors
        // on the last row *scanned*, not the last item kept by the
        // `visible_to` filter. Both invariants (and their regression
        // tests) are owned by `acdp::pagination::try_paginate_rows`.
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

    async fn lifecycle_events_of_ctx(
        &self,
        ctx_id: &str,
    ) -> Result<Vec<LifecycleEvent>, AcdpError> {
        events_for_ctx(&self.pool, ctx_id).await
    }

    // ── Transparency log reads (RFC-ACDP-0012) ─────────────────────────

    async fn log_tree_size(&self) -> Result<u64, AcdpError> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM log_leaves")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("log_tree_size: {e}")))?;
        Ok(n.max(0) as u64)
    }

    async fn log_leaf_hashes(&self, up_to: u64) -> Result<Vec<[u8; 32]>, AcdpError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT leaf_hash FROM log_leaves WHERE leaf_index < $1 ORDER BY leaf_index ASC",
        )
        .bind(i64::try_from(up_to).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AcdpError::RegistryInternal(format!("log_leaf_hashes: {e}")))?;
        if rows.len() as u64 != up_to {
            return Err(AcdpError::RegistryInternal(format!(
                "transparency log is not dense: {} leaves stored below index {up_to} \
                 (RFC-ACDP-0012 §5.3)",
                rows.len()
            )));
        }
        rows.iter()
            .map(|(h,)| acdp::types::log::decode_sha256_hex(h))
            .collect()
    }

    async fn log_leaf_by_ctx(&self, ctx_id: &str) -> Result<Option<LogEntryRecord>, AcdpError> {
        let row = sqlx::query(
            "SELECT leaf_index, ctx_id, leaf_hash, leaf_json FROM log_leaves WHERE ctx_id = $1",
        )
        .bind(ctx_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AcdpError::RegistryInternal(format!("log_leaf_by_ctx: {e}")))?;
        row.map(|r| log_row_to_record(&r)).transpose()
    }

    async fn log_leaf_by_index(
        &self,
        leaf_index: u64,
    ) -> Result<Option<LogEntryRecord>, AcdpError> {
        let Ok(idx) = i64::try_from(leaf_index) else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT leaf_index, ctx_id, leaf_hash, leaf_json FROM log_leaves \
             WHERE leaf_index = $1",
        )
        .bind(idx)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AcdpError::RegistryInternal(format!("log_leaf_by_index: {e}")))?;
        row.map(|r| log_row_to_record(&r)).transpose()
    }

    async fn log_entries(&self, start: u64, end: u64) -> Result<Vec<LogEntryRecord>, AcdpError> {
        let rows = sqlx::query(
            "SELECT leaf_index, ctx_id, leaf_hash, leaf_json FROM log_leaves \
             WHERE leaf_index >= $1 AND leaf_index < $2 ORDER BY leaf_index ASC",
        )
        .bind(i64::try_from(start).unwrap_or(i64::MAX))
        .bind(i64::try_from(end).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AcdpError::RegistryInternal(format!("log_entries: {e}")))?;
        rows.iter().map(log_row_to_record).collect()
    }
}

/// Decode one `log_leaves` row.
fn log_row_to_record(r: &PgRow) -> Result<LogEntryRecord, AcdpError> {
    let leaf_index: i64 = r.try_get("leaf_index").map_err(map_sqlx_err)?;
    Ok(LogEntryRecord {
        leaf_index: u64::try_from(leaf_index).map_err(|_| {
            AcdpError::RegistryInternal(format!("negative leaf_index {leaf_index}"))
        })?,
        ctx_id: r.try_get("ctx_id").map_err(map_sqlx_err)?,
        leaf_hash: r.try_get("leaf_hash").map_err(map_sqlx_err)?,
        leaf_json: r.try_get("leaf_json").map_err(map_sqlx_err)?,
    })
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

// ── RegistryStore ────────────────────────────────────────────────────────────

impl RegistryStore for PgStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
            insert_body(&mut tx, &body, Status::Active, None, None).await?;
            tx.commit().await.map_err(map_sqlx_err)?;
            Ok(())
        })
    }

    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        self.block_on(async {
            let row = sqlx::query(
                "SELECT body_json, status, registry_receipt, retracted FROM contexts \
                 WHERE ctx_id = $1",
            )
            .bind(ctx_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            let Some(row) = row else {
                return Ok(None);
            };
            let mut ctx = row_to_context(&row)?;
            // RFC-ACDP-0013 §4.1: full retrieval serves the event array
            // inside registry_state (omitted, not [], when empty).
            let events = events_for_ctx(&self.pool, ctx_id.as_str()).await?;
            if !events.is_empty() {
                ctx.registry_state.lifecycle_events = Some(events);
            }
            Ok(Some(project_context(ctx, Utc::now())))
        })
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.block_on(async {
            let rows = sqlx::query(
                "SELECT body_json, status, registry_receipt, retracted FROM contexts \
                 WHERE lineage_id = $1 \
                 ORDER BY version ASC, created_at ASC",
            )
            .bind(lineage_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            // RFC-ACDP-0013 §4.1: the lineage array carries each version's
            // lifecycle_events. One batch query for the whole lineage.
            let mut events_by_ctx = events_for_lineage(&self.pool, lineage_id.as_str()).await?;
            let now = Utc::now();
            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                let mut ctx = row_to_context(r)?;
                if let Some(events) = events_by_ctx.remove(ctx.body.ctx_id.as_str()) {
                    if !events.is_empty() {
                        ctx.registry_state.lifecycle_events = Some(events);
                    }
                }
                out.push(project_context(ctx, now));
            }
            Ok(out)
        })
    }

    fn current(&self, lineage_id: &LineageId) -> Result<Option<FullContext>, AcdpError> {
        let all = self.lineage(lineage_id)?;
        for ctx in all.into_iter().rev() {
            // RFC-ACDP-0004 §5.2 as amended by RFC-ACDP-0013 §8.3: the head
            // is the newest version that is neither superseded nor retracted
            // (an expired head is still a valid head; a retracted one never
            // is — fixture lc-003).
            if !matches!(
                ctx.registry_state.status,
                Status::Superseded | Status::Retracted
            ) {
                return Ok(Some(ctx));
            }
        }
        Ok(None)
    }

    fn commit_lifecycle_event(
        &self,
        event: &LifecycleEvent,
    ) -> Result<LifecycleCommitOutcome, AcdpError> {
        let event = event.clone();
        self.block_on(async move {
            let now = Utc::now();
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx begin: {e}")))?;

            // 1. Resolve and ROW-LOCK the context (`FOR UPDATE`, the
            //    Postgres analog of SQLite's BEGIN IMMEDIATE): two racing
            //    lifecycle writes serialize here, so the loser observes
            //    the winner's committed history and gets the contract
            //    outcome (idempotent replay / invalid_lifecycle_transition)
            //    instead of a lost update.
            let row = sqlx::query(
                "SELECT body_json, status, registry_receipt, retracted, tenant_id \
                 FROM contexts WHERE ctx_id = $1 FOR UPDATE",
            )
            .bind(event.ctx_id.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
            let Some(row) = row else {
                return Err(AcdpError::NotFound(format!(
                    "context '{}' not found in this registry",
                    event.ctx_id
                )));
            };
            let tenant_id: String = row.try_get("tenant_id").map_err(map_sqlx_err)?;
            let ctx = row_to_context(&row)?;

            // 2. Load the append-ordered event history under the row lock.
            let ev_rows = sqlx::query(
                "SELECT event_id, ctx_id, event_type, occurred_at, actor, reason, signature \
                 FROM lifecycle_events WHERE ctx_id = $1 ORDER BY seq ASC",
            )
            .bind(event.ctx_id.as_str())
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
            let mut events = Vec::with_capacity(ev_rows.len() + 1);
            for r in &ev_rows {
                events.push(event_from_row(r)?);
            }

            // 3. §6 retry idempotency / duplicate event_id (step 2).
            if let Some(prior) = events.iter().find(|e| e.event_id == event.event_id) {
                if *prior == event {
                    tx.rollback().await.ok();
                    let ctx = attach_events(ctx, events);
                    return Ok(LifecycleCommitOutcome::IdempotentReplay(project_context(
                        ctx, now,
                    )));
                }
                return Err(AcdpError::SchemaViolation(format!(
                    "event_id '{}' was already appended with different content \
                     (RFC-ACDP-0013 §4: event_id MUST be unique within lifecycle_events)",
                    event.event_id
                )));
            }

            // 4. §6 step 4 — strict retracted/republished alternation
            //    against the §7.1 retraction state.
            let currently_retracted = retraction_state(&events);
            match &event.event_type {
                LifecycleEventType::Retracted if currently_retracted => {
                    return Err(AcdpError::InvalidLifecycleTransition(format!(
                        "context '{}' is already retracted — double retract violates the \
                         strict alternation rule (RFC-ACDP-0013 §6 step 4)",
                        event.ctx_id
                    )));
                }
                LifecycleEventType::Republished if !currently_retracted => {
                    return Err(AcdpError::InvalidLifecycleTransition(format!(
                        "context '{}' is not retracted — republish requires a prior \
                         retraction (RFC-ACDP-0013 §6 step 4)",
                        event.ctx_id
                    )));
                }
                LifecycleEventType::Other(other) => {
                    return Err(AcdpError::SchemaViolation(format!(
                        "event_type '{other}' is not registered for acceptance in 0.3.0 — \
                         only 'retracted' and 'republished' transition state \
                         (RFC-ACDP-0013 §7.3)"
                    )));
                }
                LifecycleEventType::Retracted | LifecycleEventType::Republished => {}
            }

            // 5. §6 step 5 — append the event AND apply its status effect
            //    (the denormalized `retracted` flag the read paths project
            //    from) in ONE transaction. Stored `status` keeps tracking
            //    supersession only.
            let signature_json = event
                .signature
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| AcdpError::RegistryInternal(format!("encode signature: {e}")))?;
            sqlx::query(
                "INSERT INTO lifecycle_events \
                 (ctx_id, event_id, event_type, occurred_at, actor, reason, signature, tenant_id) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(event.ctx_id.as_str())
            .bind(event.event_id.as_str())
            .bind(event.event_type.as_str())
            .bind(canonical_ms(event.occurred_at))
            .bind(event.actor.as_str())
            .bind(event.reason.clone())
            .bind(signature_json)
            .bind(&tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
            let retracted_now = matches!(event.event_type, LifecycleEventType::Retracted);
            sqlx::query("UPDATE contexts SET retracted = $1 WHERE ctx_id = $2")
                .bind(retracted_now)
                .bind(event.ctx_id.as_str())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
            tx.commit()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx commit: {e}")))?;

            // Post-transition projection: recompute the served status from
            // the NEW retraction state (row_to_context above applied the
            // pre-transition flag).
            events.push(event.clone());
            let mut ctx = attach_events(ctx, events);
            ctx.registry_state.status = if retracted_now {
                Status::Retracted
            } else {
                // Republished: re-derive from the stored (supersession-only)
                // status + expiry, as though never retracted (§7.2).
                let stored: String = row.try_get("status").map_err(map_sqlx_err)?;
                project_status_inline(&parse_status(&stored), ctx.body.expires_at, now)
            };
            Ok(LifecycleCommitOutcome::Applied(ctx))
        })
    }

    fn mark_superseded(&self, ctx_id: &CtxId) -> Result<(), AcdpError> {
        self.block_on(async {
            sqlx::query("UPDATE contexts SET status = 'superseded' WHERE ctx_id = $1")
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
                "SELECT ctx_id FROM contexts WHERE lineage_id = $1 \
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
        // don't burn a DELETE on every read.
        self.block_on(async {
            let row = sqlx::query(
                "SELECT content_hash, response_json, expires_at \
                 FROM idempotency_records WHERE agent_id = $1 AND key = $2",
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
            let response_json: serde_json::Value =
                row.try_get("response_json").map_err(map_sqlx_err)?;
            let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(map_sqlx_err)?;
            let response: PublishResponse = serde_json::from_value(response_json)
                .map_err(|e| AcdpError::RegistryInternal(format!("decode response: {e}")))?;
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
        let response_json = serde_json::to_value(response)
            .map_err(|e| AcdpError::RegistryInternal(format!("encode response: {e}")))?;
        self.block_on(async {
            sqlx::query(
                "INSERT INTO idempotency_records (agent_id, key, content_hash, response_json, expires_at) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (agent_id, key) DO UPDATE SET \
                   content_hash = EXCLUDED.content_hash, \
                   response_json = EXCLUDED.response_json, \
                   expires_at = EXCLUDED.expires_at",
            )
            .bind(agent_id.as_str())
            .bind(key)
            .bind(hash.0.as_str())
            .bind(response_json)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_sqlx_err)
        })
    }

    fn idempotency_evict_expired(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        self.block_on(self.evict_idempotency_inner(now))
    }

    fn commit_publish(&self, commit: PublishCommit<'_>) -> Result<PublishCommitOutcome, AcdpError> {
        let PublishCommit {
            req,
            authority,
            idempotency,
            tenant,
            receipt_minter,
        } = commit;
        let req = req.clone();
        let authority = authority.to_string();
        let tenant = tenant.map(|t| t.to_string());
        let idem = idempotency.map(|i| (i.key.to_string(), i.ttl));
        let now = Utc::now();

        self.block_on(async move {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| AcdpError::RegistryInternal(format!("tx begin: {e}")))?;

            // 1. Idempotency replay.
            if let Some((key, _ttl)) = &idem {
                // Evict an expired record for this key first so the claim in
                // step 7 (ON CONFLICT DO NOTHING) does not collide with a stale
                // row after its TTL has lapsed.
                sqlx::query(
                    "DELETE FROM idempotency_records \
                     WHERE agent_id = $1 AND key = $2 AND expires_at <= $3",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                let row = sqlx::query(
                    "SELECT content_hash, response_json, expires_at \
                     FROM idempotency_records WHERE agent_id = $1 AND key = $2 FOR UPDATE",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                if let Some(row) = row {
                    let prior_hash: String = row.try_get("content_hash").map_err(map_sqlx_err)?;
                    let response_json: serde_json::Value =
                        row.try_get("response_json").map_err(map_sqlx_err)?;
                    let expires_at: DateTime<Utc> =
                        row.try_get("expires_at").map_err(map_sqlx_err)?;
                    if expires_at > now {
                        if prior_hash == req.content_hash.0 {
                            let response: PublishResponse = serde_json::from_value(response_json)
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

            // 2. Supersession coherence.
            let first_v1 = if let Some(prev) = &req.supersedes {
                let row = sqlx::query(
                    "SELECT lineage_id, version, status, agent_id, contributors, tenant_id \
                     FROM contexts WHERE ctx_id = $1 FOR UPDATE",
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
                let prev_version: i32 = row.try_get("version").map_err(map_sqlx_err)?;
                let prev_status: String = row.try_get("status").map_err(map_sqlx_err)?;
                let prev_agent: String = row.try_get("agent_id").map_err(map_sqlx_err)?;
                let prev_contributors: Vec<String> =
                    row.try_get("contributors").map_err(map_sqlx_err)?;
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
                if req.version as i32 != prev_version + 1 {
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
                let first_row = sqlx::query(
                    "SELECT ctx_id FROM contexts WHERE lineage_id = $1 \
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

            // 3. Assign identifiers.
            let validated = ValidatedPublish {
                recomputed_hash: req.content_hash.clone(),
            };
            let (ctx_id, lineage_id) = acdp::registry::assign_identifiers(
                &authority,
                &req.supersedes,
                first_v1.as_ref(),
                &validated,
            )?;

            // 4. Build Body via the SDK's single materialization point
            // (`from_publish_request` ms-truncates `created_at` and starts
            // with empty extensions, exactly as the hand-rolled copy did).
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

            // 5. Insert.
            insert_body(
                &mut tx,
                &body,
                Status::Active,
                tenant.as_deref(),
                receipt.as_ref(),
            )
            .await?;

            // 5.5. Append the transparency-log leaf (RFC-ACDP-0012 §7.1)
            // in the SAME transaction as the context row and its receipt:
            // the three commit together, or none does. Unlike SQLite's
            // BEGIN IMMEDIATE, concurrent PG publishes would race the
            // dense leaf_index assignment (§5.3), so appends serialize on
            // a transaction-scoped advisory lock first.
            if self.log_enabled {
                let Some(receipt) = receipt.as_ref() else {
                    return Err(AcdpError::RegistryInternal(
                        "transparency log is enabled but no receipt was minted for this \
                         publish — the log profile's prerequisite is the receipts profile \
                         (RFC-ACDP-0012 §11) and there is no degraded mode (§7.1); \
                         aborting the publish"
                            .into(),
                    ));
                };
                let (leaf_json, leaf_hash) =
                    acdp_registry_store::build_leaf_record(&body, receipt)?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(LOG_APPEND_LOCK_KEY)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_err)?;
                sqlx::query(
                    "INSERT INTO log_leaves (leaf_index, ctx_id, leaf_json, leaf_hash) \
                     VALUES ((SELECT COUNT(*) FROM log_leaves), $1, $2, $3)",
                )
                .bind(body.ctx_id.as_str())
                .bind(&leaf_json)
                .bind(&leaf_hash)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
            }

            // 6. Mark predecessor superseded.
            if let Some(prev) = &req.supersedes {
                sqlx::query("UPDATE contexts SET status = 'superseded' WHERE ctx_id = $1")
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
                let response_json = serde_json::to_value(&response)
                    .map_err(|e| AcdpError::RegistryInternal(format!("encode response: {e}")))?;
                let inserted = sqlx::query(
                    "INSERT INTO idempotency_records (agent_id, key, content_hash, response_json, expires_at) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (agent_id, key) DO NOTHING",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .bind(req.content_hash.0.as_str())
                .bind(response_json)
                .bind(expires_at)
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
                         FROM idempotency_records WHERE agent_id = $1 AND key = $2",
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
                    let response_json: serde_json::Value =
                        row.try_get("response_json").map_err(map_sqlx_err)?;
                    let winner: PublishResponse = serde_json::from_value(response_json)
                        .map_err(|e| AcdpError::RegistryInternal(format!("decode response: {e}")))?;
                    return Ok(PublishCommitOutcome::IdempotentReplay(winner));
                }
            }

            tx.commit().await.map_err(map_sqlx_err)?;
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
            let created_after = parse_opt_rfc3339(&params.created_after)?;
            let created_before = parse_opt_rfc3339(&params.created_before)?;
            let expires_after = parse_opt_rfc3339(&params.expires_after)?;
            let expires_before = parse_opt_rfc3339(&params.expires_before)?;
            let dp_start_after = parse_opt_rfc3339(&params.data_period_start_after)?;
            let dp_end_before = parse_opt_rfc3339(&params.data_period_end_before)?;

            // Parameterized query: every value is bound with $N placeholders.
            let mut sql =
                String::from("SELECT body_json, status, retracted FROM contexts WHERE 1=1");
            let mut idx = 1usize;
            let mut next = || {
                let i = idx;
                idx += 1;
                i
            };

            // Track tag list for native array containment.
            let mut tag_list: Option<Vec<String>> = None;
            if let Some(t) = &params.tags {
                let want: Vec<String> = t
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !want.is_empty() {
                    tag_list = Some(want);
                }
            }

            // Holder for binds in declaration order.
            #[derive(Debug)]
            enum Bind {
                Str(String),
                Ts(DateTime<Utc>),
                TextArray(Vec<String>),
            }
            let mut binds: Vec<Bind> = Vec::new();

            if let Some(q) = &params.q {
                sql.push_str(&format!(
                    " AND search_vector @@ plainto_tsquery('english', ${})",
                    next()
                ));
                binds.push(Bind::Str(q.clone()));
            }
            if let Some(d) = &params.domain {
                sql.push_str(&format!(" AND domain = ${}", next()));
                binds.push(Bind::Str(d.clone()));
            }
            if let Some(a) = &params.agent_id {
                sql.push_str(&format!(" AND agent_id = ${}", next()));
                binds.push(Bind::Str(a.clone()));
            }
            if let Some(t) = &params.context_type {
                sql.push_str(&format!(" AND context_type = ${}", next()));
                binds.push(Bind::Str(t.clone()));
            }
            if let Some(s) = &params.schema_uri {
                sql.push_str(&format!(" AND (body_json ->> 'schema_uri') = ${}", next()));
                binds.push(Bind::Str(s.clone()));
            }
            if let Some(tags) = tag_list {
                sql.push_str(&format!(" AND tags @> ${}", next()));
                binds.push(Bind::TextArray(tags));
            }
            if let Some(after) = created_after {
                sql.push_str(&format!(" AND created_at >= ${}", next()));
                binds.push(Bind::Ts(after));
            }
            if let Some(before) = created_before {
                sql.push_str(&format!(" AND created_at <= ${}", next()));
                binds.push(Bind::Ts(before));
            }
            if let Some(after) = expires_after {
                sql.push_str(&format!(
                    " AND expires_at IS NOT NULL AND expires_at >= ${}",
                    next()
                ));
                binds.push(Bind::Ts(after));
            }
            if let Some(before) = expires_before {
                sql.push_str(&format!(
                    " AND expires_at IS NOT NULL AND expires_at <= ${}",
                    next()
                ));
                binds.push(Bind::Ts(before));
            }
            if let Some(after) = dp_start_after {
                sql.push_str(&format!(
                    " AND ((body_json #>> '{{data_period,start}}')::timestamptz) >= ${}",
                    next()
                ));
                binds.push(Bind::Ts(after));
            }
            if let Some(before) = dp_end_before {
                sql.push_str(&format!(
                    " AND ((body_json #>> '{{data_period,end}}')::timestamptz) <= ${}",
                    next()
                ));
                binds.push(Bind::Ts(before));
            }

            // BUG-02: bind the cursor predicate AND the per-page LIMIT so
            // search doesn't fetch the entire matching set into memory
            // before discarding everything past the page. On a registry
            // with thousands of matching rows this would allocate and
            // drop them on every paginated call.
            let cursor_anchor = params
                .cursor
                .as_deref()
                .map(decode_cursor)
                .transpose()?
                .flatten();
            if let Some((anchor_ts, anchor_id)) = cursor_anchor.as_ref() {
                let a = next();
                let b = next();
                sql.push_str(&format!(
                    " AND (created_at < ${a} OR (created_at = ${a} AND ctx_id > ${b}))",
                ));
                binds.push(Bind::Ts(*anchor_ts));
                binds.push(Bind::Str(anchor_id.clone()));
            }
            let limit = params.limit.unwrap_or(50).min(100) as usize;
            sql.push_str(&format!(
                " ORDER BY created_at DESC, ctx_id ASC LIMIT ${}",
                next()
            ));

            let mut query = sqlx::query(&sql);
            for b in &binds {
                query = match b {
                    Bind::Str(s) => query.bind(s),
                    Bind::Ts(t) => query.bind(*t),
                    Bind::TextArray(v) => query.bind(v),
                };
            }
            query = query.bind((limit as i64) + 1);
            let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

            let now = Utc::now();
            let want_status = params.status.as_deref().unwrap_or("active");
            // REG-P2-8: the `limit + 1` sentinel and the "anchor the next
            // cursor on the last RAW scanned row, not the last visible
            // match" rule (a fully-filtered page must not terminate
            // pagination early) are owned by `acdp::pagination`.
            let page = try_paginate_rows(
                rows,
                limit,
                |r| -> Result<FullContext, AcdpError> {
                    let body_json: serde_json::Value =
                        r.try_get("body_json").map_err(map_sqlx_err)?;
                    let status: String = r.try_get("status").map_err(map_sqlx_err)?;
                    // RFC-ACDP-0013 §8.2: project the retraction flag so a
                    // retracted context falls out of the default (active)
                    // filter — and out of status=superseded / status=expired
                    // even where those facts also hold (§7.2 precedence).
                    let retracted: bool = r.try_get("retracted").map_err(map_sqlx_err)?;
                    let body: Body = serde_json::from_value(body_json)
                        .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
                    // Receipts aren't projected into SearchResult rows, so the
                    // search SELECT deliberately skips the column.
                    let stored = if retracted {
                        Status::Retracted
                    } else {
                        parse_status(&status)
                    };
                    let mut ctx = full_context(body, stored, None);
                    ctx.registry_state.status =
                        project_status_inline(&ctx.registry_state.status, ctx.body.expires_at, now);
                    Ok(ctx)
                },
                |ctx| {
                    can_surface_in_search(ctx, requester, anonymous_public_reads)
                        && ctx.registry_state.status.as_str() == want_status
                        && params
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

            // DESIGN-05: dropped the page-local count masquerading as a
            // registry-wide total. See SqliteStore::search for context.
            Ok(SearchResponse {
                matches: projected,
                total_estimate: None,
                next_cursor,
            })
        })
    }
}

impl PgStore {
    async fn evict_idempotency_inner(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        sqlx::query("DELETE FROM idempotency_records WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_sqlx_err)
    }

    /// Public wrapper for the background eviction task spawned by the
    /// server binary.
    pub async fn evict_idempotency(&self, now: DateTime<Utc>) -> Result<(), AcdpError> {
        self.evict_idempotency_inner(now).await
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn insert_body<'c>(
    tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
    body: &Body,
    status: Status,
    tenant: Option<&str>,
    receipt: Option<&serde_json::Value>,
) -> Result<(), AcdpError> {
    let body_json = serde_json::to_value(body)
        .map_err(|e| AcdpError::RegistryInternal(format!("encode body: {e}")))?;
    let contributors: Vec<String> = body
        .contributors
        .iter()
        .map(|d| d.as_str().to_string())
        .collect();
    let tags: Vec<String> = body
        .tags
        .as_deref()
        .map(<[String]>::to_vec)
        .unwrap_or_default();
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
    sqlx::query(
        "INSERT INTO contexts (\
            ctx_id, lineage_id, agent_id, contributors, origin_registry, \
            created_at, status, visibility, context_type, version, supersedes, \
            title, description, summary, domain, tags, expires_at, content_hash, body_json, \
            tenant_id, registry_receipt\
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
    )
    .bind(body.ctx_id.as_str())
    .bind(body.lineage_id.as_str())
    .bind(body.agent_id.as_str())
    .bind(&contributors)
    .bind(&body.origin_registry)
    .bind(body.created_at)
    .bind(status.as_str())
    .bind(visibility)
    .bind(context_type)
    .bind(body.version as i32)
    .bind(body.supersedes.as_ref().map(|c| c.as_str().to_string()))
    .bind(&body.title)
    .bind(body.description.clone())
    .bind(body.summary.clone())
    .bind(body.domain.clone())
    .bind(&tags)
    .bind(body.expires_at)
    .bind(body.content_hash.0.as_str())
    .bind(body_json)
    .bind(tenant_id)
    .bind(receipt)
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    sqlx::query(
        "INSERT INTO lineages (lineage_id, first_version_ctx, latest_ctx) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (lineage_id) DO UPDATE SET latest_ctx = EXCLUDED.latest_ctx",
    )
    .bind(body.lineage_id.as_str())
    .bind(body.ctx_id.as_str())
    .bind(body.ctx_id.as_str())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    Ok(())
}

/// STATUS PROJECTION (RFC-ACDP-0013 §7.2): the stored `status` column
/// tracks supersession ONLY; the denormalized `retracted` flag (kept in
/// lockstep with `lifecycle_events` by `commit_lifecycle_event`) dominates
/// it here, so the materialized context always carries the
/// `retracted > superseded > expired > active` precedence. Expiry is
/// projected afterwards by [`project_context`].
fn row_to_context(r: &PgRow) -> Result<FullContext, AcdpError> {
    let body_json: serde_json::Value = r.try_get("body_json").map_err(map_sqlx_err)?;
    let status: String = r.try_get("status").map_err(map_sqlx_err)?;
    let retracted: bool = r.try_get("retracted").map_err(map_sqlx_err)?;
    let receipt: Option<serde_json::Value> = r.try_get("registry_receipt").map_err(map_sqlx_err)?;
    let body: Body = serde_json::from_value(body_json)
        .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
    let status = if retracted {
        Status::Retracted
    } else {
        parse_status(&status)
    };
    Ok(full_context(body, status, receipt))
}

/// Canonical millisecond-precision RFC 3339 UTC text (RFC-ACDP-0001 §5.3)
/// — the exact byte form the strict event serde emits; `occurred_at` is a
/// signed member and must be stored/re-served byte-identically.
fn canonical_ms(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Decode one `lifecycle_events` row back into a validated
/// [`LifecycleEvent`] through the closed RFC-ACDP-0013 §4 schema. Every
/// column was written from a strictly parsed event, so this round-trips
/// byte-identically (including the signed `occurred_at` form).
fn event_from_row(r: &PgRow) -> Result<LifecycleEvent, AcdpError> {
    let event_id: String = r.try_get("event_id").map_err(map_sqlx_err)?;
    let ctx_id: String = r.try_get("ctx_id").map_err(map_sqlx_err)?;
    let event_type: String = r.try_get("event_type").map_err(map_sqlx_err)?;
    let occurred_at: String = r.try_get("occurred_at").map_err(map_sqlx_err)?;
    let actor: String = r.try_get("actor").map_err(map_sqlx_err)?;
    let reason: Option<String> = r.try_get("reason").map_err(map_sqlx_err)?;
    let signature: Option<serde_json::Value> = r.try_get("signature").map_err(map_sqlx_err)?;
    let mut value = serde_json::json!({
        "event_id": event_id,
        "ctx_id": ctx_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": actor,
    });
    if let Some(reason) = reason {
        value["reason"] = serde_json::Value::String(reason);
    }
    if let Some(sig) = signature {
        value["signature"] = sig;
    }
    LifecycleEvent::from_value(&value)
}

/// One context's lifecycle events in registry acceptance order (`seq`).
async fn events_for_ctx(pool: &PgPool, ctx_id: &str) -> Result<Vec<LifecycleEvent>, AcdpError> {
    let rows = sqlx::query(
        "SELECT event_id, ctx_id, event_type, occurred_at, actor, reason, signature \
         FROM lifecycle_events WHERE ctx_id = $1 ORDER BY seq ASC",
    )
    .bind(ctx_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx_err)?;
    rows.iter().map(event_from_row).collect()
}

/// All lifecycle events across a lineage, grouped by ctx_id, each group
/// in acceptance order — one round-trip for the whole lineage array.
async fn events_for_lineage(
    pool: &PgPool,
    lineage_id: &str,
) -> Result<std::collections::HashMap<String, Vec<LifecycleEvent>>, AcdpError> {
    let rows = sqlx::query(
        "SELECT e.event_id, e.ctx_id, e.event_type, e.occurred_at, e.actor, e.reason, e.signature \
         FROM lifecycle_events e \
         JOIN contexts c ON c.ctx_id = e.ctx_id \
         WHERE c.lineage_id = $1 ORDER BY e.seq ASC",
    )
    .bind(lineage_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx_err)?;
    let mut grouped: std::collections::HashMap<String, Vec<LifecycleEvent>> =
        std::collections::HashMap::new();
    for r in &rows {
        let event = event_from_row(r)?;
        grouped
            .entry(event.ctx_id.as_str().to_string())
            .or_default()
            .push(event);
    }
    Ok(grouped)
}

/// Attach a (possibly empty) event history to a context, honoring the
/// absent-vs-empty wire rule (RFC-ACDP-0013 §4.1: omit, never `[]`).
fn attach_events(mut ctx: FullContext, events: Vec<LifecycleEvent>) -> FullContext {
    ctx.registry_state.lifecycle_events = if events.is_empty() {
        None
    } else {
        Some(events)
    };
    ctx
}

fn full_context(body: Body, status: Status, receipt: Option<serde_json::Value>) -> FullContext {
    FullContext {
        body,
        registry_state: RegistryState {
            status,
            lifecycle_events: None,
            extensions: Default::default(),
        },
        registry_receipt: receipt,
        lineage_head_receipt: None,
        log_inclusion: None,
        extensions: Default::default(),
    }
}

/// DESIGN-04: typed accessor for the wire-form of `ContextType`. See the
/// SQLite store for the rationale.
fn context_type_str(t: &acdp::types::primitives::ContextType) -> String {
    use acdp::types::primitives::ContextType;
    match t {
        ContextType::DataSnapshot => "data_snapshot".into(),
        ContextType::Analysis => "analysis".into(),
        ContextType::Prediction => "prediction".into(),
        ContextType::Alert => "alert".into(),
        ContextType::KeyRevocation => "key-revocation".into(),
        ContextType::Custom(s) => s.clone(),
    }
}

fn parse_status(s: &str) -> Status {
    match s {
        "active" => Status::Active,
        "superseded" => Status::Superseded,
        "expired" => Status::Expired,
        "retracted" => Status::Retracted,
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
    AcdpError::RegistryInternal(format!("postgres: {e}"))
}
