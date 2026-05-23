//! Postgres implementation of `RegistryStore` + `ExtendedRegistryStore`.

use acdp::error::AcdpError;
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
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, AcdpError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect(url)
            .await
            .map_err(|e| AcdpError::RegistryInternal(format!("pg connect: {e}")))?;
        Ok(Self { pool })
    }

    fn block_on<F: std::future::Future<Output = T>, T>(&self, fut: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
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

    async fn list_contexts(
        &self,
        limit: u32,
        cursor: Option<&str>,
        requester: Option<&AgentDid>,
    ) -> Result<Page<FullContext>, AcdpError> {
        let limit = limit.clamp(1, 200) as i64;
        let anchor = cursor.map(decode_cursor).transpose()?.flatten();

        let mut q = String::from("SELECT body_json, status FROM contexts WHERE 1=1");
        if anchor.is_some() {
            // Keyset compare with ctx_id tiebreaker for stable pagination when
            // multiple rows share a created_at.
            q.push_str(" AND (created_at < $1 OR (created_at = $1 AND ctx_id > $2))");
        }
        q.push_str(" ORDER BY created_at DESC, ctx_id ASC LIMIT ");
        // Bind limit inline since sqlx 0.8 doesn't allow more bind positions
        // after the optional ones cleanly; use a literal.
        q.push_str(&(limit + 1).to_string());

        let mut query = sqlx::query(&q);
        if let Some((anchor_ts, anchor_ctx)) = anchor.as_ref() {
            query = query.bind(*anchor_ts).bind(anchor_ctx);
        }
        let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

        let mut items = Vec::new();
        for r in rows.iter().take(limit as usize) {
            let body_json: serde_json::Value = r.try_get("body_json").map_err(map_sqlx_err)?;
            let status: String = r.try_get("status").map_err(map_sqlx_err)?;
            let body: Body = serde_json::from_value(body_json)
                .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
            let ctx = full_context(body, parse_status(&status));
            if visible_to(&ctx, requester) {
                items.push(ctx);
            }
        }
        let next_cursor = if rows.len() > items.len() {
            items.last().map(|c| {
                encode_cursor(c.body.created_at.timestamp_millis(), c.body.ctx_id.as_str())
            })
        } else {
            None
        };
        Ok(Page { items, next_cursor })
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

// ── RegistryStore ────────────────────────────────────────────────────────────

impl RegistryStore for PgStore {
    fn put(&self, body: Body) -> Result<(), AcdpError> {
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
            insert_body(&mut tx, &body, Status::Active).await?;
            tx.commit().await.map_err(map_sqlx_err)?;
            Ok(())
        })
    }

    fn get(&self, ctx_id: &CtxId) -> Result<Option<FullContext>, AcdpError> {
        self.block_on(async {
            let row = sqlx::query("SELECT body_json, status FROM contexts WHERE ctx_id = $1")
                .bind(ctx_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_err)?;
            let Some(row) = row else {
                return Ok(None);
            };
            Ok(Some(project_context(row_to_context(&row)?, Utc::now())))
        })
    }

    fn lineage(&self, lineage_id: &LineageId) -> Result<Vec<FullContext>, AcdpError> {
        self.block_on(async {
            let rows = sqlx::query(
                "SELECT body_json, status FROM contexts WHERE lineage_id = $1 \
                 ORDER BY version ASC, created_at ASC",
            )
            .bind(lineage_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
            let now = Utc::now();
            rows.iter()
                .map(|r| row_to_context(r).map(|c| project_context(c, now)))
                .collect()
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
        } = commit;
        let req = req.clone();
        let authority = authority.to_string();
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
                    "SELECT lineage_id, version, status FROM contexts \
                     WHERE ctx_id = $1 FOR UPDATE",
                )
                .bind(prev.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
                let Some(row) = row else {
                    return Err(AcdpError::SupersededTarget {
                        reason: acdp::error::SupersessionReason::NotFound,
                        message: format!("supersedes target '{prev}' not found"),
                    });
                };
                let prev_lineage: String = row.try_get("lineage_id").map_err(map_sqlx_err)?;
                let prev_version: i32 = row.try_get("version").map_err(map_sqlx_err)?;
                let prev_status: String = row.try_get("status").map_err(map_sqlx_err)?;
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

            // 4. Build Body.
            let created_at = acdp::time::trunc_ms(now);
            let body = Body {
                ctx_id: ctx_id.clone(),
                lineage_id: lineage_id.clone(),
                origin_registry: authority.clone(),
                created_at,
                content_hash: req.content_hash.clone(),
                signature: req.signature.clone(),
                version: req.version,
                supersedes: req.supersedes.clone(),
                agent_id: req.agent_id.clone(),
                contributors: req.contributors.clone(),
                title: req.title.clone(),
                context_type: req.context_type.clone(),
                data_refs: req.data_refs.clone(),
                derived_from: req.derived_from.clone(),
                visibility: req.visibility.clone(),
                audience: req.audience.clone(),
                acdp_version: req.acdp_version.clone(),
                description: req.description.clone(),
                summary: req.summary.clone(),
                tags: req.tags.clone(),
                domain: req.domain.clone(),
                expires_at: req.expires_at,
                data_period: req.data_period.clone(),
                metadata: req.metadata.clone(),
                schema_uri: req.schema_uri.clone(),
                extensions: Default::default(),
            };

            // 5. Insert.
            insert_body(&mut tx, &body, Status::Active).await?;

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
            };

            // 7. Record idempotency.
            if let Some((key, ttl)) = idem {
                let expires_at = now + ttl;
                let response_json = serde_json::to_value(&response)
                    .map_err(|e| AcdpError::RegistryInternal(format!("encode response: {e}")))?;
                sqlx::query(
                    "INSERT INTO idempotency_records (agent_id, key, content_hash, response_json, expires_at) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (agent_id, key) DO UPDATE SET \
                       content_hash = EXCLUDED.content_hash, \
                       response_json = EXCLUDED.response_json, \
                       expires_at = EXCLUDED.expires_at",
                )
                .bind(req.agent_id.as_str())
                .bind(key.as_str())
                .bind(req.content_hash.0.as_str())
                .bind(response_json)
                .bind(expires_at)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_err)?;
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
            let mut sql = String::from("SELECT body_json, status FROM contexts WHERE 1=1");
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

            sql.push_str(" ORDER BY created_at DESC, ctx_id ASC");

            let mut query = sqlx::query(&sql);
            for b in &binds {
                query = match b {
                    Bind::Str(s) => query.bind(s),
                    Bind::Ts(t) => query.bind(*t),
                    Bind::TextArray(v) => query.bind(v),
                };
            }
            let rows = query.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;

            let now = Utc::now();
            let want_status = params.status.as_deref().unwrap_or("active");
            let mut matches: Vec<FullContext> = Vec::new();
            for r in rows {
                let body_json: serde_json::Value = r.try_get("body_json").map_err(map_sqlx_err)?;
                let status: String = r.try_get("status").map_err(map_sqlx_err)?;
                let body: Body = serde_json::from_value(body_json)
                    .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
                let mut ctx = full_context(body, parse_status(&status));
                ctx.registry_state.status =
                    project_status_inline(&ctx.registry_state.status, ctx.body.expires_at, now);
                if !can_surface_in_search(&ctx, requester, anonymous_public_reads) {
                    continue;
                }
                if ctx.registry_state.status.as_str() != want_status {
                    continue;
                }
                if let Some(df) = &params.derived_from {
                    if !ctx.body.derived_from.iter().any(|c| c.as_str() == df) {
                        continue;
                    }
                }
                matches.push(ctx);
            }

            let total_estimate = Some(matches.len() as u64);
            let cursor_anchor = params
                .cursor
                .as_deref()
                .map(decode_cursor)
                .transpose()?
                .flatten();
            if let Some((anchor_ts, anchor_id)) = &cursor_anchor {
                let anchor_ms = anchor_ts.timestamp_millis();
                matches.retain(|c| {
                    let ms = c.body.created_at.timestamp_millis();
                    ms < anchor_ms
                        || (ms == anchor_ms && c.body.ctx_id.as_str() > anchor_id.as_str())
                });
            }

            let limit = params.limit.unwrap_or(50).min(100) as usize;
            let next_cursor = if matches.len() > limit {
                matches.get(limit - 1).map(|c| {
                    encode_cursor(c.body.created_at.timestamp_millis(), c.body.ctx_id.as_str())
                })
            } else {
                None
            };

            let projected: Vec<SearchResult> = matches
                .iter()
                .take(limit)
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

            Ok(SearchResponse {
                matches: projected,
                total_estimate,
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
    let context_type = serde_json::to_value(&body.context_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    sqlx::query(
        "INSERT INTO contexts (\
            ctx_id, lineage_id, agent_id, contributors, origin_registry, \
            created_at, status, visibility, context_type, version, supersedes, \
            title, description, summary, domain, tags, expires_at, content_hash, body_json\
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
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

fn row_to_context(r: &PgRow) -> Result<FullContext, AcdpError> {
    let body_json: serde_json::Value = r.try_get("body_json").map_err(map_sqlx_err)?;
    let status: String = r.try_get("status").map_err(map_sqlx_err)?;
    let body: Body = serde_json::from_value(body_json)
        .map_err(|e| AcdpError::RegistryInternal(format!("decode body: {e}")))?;
    Ok(full_context(body, parse_status(&status)))
}

fn full_context(body: Body, status: Status) -> FullContext {
    FullContext {
        body,
        registry_state: RegistryState {
            status,
            extensions: Default::default(),
        },
        registry_receipt: None,
        extensions: Default::default(),
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
