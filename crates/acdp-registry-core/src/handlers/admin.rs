//! Admin endpoints.
//!
//! `admin_status` ships in every build (auth-gated by `auth.admin_tokens`).
//! `admin_list` (read-only tenant-scoped listing) and `reload_pinned_keys`
//! (the one mutating helper here — hot-swaps the `[playground]` config
//! section) are compiled only with the `playground` feature. Unlike every
//! other `/admin/*` handler, `admin_list` does NOT call
//! `require_admin_bearer` / check `auth.admin_tokens` — see its doc comment
//! below and `docs/HTTP-API.md`'s `## Admin` section.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::event::WebhookEvent;
use acdp_registry_types::{RegistryConfig, RegistryError};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[cfg(feature = "playground")]
use crate::handlers::context::{caller_from_headers, tenant_for_request};
#[cfg(feature = "playground")]
use axum::extract::Query;

#[cfg(feature = "playground")]
#[derive(Debug, serde::Deserialize)]
pub struct AdminListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[cfg(feature = "playground")]
#[derive(Debug, Serialize)]
pub struct AdminListResponse {
    pub items: Vec<acdp::types::body::FullContext>,
    pub next_cursor: Option<String>,
}

/// Paginated tenant-scoped context listing (playground feature).
///
/// NOT admin-bearer gated: resolves the caller/tenant via
/// `caller_from_headers`/`tenant_for_request`, the same helpers the regular
/// read routes use, and never calls `require_admin_bearer` or checks
/// `auth.admin_tokens`. See `docs/HTTP-API.md`'s `## Admin` section.
#[cfg(feature = "playground")]
pub async fn admin_list<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Query(q): Query<AdminListQuery>,
) -> Result<Json<AdminListResponse>, RegistryError> {
    let requester = caller_from_headers(&state, &headers)?;
    let requested_tenant = tenant_for_request(&state, &headers)?;
    // Plan §7: push the tenant filter into SQL so the page-size invariant
    // holds — a caller asking for `?limit=50` now gets up to 50 rows for
    // their tenant, not "≤50 across all tenants, then in-Rust retain
    // trims to ~3". The prior post-query `tenants_of_ctxs` filter is
    // gone — its job is now done by the WHERE clause in the store.
    // REG-11 Phase 2: pass literal `true`, NOT
    // `state.config.auth.anonymous_public_reads`. This restores the
    // dropped §4.5 disclosure term to `list_contexts` at the SQL level
    // without changing this route's observable behavior in this phase —
    // `true` reproduces today's "public rows always listed" outcome
    // byte-for-byte. Wiring the real config value here belongs to a later
    // phase that flips the gate (`require_admin_bearer`) and the exposure
    // together, atomically; doing it now would ship an anonymous-behavior
    // break (403/empty listings for admins) inside a phase whose
    // CHANGELOG entry is not the BREAKING one.
    let page = state
        .server
        .store()
        .list_contexts(
            q.limit.unwrap_or(50),
            q.cursor.as_deref(),
            requester.as_ref(),
            requested_tenant.as_deref(),
            true,
        )
        .await?;
    Ok(Json(AdminListResponse {
        items: page.items,
        next_cursor: page.next_cursor,
    }))
}

#[cfg(feature = "playground")]
#[derive(Debug, Serialize)]
pub struct ReloadPinnedKeysResponse {
    pub ok: bool,
    pub count: usize,
}

/// `POST /admin/pinned-keys/reload` — re-read the on-disk config and
/// atomic-swap `state.playground` with the freshly-loaded copy.
///
/// Authorization: bearer token MUST be present in `auth.admin_tokens`.
/// Mirrors the federated-revocation-feed gate (peers carry their
/// `admin_token` in the same header). Returns 403 on bad/missing
/// auth, 500 if the config can't be re-read.
///
/// The endpoint always re-reads the WHOLE config (cheap; small TOML)
/// but applies only the `playground` section. Touching other sections
/// at runtime (storage backend, port, tls) would invalidate already-
/// open connections; those still require a restart.
///
/// Plan §2.
#[cfg(feature = "playground")]
pub async fn reload_pinned_keys<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
) -> Result<Json<ReloadPinnedKeysResponse>, AdminAuthError> {
    require_admin_bearer(&state.config, &headers)?;

    let fresh = RegistryConfig::load(None).map_err(|e| {
        tracing::warn!("pinned-keys reload: failed to re-read config: {e}");
        AdminAuthError::ConfigReload(e.to_string())
    })?;

    let count = fresh.playground.pinned_keys.len();
    {
        let mut guard = state
            .playground
            .write()
            .expect("playground RwLock poisoned");
        *guard = fresh.playground;
    }
    tracing::info!(count, "pinned-keys reloaded via admin endpoint");
    Ok(Json(ReloadPinnedKeysResponse { ok: true, count }))
}

/// Operational snapshot returned by `GET /admin/status`.
#[derive(Debug, Serialize)]
pub struct AdminStatusResponse {
    pub storage: StorageStatus,
    pub idempotency: IdempotencyStatus,
    pub webhook: WebhookStatus,
    pub revocation: RevocationStatus,
    pub migrations: MigrationStatus,
}

#[derive(Debug, Serialize)]
pub struct StorageStatus {
    pub healthy: bool,
}

#[derive(Debug, Serialize)]
pub struct IdempotencyStatus {
    /// `None` when the backend doesn't track an idempotency table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct WebhookStatus {
    pub enabled: bool,
    /// Events buffered but not yet delivered; nearing `queue_capacity` means
    /// the worker is falling behind and events are at risk of being dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_in_flight: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_capacity: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct RevocationStatus {
    pub configured_feeds: usize,
}

#[derive(Debug, Serialize)]
pub struct MigrationStatus {
    pub backend: String,
    /// Always `true` for a running server — migrations run at startup and the
    /// process aborts on failure, so a live `/admin/status` implies success.
    pub applied: bool,
}

/// `GET /admin/status` — auth-gated operational snapshot (storage health,
/// idempotency table size, webhook queue depth, configured revocation feeds,
/// storage backend). Ships in every build; gated by `auth.admin_tokens` like
/// the other admin endpoints. Not playground-gated — it's production
/// observability.
pub async fn admin_status<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
) -> Result<Json<AdminStatusResponse>, AdminAuthError> {
    require_admin_bearer(&state.config, &headers)?;

    let healthy = state.server.store().health().await.is_ok();
    let records = state
        .server
        .store()
        .count_idempotency_records()
        .await
        .ok()
        .flatten();
    let webhook = match &state.webhook {
        Some(w) => {
            let (in_flight, capacity) = w.queue_status();
            WebhookStatus {
                enabled: true,
                queue_in_flight: Some(in_flight),
                queue_capacity: Some(capacity),
            }
        }
        None => WebhookStatus {
            enabled: false,
            queue_in_flight: None,
            queue_capacity: None,
        },
    };
    Ok(Json(AdminStatusResponse {
        storage: StorageStatus { healthy },
        idempotency: IdempotencyStatus { records },
        webhook,
        revocation: RevocationStatus {
            configured_feeds: state.config.auth.revocation_feeds.len(),
        },
        migrations: MigrationStatus {
            backend: format!("{:?}", state.config.storage.backend),
            applied: true,
        },
    }))
}

/// Result of a full lineage integrity walk, returned by
/// `GET /admin/lineages/{lineage_id}/audit`.
#[derive(Debug, Serialize)]
pub struct LineageAuditResponse {
    pub lineage_id: String,
    /// Number of versions found in storage.
    pub versions: usize,
    /// True when every invariant below held.
    pub ok: bool,
    /// Human-readable invariant violations (empty when `ok`).
    pub issues: Vec<String>,
    /// Contexts in this lineage without a stored registry receipt.
    /// Informational, not a failure: contexts published before receipts
    /// were enabled legitimately stay receipt-less (no-backfill policy).
    pub receiptless_contexts: usize,
}

/// `GET /admin/lineages/{lineage_id}/audit` — the full lineage walk-back
/// as an on-demand integrity audit (ACDP 0.2.0 workstream D3).
///
/// The publish path validates a v(N+1) against the immediate
/// predecessor's *persisted* row (lineage anchoring, RFC-ACDP-0001
/// §5.6.2), trusting the registry's own storage by induction. This
/// endpoint is the other half of that bargain: it re-walks the whole
/// chain so storage corruption the anchored fast path would silently
/// inherit (a gap, a fork, a mismatched derivation) is still detectable —
/// just off the publish path. Auth-gated by `auth.admin_tokens`; ships in
/// every build like `/admin/status`.
pub async fn lineage_audit<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    axum::extract::Path(lineage_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, AdminAuthError> {
    require_admin_bearer(&state.config, &headers)?;

    let server = state.server.clone();
    let id = acdp::types::primitives::LineageId(lineage_id.clone());
    // RegistryStore::lineage is sync; run it on the blocking pool like
    // every other store call.
    let items = tokio::task::spawn_blocking(move || server.store().lineage(&id))
        .await
        .map_err(|e| AdminAuthError::Internal(format!("join: {e}")))?
        .map_err(|e| AdminAuthError::Internal(format!("lineage read: {e}")))?;

    if items.is_empty() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "message": format!("lineage '{lineage_id}' not found in this registry"),
            })),
        )
            .into_response());
    }

    let report = audit_lineage(&lineage_id, &items);
    Ok(Json(report).into_response())
}

/// Pure invariant walk over an already-loaded lineage, ordered by
/// `version ASC` (the store's `lineage` contract).
fn audit_lineage(
    requested: &str,
    items: &[acdp::types::body::FullContext],
) -> LineageAuditResponse {
    use acdp::types::primitives::Status;

    let mut issues = Vec::new();

    // 1. The chain starts at version 1 and is contiguous.
    for (i, ctx) in items.iter().enumerate() {
        let expected = (i + 1) as u32;
        if ctx.body.version != expected {
            issues.push(format!(
                "version gap: position {i} holds version {} (expected {expected})",
                ctx.body.version
            ));
        }
    }

    // 2. lineage_id is the RFC-ACDP-0001 §5.6 derivation from v1's ctx_id,
    //    and every row carries it.
    let first = &items[0];
    let derived = acdp::crypto::derive_lineage_id(&first.body.ctx_id);
    if derived.as_str() != requested {
        issues.push(format!(
            "lineage_id mismatch: derive_lineage_id(v1) = '{}' ≠ stored '{requested}'",
            derived.as_str()
        ));
    }
    for ctx in items {
        if ctx.body.lineage_id.as_str() != requested {
            issues.push(format!(
                "context '{}' carries lineage_id '{}' ≠ '{requested}'",
                ctx.body.ctx_id.as_str(),
                ctx.body.lineage_id.as_str()
            ));
        }
    }

    // 3. Supersession links: v1 supersedes nothing; v(N) supersedes v(N-1).
    if let Some(prev) = &first.body.supersedes {
        issues.push(format!(
            "v1 '{}' declares supersedes '{}' (a lineage root must not)",
            first.body.ctx_id.as_str(),
            prev.as_str()
        ));
    }
    for pair in items.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        match &next.body.supersedes {
            Some(s) if s.as_str() == prev.body.ctx_id.as_str() => {}
            Some(s) => issues.push(format!(
                "broken link: v{} supersedes '{}' ≠ predecessor '{}'",
                next.body.version,
                s.as_str(),
                prev.body.ctx_id.as_str()
            )),
            None => issues.push(format!(
                "broken link: v{} '{}' declares no supersedes",
                next.body.version,
                next.body.ctx_id.as_str()
            )),
        }
        // Producer continuity (RFC-ACDP-0003 §3.1): the successor's agent
        // must be the predecessor's producer or a declared contributor.
        let continuous = next.body.agent_id == prev.body.agent_id
            || prev.body.contributors.contains(&next.body.agent_id);
        if !continuous {
            issues.push(format!(
                "producer discontinuity: v{} published by '{}' which is neither \
                 v{}'s producer nor contributor",
                next.body.version,
                next.body.agent_id.as_str(),
                prev.body.version
            ));
        }
    }

    // 4. Exactly one non-superseded tip (it may be active or expired).
    let tips = items
        .iter()
        .filter(|c| !matches!(c.registry_state.status, Status::Superseded))
        .count();
    if tips != 1 {
        issues.push(format!(
            "expected exactly 1 non-superseded tip, found {tips}"
        ));
    }
    // ...and the tip is the highest version.
    if let Some(last) = items.last() {
        if matches!(last.registry_state.status, Status::Superseded) {
            issues.push(format!(
                "highest version v{} is marked superseded — the chain points past its end",
                last.body.version
            ));
        }
    }

    let receiptless_contexts = items
        .iter()
        .filter(|c| c.registry_receipt.is_none())
        .count();

    LineageAuditResponse {
        lineage_id: requested.to_string(),
        versions: items.len(),
        ok: issues.is_empty(),
        issues,
        receiptless_contexts,
    }
}

/// Request body for the admin lifecycle endpoints. The registry mints
/// and (where a receipt key is configured) signs the event itself — the
/// operator supplies only an optional human-readable `reason`. The shape
/// is closed (`deny_unknown_fields`) so an operator attempting to smuggle
/// body content or a full event object through this surface gets a clear
/// `schema_violation` rather than having stray members silently ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminLifecycleBody {
    /// RFC-ACDP-0013 §4 `reason` (max 1024 chars, enforced downstream by
    /// `LifecycleEvent::validate`). Informational only.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/contexts/{ctx_id}/retract` — registry-attested retraction
/// (RFC-ACDP-0013 §6 "Registry-initiated events").
///
/// The producer-signed path (`POST /contexts/{ctx_id}/retract`) is for the
/// producer withdrawing their own context. THIS path is the policy/legal
/// takedown lever: an operator (authenticated by an `auth.admin_tokens`
/// bearer, the same gate as every other `/admin/*` route) directs the
/// registry to mint a lifecycle event **attributed to the registry's own
/// DID** (`capabilities.registry_did`) — used when the producer is
/// unavailable and a context must be marked "removed by policy" without a
/// silent 404 (RFC-ACDP-0013 §6, docs/data-protection.md §5).
///
/// Signing follows the SDK helper `record_registry_lifecycle_event`
/// contract verbatim: when a `[receipt]` key is configured the event MUST
/// be signed under it (RFC-ACDP-0013 §5, the receipts-profile MUST); when
/// no receipt key is configured the event is recorded **unsigned but
/// attributed** — the registry DID still names the actor, and consumers
/// weight an unsigned registry event only as far as the response transport
/// (§5). This mirrors the helper, which permits an unsigned event exactly
/// when its `receipt_signer` is absent.
pub async fn admin_retract<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
    body: Bytes,
) -> Result<Json<acdp::types::body::FullContext>, AdminLifecycleError> {
    admin_lifecycle_transition(
        state,
        headers,
        ctx_id,
        body,
        acdp::types::lifecycle::LifecycleEventType::Retracted,
    )
    .await
}

/// `POST /admin/contexts/{ctx_id}/republish` — registry-attested
/// reversal of a prior retraction (RFC-ACDP-0013 §6). Same auth, signing,
/// and attribution rules as [`admin_retract`].
pub async fn admin_republish<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
    body: Bytes,
) -> Result<Json<acdp::types::body::FullContext>, AdminLifecycleError> {
    admin_lifecycle_transition(
        state,
        headers,
        ctx_id,
        body,
        acdp::types::lifecycle::LifecycleEventType::Republished,
    )
    .await
}

/// Shared pipeline behind the two admin lifecycle endpoints.
///
/// Ordering:
/// 1. Admin auth (`auth.admin_tokens` bearer) — the operator gate.
/// 2. Profile gate (`[lifecycle] enabled`) → `not_implemented` (501).
/// 3. Parse the closed `{reason?}` body.
/// 4. Mint a lifecycle event with `actor = did:web:<authority>` (the
///    registry DID) and a fresh RFC 9562 `event_id`.
/// 5. Sign it under the `[receipt]` key when one is configured; leave it
///    unsigned-but-attributed otherwise (the SDK helper's contract).
/// 6. `record_registry_lifecycle_event` — the same atomic
///    `commit_lifecycle_event`, status projection, transition/idempotency
///    checks, and wire-error mapping as the producer path. The transition
///    logic is actor-agnostic (RFC-ACDP-0013 §7.1 derives retraction state
///    from event-type order alone), so a producer may later `/republish` a
///    registry retraction and vice versa.
/// 7. Emit the `context.retracted`/`context.republished` webhook with
///    `actor` = the registry DID.
async fn admin_lifecycle_transition<S: ExtendedRegistryStore + 'static>(
    state: Arc<AppState<S>>,
    headers: HeaderMap,
    ctx_id: String,
    body: Bytes,
    event_type: acdp::types::lifecycle::LifecycleEventType,
) -> Result<Json<acdp::types::body::FullContext>, AdminLifecycleError> {
    use acdp::error::AcdpError;
    use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
    use acdp::types::primitives::{AgentDid, CtxId};

    // 1. Admin gate — identical convention to /admin/status etc.
    require_admin_bearer(&state.config, &headers)?;

    // 2. Profile gate. A registry not advertising acdp-registry-lifecycle
    //    answers 501 (RFC-ACDP-0013 §6), before we mint or sign anything.
    //    `record_registry_lifecycle_event` re-checks this, but doing it
    //    here keeps the message clear and avoids needless key loading.
    if !state.config.lifecycle.enabled {
        return Err(RegistryError::Acdp(AcdpError::NotImplemented(
            "this registry does not advertise acdp-registry-lifecycle \
             (RFC-ACDP-0013 §6: lifecycle endpoints are not implemented)"
                .into(),
        ))
        .into());
    }

    // 3. Closed `{reason?}` body. An empty body is allowed (reason is
    //    optional); a non-empty body must parse against the closed shape.
    let parsed: AdminLifecycleBody = if body.is_empty() {
        AdminLifecycleBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| RegistryError::Acdp(AcdpError::SchemaViolation(e.to_string())))?
    };

    let path_ctx = CtxId::parse(ctx_id).map_err(RegistryError::Acdp)?;

    // 4. Mint the registry-attributed event. `actor` MUST equal the
    //    registry DID (`record_registry_lifecycle_event` rejects otherwise
    //    with not_authorized); we derive it the same way as the receipt
    //    signer's `registry_did`, so the two always agree.
    let registry_did = acdp::did::authority_to_did_web(&state.config.registry.authority);
    let event = LifecycleEvent::new(
        uuid::Uuid::new_v4().to_string(),
        path_ctx.clone(),
        event_type.clone(),
        Utc::now(),
        AgentDid::new(registry_did.clone()),
        parsed.reason,
    )
    .map_err(RegistryError::Acdp)?;

    // 5. Sign under the receipt key when configured (MUST — §5); otherwise
    //    record unsigned-but-attributed (the helper permits this exactly
    //    when no receipt signer is present).
    let event = if state.config.receipt.is_configured() {
        let key = crate::receipt::load_signing_key(&state.config.receipt)
            .map_err(|e| RegistryError::Acdp(AcdpError::RegistryInternal(e)))?;
        let fragment = state.config.receipt.key_id_fragment.trim();
        let key_id = format!("{registry_did}#{fragment}");
        event.sign_with(key, key_id).map_err(RegistryError::Acdp)?
    } else {
        event
    };

    // 6. Atomic commit through the SDK's registry-actor helper. Sync store
    //    call → blocking pool, like every other store touch in this crate.
    let server = state.server.clone();
    let event_for_commit = event.clone();
    let ctx = tokio::task::spawn_blocking(move || {
        server.record_registry_lifecycle_event(&event_for_commit)
    })
    .await
    .map_err(|e| RegistryError::Internal(format!("join: {e}")))?
    .map_err(RegistryError::Acdp)?;

    // 7. Webhook — same downstream notification as the producer path, with
    //    `actor` = the registry DID so a control plane attributes the
    //    policy action correctly.
    if let Some(emitter) = &state.webhook {
        let stored_tenant = state
            .server
            .store()
            .tenant_of_ctx(path_ctx.as_str())
            .await
            .ok()
            .flatten()
            .filter(|t| t != "default");
        let registry_authority = state.config.registry.authority.clone();
        let ctx_id_s = ctx.body.ctx_id.as_str().to_string();
        let lineage_id_s = ctx.body.lineage_id.as_str().to_string();
        let actor = event.actor.as_str().to_string();
        let event_id = event.event_id.clone();
        let reason = event.reason.clone();
        let evt = match event_type {
            LifecycleEventType::Retracted => WebhookEvent::ContextRetracted {
                registry_authority,
                ctx_id: ctx_id_s,
                lineage_id: lineage_id_s,
                actor,
                event_id,
                reason,
                at: Utc::now(),
            },
            _ => WebhookEvent::ContextRepublished {
                registry_authority,
                ctx_id: ctx_id_s,
                lineage_id: lineage_id_s,
                actor,
                event_id,
                reason,
                at: Utc::now(),
            },
        };
        emitter.emit_with_tenant(evt, stored_tenant);
    }

    Ok(Json(ctx))
}

/// Reject the request unless `Authorization: Bearer <token>` matches
/// one of `auth.admin_tokens`. When `admin_tokens` is empty the
/// endpoint is effectively disabled — operators must opt in.
fn require_admin_bearer(
    config: &RegistryConfig,
    headers: &HeaderMap,
) -> Result<(), AdminAuthError> {
    let allowed = &config.auth.admin_tokens;
    if allowed.is_empty() {
        return Err(AdminAuthError::Forbidden);
    }
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AdminAuthError::Forbidden)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AdminAuthError::Forbidden)?;
    // #23: compare in constant time and without early return. `==` /
    // `iter().any()` short-circuit on the first differing byte / first match,
    // leaking matching-prefix length and which entry matched via timing. These
    // static admin tokens gate /admin/* (incl. live pinned-key reload), so fold
    // over every allowlist entry and accumulate the result.
    let mut matched = false;
    for t in allowed {
        matched |= ct_eq(t.as_bytes(), token.as_bytes());
    }
    if !matched {
        return Err(AdminAuthError::Forbidden);
    }
    Ok(())
}

/// Constant-time byte-slice equality. Unequal lengths return `false` (the
/// token *length* is not the secret); equal-length inputs are compared with an
/// XOR fold that never short-circuits, so timing does not reveal the
/// matching-prefix length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Admin-endpoint auth error. Kept separate from `RegistryError`
/// because admin failures are policy-level (403) rather than
/// protocol-level — `RegistryError::AuthChallenge` carries a 401
/// shape callers expect to retry against `/auth/challenge`.
#[derive(Debug)]
pub enum AdminAuthError {
    Forbidden,
    ConfigReload(String),
    /// Non-auth failure inside an admin handler (storage read, task
    /// join). Distinct from `ConfigReload` so the response body names
    /// the actual failure instead of claiming a config reload happened.
    Internal(String),
}

impl IntoResponse for AdminAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AdminAuthError::Forbidden => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "admin-only"})),
            )
                .into_response(),
            AdminAuthError::ConfigReload(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("config reload failed: {msg}")})),
            )
                .into_response(),
            AdminAuthError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("internal error: {msg}")})),
            )
                .into_response(),
        }
    }
}

/// Error for the admin lifecycle endpoints, which straddle two failure
/// domains: the admin gate ([`AdminAuthError`] — a policy 403 with the
/// `{"error":"admin-only"}` shape the other `/admin/*` routes use) and
/// the protocol pipeline ([`RegistryError`] — the RFC-ACDP-0013 wire
/// codes: `not_implemented` 501, `invalid_lifecycle_transition` 409,
/// `not_found` 404, `schema_violation` 400, …). Each arm delegates to the
/// existing `IntoResponse`, so an admin failure and a producer-path
/// lifecycle failure surface byte-identically.
#[derive(Debug)]
pub enum AdminLifecycleError {
    Auth(AdminAuthError),
    Protocol(RegistryError),
}

impl From<AdminAuthError> for AdminLifecycleError {
    fn from(e: AdminAuthError) -> Self {
        Self::Auth(e)
    }
}

impl From<RegistryError> for AdminLifecycleError {
    fn from(e: RegistryError) -> Self {
        Self::Protocol(e)
    }
}

impl IntoResponse for AdminLifecycleError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AdminLifecycleError::Auth(e) => e.into_response(),
            AdminLifecycleError::Protocol(e) => e.into_response(),
        }
    }
}

#[cfg(test)]
mod admin_auth_tests {
    use super::*;
    use acdp_registry_types::AuthConfig;
    use axum::http::HeaderValue;

    fn cfg_with_admin_tokens(tokens: &[&str]) -> RegistryConfig {
        let mut cfg = RegistryConfig::defaults();
        cfg.auth = AuthConfig {
            admin_tokens: tokens.iter().map(|s| s.to_string()).collect(),
            ..AuthConfig::default()
        };
        cfg
    }

    fn headers_with(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = auth {
            h.insert("authorization", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn rejects_when_admin_tokens_empty() {
        let cfg = cfg_with_admin_tokens(&[]);
        let res = require_admin_bearer(&cfg, &headers_with(Some("Bearer anything")));
        assert!(matches!(res, Err(AdminAuthError::Forbidden)));
    }

    #[test]
    fn rejects_when_no_auth_header() {
        let cfg = cfg_with_admin_tokens(&["t1"]);
        let res = require_admin_bearer(&cfg, &headers_with(None));
        assert!(matches!(res, Err(AdminAuthError::Forbidden)));
    }

    #[test]
    fn rejects_when_not_bearer_scheme() {
        let cfg = cfg_with_admin_tokens(&["t1"]);
        let res = require_admin_bearer(&cfg, &headers_with(Some("Basic t1")));
        assert!(matches!(res, Err(AdminAuthError::Forbidden)));
    }

    #[test]
    fn rejects_when_token_not_in_allowlist() {
        let cfg = cfg_with_admin_tokens(&["t1", "t2"]);
        let res = require_admin_bearer(&cfg, &headers_with(Some("Bearer t3")));
        assert!(matches!(res, Err(AdminAuthError::Forbidden)));
    }

    #[test]
    fn accepts_when_bearer_matches_allowlist() {
        let cfg = cfg_with_admin_tokens(&["t1", "t2"]);
        let res = require_admin_bearer(&cfg, &headers_with(Some("Bearer t2")));
        assert!(res.is_ok());
    }

    #[test]
    fn bearer_scheme_is_case_sensitive() {
        // RFC 6750 schemes are case-insensitive, but this code matches the
        // exact "Bearer " prefix; lock the current behavior so a refactor that
        // loosens it is a deliberate, reviewed change.
        let cfg = cfg_with_admin_tokens(&["t1"]);
        assert!(matches!(
            require_admin_bearer(&cfg, &headers_with(Some("bearer t1"))),
            Err(AdminAuthError::Forbidden)
        ));
    }

    #[test]
    fn rejects_token_with_extra_whitespace() {
        // "Bearer  t1" (two spaces) yields a token of " t1", which is not in
        // the allowlist — no accidental trimming.
        let cfg = cfg_with_admin_tokens(&["t1"]);
        assert!(matches!(
            require_admin_bearer(&cfg, &headers_with(Some("Bearer  t1"))),
            Err(AdminAuthError::Forbidden)
        ));
    }

    #[test]
    fn empty_presented_token_does_not_match_nonempty_allowlist() {
        let cfg = cfg_with_admin_tokens(&["t1"]);
        assert!(matches!(
            require_admin_bearer(&cfg, &headers_with(Some("Bearer "))),
            Err(AdminAuthError::Forbidden)
        ));
    }

    #[test]
    fn ct_eq_matches_only_identical_byte_slices() {
        assert!(ct_eq(b"secret-token", b"secret-token"));
        assert!(!ct_eq(b"secret-token", b"secret-toleN"));
        // Differing lengths are unequal (and don't panic on the zip).
        assert!(!ct_eq(b"short", b"longer-token"));
        // Two empty slices are trivially equal (length guard passes, fold is 0).
        assert!(ct_eq(b"", b""));
    }
}
