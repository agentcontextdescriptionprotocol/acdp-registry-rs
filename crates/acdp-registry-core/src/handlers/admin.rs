//! Admin endpoints.
//!
//! `admin_status` ships in every build (auth-gated by `auth.admin_tokens`).
//! The mutating playground helpers (`admin_list`, `reload_pinned_keys`) are
//! compiled only with the `playground` feature.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::RegistryConfig;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

#[cfg(feature = "playground")]
use crate::handlers::context::{caller_from_headers, tenant_for_request};
#[cfg(feature = "playground")]
use acdp_registry_types::RegistryError;
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
    let page = state
        .server
        .store()
        .list_contexts(
            q.limit.unwrap_or(50),
            q.cursor.as_deref(),
            requester.as_ref(),
            requested_tenant.as_deref(),
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
