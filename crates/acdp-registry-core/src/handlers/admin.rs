//! Admin endpoints — compiled only with the `playground` feature.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{RegistryConfig, RegistryError};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers::context::{caller_from_headers, tenant_for_request};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AdminListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminListResponse {
    pub items: Vec<acdp::types::body::FullContext>,
    pub next_cursor: Option<String>,
}

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
    if !allowed.iter().any(|t| t == token) {
        return Err(AdminAuthError::Forbidden);
    }
    Ok(())
}

/// Admin-endpoint auth error. Kept separate from `RegistryError`
/// because admin failures are policy-level (403) rather than
/// protocol-level — `RegistryError::AuthChallenge` carries a 401
/// shape callers expect to retry against `/auth/challenge`.
#[derive(Debug)]
pub enum AdminAuthError {
    Forbidden,
    ConfigReload(String),
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
}
