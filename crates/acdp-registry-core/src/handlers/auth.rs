//! `/auth/challenge`, `/auth/token`, `/auth/token/revoke`.

use std::sync::Arc;

use acdp_registry_auth::extract_bearer;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{AuthChallenge, RegistryError, TokenRequest, TokenResponse};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub agent_id: String,
}

pub async fn issue_challenge<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<AuthChallenge>, RegistryError> {
    // Rate-limit the unauthenticated challenge endpoint per requested
    // `agent_id`. Without this, a caller can flood `/auth/challenge` to
    // amplify nonce-store writes (and grow an in-memory store toward OOM
    // across the challenge TTL window). Keyed by `agent_id` to mirror the
    // publish limiter; per-process, so front a multi-replica deployment with
    // a shared limiter for a global bound.
    if let Some(limiter) = &state.challenge_rate_limiter {
        // #24: enforce BOTH the per-agent budget and the process-global ceiling.
        // The per-agent key is attacker-controlled (unauthenticated endpoint),
        // so the global ceiling is what bounds a flood that rotates `agent_id`
        // to defeat the per-key limit.
        if let Err(retry_after_seconds) = limiter
            .check_global()
            .and_then(|()| limiter.check(req.agent_id.as_str()))
        {
            crate::metrics::record_rate_limit_rejection("challenge_per_agent");
            return Err(RegistryError::RateLimited {
                retry_after_seconds,
            });
        }
    }
    // SEC-05: agent_id format is checked inside `AuthService::issue_challenge`.
    let challenge = state.auth.issue_challenge(&req.agent_id).await?;
    Ok(Json(challenge))
}

pub async fn issue_token<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, RegistryError> {
    let resp = state.auth.issue_token(req).await?;
    Ok(Json(resp))
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub jti: String,
}

/// FEAT-02 — `POST /auth/token/revoke`. Marks a `jti` as revoked. The
/// caller MUST present a valid bearer token; an agent may only revoke
/// tokens issued to themselves (enforced inside `AuthService::revoke_token`
/// via the `owner_of` check on the revocation store).
///
/// Returns 204 on success. 401 when the bearer is missing/invalid or
/// belongs to a different DID than the target token. 503 when the
/// registry was started without a revocation store (which means the
/// signer does not consult one either).
pub async fn revoke_token<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<Response, RegistryError> {
    // 503 when the revocation store isn't wired — match the doc contract
    // above. In current binaries `state.auth.revocations` is always
    // `Some`, so this branch is defensive against future configurations
    // that disable revocation. Falling through would surface as a 500
    // via `AuthError::Internal`, which is the wrong signal: the registry
    // is healthy; the feature simply isn't available.
    if state.auth.revocations.is_none() {
        let body = Json(json!({
            "error": {
                "code": "service_unavailable",
                "message": "token revocation is not configured on this registry"
            }
        }));
        return Ok((StatusCode::SERVICE_UNAVAILABLE, body).into_response());
    }
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer)
        .ok_or_else(|| RegistryError::AuthToken("bearer token required for revocation".into()))?;
    let caller = state.auth.validate_bearer(bearer)?;
    state.auth.revoke_token(&req.jti, caller.as_str()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
