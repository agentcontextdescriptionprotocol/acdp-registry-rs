//! `/auth/challenge`, `/auth/token`, `/auth/token/revoke`.

use std::sync::Arc;

use acdp_registry_auth::extract_bearer;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{AuthChallenge, RegistryError, TokenRequest, TokenResponse};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub agent_id: String,
}

pub async fn issue_challenge<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<AuthChallenge>, RegistryError> {
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
) -> Result<impl IntoResponse, RegistryError> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer)
        .ok_or_else(|| RegistryError::AuthToken("bearer token required for revocation".into()))?;
    let caller = state.auth.validate_bearer(bearer)?;
    state.auth.revoke_token(&req.jti, caller.as_str()).await?;
    Ok(StatusCode::NO_CONTENT)
}
