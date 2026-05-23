//! `/auth/challenge` and `/auth/token`.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{AuthChallenge, RegistryError, TokenRequest, TokenResponse};
use axum::extract::State;
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
