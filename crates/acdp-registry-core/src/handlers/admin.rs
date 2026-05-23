//! Admin endpoints — compiled only with the `playground` feature.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::RegistryError;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers::context::caller_from_headers;
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
    let page = state
        .server
        .store()
        .list_contexts(
            q.limit.unwrap_or(50),
            q.cursor.as_deref(),
            requester.as_ref(),
        )
        .await?;
    Ok(Json(AdminListResponse {
        items: page.items,
        next_cursor: page.next_cursor,
    }))
}
