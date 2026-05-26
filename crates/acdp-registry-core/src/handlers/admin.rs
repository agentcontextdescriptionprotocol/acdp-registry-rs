//! Admin endpoints — compiled only with the `playground` feature.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::RegistryError;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
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
    let mut page = state
        .server
        .store()
        .list_contexts(
            q.limit.unwrap_or(50),
            q.cursor.as_deref(),
            requester.as_ref(),
        )
        .await?;
    if let Some(tenant) = requested_tenant {
        if !page.items.is_empty() {
            let ids: Vec<&str> = page.items.iter().map(|c| c.body.ctx_id.as_str()).collect();
            let owners = state.server.store().tenants_of_ctxs(&ids).await?;
            page.items.retain(|c| {
                owners
                    .get(c.body.ctx_id.as_str())
                    .map(|t| t == &tenant)
                    .unwrap_or(false)
            });
        }
    }
    Ok(Json(AdminListResponse {
        items: page.items,
        next_cursor: page.next_cursor,
    }))
}
