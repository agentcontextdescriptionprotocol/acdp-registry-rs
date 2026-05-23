//! Capabilities + health.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

pub async fn capabilities<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.server.capabilities()).unwrap_or_else(|_| json!({})))
}

pub async fn health<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> Json<serde_json::Value> {
    let storage_ok = state.server.store().health().await.is_ok();
    Json(json!({
        "status": if storage_ok { "ok" } else { "degraded" },
        "storage": storage_ok,
    }))
}
