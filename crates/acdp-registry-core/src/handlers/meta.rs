//! Capabilities + health.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

pub async fn capabilities<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.server.capabilities()).unwrap_or_else(|_| json!({})))
}

/// BUG-05: returns HTTP 503 when storage health fails so load balancers,
/// Kubernetes readiness probes, and Prometheus blackbox exporters take the
/// pod out of rotation. Returning 200 + `"status":"degraded"` (the prior
/// behaviour) left the registry serving requests it could not satisfy.
pub async fn health<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> impl IntoResponse {
    let storage_ok = state.server.store().health().await.is_ok();
    let body = Json(json!({
        "status": if storage_ok { "ok" } else { "degraded" },
        "storage": storage_ok,
    }));
    let status = if storage_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, body)
}
