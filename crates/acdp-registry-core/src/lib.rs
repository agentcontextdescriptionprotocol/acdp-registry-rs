//! axum router + handlers for `acdp-registry-rs`.
//!
//! Storage is injected via the type parameter `S: ExtendedRegistryStore`.
//! `acdp-registry-core` itself has no compile-time dependency on a
//! specific storage crate — the binary picks one via Cargo features.

pub mod handlers;
pub mod playground;
pub mod state;

pub use state::{AppState, AppStateInner};

use std::sync::Arc;
use std::time::Duration;

use acdp_registry_store::ExtendedRegistryStore;
use axum::http::{HeaderName, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Build the registry HTTP router.
///
/// The returned router carries no global timeout for streaming endpoints —
/// upstream operators terminating TLS can layer in their own caps. The
/// `/auth/*` endpoints are mounted only when `cfg.auth.enabled` so a
/// registry running without auth doesn't advertise a token-mint endpoint
/// it can't enforce.
pub fn build_router<S: ExtendedRegistryStore + 'static>(state: AppState<S>) -> Router {
    let admin = admin_router::<S>();
    let auth_enabled = state.config.auth.enabled;
    let body_limit = state.config.limits.max_payload_bytes;
    let cors = build_cors_layer(&state.config.registry.cors.allowed_origins);

    let mut router = Router::new()
        // Capabilities + health
        .route("/.well-known/acdp.json", get(handlers::capabilities::<S>))
        .route("/.well-known/jwks.json", get(handlers::jwks::<S>))
        .route("/healthz", get(handlers::health::<S>))
        // Contexts
        .route("/contexts", post(handlers::publish::<S>))
        .route("/contexts/search", get(handlers::search::<S>))
        .route("/contexts/:ctx_id", get(handlers::retrieve::<S>))
        .route("/contexts/:ctx_id/body", get(handlers::retrieve_body::<S>))
        // Lineages
        .route("/lineages/:lineage_id", get(handlers::lineage::<S>))
        .route("/lineages/:lineage_id/current", get(handlers::current::<S>));

    if auth_enabled {
        router = router
            .route("/auth/challenge", post(handlers::issue_challenge::<S>))
            .route("/auth/token", post(handlers::issue_token::<S>))
            .route("/auth/token/revoke", post(handlers::revoke_token::<S>));
    }

    router
        .merge(admin)
        .with_state(Arc::new(state))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        // SEC-06: cap every request body uniformly. The publish handler
        // used to perform this check inline; the layer applies it to
        // `/auth/challenge` and `/auth/token` as well so an unauthenticated
        // caller can't push arbitrarily-large JSON at those routes.
        .layer(RequestBodyLimitLayer::new(
            usize::try_from(body_limit).unwrap_or(usize::MAX),
        ))
        .layer(cors)
}

/// SEC-02: build a CORS layer driven by `[registry.cors] allowed_origins`.
///
/// Default (empty list) sends no CORS headers — third-party origins
/// cannot make cross-origin authenticated requests using a visitor's
/// stored bearer token. `CorsLayer::permissive()` (the prior default)
/// unconditionally set `Access-Control-Allow-Origin: *`, which was
/// inappropriate for a registry that serves restricted/private contexts.
fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        return CorsLayer::new();
    }
    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(parsed))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-run-id"),
        ])
}

#[cfg(feature = "playground")]
fn admin_router<S: ExtendedRegistryStore + 'static>() -> Router<Arc<AppState<S>>> {
    Router::new().route("/admin/contexts", get(handlers::admin_list::<S>))
}

#[cfg(not(feature = "playground"))]
fn admin_router<S: ExtendedRegistryStore + 'static>() -> Router<Arc<AppState<S>>> {
    Router::new()
}
