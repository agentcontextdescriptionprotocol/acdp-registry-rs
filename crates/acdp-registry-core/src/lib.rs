//! axum router + handlers for `acdp-registry-rs`.
//!
//! Storage is injected via the type parameter `S: ExtendedRegistryStore`.
//! `acdp-registry-core` itself has no compile-time dependency on a
//! specific storage crate — the binary picks one via Cargo features.

pub mod handlers;
pub mod log;
pub mod metrics;
pub mod playground;
pub mod rate_limit;
pub mod receipt;
pub mod state;
pub mod witness;

pub use state::{AppState, AppStateInner};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::RegistryError;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
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
    // FEAT-06/FEAT-10: `from_fn_with_state` middleware (the `/auth/*` limiter)
    // and the `/metrics` route both need the shared state up front, so build
    // the `Arc` here rather than only at `.with_state` time.
    let state = Arc::new(state);
    let admin = admin_router::<S>();
    let auth_enabled = state.config.auth.enabled;
    let metrics_enabled = state.metrics.is_some();
    let body_limit = state.config.limits.max_payload_bytes;
    let cors = build_cors_layer(&state.config.registry.cors.allowed_origins);

    // ACDP data + capabilities + auth endpoints. RFC-ACDP-0007 §4 requires
    // `application/acdp+json` on EVERY response from these endpoints (success
    // bodies and error envelopes alike), so they are grouped under a
    // response-header layer that sets the media type. JWKS, health, and the
    // operational admin routes keep their conventional media types and are
    // mounted separately below.
    let mut acdp = Router::new()
        .route("/.well-known/acdp.json", get(handlers::capabilities::<S>))
        // Contexts
        .route("/contexts", post(handlers::publish::<S>))
        .route("/contexts/search", get(handlers::search::<S>))
        .route("/contexts/:ctx_id", get(handlers::retrieve::<S>))
        .route("/contexts/:ctx_id/body", get(handlers::retrieve_body::<S>))
        // Lifecycle events & retraction (RFC-ACDP-0013 §6). Always
        // mounted: a registry not advertising `acdp-registry-lifecycle`
        // answers 501 not_implemented from the handler, per §6.
        .route("/contexts/:ctx_id/retract", post(handlers::retract::<S>))
        .route(
            "/contexts/:ctx_id/republish",
            post(handlers::republish::<S>),
        )
        // Lineages
        .route("/lineages/:lineage_id", get(handlers::lineage::<S>))
        .route("/lineages/:lineage_id/current", get(handlers::current::<S>))
        // Transparency log (RFC-ACDP-0012 §8). Always mounted: a
        // registry not advertising `acdp-registry-transparency-log`
        // answers 501 not_implemented from the handler (the lifecycle
        // posture); there is never a `log_unavailable` (§7.1).
        .route("/log/checkpoint", get(handlers::log_checkpoint::<S>))
        .route("/log/proof", get(handlers::log_proof::<S>))
        .route("/log/entries", get(handlers::log_entries::<S>));

    if auth_enabled {
        // FEAT-06: the `/auth/*` endpoints are the most attacker-controllable
        // surface (token issuance / refresh / revoke: unauthenticated writes,
        // RNG, DID-document fetches, Ed25519 verifies). Group them in their
        // own subrouter carrying the per-IP + process-global limiter as a
        // `route_layer` — it fires only on these matched routes, not on 404s
        // or any other endpoint. The per-agent `[limits]` budgets still apply
        // inside the handlers on top of this.
        let auth = Router::new()
            .route("/auth/challenge", post(handlers::issue_challenge::<S>))
            .route("/auth/token", post(handlers::issue_token::<S>))
            .route("/auth/token/revoke", post(handlers::revoke_token::<S>))
            .route_layer(from_fn_with_state(state.clone(), auth_rate_limit::<S>));
        acdp = acdp.merge(auth);
    }

    let acdp = acdp.layer(SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/acdp+json"),
    ));

    // Non-ACDP endpoints: JWKS sets `application/jwk-set+json` itself, health
    // and admin/status are operational JSON — none get the acdp+json override.
    let mut aux = Router::new()
        .route("/.well-known/jwks.json", get(handlers::jwks::<S>))
        // The registry's own did:web document (receipt verification keys,
        // RFC-ACDP-0010). Conventional application/json — DID resolvers
        // don't expect the acdp+json media type here.
        .route(
            "/.well-known/did.json",
            get(handlers::registry_did_document::<S>),
        )
        .route("/healthz", get(handlers::health::<S>))
        // Admin status (auth-gated by auth.admin_tokens; ships in every build)
        .route("/admin/status", get(handlers::admin_status::<S>))
        // Full lineage walk as an on-demand integrity audit (D3) — the
        // publish path anchors on the immediate predecessor; this is where
        // the complete chain is still re-checked.
        .route(
            "/admin/lineages/:lineage_id/audit",
            get(handlers::lineage_audit::<S>),
        )
        // Registry-attested lifecycle (RFC-ACDP-0013 §6 registry-initiated
        // events): admin-gated retract/republish attributed to the
        // registry's own DID — the policy/legal takedown lever for when a
        // producer is unavailable. Auth-gated by `auth.admin_tokens` like
        // every other `/admin/*` route; requires `[lifecycle] enabled`
        // (501 otherwise). Ships in every build.
        .route(
            "/admin/contexts/:ctx_id/retract",
            post(handlers::admin_retract::<S>),
        )
        .route(
            "/admin/contexts/:ctx_id/republish",
            post(handlers::admin_republish::<S>),
        );

    // FEAT-10: mount `GET /metrics` only when a recorder is installed
    // ([metrics] enabled). Deliberately in the un-authed, un-rate-limited
    // `aux` group so a Prometheus scraper reaches it unimpeded; the handler
    // applies its own optional `metrics.bearer_token` gate.
    if metrics_enabled {
        aux = aux.route("/metrics", get(metrics::metrics_endpoint::<S>));
    }

    let mut app = acdp
        .merge(aux)
        .merge(admin)
        .with_state(state)
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id());

    // FEAT-10: request-level metrics near the top of the stack, so the
    // observed latency includes the middleware below it. Added only when
    // metrics are enabled — the `counter!`/`histogram!` macros would no-op
    // without a recorder, but skipping the layer avoids the per-request
    // `MatchedPath` clone entirely on the common (metrics-off) path.
    if metrics_enabled {
        app = app.layer(from_fn(metrics::track_metrics));
    }

    app.layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        // SEC-06: cap every request body uniformly. The publish handler
        // used to perform this check inline; the layer applies it to
        // `/auth/challenge` and `/auth/token` as well so an unauthenticated
        // caller can't push arbitrarily-large JSON at those routes.
        .layer(RequestBodyLimitLayer::new(
            usize::try_from(body_limit).unwrap_or(usize::MAX),
        ))
        .layer(cors)
        // RFC-ACDP-0007 §4: failures generated by the outer middleware itself
        // (the 413 from RequestBodyLimitLayer, a 408 from TimeoutLayer) bypass
        // both the per-route acdp+json layer and RegistryError::into_response,
        // so they would otherwise carry no ACDP media type. Set it here, as the
        // outermost layer, only when the response carries no Content-Type — so
        // JWKS (`application/jwk-set+json`), health, and every handler/error
        // response that already set their own media type are left untouched.
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/acdp+json"),
        ))
}

/// FEAT-06: per-IP + process-global rate limiting middleware for `/auth/*`.
///
/// Runs before the auth handlers (which apply their own per-agent budgets).
/// The client IP is resolved from `ConnectInfo<SocketAddr>` (the TCP socket
/// peer) plus the trusted-proxy `X-Forwarded-For` policy — see
/// [`rate_limit::client_ip`] for the security rationale. When no
/// `ConnectInfo` is present (e.g. an in-process `oneshot` test that did not
/// inject one) the peer defaults to `0.0.0.0` so every such request shares a
/// single bucket rather than panicking.
async fn auth_rate_limit<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(limiter) = &state.auth_ip_limiter else {
        return next.run(req).await;
    };
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| rate_limit::canonical_ip(ci.0.ip()))
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let ip = rate_limit::client_ip(peer, xff, &state.trusted_proxies);
    let rl = &state.config.rate_limit;

    // Process-global ceiling first (bounds a source-IP-rotating flood), then
    // the per-IP budget. Mirrors the challenge handler's global-then-key
    // ordering.
    if rl.global_per_minute > 0 {
        if let Err(retry_after_seconds) = limiter.check_global() {
            metrics::record_rate_limit_rejection("auth_global");
            return RegistryError::RateLimited {
                retry_after_seconds,
            }
            .into_response();
        }
    }
    if rl.per_ip_per_minute > 0 {
        if let Err(retry_after_seconds) = limiter.check(&ip.to_string()) {
            metrics::record_rate_limit_rejection("auth_per_ip");
            return RegistryError::RateLimited {
                retry_after_seconds,
            }
            .into_response();
        }
    }
    next.run(req).await
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
    Router::new()
        .route("/admin/contexts", get(handlers::admin_list::<S>))
        .route(
            "/admin/pinned-keys/reload",
            post(handlers::reload_pinned_keys::<S>),
        )
}

#[cfg(not(feature = "playground"))]
fn admin_router<S: ExtendedRegistryStore + 'static>() -> Router<Arc<AppState<S>>> {
    Router::new()
}
