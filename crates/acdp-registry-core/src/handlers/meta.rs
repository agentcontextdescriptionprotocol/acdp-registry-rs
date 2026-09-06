//! Capabilities + health.

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

/// The running build's identifier, served as `version` on `GET /healthz`
/// and inside the `build` group on `GET /admin/status` (#117).
///
/// Composed rather than read from a single source, because the workspace
/// crates still carry a placeholder `CARGO_PKG_VERSION` (`0.1.0`): the
/// package version alone would not distinguish two builds. CI injects the
/// commit through the `ACDP_BUILD_SHA` build ARG (see `docker/Dockerfile`),
/// giving `0.1.0+g<sha>`; a plain `cargo build` leaves it unset and yields
/// the bare package version, which does NOT uniquely identify a build.
/// `+g<sha>` is SemVer build metadata, so the result stays valid SemVer
/// either way.
///
/// This composes with — rather than being replaced by — a future fix to the
/// release pipeline: once the package version bumps, the same expression
/// emits `0.4.0+g<sha>` with no code change.
///
/// `option_env!` is resolved at compile time, so a cached build layer keeps
/// whatever SHA it was built with; the Dockerfile places the ARG after the
/// dependency-cook layer so the final layer rebuilds each commit.
///
/// Consumers MUST treat this as opaque — display or equality at most, never
/// parsing. See `docs/HTTP-API.md`.
pub fn build_version() -> String {
    match option_env!("ACDP_BUILD_SHA") {
        Some(sha) => format!("{}+g{sha}", env!("CARGO_PKG_VERSION")),
        None => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// `GET /.well-known/acdp.json` — the registry capabilities document.
///
/// RFC-ACDP-0006 §4.2.1: registries SHOULD emit `Cache-Control: max-age=300`
/// or higher. The document changes rarely, so a 5-minute TTL lets clients and
/// CDNs hold it without re-fetching on every discovery probe.
pub async fn capabilities<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> impl IntoResponse {
    let body =
        Json(serde_json::to_value(state.server.capabilities()).unwrap_or_else(|_| json!({})));
    (
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        body,
    )
}

/// `GET /.well-known/did.json` — the registry's own `did:web` DID document
/// (RFC-ACDP-0010 workstream A1).
///
/// `did:web:<authority>` resolves to exactly this URL, so serving it here
/// makes the registry's receipt verification key discoverable without any
/// out-of-band hosting. The document is precomputed at startup from
/// `[receipt]`: the active signing key sits in both `verificationMethod`
/// and `assertionMethod`; rotated-out keys (`[[receipt.retired_keys]]`)
/// stay in `verificationMethod` forever — removing one bricks every
/// receipt it signed. 404 when no receipt key is configured.
pub async fn registry_did_document<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> impl IntoResponse {
    match &state.registry_did_document {
        Some(doc) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
            Json(doc.clone()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message":
                    "this registry serves no DID document (no receipt signing key configured)",
            })),
        )
            .into_response(),
    }
}

/// `GET /.well-known/jwks.json` — publish the public key(s) federated
/// peers should use to verify tokens issued by this registry.
///
/// Returns:
///   - EdDSA: `{ keys: [<OKP/Ed25519 JWK>] }`
///   - HS256: `{ keys: [] }` (symmetric secrets are never published)
///
/// `Cache-Control: public, max-age=300` matches the typical JWKS-client
/// cache TTL so peers can hold the response without hammering the registry.
pub async fn jwks<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> impl IntoResponse {
    let body = Json(state.auth.signer.jwks());
    (
        [
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
            (axum::http::header::CONTENT_TYPE, "application/jwk-set+json"),
        ],
        body,
    )
}

/// BUG-05: returns HTTP 503 when storage health fails so load balancers,
/// Kubernetes readiness probes, and Prometheus blackbox exporters take the
/// pod out of rotation. Returning 200 + `"status":"degraded"` (the prior
/// behaviour) left the registry serving requests it could not satisfy.
pub async fn health<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> impl IntoResponse {
    let storage_ok = state.server.store().health().await.is_ok();
    // `version` rides the degraded/503 body too: build identity matters most
    // when the service is unhealthy, and `acdp-control-plane` sets the same
    // precedent (its health tests pin `version` on the DB-failure path).
    let body = Json(json!({
        "status": if storage_ok { "ok" } else { "degraded" },
        "storage": storage_ok,
        "version": build_version(),
    }));
    let status = if storage_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, body)
}
