//! FEAT-10: Prometheus metrics.
//!
//! Uses the `metrics` facade + `metrics-exporter-prometheus` recorder rather
//! than `axum-prometheus`: domain counters can be emitted from any crate
//! (storage, webhook, witness poller) with a plain `metrics::counter!` call —
//! no axum dependency leaks downward — and label cardinality is under our
//! explicit control.
//!
//! The `/metrics` endpoint is served through the existing axum stack (not a
//! second HTTP listener), so the recorder is installed with the exporter's
//! HTTP listener feature OFF. Handlers call the `counter!` / `histogram!`
//! macros unconditionally; when no recorder is installed (metrics disabled)
//! they compile to cheap no-ops, so instrumentation never has to branch on a
//! config flag.

use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

use std::sync::Arc;

use acdp_registry_store::ExtendedRegistryStore;

use crate::state::AppState;

/// Metric names. Centralised so the middleware, the domain-counter helpers,
/// and the tests agree on the exact strings.
pub const REQUEST_TOTAL: &str = "acdp_registry_request_total";
pub const REQUEST_DURATION: &str = "acdp_registry_request_duration_seconds";
pub const PUBLISH_TOTAL: &str = "acdp_registry_publish_total";
pub const RECEIPTS_MINTED_TOTAL: &str = "acdp_registry_receipts_minted_total";
pub const LIFECYCLE_EVENT_TOTAL: &str = "acdp_registry_lifecycle_event_total";
pub const LOG_LEAVES_TOTAL: &str = "acdp_registry_log_leaves_total";
pub const WITNESS_COSIGNATURES_TOTAL: &str = "acdp_registry_witness_cosignatures_total";
pub const RATE_LIMIT_REJECTIONS_TOTAL: &str = "acdp_registry_rate_limit_rejections_total";

/// Process-global recorder handle. `metrics-exporter-prometheus` installs a
/// single global recorder; a second install returns an error. A `OnceLock`
/// makes `install_recorder` idempotent so multiple in-process test harnesses
/// (each building their own `AppState`) share one recorder instead of the
/// second one panicking.
static RECORDER: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the process-global Prometheus recorder (idempotent) and return a
/// handle whose `render()` produces the text exposition. `duration_buckets`
/// sizes the request-latency histogram; it is honoured only on the first
/// call (the global recorder is immutable thereafter).
pub fn install_recorder(duration_buckets: &[f64]) -> PrometheusHandle {
    RECORDER
        .get_or_init(|| {
            let mut builder = PrometheusBuilder::new();
            if !duration_buckets.is_empty() {
                builder = builder
                    .set_buckets_for_metric(
                        Matcher::Full(REQUEST_DURATION.to_string()),
                        duration_buckets,
                    )
                    .expect("static histogram bucket configuration is valid");
            }
            builder
                .install_recorder()
                .expect("no other global metrics recorder is installed")
        })
        .clone()
}

/// Request-level middleware (FEAT-10). Records one `REQUEST_TOTAL` count and
/// one `REQUEST_DURATION` observation per request, labelled by the **matched
/// route pattern** (`/contexts/{ctx_id}`, never the resolved `ctx_id`, so
/// label cardinality stays bounded), method, and status class.
///
/// Adding a new route needs no change here — the labels come from whatever
/// `MatchedPath` axum resolved.
pub async fn track_metrics(matched: Option<MatchedPath>, req: Request, next: Next) -> Response {
    let route = matched
        .as_ref()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let method = req.method().as_str().to_string();
    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    let status_class = format!("{}xx", response.status().as_u16() / 100);

    metrics::counter!(
        REQUEST_TOTAL,
        "route" => route.clone(),
        "method" => method.clone(),
        "status_class" => status_class,
    )
    .increment(1);
    metrics::histogram!(
        REQUEST_DURATION,
        "route" => route,
        "method" => method,
    )
    .record(elapsed);

    response
}

/// `GET /metrics` — Prometheus text exposition (version 0.0.4).
///
/// Mounted only when `[metrics] enabled` (the handle is `Some`). Optionally
/// bearer-gated via `metrics.bearer_token`; when the token is empty the
/// endpoint is open so a scrape network can reach it without ACDP auth.
pub async fn metrics_endpoint<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
) -> Response {
    let Some(handle) = &state.metrics else {
        // Should not happen (the route is not mounted without a handle), but
        // be explicit rather than unwrap.
        return (StatusCode::NOT_FOUND, "metrics disabled").into_response();
    };
    let token = state.config.metrics.bearer_token.trim();
    if !token.is_empty() {
        let presented = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        if presented != Some(token) {
            return (
                StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    "Bearer realm=\"metrics\"",
                )],
                "unauthorized",
            )
                .into_response();
        }
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        handle.render(),
    )
        .into_response()
}

// ── Domain counter helpers ──────────────────────────────────────────────
//
// Thin wrappers so handlers express intent without repeating metric-name and
// label strings. All are no-ops when no recorder is installed.

/// One publish attempt with its outcome (`inserted`, `idempotent_replay`, or
/// a wire error code such as `payload_too_large`).
pub fn record_publish(outcome: &'static str) {
    metrics::counter!(PUBLISH_TOTAL, "outcome" => outcome).increment(1);
}

/// A registry receipt was minted for an accepted publish (RFC-ACDP-0010).
pub fn record_receipt_minted() {
    metrics::counter!(RECEIPTS_MINTED_TOTAL).increment(1);
}

/// A transparency-log leaf was appended for an accepted publish
/// (RFC-ACDP-0012 §4).
pub fn record_log_leaf() {
    metrics::counter!(LOG_LEAVES_TOTAL).increment(1);
}

/// A producer lifecycle event (`retract` / `republish`) with its outcome.
pub fn record_lifecycle_event(event: &'static str, outcome: &'static str) {
    metrics::counter!(LIFECYCLE_EVENT_TOTAL, "event" => event, "outcome" => outcome).increment(1);
}

/// A witness cosignature poll result (RFC-ACDP-0015 §6.1): `aggregated` when
/// verified and stored, `rejected` when it failed verification.
pub fn record_witness_cosignature(outcome: &'static str) {
    metrics::counter!(WITNESS_COSIGNATURES_TOTAL, "outcome" => outcome).increment(1);
}

/// A request rejected with 429 by the rate limiter, labelled by scope
/// (`auth_per_ip`, `auth_global`, `publish_per_agent`, `challenge_per_agent`,
/// `challenge_global`).
pub fn record_rate_limit_rejection(scope: &'static str) {
    metrics::counter!(RATE_LIMIT_REJECTIONS_TOTAL, "scope" => scope).increment(1);
}
