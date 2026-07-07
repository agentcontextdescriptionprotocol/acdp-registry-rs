//! Shared HTTP-layer state. Held inside `Arc` by axum.

use std::sync::{Arc, RwLock};

use acdp::client::CrossRegistryResolver;
use acdp::registry::RegistryServer;
use acdp_registry_auth::AuthService;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{PlaygroundConfig, RegistryConfig};
use acdp_registry_webhook::WebhookEmitter;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::rate_limit::{AgentRateLimiter, TrustedProxies};

/// Public alias — the value axum actually carries is `Arc<AppState<S>>`.
pub type AppState<S> = AppStateInner<S>;

pub struct AppStateInner<S: ExtendedRegistryStore> {
    pub server: Arc<RegistryServer<S>>,
    pub auth: Arc<AuthService>,
    pub webhook: Option<WebhookEmitter>,
    pub config: RegistryConfig,
    /// FEAT-01: cross-registry resolver consulted by `retrieve` when the
    /// requested `ctx_id`'s authority differs from this registry's
    /// `config.registry.authority`. `None` disables forwarding.
    pub cross_registry: Option<Arc<CrossRegistryResolver>>,
    /// Live-mutable playground configuration (plan §2: pinned-key
    /// rotation + admin reload). Seeded from `config.playground` at
    /// startup; the `POST /admin/pinned-keys/reload` endpoint re-reads
    /// the on-disk config and atomic-swaps this cell so an operator
    /// can rotate keys without restarting the process.
    ///
    /// Read path holds the lock only long enough to clone the struct
    /// (small + Clone), so no read ever blocks on a writer. Writers
    /// hold the lock for the duration of the env-driven swap.
    pub playground: Arc<RwLock<PlaygroundConfig>>,
    /// REG-P1-3: per-agent `POST /contexts` limiter (RFC-ACDP-0008 §4.3).
    /// `None` when `limits.publish_rate_per_minute == 0` (disabled).
    pub rate_limiter: Option<Arc<AgentRateLimiter>>,
    /// Per-agent `POST /auth/challenge` limiter. The challenge endpoint is
    /// unauthenticated; without this an attacker can flood it to amplify
    /// writes and grow the nonce store. `None` when
    /// `limits.challenge_rate_per_minute == 0` (disabled).
    pub challenge_rate_limiter: Option<Arc<AgentRateLimiter>>,
    /// FEAT-06: per-IP + process-global limiter applied as middleware over the
    /// whole `/auth/*` subrouter, keyed by the resolved client IP. Complements
    /// the per-agent `challenge_rate_limiter` — an unauthenticated attacker
    /// controls `agent_id` and can rotate it, but not their source IP (short
    /// of a botnet, which the global ceiling then bounds). `None` when
    /// `[rate_limit] enabled = false` or both budgets are `0`.
    pub auth_ip_limiter: Option<Arc<AgentRateLimiter>>,
    /// FEAT-06: parsed `[rate_limit] trusted_proxies` CIDRs. Empty (the
    /// default) means `X-Forwarded-For` is never trusted and the TCP socket
    /// peer is always used as the client IP.
    pub trusted_proxies: TrustedProxies,
    /// FEAT-10: process-global Prometheus recorder handle. `Some` only when
    /// `[metrics] enabled` — the `/metrics` route is mounted iff this is set.
    pub metrics: Option<PrometheusHandle>,
    /// The registry's own `did:web` DID document, served at
    /// `GET /.well-known/did.json` so consumers can resolve the receipt
    /// verification key (RFC-ACDP-0010). Precomputed at startup from
    /// `config.receipt` — `None` when no receipt key is configured (the
    /// endpoint then 404s). Static for the process lifetime: key rotation
    /// is a config change + restart.
    pub registry_did_document: Option<serde_json::Value>,
    /// Transparency-log serving state (RFC-ACDP-0012): the checkpoint
    /// signer (= the RFC-ACDP-0010 receipt signer, §6), the `log_id`,
    /// and the head-root cache. `None` when `log.enabled` is false —
    /// the `/log/*` endpoints then answer 501 `not_implemented`.
    pub log: Option<Arc<crate::log::LogState>>,
}

impl<S: ExtendedRegistryStore> AppStateInner<S> {
    /// Build state with a fresh `playground` cell seeded from
    /// `config.playground`. Centralises the lock setup so test
    /// harnesses don't have to know the cell exists.
    pub fn new(
        server: Arc<RegistryServer<S>>,
        auth: Arc<AuthService>,
        webhook: Option<WebhookEmitter>,
        config: RegistryConfig,
        cross_registry: Option<Arc<CrossRegistryResolver>>,
    ) -> Self {
        let playground = Arc::new(RwLock::new(config.playground.clone()));
        let rate_limiter = match config.limits.publish_rate_per_minute {
            0 => None,
            n => Some(Arc::new(AgentRateLimiter::new(n))),
        };
        let challenge_rate_limiter = match config.limits.challenge_rate_per_minute {
            0 => None,
            // #24: `/auth/challenge` is unauthenticated and keyed by the
            // attacker-controlled `agent_id`, so also enforce a process-global
            // ceiling (64× the per-agent budget) — varying `agent_id` can no
            // longer flood the nonce store without bound.
            n => Some(Arc::new(AgentRateLimiter::with_global_ceiling(
                n,
                n.saturating_mul(64),
            ))),
        };
        // Receipt key problems are caught at startup by the binary's
        // validate_config; if the key still fails to load here, serve no
        // DID document rather than panic mid-construction (test harnesses
        // build state without running validate_config first).
        let registry_did_document = if config.receipt.is_configured() {
            crate::receipt::build_did_document(&config.receipt, &config.registry.authority)
                .map_err(|e| tracing::error!(error = %e, "receipt DID document unavailable"))
                .ok()
        } else {
            None
        };
        // Transparency log (RFC-ACDP-0012). Misconfigurations are caught
        // at startup by the binary's validate_config; if construction
        // still fails here, serve 501s rather than panic mid-construction
        // (test harnesses build state without running validate_config).
        let log = crate::log::LogState::from_config(&config)
            .map_err(|e| tracing::error!(error = %e, "transparency log unavailable"))
            .ok()
            .flatten()
            .map(Arc::new);
        // FEAT-06: per-IP + global `/auth/*` limiter. Reuses the fixed-window
        // `AgentRateLimiter`, keyed by client IP. A `0` global budget maps to
        // the `u32::MAX` "disabled" sentinel; the per-IP check is skipped by
        // the middleware when `per_ip_per_minute == 0`.
        let rl = &config.rate_limit;
        let auth_ip_limiter =
            if rl.enabled && (rl.per_ip_per_minute > 0 || rl.global_per_minute > 0) {
                let global = if rl.global_per_minute == 0 {
                    u32::MAX
                } else {
                    rl.global_per_minute
                };
                Some(Arc::new(AgentRateLimiter::with_global_ceiling(
                    rl.per_ip_per_minute,
                    global,
                )))
            } else {
                None
            };
        let trusted_proxies = TrustedProxies::parse_lossy(&rl.trusted_proxies);
        // FEAT-10: install the process-global recorder when metrics are
        // enabled. Idempotent — many in-process test harnesses share one.
        let metrics = if config.metrics.enabled {
            Some(crate::metrics::install_recorder(
                &config.metrics.duration_buckets,
            ))
        } else {
            None
        };
        Self {
            server,
            auth,
            webhook,
            config,
            cross_registry,
            playground,
            rate_limiter,
            challenge_rate_limiter,
            auth_ip_limiter,
            trusted_proxies,
            metrics,
            registry_did_document,
            log,
        }
    }
}
