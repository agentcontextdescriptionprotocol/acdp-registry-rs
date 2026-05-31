//! Shared HTTP-layer state. Held inside `Arc` by axum.

use std::sync::{Arc, RwLock};

use acdp::client::CrossRegistryResolver;
use acdp::registry::RegistryServer;
use acdp_registry_auth::AuthService;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{PlaygroundConfig, RegistryConfig};
use acdp_registry_webhook::WebhookEmitter;

use crate::rate_limit::AgentRateLimiter;

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
        Self {
            server,
            auth,
            webhook,
            config,
            cross_registry,
            playground,
            rate_limiter,
        }
    }
}
