//! Shared HTTP-layer state. Held inside `Arc` by axum.

use std::sync::Arc;

use acdp::client::CrossRegistryResolver;
use acdp::registry::RegistryServer;
use acdp_registry_auth::AuthService;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::RegistryConfig;
use acdp_registry_webhook::WebhookEmitter;

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
}
