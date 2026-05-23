//! Shared HTTP-layer state. Held inside `Arc` by axum.

use std::sync::Arc;

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
}
