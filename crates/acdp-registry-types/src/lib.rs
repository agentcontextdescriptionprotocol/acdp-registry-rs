//! Shared types used across `acdp-registry-*` crates.
//!
//! No storage or HTTP-handler logic lives here — every other crate depends
//! on this leaf.

pub mod auth;
pub mod config;
pub mod error;
pub mod event;

pub use auth::{AuthChallenge, BearerClaims, TokenRequest, TokenResponse};
pub use config::{
    AuthConfig, CorsConfig, LifecycleConfig, LimitsConfig, LogConfig, PlaygroundConfig,
    ReceiptConfig, RegistryConfig, RegistrySection, RetiredReceiptKey, StorageBackend,
    StorageConfig, TenantAgentBinding, WebhookConfig, WitnessConfig,
};
pub use error::RegistryError;
pub use event::WebhookEvent;
