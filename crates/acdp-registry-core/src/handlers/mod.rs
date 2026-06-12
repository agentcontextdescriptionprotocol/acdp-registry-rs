//! Axum handlers for every ACDP HTTP endpoint.

mod auth;
mod context;
mod meta;

pub use auth::{issue_challenge, issue_token, revoke_token};
pub use context::{current, lineage, publish, retrieve, retrieve_body, search};
pub use meta::{capabilities, health, jwks, registry_did_document};

mod admin;
#[cfg(feature = "playground")]
pub use admin::{admin_list, reload_pinned_keys};
pub use admin::{admin_status, lineage_audit};
