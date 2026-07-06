//! Axum handlers for every ACDP HTTP endpoint.

mod auth;
mod context;
mod log;
mod meta;

pub use auth::{issue_challenge, issue_token, revoke_token};
pub use context::{current, lineage, publish, republish, retract, retrieve, retrieve_body, search};
pub use log::{log_checkpoint, log_entries, log_proof};
pub use meta::{capabilities, health, jwks, registry_did_document};

mod admin;
#[cfg(feature = "playground")]
pub use admin::{admin_list, reload_pinned_keys};
pub use admin::{admin_republish, admin_retract, admin_status, lineage_audit};
