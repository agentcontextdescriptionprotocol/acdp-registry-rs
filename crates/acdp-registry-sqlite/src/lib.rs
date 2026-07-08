//! SQLite-backed `acdp-registry-store` implementation.
//!
//! Intended for local development, conformance tests, and the playground
//! profile. Production deployments use `acdp-registry-pg`.

pub mod store;

pub use store::SqliteStore;
