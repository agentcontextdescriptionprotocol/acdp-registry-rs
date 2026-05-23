//! Postgres-backed `acdp-registry-store` implementation.
//!
//! Logically identical to [`acdp_registry_sqlite`] but with native
//! `TIMESTAMPTZ`, `TEXT[]`, `JSONB`, and Postgres FTS.

pub mod store;

pub use store::PgStore;
