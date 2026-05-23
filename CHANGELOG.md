# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial 8-crate workspace scaffold.
- `acdp-registry-types`: configuration (TOML + env), `RegistryError` with HTTP
  projection, webhook event envelopes, JWT bearer claims.
- `acdp-registry-store`: `ExtendedRegistryStore` trait extending
  `acdp::registry::RegistryStore` with `list_contexts`, `health`, `migrate`.
- `acdp-registry-sqlite`: SQLite backend with FTS5 virtual table, migrations,
  atomic `commit_publish`, idempotency cache, and visibility-filtered search.
- `acdp-registry-pg`: Postgres backend with `TIMESTAMPTZ` / `TEXT[]` / `JSONB`,
  `tsvector` FTS, `FOR UPDATE` row locking on the supersession check.
- `acdp-registry-auth`: DID challenge-response via `acdp::did::WebResolver` +
  `verify_ed25519`, HS256 JWT issuance/validation, pluggable
  `ChallengeStore` (in-memory + SQLite + Postgres).
- `acdp-registry-webhook`: HMAC-SHA256-signed POSTs with retry/backoff.
- `acdp-registry-core`: axum router + handlers generic over the storage trait.
- `acdp-registry-server`: binary wiring via Cargo features
  (`storage-sqlite` default, `storage-pg`, `playground`).
- Docker image (multi-stage with `cargo-chef`) + docker-compose with Postgres.
- GitHub Actions: `ci.yml` (fmt + clippy across feature matrix + test +
  cargo-deny), `release-plz.yml`, `docker.yml`.
