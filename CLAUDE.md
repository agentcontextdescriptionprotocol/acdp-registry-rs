# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this workspace is

`acdp-registry-rs` is the reference **registry** for the Agent Context
Description Protocol v0.1.0. It is an 8-crate Cargo workspace built on top of
[`acdp`](../acdp-rs) (the protocol library), which is consumed as a path
dependency until promoted to crates.io.

The HTTP layer is `axum 0.7`, storage is `sqlx 0.8` (Postgres + SQLite), and
authentication is a DID challenge-response → HS256 JWT design.

## Commands

```bash
# Pre-PR check set
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test  --workspace

# Postgres-feature variant
cargo clippy -p acdp-registry-server --no-default-features --features storage-pg --all-targets -- -D warnings

# Playground variant
cargo clippy -p acdp-registry-server --features storage-sqlite,playground --all-targets -- -D warnings

# Run the dev server (SQLite under ./data/registry.db)
cargo run  -p acdp-registry-server
ACDP_REGISTRY_CONFIG=config/registry.example.toml cargo run -p acdp-registry-server
```

`cargo deny check` runs in CI; install locally only when touching dependencies.

## Crate map

| Crate                       | Role |
|-----------------------------|------|
| `acdp-registry-types`       | Leaf: config (TOML+env), errors with HTTP projection, webhook events. Depends only on `acdp` + serde. |
| `acdp-registry-store`       | `ExtendedRegistryStore` trait — adds `list_contexts`, `health`, `migrate` to `acdp::registry::RegistryStore`. |
| `acdp-registry-pg`          | Postgres backend (sqlx, native `TIMESTAMPTZ` / `TEXT[]` / `JSONB` / `tsvector`). |
| `acdp-registry-sqlite`      | SQLite backend (FTS5 virtual table; arrays as JSON-encoded TEXT). |
| `acdp-registry-auth`        | DID challenge → JWT; reuses `acdp::did::WebResolver` and `verify_ed25519`. |
| `acdp-registry-webhook`     | HMAC-SHA256-signed POSTs over a bounded mpsc channel. |
| `acdp-registry-core`        | axum router + handlers, generic over `S: ExtendedRegistryStore`. |
| `acdp-registry-server`      | Binary: feature flags select the storage backend at compile time. |

## Architecture (big picture)

- The store trait is **synchronous** (inherited from `acdp::registry::RegistryStore`).
  Postgres/SQLite implementations bridge to async sqlx via
  `tokio::task::block_in_place + Handle::current().block_on(...)`. HTTP handlers
  wrap sync calls in `tokio::task::spawn_blocking`.
- `acdp-registry-core` is **generic** over the store, not boxed. The server
  binary monomorphizes the type when constructing `Arc<RegistryServer<S>>`.
- The publish pipeline reuses `RegistryServer::publish_verified` from
  `acdp::registry::server` — we add storage adapters, NOT a parallel validator.
- DID verification reuses `acdp`'s `WebResolver` (LRU-cached, SSRF-policy-gated)
  for both publish AND auth-challenge verification. There is intentionally only
  one resolver per server instance.

## Conventions

- **Conventional Commits** (`feat:` / `fix:` / `docs:` / `refactor:` / `test:` /
  `chore:` / `BREAKING CHANGE:`). `release-plz` derives the changelog.
- **No `unsafe`** — `unsafe_code = "forbid"` at the workspace level.
- **No `clap`** in the binary — config loading is the `config` crate plus env
  vars (same dep-graph minimization principle as `acdp-rs`).
- The webhook signature scheme matches GitHub's exactly
  (`X-ACDP-Signature: sha256=<hex>` over the raw JSON body). Stay compatible.
- The auth challenge signing input is namespaced:
  `acdp-registry-auth:v1:{nonce}:{agent_id}:{registry_authority}:{expires_at}`.
  Do NOT remove the version prefix or the registry-authority binding — they
  prevent cross-context signature replay.
- Migrations live in `crates/acdp-registry-<backend>/migrations/`. Number them
  sequentially; never rewrite an applied migration.

## Adding a new endpoint

1. Add the handler to `crates/acdp-registry-core/src/handlers/`.
2. Wire it into `build_router()` in `crates/acdp-registry-core/src/lib.rs`.
3. If it returns ACDP-typed data, route errors through `RegistryError` so the
   wire envelope (RFC-ACDP-0007 §5) lands automatically.
4. Cover the visibility rule in `RegistryServer::can_retrieve` / the search
   disclosure predicate — never branch on visibility inside the handler.

## Tests

- Unit tests live alongside each module.
- Integration tests for the registry pipeline go in
  `crates/acdp-registry-server/tests/` (round-trips publish → search → retrieve
  via in-process axum).
- Conformance fixtures from the spec repo are picked up via `ACDP_SPEC_DIR`
  (same convention as `acdp-rs`).

## Security defaults

- HTTPS-only DID resolution (`WebResolver` enforces it).
- 1 MB payload cap, 64 KB embedded-data cap (configurable via `[limits]`).
- JWT secret must decode to ≥32 bytes; tokens are HS256 with `iss`, `sub`,
  `jti`, `iat`, `exp` plus `acdp.{registry, key_id}`.
- Anonymous public reads are off by default for new registries unless the
  config explicitly opts in.
- Migrations are idempotent (`CREATE TABLE IF NOT EXISTS`).
- Cross-registry federation is **public-only**: foreign contexts are fetched
  anonymously (no caller-credential forwarding), so only remote `public`
  contexts are ever surfaced. The `SsrfPolicy` on the resolver rejects
  private/internal authorities (502 `cross_registry_resolution_failed`).
- Per-agent `POST /contexts` rate limit (`limits.publish_rate_per_minute`,
  default 60; 429 + `Retry-After`).
