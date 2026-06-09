# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this workspace is

`acdp-registry-rs` is the reference **registry** for the Agent Context
Distribution Protocol v0.1.0. It is an 8-crate Cargo workspace built on top of
[`acdp`](https://crates.io/crates/acdp) (the protocol library), consumed as a
crates.io dependency.

The HTTP layer is `axum 0.7`, storage is `sqlx 0.8` (Postgres + SQLite), and
authentication is a DID challenge-response → JWT design (HS256 by default,
optionally EdDSA/Ed25519 with a published JWKS). The registry is
**multi-tenant**: a `tenant` JWT claim (or `X-Tenant-Id` fallback) scopes
publish, retrieve, search, lineage, and pagination.

## Commands

```bash
# Pre-PR check set
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test  --workspace

# Run a single test (by name substring), or one integration suite
cargo test -p acdp-registry-server <test_name>
cargo test -p acdp-registry-server --test http_integration
cargo test -p acdp-registry-server --test http_integration -- --nocapture <test_name>

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
| `acdp-registry-store`       | `ExtendedRegistryStore` trait — adds `list_contexts(tenant)`, `health`, `migrate`, plus tenant binding (`set_tenant_of_ctx`/`tenant_of_ctx`/`tenants_of_ctxs`) to `acdp::registry::RegistryStore`. |
| `acdp-registry-pg`          | Postgres backend (sqlx, native `TIMESTAMPTZ` / `TEXT[]` / `JSONB` / `tsvector`). |
| `acdp-registry-sqlite`      | SQLite backend (FTS5 virtual table; arrays as JSON-encoded TEXT). |
| `acdp-registry-auth`        | DID challenge → JWT (HS256 or EdDSA); tenant-bound claims, revocation store + cursors, cross-issuer revocation pollers. Reuses `acdp::did::WebResolver` and `verify_ed25519`. |
| `acdp-registry-webhook`     | HMAC-SHA256-signed POSTs over a bounded mpsc channel. |
| `acdp-registry-core`        | axum router + handlers, generic over `S: ExtendedRegistryStore`. |
| `acdp-registry-server`      | Binary (`acdp-registry`): feature flags select the storage backend at compile time. |

## Feature flags (server / core)

Storage backend is chosen at **compile time** (`acdp-registry-server`
`[features]`): `storage-sqlite` (default), `storage-pg`, or `storage-memory`.
One capability flag layers on top:

- `playground` — operator/dev tooling: compiles in `admin_router`, which mounts
  `GET /admin/contexts` and `POST /admin/pinned-keys/reload`. Per the README it
  also relaxes DID verification for hands-on demos.

The auth routes (`POST /auth/challenge`, `/auth/token`, `/auth/token/revoke`)
are **not** feature-gated — they are mounted at runtime via an `auth_enabled`
flag in `build_router()`. `GET /admin/status` always ships and is auth-gated at
runtime by `auth.admin_tokens`.

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
  `acdp-registry-auth:v1:{nonce}:{agent_id}:{registry_authority}:{expires_at}`
  (see `AuthChallenge::signing_input` in `acdp-registry-types/src/auth.rs`).
  Do NOT remove the version prefix or the registry-authority binding — they
  prevent cross-context signature replay.
- Migrations live in `crates/acdp-registry-<backend>/migrations/`. Number them
  sequentially; never rewrite an applied migration.

## Multi-tenancy

- Tenant resolution is centralized in `tenant_for_request()`
  (`acdp-registry-core/src/handlers/context.rs`). **Precedence:** JWT `tenant`
  claim (authoritative, issuer-signed) → `X-Tenant-Id` header (fallback) →
  `None` (V0 backward-compatible, no filter). If a bound token's claim and the
  header disagree, the request is rejected (tenant assertion mismatch).
- Always resolve the tenant *before* the DB read (publish validates upfront,
  retrieve resolves first to avoid an existence oracle). NEVER trust
  `X-Tenant-Id` once a token carries a `tenant` claim. Do not branch on tenant
  inside handlers ad hoc — go through `tenant_for_request()`.
- The store carries the binding: `set_tenant_of_ctx` / `tenant_of_ctx` /
  `tenants_of_ctxs`, and `list_contexts(tenant)` filters at the SQL level so
  pagination pages don't short. Search/lineage post-filter with a bounded
  refill loop.
- Strict mode (`auth.require_tenant = true`): a request resolving to `None`
  tenant is default-denied (401), and bound tokens may assert a tenant only via
  the JWT claim. Agent→tenant bindings come from `[[auth.tenant_agents]]`
  (`agent_did` + `tenant_id`); unbound agents get `tenant: None`.

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
  via in-process axum). The suites are `http_integration`, `conformance`, and
  `pg_integration` (the last needs `--features storage-pg` plus a reachable
  Postgres; its tests are serialized via `serial_test`).
- Conformance fixtures from the spec repo are picked up via `ACDP_SPEC_DIR`
  (same convention as `acdp-rs`).

## Security defaults

- HTTPS-only DID resolution (`WebResolver` enforces it).
- 1 MB payload cap, 64 KB embedded-data cap (configurable via `[limits]`).
- JWT signing is configurable via `auth.jwt_signing_alg`:
  - **HS256** (default, backward-compatible) — symmetric, `jwt_secret` must
    decode to ≥32 bytes; secrets are never published (`/.well-known/jwks.json`
    returns an empty key set).
  - **EdDSA** (Ed25519) — asymmetric, `jwt_private_key_pem`; the public key is
    published at `GET /.well-known/jwks.json` so federated peers verify without
    sharing a secret.
- Tokens carry `iss`, `sub`, `jti`, `iat`, `exp`, `acdp.{registry, key_id}`,
  plus an optional `tenant` claim (present only for bound agents).
- Token revocation: `POST /auth/token/revoke` ({ `jti` }, bearer-authed; caller
  must own the token). Issued/revoked state lives in the revocation store
  (`acdp-registry-auth/src/revocation_store.rs`); `is_revoked` is checked on
  every bearer validation.
- Cross-issuer revocation federation is **consume-only**: pollers
  (`acdp-registry-auth/src/revocation_poller.rs`) fetch peers'
  `GET /auth/revocations?since={cursor_ms}&limit=...` feeds configured by
  `[[auth.revocation_feeds]]` and apply remote revocations to the local store.
  (This registry does not itself expose a `/auth/revocations` feed route.)
  **Durable cursors** (`get_revocation_cursor` / `set_revocation_cursor`, unix
  ms) survive restarts; the cursor only advances when an entire page applies
  cleanly.
- Admin endpoints are bearer-gated against `auth.admin_tokens` (empty = disabled):
  `GET /admin/status` (operational snapshot), `GET /admin/contexts` and
  `POST /admin/pinned-keys/reload` (playground feature; hot-reloads only the
  `[playground]` config section).
- Anonymous public reads are off by default for new registries unless the
  config explicitly opts in.
- Migrations are idempotent (`CREATE TABLE IF NOT EXISTS`).
- Cross-registry federation is **public-only**: foreign contexts are fetched
  anonymously (no caller-credential forwarding), so only remote `public`
  contexts are ever surfaced. The `SsrfPolicy` on the resolver rejects
  private/internal authorities (502 `cross_registry_resolution_failed`).
- Per-agent `POST /contexts` rate limit (`limits.publish_rate_per_minute`,
  default 60; 429 + `Retry-After`). Unauthenticated `POST /auth/challenge` is
  bounded per `agent_id` by `limits.challenge_rate_per_minute` (default 60).
