# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JWT revocation** (`SEC-01`, `FEAT-02`): new `RevocationStore` trait with
  in-memory, SQLite, and Postgres backends; `issued_tokens` migrations
  (Sqlite 006, Postgres 005); `AuthService::issue_token` records every
  minted `jti` so `POST /auth/token/revoke` can authorize ownership;
  `JwtSigner::with_revocations` rejects revoked tokens at validate time.
- **Cross-registry resolution** (`FEAT-01`): `retrieve` forwards `ctx_id`s
  whose authority differs from the local registry through
  `acdp::client::CrossRegistryResolver`. Gated by
  `registry.cross_registry_resolution = true` (default).
- **Visibility search filter** (`FEAT-07`):
  `GET /contexts/search?visibility=public|restricted|private`.
- **Webhook event correlation** (`FEAT-04`, `FEAT-05`):
  `ContextPublished` carries `X-Run-Id` and the publish request's
  `derived_from` list.
- **Configurable CORS** (`SEC-02`): `[registry.cors] allowed_origins`.
  Empty (default) sends no CORS headers — replaces the prior
  `CorsLayer::permissive()`.
- **Body-size limit layer** (`SEC-06`): `tower_http`
  `RequestBodyLimitLayer` applies `limits.max_payload_bytes` to every
  route, not just publish.
- **SSRF guard on webhook URL** (`SEC-03`) and **non-empty webhook
  secret** (`SEC-04`): both enforced at startup by
  `WebhookEmitter::try_spawn` and `main::validate_config`.
- **DID-method fast-fail** (`SEC-05`):
  `AuthService::issue_challenge` rejects `agent_id`s that don't begin
  with `did:web:` before writing to the challenge store.
- **Pre-bind config validation** (`FEAT-09`): `main::validate_config`
  decodes `jwt_secret`, validates the webhook URL via the SSRF policy,
  checks TLS materials exist, and refuses the literal `changeme`
  placeholder.
- **Conformance harness** (`BUG-07`): `tests/conformance.rs` replays
  `pub-*` and `vis-*` fixtures from `ACDP_SPEC_DIR` when present;
  status + `json_contains` assertions with a null-as-wildcard sentinel.
- **Playground matrix test** (`DESIGN-03`): asserts `/admin/contexts` is
  mounted when the `playground` feature is compiled in but the runtime
  flag is off.
- **`POST /auth/token/revoke` endpoint** (`FEAT-02`).
- **Graceful shutdown** (`OPS-03`): `axum_server::Handle` with a 30s
  drain on `SIGTERM` / `Ctrl-C`.
- **Pretty-log toggle** (`OPS-04`): `ACDP_LOG_FORMAT=pretty` switches
  `tracing-subscriber` away from JSON for local development.
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

### Changed

- **BREAKING** (`SEC-07`): `auth.anonymous_public_reads` now defaults
  to `false`, matching `CLAUDE.md`. Operators upgrading who rely on
  world-readable public contexts MUST set the field explicitly:
  `[auth] anonymous_public_reads = true`.
- **Pagination, search** (`BUG-01`, `BUG-02`, `BUG-03`): cursor-based
  pagination is now driven by the SQL `LIMIT limit+1` sentinel — no
  more phantom next pages when the in-Rust visibility filter drops
  rows. Postgres `list_contexts` binds `LIMIT` via `$N` instead of
  string concatenation; search applies the cursor predicate and limit
  in SQL on both backends.
- **Health endpoint** (`BUG-05`): `GET /healthz` returns HTTP 503
  (with `status: "degraded"`) when storage health fails, so load
  balancers and Kubernetes readiness probes take the pod out of
  rotation. The body shape is unchanged.
- **DB-backed challenge store** (`BUG-06`, `DESIGN-02`): SQLite and
  Postgres binaries now wire `SqliteChallengeStore` /
  `PgChallengeStore` instead of the in-memory store. Multi-replica
  Postgres deployments no longer break the handshake when an agent
  hits a different replica for the token step.
- **Challenge duplicate-nonce error mapping** (`BUG-04`): SQLite and
  Postgres `ChallengeStore::put` map unique-constraint violations to
  `AuthError::ChallengeReplay`, matching `InMemoryChallengeStore`.
- **Cross-registry resolution failures** map to HTTP 502 (bad
  gateway), matching `KeyResolutionUnreachable`.
- **`total_estimate` in search responses** (`DESIGN-05`) is now `None`
  rather than the page-local match count (which was misleading; it was
  always ≤ `limit`).
- **`ContextType` storage** (`DESIGN-04`): typed accessor replaces the
  `serde_json::to_value(...).as_str()` round-trip in both backends and
  the publish event, so future multi-field variants don't silently
  serialize to the empty string.
- **Webhook emitter constructor** is now `WebhookEmitter::try_spawn`
  (URL + secret validation); `spawn` is kept for tests but no longer
  invoked by the server binary.
- **Default tracing format** stays JSON; opt into pretty via
  `ACDP_LOG_FORMAT=pretty`.
- **Docker Compose**: secrets sourced from `${VAR:-default}` env
  substitution; `auth.jwt_secret = "changeme"` aborts startup.

### Security

- `SEC-01` through `SEC-07` — full sweep landed; see Added/Changed
  above for individual items. Notable: empty-string webhook secrets
  no longer silently produce valid HMACs (`SEC-04`), and the
  `RequestBodyLimitLayer` (`SEC-06`) protects every route from
  arbitrarily-large request bodies.
- **`h2` bumped 0.4.15 → 0.4.19** (lockfile-only version bump, not a
  `deny.toml` ignore): resolves `RUSTSEC-2026-0258`, in which `h2`
  queued empty `DATA` frames without limit, risking unbounded memory
  growth or a length-overflow panic. Reached transitively via
  `hyper` ← `axum` / `axum-server` / `hyper-rustls` / `reqwest`.
- **`[graph] all-features = true`** (`REG-7`) in `deny.toml`: the
  cargo-deny advisory/license/bans gate now resolves every
  feature-gated subgraph, including the `storage-pg` path the Docker
  image ships (`STORAGE_FEATURE=storage-pg` by default in
  `docker/Dockerfile`), instead of only the default-features graph.
  `cargo deny --workspace check` remains green with no new findings.

### Documentation

- Reference guides under `docs/`: an index (`README.md`) plus
  `HTTP-API.md` (every endpoint, media types, and the RFC-ACDP-0007
  error envelope), `AUTHENTICATION.md` (DID challenge-response, JWT
  claims, HS256 vs EdDSA/JWKS, token revocation, cross-issuer
  revocation federation), `CONFIGURATION.md` (the full config tree and
  startup validation), `MULTI-TENANCY.md` (tenant resolution and strict
  mode), and `WEBHOOKS.md` (event payloads and the signature scheme).
- `ARCHITECTURE.md` and `OPERATIONS.md` refreshed to match the current
  code (crates.io `acdp` dependency, EdDSA/JWKS, revocation federation,
  multi-tenancy, admin endpoints, rate limiting). Protocol-level material
  links to the `acdp` library docs rather than being restated.
- `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` corrected to reflect
  that `acdp` is consumed from crates.io (no sibling path dependency) and
  the current auth/hardening surface.
