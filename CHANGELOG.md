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
  `pub-*` and `ret-*` fixtures from `ACDP_SPEC_DIR` when present;
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

- **Pinned conformance spec SHA** (`REG-2`) adopted in
  `.github/workflows/ci.yml`: now `31cf8743b62debe2c7c8572ce3a3a0b7ca5ad099`.
  Annotation-only at this pin: RFC-ACDP-0015 promoted Draft → **Final**
  (0.4.0), the `invalid_witness_cosignature` error code promoted
  Proposed → **Stable**, and the `acdp-log-witness` profile promoted
  Draft → **Final**. No fixture family, fixture shape, `id`, `request`,
  or `expected` field changed; the conformance harness runs unchanged
  against the new pin (`16 passed; 0 failed`, 4 exchanges replayed).
- **SHA-pinned credential-bearing workflow actions** (`REG-8`): every
  third-party action in `docker.yml` and `release-plz.yml` (plus
  `peter-evans/repository-dispatch` in `notify-website.yml`) now
  resolves at an immutable 40-hex commit SHA with a `# vX.Y.Z` (or
  `# stable` for `dtolnay/rust-toolchain`, a selector rather than a
  version) comment, matching `acdp-rs`'s two-tier pinning posture:
  `docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f
  # v3.12.0`, `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9
  # v3.7.0`, `docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051
  # v5.10.0`, `docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  # v6.19.2` (both call sites), `dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30
  # stable` (matches `acdp-rs`'s own current pin verbatim),
  `MarcoIeni/release-plz-action@2eb1d8bcb770b4c48ccfaad919734b38b51958c9
  # v0.5.131`, and `peter-evans/repository-dispatch@28959ce8df70de7be546dd1250a005dd32156697
  # v4.0.1`. First-party `actions/checkout@v4` stays tag-pinned
  (deliberate, matching the sibling's first-party tier), and the
  `acdp-ci/.github/workflows/*@v1` reusable-workflow refs are
  untouched (pinning those would break family propagation).
  `docker/login-action`, the pushing `docker/build-push-action` call,
  `MarcoIeni/release-plz-action`, and `dtolnay/rust-toolchain` are not
  exercised by this PR's own CI (gated off `pull_request` events or
  behind `on: push: branches: [main]`). `docker/login-action`,
  `docker/build-push-action`, and `MarcoIeni/release-plz-action` were
  each independently re-verified against their tag via `gh api`.
  `dtolnay/rust-toolchain` is the one deliberate exception: it is
  pinned to match `acdp-rs`'s own current SHA verbatim rather than to
  whatever `@stable` resolves to today (the two diverge — see the
  Approach section of `plans/reg2-reg5-reg6-reg8-reg9-wave4.md`
  Phase 9), so verifying it against `@stable` would show a mismatch
  by design; parity with the sibling's pin is the actual check.
- **Retired stale supply-chain narration** (`REG-9`): the
  `Cargo.toml` comment above the `acdp` dependency wrongly described a
  0.5.3-era, per-sub-crate version mix; it now states that `acdp`
  0.8.1 is a facade crate over eleven sub-crates published to
  crates.io and kept in lockstep at the same version, without naming
  individual sub-crate versions. `deny.toml`'s dead `allow-git` entry
  for the `acdp-rs` repo (a leftover from when `acdp` was git-sourced)
  is removed, which silences a persistent `cargo deny`
  `unmatched-source` warning. The one behavioral consequence: any
  future git dependency on `acdp-rs` is now a `cargo deny` finding
  instead of a silent allowance.
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
- **`axum-server` bumped 0.7 → 0.8** (`REG-6`): removes `rustls-pemfile`
  from the dependency graph entirely (0.8.0 replaced it with
  `rustls-pki-types`'s `PemObject` trait), so the `RUSTSEC-2025-0134`
  ignore entry is deleted from `deny.toml` rather than merely
  satisfied. `axum_server::Handle` is now generic over the bind
  address (`Handle<A: Address>`); `main.rs` annotates its one
  `Handle::<SocketAddr>::new()` construction site (shared by both the
  non-TLS and TLS-capable serve paths) and the `spawn_shutdown_watcher`
  signature accordingly. No router or crypto-provider changes —
  `tls-rustls` still resolves to `rustls/aws-lc-rs`.

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
