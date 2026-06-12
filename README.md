# acdp-registry-rs

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue)](Cargo.toml)

Reference **registry** implementation for the
[Agent Context Distribution Protocol](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol)
v0.1.0 / v0.2.0. Implements the `acdp-registry-core` and
`acdp-registry-discovery` profiles on top of
[`acdp`](https://github.com/agentcontextdistributionprotocol/acdp-rs) —
plus, with a `[receipt]` signing key configured, the ACDP 0.2.0
trust-hardening surface: the `acdp-registry-receipts` profile (signed,
atomically-persisted publish receipts, RFC-ACDP-0010), self-certifying
`did:key` producers, and a self-hosted `/.well-known/did.json`
(see [docs/RECEIPTS.md](docs/RECEIPTS.md)).

## What you get

- **RFC-ACDP-0003-conformant publish pipeline** — full DID-resolution +
  signature verification + lineage coherence + atomic commit.
- **Pluggable storage** — Postgres (production) and SQLite (dev / CI), behind a
  unified `ExtendedRegistryStore` trait.
- **DID-bound authentication** — challenge / response over Ed25519, short-lived
  JWTs (HS256 or EdDSA with a published JWKS), token revocation, anonymous
  public reads opt-in.
- **Multi-tenancy** — tenant-scoped publish / retrieve / search via a signed JWT
  `tenant` claim, with an optional strict mode.
- **Cross-registry resolution** — foreign `ctx_id`s are resolved against their
  home registry (public-only, SSRF-guarded).
- **HMAC-signed webhooks** — `context.published`, `context.retrieved`,
  `search.executed`.
- **Playground mode** — compile-time + runtime feature that skips DID
  verification for hands-on demos.

## Repository layout

```
acdp-registry-rs/
├── Cargo.toml                      # workspace
├── crates/
│   ├── acdp-registry-types/        # config, wire types, errors
│   ├── acdp-registry-store/        # ExtendedRegistryStore trait
│   ├── acdp-registry-pg/           # Postgres backend
│   ├── acdp-registry-sqlite/       # SQLite backend (dev / test)
│   ├── acdp-registry-auth/         # DID challenge-response + JWT
│   ├── acdp-registry-webhook/      # HMAC-signed event emitter
│   ├── acdp-registry-core/         # axum router + handlers
│   └── acdp-registry-server/       # binary: `acdp-registry`
├── docker/                         # Dockerfile + docker-compose
├── config/                         # example TOML configs
└── docs/                           # reference docs (API, auth, config, ops)
```

See [`docs/`](docs/README.md) for architecture, the HTTP API, authentication,
configuration, multi-tenancy, webhooks, and operations.

## Quick start

### Local dev (SQLite)

```bash
# `acdp` is pulled from crates.io — no sibling checkout needed.
# Run with default config (SQLite under ./data/registry.db).
cargo run -p acdp-registry-server

# Or with a config file
ACDP_REGISTRY_CONFIG=config/registry.example.toml \
    cargo run -p acdp-registry-server
```

Then:

```bash
curl http://localhost:8443/.well-known/acdp.json
curl http://localhost:8443/healthz
```

### Production (Postgres + Docker)

```bash
cd docker
docker compose up --build
```

## Configuration

Configuration is loaded from a TOML file (`ACDP_REGISTRY_CONFIG` env var, or
`config/registry.example.toml`) and overridden by `ACDP_REGISTRY_<SECTION>__<FIELD>`
environment variables (double underscore separates levels). See
[`config/registry.example.toml`](config/registry.example.toml).

Selected fields:

| TOML key                          | Env var                                     | Notes |
|-----------------------------------|---------------------------------------------|-------|
| `registry.authority`              | `ACDP_REGISTRY_REGISTRY__AUTHORITY`         | Bare lowercase DNS name; also the `did:web` identifier. |
| `registry.port`                   | `ACDP_REGISTRY_REGISTRY__PORT`              | Default `8443`. |
| `storage.backend`                 | `ACDP_REGISTRY_STORAGE__BACKEND`            | `"postgres"` or `"sqlite"`. |
| `storage.postgres_url`            | `ACDP_REGISTRY_STORAGE__POSTGRES_URL`       | Required when `backend = "postgres"`. |
| `auth.jwt_secret`                 | `ACDP_REGISTRY_AUTH__JWT_SECRET`            | Base64-encoded ≥32-byte secret. |
| `webhook.url`                     | `ACDP_REGISTRY_WEBHOOK__URL`                | HMAC-signed POST target. |
| `playground.enabled`              | `ACDP_REGISTRY_PLAYGROUND__ENABLED`         | Skips DID verification — dev only. |

## HTTP surface

| Method | Path                              | Notes |
|--------|-----------------------------------|-------|
| GET    | `/.well-known/acdp.json`          | Capabilities document. |
| GET    | `/.well-known/jwks.json`          | JWKS (EdDSA public key; empty for HS256). |
| GET    | `/healthz`                        | Storage liveness. |
| POST   | `/contexts`                       | Publish (full RFC-ACDP-0003 §2.1 pipeline). |
| GET    | `/contexts/{ctx_id}`              | Retrieve full context. |
| GET    | `/contexts/{ctx_id}/body`         | Retrieve body only. |
| GET    | `/contexts/search`                | Keyword + filter search. |
| GET    | `/lineages/{lineage_id}`          | Full lineage (visibility-filtered). |
| GET    | `/lineages/{lineage_id}/current`  | Newest non-superseded version. |
| POST   | `/auth/challenge`                 | Issue a nonce for DID challenge-response (when `auth.enabled`). |
| POST   | `/auth/token`                     | Verify signed challenge → JWT (when `auth.enabled`). |
| POST   | `/auth/token/revoke`              | Revoke your own token by `jti` (when `auth.enabled`). |
| GET    | `/admin/status`                   | Operational snapshot (admin bearer). |
| GET    | `/admin/contexts`                 | Compile-gated by `playground` (admin bearer). |
| POST   | `/admin/pinned-keys/reload`       | Compile-gated by `playground` (admin bearer). |

Visibility (`public` / `restricted` / `private`) is enforced server-side per
RFC-ACDP-0008 §4.5; authenticated callers identify themselves via
`Authorization: Bearer <jwt>`. Full request/response shapes, error envelope,
auth flow, config, and ops are documented under [`docs/`](docs/README.md).

When `auth.enabled = false`, the `/auth/challenge` and `/auth/token` routes
are not mounted, and any `Authorization` header is ignored — every caller
is treated as anonymous, so the public/restricted/private gate runs against
`None`.

## Production TLS

The server's `[registry.tls]` block can serve HTTPS directly via `rustls`,
but the recommended production topology is to **terminate TLS upstream**
(Nginx, Caddy, an ALB) and let `acdp-registry` listen on plain HTTP behind
it. The example config's `port = 8443` is a hint that HTTPS is expected at
the edge; the binary itself happily serves plain HTTP on any port. Reasons:

- The DID-web SSRF policy in `acdp-rs` requires HTTPS for *outbound*
  resolution; that's separate from how the registry serves inbound
  traffic.
- TLS termination at the load balancer is the standard ops pattern, gives
  you cert rotation without restarting the registry, and decouples
  performance tuning from the protocol implementation.

For the **playground** profile (`--features storage-sqlite,playground`),
inbound HTTPS is convenient for cross-registry demos; set
`registry.tls.enabled = true` and point `cert_path` / `key_path` at a
self-signed cert.

## Running PG integration tests locally

The Postgres-backed integration suite (`tests/pg_integration.rs`) mirrors the
SQLite suite but exercises `PgStore`. It's gated on `ACDP_REGISTRY_TEST_PG_URL`
and skips cleanly when unset, so day-to-day `cargo test` is unaffected.

```bash
docker run --rm -d --name acdp-test-pg -p 5433:5432 \
  -e POSTGRES_USER=acdp -e POSTGRES_PASSWORD=acdp -e POSTGRES_DB=acdp_registry \
  postgres:16-alpine

ACDP_REGISTRY_TEST_PG_URL=postgres://acdp:acdp@localhost:5433/acdp_registry \
  cargo test -p acdp-registry-server \
  --no-default-features --features storage-pg \
  --test pg_integration

docker stop acdp-test-pg
```

Tests run serially (`#[serial_test::serial]`) and truncate the registry
tables between cases.

## Build matrix

```bash
cargo build --release                                          # default = SQLite
cargo build --release -p acdp-registry-server                   \
    --no-default-features --features storage-pg                # Postgres only
cargo build --release -p acdp-registry-server                   \
    --features storage-sqlite,playground                       # Playground
```

CI exercises every combination on every commit.

## License

Dual-licensed under either of

- Apache License, Version 2.0
- MIT License

at your option. See [LICENSE](LICENSE).
