# acdp-registry-rs

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue)](Cargo.toml)

Reference **registry** implementation for the
[Agent Context Distribution Protocol](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol)
v0.1.0 through v0.5.0. Implements the `acdp-registry-core` and
`acdp-registry-discovery` profiles on top of
[`acdp`](https://github.com/agentcontextdistributionprotocol/acdp-rs) —
plus, as the corresponding config sections are enabled: the ACDP 0.2.0
trust-hardening surface (the `acdp-registry-receipts` profile — signed,
atomically-persisted publish receipts, RFC-ACDP-0010 — self-certifying
`did:key` producers, and a self-hosted `/.well-known/did.json`,
see [docs/RECEIPTS.md](docs/RECEIPTS.md)), the 0.3.0 lifecycle,
transparency-log, and head-receipt profiles, and 0.4.0 witness cosignature
aggregation (RFC-ACDP-0015). Version-gated `anchors` acceptance
(RFC-ACDP-0016, Draft) is unconditional — every deployment advertises
`acdp_version >= 0.5.0` and accepts well-formed anchors on every publish,
see [docs/HTTP-API.md](docs/HTTP-API.md).

## What you get

- **RFC-ACDP-0003-conformant publish pipeline** — full DID-resolution +
  signature verification + lineage coherence + atomic commit.
- **Pluggable storage** — Postgres (production), SQLite (dev / CI), and an
  in-memory backend, behind a unified `ExtendedRegistryStore` trait.
- **DID-bound authentication** — challenge / response over Ed25519, short-lived
  JWTs (HS256 or EdDSA with a published JWKS), token revocation, anonymous
  public reads opt-in.
- **Multi-tenancy** — tenant-scoped publish / retrieve / search via a signed JWT
  `tenant` claim, with an optional strict mode.
- **Cross-registry resolution** — foreign `ctx_id`s are resolved against their
  home registry (public-only, SSRF-guarded).
- **Signed receipts & lifecycle** — RFC-ACDP-0010 publish receipts and head
  receipts, plus RFC-ACDP-0013 retract/republish lifecycle events.
- **Transparency log** — RFC-ACDP-0012 append-only Merkle log with signed
  checkpoints, inclusion/consistency proofs, and RFC-ACDP-0015 witness
  cosignature aggregation.
- **HMAC-signed webhooks** — `context.published`, `context.retrieved`,
  `search.executed`.
- **Abuse controls & observability** — per-IP and global `/auth/*` rate
  limiting, and an optional Prometheus `/metrics` endpoint.
- **Playground mode** — a runtime config flag (`[playground] enabled = true`,
  compiled into every build) that skips DID verification for hands-on demos;
  never enable in production. Only its admin routes are compile-gated behind
  the `playground` Cargo feature.

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
| `storage.backend`                 | `ACDP_REGISTRY_STORAGE__BACKEND`            | `"postgres"`, `"sqlite"`, or `"memory"`. |
| `storage.postgres_url`            | `ACDP_REGISTRY_STORAGE__POSTGRES_URL`       | Required when `backend = "postgres"`. |
| `auth.jwt_secret`                 | `ACDP_REGISTRY_AUTH__JWT_SECRET`            | Base64-encoded ≥32-byte secret. |
| `webhook.url`                     | `ACDP_REGISTRY_WEBHOOK__URL`                | HMAC-signed POST target. |
| `playground.enabled`              | `ACDP_REGISTRY_PLAYGROUND__ENABLED`         | Skips DID verification — dev only. |

## HTTP surface

Selected routes (the full surface, including request/response shapes, is in
[docs/HTTP-API.md](docs/HTTP-API.md)):

| Method | Path                              | Notes |
|--------|-----------------------------------|-------|
| GET    | `/.well-known/acdp.json`          | Capabilities document. |
| GET    | `/.well-known/jwks.json`          | JWKS (EdDSA public key; empty for HS256). |
| GET    | `/.well-known/did.json`           | Registry DID document (when a receipt key is configured). |
| GET    | `/healthz`                        | Storage liveness. |
| GET    | `/metrics`                        | Prometheus metrics (when `metrics.enabled`). |
| POST   | `/contexts`                       | Publish (full RFC-ACDP-0003 §2.1 pipeline). |
| GET    | `/contexts/{ctx_id}`              | Retrieve full context. |
| GET    | `/contexts/{ctx_id}/body`         | Retrieve body only. |
| GET    | `/contexts/search`                | Keyword + filter search. |
| POST   | `/contexts/{ctx_id}/retract`      | Producer retraction (RFC-ACDP-0013). |
| POST   | `/contexts/{ctx_id}/republish`    | Producer republish (RFC-ACDP-0013). |
| GET    | `/lineages/{lineage_id}`          | Full lineage (visibility-filtered). |
| GET    | `/lineages/{lineage_id}/current`  | Newest non-superseded version. |
| GET    | `/log/checkpoint`                 | Signed transparency-log checkpoint (RFC-ACDP-0012). |
| GET    | `/log/proof`                      | Inclusion / consistency proofs. |
| GET    | `/log/entries`                    | Log leaves (visibility-filtered). |
| POST   | `/auth/challenge`                 | Issue a nonce for DID challenge-response (when `auth.enabled`). |
| POST   | `/auth/token`                     | Verify signed challenge → JWT (when `auth.enabled`). |
| POST   | `/auth/token/revoke`              | Revoke your own token by `jti` (when `auth.enabled`). |
| GET    | `/admin/status`                   | Operational snapshot (admin bearer). |
| GET    | `/admin/lineages/{id}/audit`      | On-demand lineage integrity audit (admin bearer). |
| POST   | `/admin/contexts/{id}/retract`    | Admin retraction (admin bearer). |
| POST   | `/admin/contexts/{id}/republish`  | Admin republish (admin bearer). |
| GET    | `/admin/contexts`                 | Compile-gated by `playground` (admin bearer). |
| POST   | `/admin/pinned-keys/reload`       | Compile-gated by `playground` (admin bearer). |

Visibility (`public` / `restricted` / `private`) is enforced server-side per
RFC-ACDP-0008 §4.5; authenticated callers identify themselves via
`Authorization: Bearer <jwt>`. Full request/response shapes, error envelope,
auth flow, config, and ops are documented under [`docs/`](docs/README.md).

When `auth.enabled = false`, the `/auth/challenge`, `/auth/token`, and
`/auth/token/revoke` routes are not mounted, and any `Authorization` header is ignored — every caller
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
    --no-default-features --features storage-memory            # In-memory
cargo build --release -p acdp-registry-server                   \
    --features storage-sqlite,playground                       # Playground
```

CI exercises every combination on every commit.

## License

Dual-licensed under either of

- Apache License, Version 2.0
- MIT License

at your option. See [LICENSE](LICENSE).
