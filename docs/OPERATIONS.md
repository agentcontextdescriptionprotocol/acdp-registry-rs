# Operations Guide

## Deploying with Docker

```bash
cd docker
docker compose up -d --build
```

The compose file boots Postgres + the registry server. Configuration is read
from `docker/config.docker.toml` (mounted read-only); the Postgres URL comes
from `ACDP_REGISTRY_STORAGE__POSTGRES_URL`.

For multi-host deployments, put `acdp-registry` behind a TLS-terminating
proxy (Caddy, Nginx, ALB). Cross-registry resolution requires HTTPS because
`acdp`'s `SsrfPolicy` refuses HTTP URLs.

## Configuration precedence

```
defaults  <  TOML file  <  ACDP_REGISTRY_* env vars
```

`ACDP_REGISTRY_<SECTION>__<FIELD>` uses double underscore as the level
separator. Example:

```bash
export ACDP_REGISTRY_STORAGE__POSTGRES_URL="postgres://acdp:acdp@db:5432/acdp"
export ACDP_REGISTRY_AUTH__JWT_SECRET="$(openssl rand -base64 32)"
export ACDP_REGISTRY_WEBHOOK__URL="https://example.com/hooks/acdp"
export ACDP_REGISTRY_WEBHOOK__SECRET="$(openssl rand -base64 32)"
export ACDP_REGISTRY_WEBHOOK__ENABLED="true"
```

## Migrations

Migrations run automatically at startup. They're idempotent — restarting an
already-migrated database is a no-op. To add a new migration, drop a new
sequential SQL file into `crates/acdp-registry-<backend>/migrations/` and let
CI cover the upgrade path. Never edit an applied migration.

## Webhooks

Receivers verify the `X-ACDP-Signature` header — same scheme as GitHub:

```
X-ACDP-Signature: sha256=<hex of HMAC-SHA256(secret, body_bytes)>
X-ACDP-Event:     context.published | context.retrieved | search.executed
Content-Type:     application/json
```

Failed deliveries retry with exponential backoff (capped at 15 s) up to
`webhook.max_retries`. The emitter never blocks the HTTP request.

## Observability

The binary emits JSON-structured `tracing` logs. The default filter is
`info,acdp=info,acdp_registry=info`; override with `RUST_LOG`. Every request
gets an `x-request-id` header (UUIDv4 if missing on input) that propagates
through to downstream calls.

For metrics, point an OpenTelemetry collector at the process — the
`tracing-subscriber` JSON output is structured well for forwarding via
`tracing-opentelemetry` if you want to add it.

## Backup and restore

Postgres deployments should use logical (`pg_dump`) or physical
(`pg_basebackup`) backups in the normal fashion. The `contexts.body_json`
column is the canonical projection — `body_json` plus `status` is enough to
reconstruct every other index.

SQLite deployments: stop the writer, copy the `.db`, `.db-wal`, and `.db-shm`
files atomically (or use the `.backup` SQLite command).

## Key rotation

The JWT secret can be rotated by setting `ACDP_REGISTRY_AUTH__JWT_SECRET` and
restarting. Outstanding tokens become invalid immediately; clients re-run the
challenge-response flow to obtain new tokens.
