# Operations Guide

Running `acdp-registry` in production. See [CONFIGURATION.md](CONFIGURATION.md)
for the full config reference and [AUTHENTICATION.md](AUTHENTICATION.md) for the
auth/federation model.

## Deploying with Docker

```bash
cd docker
docker compose up -d --build
```

The compose file boots Postgres + the registry server. Configuration is read
from `docker/config.docker.toml` (mounted read-only); the Postgres URL comes
from `ACDP_REGISTRY_STORAGE__POSTGRES_URL`. The image is built with the
`storage-pg` feature (`STORAGE_FEATURE` build arg), and `acdp` is pulled from
crates.io, so the build context is just this repo.

**Secrets** are sourced from the environment or a sibling `.env` file via
`${VAR:-default}` substitution. The placeholder default for the JWT secret is
`changeme` — the startup validator **refuses to launch** with that literal, so
set a real one before promoting beyond a disposable demo:

```bash
echo "ACDP_REGISTRY_JWT_SECRET=$(openssl rand -base64 32)" >> docker/.env
```

For multi-host deployments, put `acdp-registry` behind a TLS-terminating proxy
(Caddy, Nginx, ALB). See [RAILWAY.md](../docker/RAILWAY.md) for a Railway recipe.

## TLS

The `[registry.tls]` block can serve HTTPS directly via rustls, but the
recommended topology is to **terminate TLS upstream** and let the registry serve
plain HTTP behind it — cert rotation without restarts, standard ops. The example
`port = 8443` is a hint that HTTPS is expected at the edge; the binary serves
plain HTTP on any port.

Note the asymmetry: cross-registry resolution and webhook delivery are
**outbound** and require HTTPS (the `acdp` `SsrfPolicy` refuses HTTP and
private/internal authorities). That's independent of how you serve inbound
traffic.

### Binding a public interface

A non-loopback `bind` (e.g. `0.0.0.0`) with neither TLS nor auth enabled fails
startup unless you set `registry.allow_public_bind = true`. This is a guardrail
against accidentally exposing an unauthenticated registry — prefer enabling auth
or fronting with a proxy over flipping the flag.

## Configuration precedence

```
defaults  <  TOML file  <  ACDP_REGISTRY_* env vars
```

`ACDP_REGISTRY_<SECTION>__<FIELD>` uses a single underscore after the prefix and
double underscores between nesting levels:

```bash
export ACDP_REGISTRY_STORAGE__POSTGRES_URL="postgres://acdp:acdp@db:5432/acdp"
export ACDP_REGISTRY_AUTH__JWT_SECRET="$(openssl rand -base64 32)"
export ACDP_REGISTRY_WEBHOOK__URL="https://example.com/hooks/acdp"
export ACDP_REGISTRY_WEBHOOK__SECRET="$(openssl rand -base64 32)"
export ACDP_REGISTRY_WEBHOOK__ENABLED="true"
```

## Migrations

Migrations run automatically at startup and are idempotent — restarting an
already-migrated database is a no-op. To add one, drop a new sequential SQL file
into `crates/acdp-registry-<backend>/migrations/` and let CI cover the upgrade
path. Never edit an applied migration.

## Admin endpoints

Bearer-gated against `auth.admin_tokens` (constant-time compare; an empty list
disables every admin route). Generate tokens out of band and distribute them to
operators / monitoring.

- `GET /admin/status` — always shipped. An operational snapshot: storage health,
  idempotency record count, webhook queue depth, configured revocation feeds,
  and migration state. Good for a readiness probe richer than `/healthz`. Shape
  in [HTTP-API.md](HTTP-API.md#get-adminstatus).
- `GET /admin/contexts`, `POST /admin/pinned-keys/reload` — only in builds with
  the `playground` Cargo feature.

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://registry.example.com/admin/status
```

## JWKS and key distribution

With `auth.jwt_signing_alg = "EdDSA"`, the registry's Ed25519 public key is
published at `GET /.well-known/jwks.json` so federated peers verify your tokens
without a shared secret. With the default `HS256`, that endpoint returns an
empty key set and the symmetric `jwt_secret` is never exposed. See
[AUTHENTICATION.md](AUTHENTICATION.md#signing-algorithms).

## Revocation federation

This registry is a revocation **consumer**: it polls peers' feeds and mirrors
their revocations locally. Configure peers with `[[auth.revocation_feeds]]`
(`issuer`, `feed_url`, `admin_token`, `poll_seconds`). Cursors are durable
(unix-ms) and advance only when an entire page applies cleanly, so a restart or
a mid-page failure replays rather than skips. `GET /admin/status` reports the
configured feed count. Full behavior:
[AUTHENTICATION.md](AUTHENTICATION.md#cross-issuer-revocation-federation).

## Cross-registry federation

With `registry.cross_registry_resolution = true`, a `GET /contexts/{ctx_id}` for
a foreign authority is resolved against that registry **anonymously** (no
caller-credential forwarding), so only remote `public` contexts are surfaced.
The `acdp` `SsrfPolicy` (see [acdp-rs · Security Model][acdp-security]) rejects
private/internal authorities with `502 cross_registry_resolution_failed`. Set
the key to `false` to return `404` for foreign ids instead.

[acdp-security]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md

## Rate limiting

Two per-agent, per-process, in-memory token buckets ship today:
`limits.publish_rate_per_minute` on `POST /contexts` and
`limits.challenge_rate_per_minute` on `POST /auth/challenge` (both default 60,
`0` disables; `429` + `Retry-After` when drained). Because they're per-process,
front a multi-replica deployment with a shared limiter (or proxy-level limits)
for a global bound.

## Webhooks

Receivers verify `X-ACDP-Signature` (GitHub-compatible HMAC-SHA256 over the raw
body). Delivery is non-blocking with exponential backoff (250 ms → cap 15 s) up
to `webhook.max_retries`; a full queue drops events with a warn. Full reference:
[WEBHOOKS.md](WEBHOOKS.md).

## Observability

The binary emits JSON-structured `tracing` logs. The default filter is
`info,acdp=info,acdp_registry=info`; override with `RUST_LOG`. Every request
carries an `x-request-id` header (UUIDv4 if absent on input) propagated
downstream. At startup it logs the authority, port, storage backend, and
playground flag; on bind it logs the listen address; on `SIGTERM`/`Ctrl-C` it
drains in-flight requests for up to 30 s before exiting.

There is no Prometheus `/metrics` endpoint yet. In the meantime, forward the
JSON logs and poll `GET /admin/status` for queue/idempotency/migration state.

## Backup and restore

Postgres: logical (`pg_dump`) or physical (`pg_basebackup`) backups as usual.
The `contexts.body_json` column is the canonical projection — `body_json` plus
`status` is enough to reconstruct every other index.

SQLite: stop the writer and copy the `.db`, `.db-wal`, and `.db-shm` files
atomically (or use the `.backup` command).

## Key rotation

- **HS256** — set a new `ACDP_REGISTRY_AUTH__JWT_SECRET` and restart. Outstanding
  tokens become invalid immediately; clients re-run challenge-response.
- **EdDSA** — rotate `auth.jwt_private_key_pem` (and optionally `jwt_kid`) and
  restart; the new public key is published at `/.well-known/jwks.json`.
  Outstanding tokens stop verifying once the old public key is gone — coordinate
  with federated verifiers that cache the JWKS (300 s `max-age`).

For targeted revocation without rotating the signing key, use
`POST /auth/token/revoke` (see [AUTHENTICATION.md](AUTHENTICATION.md#token-revocation)).
