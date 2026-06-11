# Security Policy

## Supported versions

`acdp-registry-rs` is pre-1.0; only the current release line is supported.

## Reporting a vulnerability

Please report security issues privately via GitHub's **security advisory**
workflow (`Security` → `Report a vulnerability`) rather than opening a public
issue. We aim to acknowledge reports within 72 hours.

## Hardening guidance

- Always set a real `ACDP_REGISTRY_AUTH__JWT_SECRET` in production (≥32-byte
  base64-encoded random material). With auth enabled and HS256, the startup
  validator refuses to boot on an empty secret — the random process-lifetime
  fallback requires an explicit `auth.allow_ephemeral_secret = true` and is for
  local development only (its tokens do not survive a restart). The literal
  `changeme` is always rejected.
- For federated deployments, prefer EdDSA (`auth.jwt_signing_alg = "EdDSA"`) so
  peers verify your tokens against the public key at `/.well-known/jwks.json`
  instead of a shared secret. See [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).
- Run behind a TLS-terminating proxy. A non-loopback `bind` without TLS or auth
  refuses to start unless `registry.allow_public_bind = true`. Outbound
  cross-registry resolution and webhook delivery require HTTPS — `acdp`'s
  `SsrfPolicy` rejects HTTP and private/internal authorities.
- Keep `auth.anonymous_public_reads = false` unless the registry is meant to
  serve world-readable public contexts; otherwise require a bearer for reads.
  On multi-tenant deployments set `auth.require_tenant = true` so a request that
  resolves to no tenant is denied rather than served unscoped
  (see [docs/MULTI-TENANCY.md](docs/MULTI-TENANCY.md)).
- Set `auth.admin_tokens` to gate `/admin/*`; an empty list disables those
  routes entirely. Distribute admin tokens out of band.
- Leave the per-agent rate limits (`limits.publish_rate_per_minute`,
  `limits.challenge_rate_per_minute`) enabled; front multi-replica deployments
  with a shared/proxy limiter for a global bound.
- Revoke compromised tokens with `POST /auth/token/revoke` instead of rotating
  the signing key when a full rotation is too disruptive.
- Restrict the Postgres role to the application database — the migrations are
  the source of truth for the schema; do not let the registry user create
  extensions or alter system tables.
- Disable `playground` mode in any environment that touches non-test data. The
  feature exists for hands-on demos; it skips DID verification on publish.
- Pin your container image by digest, not by tag.
