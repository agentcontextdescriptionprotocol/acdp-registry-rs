# Security Policy

## Supported versions

`acdp-registry-rs` is pre-1.0; only the current release line is supported.

## Reporting a vulnerability

Please report security issues privately via GitHub's **security advisory**
workflow (`Security` → `Report a vulnerability`) rather than opening a public
issue. We aim to acknowledge reports within 72 hours.

## Hardening guidance

- Always set `ACDP_REGISTRY_AUTH__JWT_SECRET` in production (≥32-byte
  base64-encoded random material). The default ephemeral key is regenerated on
  every restart, which invalidates outstanding tokens.
- Run behind a TLS-terminating proxy. Cross-registry resolution requires HTTPS
  because `acdp`'s `SsrfPolicy` rejects HTTP.
- Restrict the Postgres role to the application database — the migrations are
  the source of truth for the schema; do not let the registry user create
  extensions or alter system tables.
- Disable `playground` mode in any environment that touches non-test data. The
  feature exists for hands-on demos; it skips DID verification on publish.
- Pin your container image by digest, not by tag.
