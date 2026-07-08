# Architecture

How the 8-crate workspace fits together, and the path a request takes through
it. The per-topic docs linked below go deeper on each subsystem.

```
                       ┌────────────────────────┐
                       │  acdp (crates.io dep)  │
                       │  types / crypto / did  │
                       │  validator + server    │
                       └───────┬────────────────┘
                               │
            ┌──────────────────┴─────────────────────┐
            │                                        │
   ┌────────▼────────────┐               ┌───────────▼────────────┐
   │ acdp-registry-types │               │ acdp-registry-store    │
   │  config / errors    │               │  trait Extended…       │
   │  wire / events      │               └───────────┬────────────┘
   └────────┬────────────┘                           │
            │                                        │
            │      ┌─────────────────┬───────────────┤
            │      │                 │               │
            │  ┌───▼────────┐ ┌──────▼─────┐ ┌───────▼───────────┐
            │  │ -pg        │ │ -sqlite    │ │ -auth             │
            │  │ Postgres   │ │ SQLite     │ │ DID + JWT + revoke│
            │  └───┬────────┘ └──────┬─────┘ └───────┬───────────┘
            │      │                 │               │
            │      │  ┌──────────────▼───┐           │
            │      │  │ -webhook         │           │
            │      │  │ HMAC POSTs       │           │
            │      │  └──────────────────┘           │
            │      │                                 │
            │      └────────────────┬────────────────┘
            │                       │
            │              ┌────────▼────────────┐
            │              │ acdp-registry-core   │
            │              │ axum + handlers      │
            │              │ (generic over S)     │
            │              └────────┬────────────┘
            │                       │
            │              ┌────────▼────────────┐
            └──────────────► acdp-registry-server│
                           │ binary; picks S via │
                           │ Cargo features      │
                           └─────────────────────┘
```

The protocol library [`acdp`](https://crates.io/crates/acdp) is consumed as a
**crates.io** dependency (not a path dep) — `types`, crypto, `did` resolution,
the publish validator, and the `RegistryServer` algorithm all live there. This
repo adds storage backends, HTTP wiring, auth, tenancy, webhooks, and the
binary on top.

## Storage trait

`ExtendedRegistryStore: acdp::registry::RegistryStore + Send + Sync` adds, on
top of the upstream sync trait:

- `list_contexts(limit, cursor, requester) -> Page<FullContext>` —
  visibility-filtered admin/debug pagination.
- `health()` — ping the backend (drives `/healthz`).
- `migrate()` — apply pending migrations at startup.
- Tenant binding — `set_tenant_of_ctx` / `tenant_of_ctx` / `tenants_of_ctxs`,
  plus the durable revocation cursors used by federation. See
  [MULTI-TENANCY.md](MULTI-TENANCY.md).

The sync `RegistryStore` methods inherited from `acdp` are required so the
upstream `RegistryServer::publish_verified` algorithm runs unchanged. The
Postgres and SQLite implementations bridge to async sqlx via
`tokio::task::block_in_place + Handle::current().block_on(...)`; HTTP handlers
wrap the sync calls in `tokio::task::spawn_blocking`.

`acdp-registry-core` is **generic** over `S`, not boxed — the server binary
monomorphizes the type when it builds `Arc<AppState<S>>`. The storage backend is
chosen at **compile time** by the `acdp-registry-server` Cargo features; the
`storage.backend` config key must agree with the built binary.

## Request lifecycle

Every request passes through the middleware stack assembled in `build_router()`
(`crates/acdp-registry-core/src/lib.rs`), outermost first: `x-request-id`
assignment + propagation → request metrics (when `metrics.enabled`; FEAT-10) →
`TraceLayer` → 30 s `TimeoutLayer` → `RequestBodyLimitLayer` (capped at
`limits.max_payload_bytes`) → CORS. The `/auth/*` routes additionally carry the
FEAT-06 per-IP/global rate-limit `route_layer`, and ACDP data and auth routes
carry an `application/acdp+json` response-header layer; an outermost
`if_not_present` layer stamps that media type on middleware-generated errors
(413/408) that bypass the per-route layer. Full endpoint reference:
[HTTP-API.md](HTTP-API.md).

## Publish pipeline

The protocol-critical part of `POST /contexts` is **not** implemented here — it
is `acdp`'s `RegistryServer::publish_verified`, the ordered RFC-ACDP-0003 §2.1
algorithm (schema/size validation → `content_hash` recompute → algorithm + DID
key resolution → signature verification → atomic commit). Its one invariant —
*never persist a context before its signature is verified* — and the full step
list are documented in [acdp-rs · Implementing a Registry][acdp-registry]. We
reuse it unchanged and add storage adapters, **not** a parallel validator.

What this registry wraps around that call:

1. Body-size cap (the `RequestBodyLimitLayer`, uniformly across routes).
2. JSON deserialization into `acdp::types::publish::PublishRequest`.
3. Per-agent rate-limit check (`limits.publish_rate_per_minute`) — *before* the
   expensive verify.
4. Tenant resolution for the write (`tenant_for_publish`; see
   [MULTI-TENANCY.md](MULTI-TENANCY.md)).
5. → `RegistryServer::publish_verified(req, idempotency_key, resolver)`.
6. Receipt minting and the transparency-log leaf append, when `[receipt]` /
   `[log]` are enabled (see [RECEIPTS.md](RECEIPTS.md)).
7. A `context.published` webhook on success (see [WEBHOOKS.md](WEBHOOKS.md)).

DID verification reuses `acdp`'s `WebResolver` (LRU-cached, SSRF-policy-gated —
see [acdp-rs · Security Model][acdp-security]) for **both** publish and
auth-challenge verification; there is intentionally only one resolver per server
instance. In playground mode the binary calls `publish_unverified_for_tests`
instead, skipping the §2.1 signature-verification steps — a protocol violation
reserved for demos.

[acdp-registry]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/registry.md
[acdp-security]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md

## Auth

A DID challenge-response flow mints a short-lived JWT bound to the agent DID and
this registry's authority; the validator checks the signature, `exp` (with
`auth.token_leeway_seconds` leeway), the `aud` / `acdp.registry` binding, and the
revocation store. This flow is registry-specific (it is not part of the `acdp`
protocol library). The full treatment — sequence, JWT claims, HS256 vs EdDSA,
revocation, cross-issuer federation — is in
[AUTHENTICATION.md](AUTHENTICATION.md).

## Visibility

Visibility enforcement is centralized: `RegistryServer::can_retrieve` for
single-object retrieval, and the SQL `WHERE` clause each store builds for
search (DESIGN-01 pushed the predicate into SQL on both backends). Both
implement the same RFC-ACDP-0008 §4.5 rule — handlers must never reimplement
it. When you add an endpoint that returns ACDP-typed data, route errors through
`RegistryError` (so the wire envelope lands automatically) and cover the
visibility rule in those shared paths, not in the handler.

## Crate map

| Crate | Role |
|-------|------|
| `acdp-registry-types`  | Leaf: config (TOML+env), errors with HTTP projection, webhook events. |
| `acdp-registry-store`  | `ExtendedRegistryStore` trait — extends `acdp::registry::RegistryStore`. |
| `acdp-registry-pg`     | Postgres backend (native `TIMESTAMPTZ` / `TEXT[]` / `JSONB` / `tsvector`). |
| `acdp-registry-sqlite` | SQLite backend (FTS5 virtual table; arrays as JSON TEXT). |
| `acdp-registry-auth`   | DID challenge → JWT (HS256/EdDSA), revocation store + cross-issuer pollers. |
| `acdp-registry-webhook`| HMAC-SHA256-signed POSTs over a bounded mpsc channel. |
| `acdp-registry-core`   | axum router + handlers, generic over `S`. |
| `acdp-registry-server` | Binary (`acdp-registry`); features select the storage backend. |
