# Architecture

A condensed view of how the crates fit together. The full design lives in
[`plans/acdp-registry-rs-design.md`](../plans/acdp-registry-rs-design.md).

```
                       ┌────────────────────────┐
                       │   acdp (path dep)      │
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
            │  │ Postgres   │ │ SQLite     │ │ DID + JWT         │
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

## Storage trait

`ExtendedRegistryStore: acdp::registry::RegistryStore + Send + Sync` adds three
async methods:

- `list_contexts(limit, cursor, requester) -> Page<FullContext>` — admin /
  debug pagination, visibility-filtered.
- `health() -> ()` — ping the backend.
- `migrate() -> ()` — apply pending migrations at startup.

The sync `RegistryStore` methods inherited from `acdp` are required so the
upstream `RegistryServer::publish_verified` algorithm runs unchanged. The
Postgres and SQLite implementations bridge to async sqlx via
`tokio::task::block_in_place + Handle::current().block_on(...)`.

## Publish pipeline

`POST /contexts` runs:

1. Body size check vs `config.limits.max_payload_bytes`.
2. JSON deserialization into `acdp::types::publish::PublishRequest`.
3. `RegistryServer::publish_verified(req, idempotency_key, resolver)`:
   - schema validation (step 1 of RFC-ACDP-0003 §2.1)
   - payload + embedded size (steps 2–3)
   - content-hash recomputation (step 4)
   - algorithm + key-id binding (steps 5–6)
   - DID resolution + signature verification (steps 7–8)
   - atomic `commit_publish` — assign identifiers, insert body,
     mark predecessor superseded, record idempotency (steps 9–13).
4. Webhook event (`context.published`) is emitted on success.

In playground mode the binary calls `publish_unverified_for_tests` instead,
which stops after step 6.

## Auth

The challenge-response flow ends in an HS256 JWT bound to the agent DID. The
signing input for the challenge is namespaced so a content-hash signature
cannot be replayed as a challenge response and vice versa:

```
acdp-registry-auth:v1:{nonce}:{agent_id}:{registry_authority}:{expires_at_unix}
```

JWT claims:

```json
{
  "iss": "did:web:registry.example.com",
  "sub": "did:web:agents.example.com:my-agent",
  "jti": "<uuid-v4>",
  "iat": 1748000000,
  "exp": 1748003600,
  "acdp": {
    "registry": "registry.example.com",
    "key_id":   "did:web:agents.example.com:my-agent#key-1"
  }
}
```

The validator checks `iss`, `exp` (with 30 s leeway), and the `acdp.registry`
binding.

## Visibility

Visibility enforcement is centralized in `RegistryServer::can_retrieve` (for
retrieval) and `RegistryStore::search`'s `can_surface_in_search` (for search).
Both endpoints share the same RFC-ACDP-0008 §4.5 predicate — handlers must
never reimplement it.
