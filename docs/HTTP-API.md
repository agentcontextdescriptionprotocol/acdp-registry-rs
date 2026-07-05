# HTTP API

The complete inbound surface of `acdp-registry`. Routes are assembled in
`build_router()` (`crates/acdp-registry-core/src/lib.rs`); handlers live under
`crates/acdp-registry-core/src/handlers/`.

## Endpoint summary

| Method | Path | Auth | Built when |
|--------|------|------|------------|
| GET  | `/.well-known/acdp.json`         | none        | always |
| GET  | `/.well-known/jwks.json`         | none        | always |
| GET  | `/.well-known/did.json`          | none        | always (404 unless `[receipt]` configured) |
| GET  | `/healthz`                       | none        | always |
| POST | `/contexts`                      | producer signature | always |
| GET  | `/contexts/{ctx_id}`             | optional bearer | always |
| GET  | `/contexts/{ctx_id}/body`        | optional bearer | always |
| GET  | `/contexts/search`               | optional bearer | always |
| POST | `/contexts/{ctx_id}/retract`     | producer-signed event | always (501 unless `lifecycle.enabled`) |
| POST | `/contexts/{ctx_id}/republish`   | producer-signed event | always (501 unless `lifecycle.enabled`) |
| GET  | `/lineages/{lineage_id}`         | optional bearer | always |
| GET  | `/lineages/{lineage_id}/current` | optional bearer | always |
| POST | `/auth/challenge`                | none        | `auth.enabled` |
| POST | `/auth/token`                    | challenge signature | `auth.enabled` |
| POST | `/auth/token/revoke`             | bearer      | `auth.enabled` |
| GET  | `/admin/status`                  | admin bearer | always |
| GET  | `/admin/lineages/{lineage_id}/audit` | admin bearer | always |
| GET  | `/admin/contexts`                | admin bearer | `playground` feature |
| POST | `/admin/pinned-keys/reload`      | admin bearer | `playground` feature |

The `/auth/*` routes are mounted at runtime only when `auth.enabled = true`. The
two `/admin/{contexts,pinned-keys}` routes are compiled in only with the
`playground` Cargo feature; `/admin/status` always ships.

## Media types and middleware

Every ACDP data and auth endpoint returns `application/acdp+json` — on both
success bodies and error envelopes (RFC-ACDP-0007 §4). `/.well-known/jwks.json`
returns `application/jwk-set+json`; `/healthz` and `/admin/*` return plain
operational JSON.

All requests pass through, outermost first: request-id assignment
(`x-request-id`, a UUIDv4 minted if absent and propagated downstream),
`TraceLayer`, a 30 s `TimeoutLayer`, a `RequestBodyLimitLayer` capped at
`limits.max_payload_bytes` (so even unauthenticated `/auth/*` calls can't push
oversized JSON), and the CORS layer (off unless `registry.cors.allowed_origins`
is populated).

---

## Metadata

### `GET /.well-known/acdp.json`

Capabilities document. `Cache-Control: max-age=300`.

```json
{
  "acdp_version": "0.1.0",
  "registry_did": "did:web:registry.example.com",
  "supported_signature_algorithms": ["ed25519"],
  "supported_did_methods": ["did:web"],
  "profiles": ["acdp-registry-core", "acdp-registry-discovery"],
  "limits": {
    "max_payload_bytes": 1048576,
    "max_embedded_bytes": 65536,
    "idempotency_key_ttl_seconds": 86400
  }
}
```

`supported_did_methods` mirrors `auth.did_methods`; `profiles` mirrors
`registry.profiles`; `limits` mirrors the `[limits]` config section.

With a `[receipt]` signing key configured (ACDP 0.2.0), `acdp_version`
becomes `"0.2.0"` and `profiles` additionally carries
`"acdp-registry-receipts"`. `supported_did_methods` may include `"did:key"`
when enabled via `auth.did_methods`.

### `GET /.well-known/jwks.json`

JSON Web Key Set for verifying this registry's JWTs. `Cache-Control:
max-age=300`, `Content-Type: application/jwk-set+json`.

- **EdDSA mode** — one OKP/Ed25519 public key:
  ```json
  { "keys": [ { "kty": "OKP", "crv": "Ed25519", "use": "sig",
                "alg": "EdDSA", "kid": "<fingerprint-or-config>", "x": "<base64url>" } ] }
  ```
- **HS256 mode** — `{ "keys": [] }`. Symmetric secrets are never published.

See [AUTHENTICATION.md](AUTHENTICATION.md#signing-algorithms).

### `GET /.well-known/did.json` *(ACDP 0.2.0)*

The registry's own `did:web` DID document, generated from `[receipt]` —
this is where consumers resolve the receipt verification key
(`did:web:<authority>` resolves to exactly this URL). The active signing
key appears in `verificationMethod` **and** `assertionMethod`; retired keys
(`[[receipt.retired_keys]]`) appear in `verificationMethod` only, per the
RFC-ACDP-0010 §9 retention rule. `Cache-Control: max-age=300`. `404` when no
receipt key is configured. See [RECEIPTS.md](RECEIPTS.md).

### `GET /healthz`

Storage liveness. `200` with `{"status":"ok","storage":true}` when the backend
responds, `503` with `{"status":"degraded","storage":false}` otherwise.

---

## Contexts

### `POST /contexts`

Publish a context. **Not** bearer-authed — the producer's signature over the
`content_hash` is the authentication. Runs the full RFC-ACDP-0003 §2.1 pipeline
(see [ARCHITECTURE.md](ARCHITECTURE.md#publish-pipeline)).

Request headers:

| Header | Required | Notes |
|--------|----------|-------|
| `Idempotency-Key` | optional | 1–256 ASCII chars; replays return the prior result within `limits.idempotency_key_ttl_seconds`. |
| `X-Run-Id`        | optional | ≤256 chars; correlation id echoed into the `context.published` webhook. |
| `X-Tenant-Id`     | optional | Tenant fallback; see [MULTI-TENANCY.md](MULTI-TENANCY.md). For writes the producer's `[[auth.tenant_agents]]` binding is authoritative. |

Body: an RFC-ACDP-0003 `PublishRequest` (JSON). Response: `200` with a
`PublishResponse` (assigned `ctx_id`, `lineage_id`, `version`, `status`, and —
on a receipts-advertising registry — the top-level `registry_receipt`, the
signed RFC-ACDP-0010 attestation minted atomically with the row). A
per-agent rate limit (`limits.publish_rate_per_minute`, default 60) is checked
before the expensive verify — `429` + `Retry-After` when drained.

did:key producers (ACDP 0.2.0) are verified **offline** — no DID-document
fetch — when `"did:key"` is in `supported_did_methods`; otherwise the publish
is rejected with `key_resolution_failed` (400, permanent).

### `GET /contexts/{ctx_id}`

Retrieve a full context. Optional `Authorization: Bearer <jwt>` identifies the
caller for the visibility gate (RFC-ACDP-0008 §4.5). `404` when not found **or**
not visible to the caller (no existence oracle). If `ctx_id`'s authority differs
from this registry's and `registry.cross_registry_resolution = true`, the
request is resolved against the foreign registry anonymously — only remote
`public` contexts are surfaced (see
[OPERATIONS.md](OPERATIONS.md#cross-registry-federation)).

On a receipts-advertising registry the response carries the top-level
`registry_receipt` member (outside `body` and `registry_state`); contexts
published before receipts were enabled omit it (no backfill — see
[RECEIPTS.md](RECEIPTS.md)). Foreign retrievals pass the upstream's verified
receipt through verbatim.

On a lifecycle-advertising registry (`lifecycle.enabled`, ACDP 0.3.0) a
context that has been retracted/republished carries its append-only
`registry_state.lifecycle_events` array (RFC-ACDP-0013 §4.1; omitted when
empty) and its `status` reflects the §7.2 precedence
(`retracted` > `superseded` > `expired` > `active`). Retraction is
mark-not-delete: the body of a retracted context is served unchanged.

### `GET /contexts/{ctx_id}/body`

As above, but returns only the context `Body` (no envelope metadata, and
never `registry_receipt` — the immutable-cache story is unchanged).

### `GET /contexts/search`

Keyword + filter search. Optional bearer scopes which contexts are disclosable.

Query parameters (all optional):

| Param | Meaning |
|-------|---------|
| `q` | Full-text query. |
| `type` | Context type filter. |
| `domain`, `tags`, `agent_id`, `schema_uri`, `derived_from` | Exact-match facets. |
| `status` | Status filter (default `active`). A retracted context matches only `status=retracted` — never the default, nor `superseded`/`expired` even where those facts also hold (RFC-ACDP-0013 §8.2). |
| `visibility` | Narrow to `public` / `restricted` / `private`. |
| `created_after`, `created_before` | RFC 3339 bounds on creation time. |
| `data_period_start_after`, `data_period_end_before` | Bounds on the context data period. |
| `expires_after`, `expires_before` | Bounds on expiry. |
| `limit` | Page size, default 20. |
| `cursor` | Opaque pagination cursor from a prior `next_cursor`. |

Response: a `SearchResponse` — `{ matches: [...], total_estimate, next_cursor }`.
Visibility and tenant are post-filtered with a bounded refill loop (up to 6
inner pages), so a page may return fewer than `limit` rows near the end of a
result set even though `next_cursor` is set — keep paging until `next_cursor`
is absent.

### `GET /lineages/{lineage_id}`

Every version in a lineage as a `FullContext` array, visibility- and
tenant-filtered. Optional bearer. Each version carries its own projected
`status` and (under the lifecycle profile) its `lifecycle_events` — the
lineage array is the record, and the record includes withdrawals.

### `GET /lineages/{lineage_id}/current`

The newest version that is **neither superseded nor retracted**
(RFC-ACDP-0004 §5.2 as amended by RFC-ACDP-0013 §8.3 — an expired head is
still a valid head). `404` when the lineage is unknown, no version is
visible, or every version is superseded-or-retracted; retracting a linear
lineage's head therefore takes the lineage off `/current` entirely until
the producer republishes it or supersedes it with a fresh version.

When `receipt.head_receipts = true` (ACDP 0.3.0 / RFC-ACDP-0011) the
response additionally carries a top-level `lineage_head_receipt`: a
registry-signed, per-response attestation that "as of `as_of`, the head of
this lineage is `head_ctx_id` at `head_version` with `head_status`". It is
minted after head selection (so it can never name a superseded or
retracted head), signed with the RFC-ACDP-0010 receipt key, never
persisted, and never attached to body-only responses. See
[RECEIPTS.md](RECEIPTS.md#lineage-head-receipts-acdp-030--rfc-acdp-0011).

### `POST /contexts/{ctx_id}/retract`, `POST /contexts/{ctx_id}/republish` *(ACDP 0.3.0)*

Lifecycle events & retraction (RFC-ACDP-0013 §6). Mounted always; a
registry without `lifecycle.enabled = true` answers
`501 not_implemented`. The request body is a closed envelope with exactly
one member:

```json
{
  "event": {
    "event_id": "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f",
    "ctx_id": "acdp://registry.example.com/1234...",
    "event_type": "retracted",
    "occurred_at": "2026-07-04T09:15:42.000Z",
    "actor": "did:web:agents.example.com:producer",
    "reason": "underlying data source found to be fabricated",
    "signature": { "algorithm": "ed25519", "key_id": "…#key-2", "value": "…" }
  }
}
```

Processing follows §6 in order: visibility-first resolution (an invisible
context 404s — no existence oracle), closed-shape validation (any `body`
member or body-field-named member → `400 immutable_field`; other unknown
members → `schema_violation`; `event.ctx_id` must equal the path
`{ctx_id}`; `event_type` must match the endpoint), actor authentication
(`actor` must equal the context's `body.agent_id`; the event **must** be
signed and the signature verifies through the same DID pipeline as a
publish — `did:web` via resolution, `did:key` offline), then the strict
alternation check (`retracted` only when not retracted, `republished` only
when retracted; violation → `409 invalid_lifecycle_transition`) and the
atomic append. Per-agent rate limiting applies as to publish, keyed by the
event actor.

Response: `200` with the post-transition full-retrieval envelope (`body` +
`registry_state`, `status` re-derived, `lifecycle_events` including the
new event). A retry with an already-appended `event_id` and byte-identical
content is idempotent (200, nothing appended); the same `event_id` with
different content is a `400 schema_violation`.

Only the producer may use these endpoints (delegation and a
registry-attested admin path are out of scope for now; registry-initiated
events would be recorded directly by the operator against the store).

---

## Auth

Mounted only when `auth.enabled = true`. Full flow and JWT details in
[AUTHENTICATION.md](AUTHENTICATION.md).

### `POST /auth/challenge`

Body `{ "agent_id": "did:web:..." }`. Returns an `AuthChallenge`:

```json
{
  "nonce": "<24 random bytes, url-safe base64>",
  "registry_authority": "registry.example.com",
  "expires_at": 1748000300,
  "signing_input": "acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}"
}
```

`agent_id` must be a `did:web:` DID (8–2048 bytes). Bounded by
`limits.challenge_rate_per_minute` (default 60) per `agent_id` plus a
process-global ceiling; `429` + `Retry-After` when drained.

### `POST /auth/token`

Exchange a signed challenge for a JWT. Body:

```json
{
  "agent_id": "did:web:agents.example.com:my-agent",
  "key_id":   "did:web:agents.example.com:my-agent#key-1",
  "nonce":    "<from the challenge>",
  "expires_at": 1748000300,
  "algorithm": "ed25519",
  "signature": "<base64 signature over signing_input>"
}
```

`algorithm` is `ed25519` or `ecdsa-p256`; it must match the algorithm declared
on the resolved verification method (downgrade defense). Response:

```json
{ "token": "<jwt>", "token_type": "Bearer", "expires_at": 1748003600 }
```

### `POST /auth/token/revoke`

Body `{ "jti": "<token id>" }`. Requires `Authorization: Bearer <jwt>`; the
caller's DID must own the `jti`. `204` on success. `503` if no revocation store
is configured. See [AUTHENTICATION.md](AUTHENTICATION.md#token-revocation).

---

## Admin

Bearer-gated against `auth.admin_tokens` (constant-time compare; empty list
disables every admin route). See
[OPERATIONS.md](OPERATIONS.md#admin-endpoints).

### `GET /admin/status`

Operational snapshot. Always shipped.

```json
{
  "storage":     { "healthy": true },
  "idempotency": { "records": 128 },
  "webhook":     { "enabled": true, "queue_in_flight": 0, "queue_capacity": 1024 },
  "revocation":  { "configured_feeds": 2 },
  "migrations":  { "backend": "Sqlite", "applied": true }
}
```

`idempotency.records` and the webhook queue fields are `null` when the backend
doesn't track them.

### `GET /admin/lineages/{lineage_id}/audit` *(ACDP 0.2.0)*

Full lineage walk as an on-demand integrity check (workstream D3): the
publish path validates only against the immediate predecessor's persisted
row (lineage anchoring); this endpoint re-walks the entire chain. Always
shipped.

```json
{
  "lineage_id": "lin:sha256:…",
  "versions": 4,
  "ok": true,
  "issues": [],
  "receiptless_contexts": 1
}
```

Checks: version contiguity from 1, `supersedes` links, the `lineage_id`
derivation from v1's `ctx_id`, producer continuity, and the
single-non-superseded-tip invariant. `receiptless_contexts` counts rows
without a stored receipt (informational — pre-receipts history is
legitimate; see [RECEIPTS.md](RECEIPTS.md)). `404` for an unknown lineage.

### `GET /admin/contexts` *(playground feature)*

Paginated dump of stored contexts for the requested tenant. Query: `limit`
(default 50), `cursor`. Returns `{ items: [...], next_cursor }`. Tenant filter
applies at the SQL level.

### `POST /admin/pinned-keys/reload` *(playground feature)*

Re-reads config from disk and hot-swaps **only** the `[playground]` section
(pinned keys). No body. Returns `{ "ok": true, "count": <n> }`. Other config
sections require a restart.

---

## Error envelope

Errors follow RFC-ACDP-0007 §5 and are emitted as `application/acdp+json`:

```json
{
  "error": {
    "code": "schema_violation",
    "message": "human-readable detail",
    "details": { }
  }
}
```

`details` is present only for codes that carry structured context (e.g.
`superseded_target` carries `details.reason`). `internal_error` responses never
leak detail — the message is always `"internal error"`, with the real cause in
the server log only.

The `code` strings are the canonical RFC-ACDP-0007 §5 registry. Their definitive
list, and how an `acdp` client maps each one back to a typed `AcdpError` (with
retry guidance), is in [acdp-rs · Errors & Retries][acdp-errors] — this page
documents only the registry's HTTP-status projection of them.

### Status / code table

| HTTP | Wire `code` | Raised when |
|------|-------------|-------------|
| 400 | `schema_violation` | Malformed body, missing field, schema mismatch. |
| 400 | `hash_mismatch` | Recomputed `content_hash` ≠ declared. |
| 400 | `data_ref_hash_mismatch` | An embedded/remote `data_ref` hash ≠ declared. |
| 400 | `key_resolution_failed` | DID document fetched but the key isn't usable. |
| 400 | `immutable_field` | A lifecycle request tried to supply/alter body content (RFC-ACDP-0013 §6 step 2). |
| 400 | (signature) | Bad signature / unsupported algorithm. |
| 403 | `not_authorized` | Bad/expired/revoked bearer, challenge failure, visibility denial, tenant-scope denial in strict mode. |
| 404 | `not_found` | Context/lineage absent or not visible to the caller. |
| 409 | `duplicate_publish` / `superseded_target` | Idempotency/lineage conflict (race). |
| 409 | `invalid_lifecycle_transition` | Double retract, or republish of a never-retracted context (RFC-ACDP-0013 §6 step 4). |
| 413 | (payload) | Body over `max_payload_bytes`, or embedded data over `max_embedded_bytes`. |
| 429 | `rate_limited` | Publish/challenge bucket drained; carries `Retry-After`. |
| 500 | `internal_error` | Storage/config/internal failure (detail logged, not returned). |
| 501 | `not_implemented` | Unimplemented protocol feature. |
| 502 | `key_resolution_unreachable` / `cross_registry_resolution_failed` | DID document or foreign registry unreachable (also covers SSRF-policy rejection). |

Note: auth failures surface as `403 not_authorized`, not `401` — the registry
does not emit a `WWW-Authenticate` challenge.

[acdp-errors]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md
