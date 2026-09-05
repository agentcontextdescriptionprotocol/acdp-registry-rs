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
| GET  | `/metrics`                       | optional scrape bearer | `metrics.enabled` |
| POST | `/contexts`                      | producer signature | always |
| GET  | `/contexts/{ctx_id}`             | optional bearer | always |
| GET  | `/contexts/{ctx_id}/body`        | optional bearer | always |
| GET  | `/contexts/search`               | optional bearer | always |
| POST | `/contexts/{ctx_id}/retract`     | producer-signed event | always (501 unless `lifecycle.enabled`) |
| POST | `/contexts/{ctx_id}/republish`   | producer-signed event | always (501 unless `lifecycle.enabled`) |
| GET  | `/lineages/{lineage_id}`         | optional bearer | always |
| GET  | `/lineages/{lineage_id}/current` | optional bearer | always |
| GET  | `/log/checkpoint`                | none        | always (501 unless `log.enabled`) |
| GET  | `/log/proof`                     | optional bearer | always (501 unless `log.enabled`) |
| GET  | `/log/entries`                   | optional bearer | always (501 unless `log.enabled`) |
| POST | `/auth/challenge`                | none        | `auth.enabled` |
| POST | `/auth/token`                    | challenge signature | `auth.enabled` |
| POST | `/auth/token/revoke`             | bearer      | `auth.enabled` |
| GET  | `/admin/status`                  | admin bearer | always |
| GET  | `/admin/lineages/{lineage_id}/audit` | admin bearer | always |
| POST | `/admin/contexts/{ctx_id}/retract`   | admin bearer | always (501 unless `lifecycle.enabled`) |
| POST | `/admin/contexts/{ctx_id}/republish` | admin bearer | always (501 unless `lifecycle.enabled`) |
| GET  | `/admin/contexts`                | optional bearer\* | `playground` feature |
| POST | `/admin/pinned-keys/reload`      | admin bearer | `playground` feature |

The `/auth/*` routes are mounted at runtime only when `auth.enabled = true`. The
two `/admin/{contexts,pinned-keys}` routes are compiled in only with the
`playground` Cargo feature; `/admin/status` always ships.

\* Despite living under `/admin/`, `GET /admin/contexts` is **not** gated by
the admin bearer (`auth.admin_tokens`) — see [Admin](#admin) below for what it
actually checks.

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
is populated). When `metrics.enabled`, a request-metrics layer near the top of
the stack records count/latency/status by matched route.

The `/auth/*` subrouter additionally carries the FEAT-06 per-IP + process-global
rate limiter (`[rate_limit]`): it admits or rejects a request with `429` +
`Retry-After` **before** any DID resolution, keyed by the resolved client IP
(TCP peer, or the trusted-proxy `X-Forwarded-For` policy).

---

## Metadata

### `GET /.well-known/acdp.json`

Capabilities document. `Cache-Control: max-age=300`.

```json
{
  "acdp_version": "0.5.0",
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

`acdp_version` is unconditionally `"0.5.0"` (RFC-ACDP-0016 §10 — anchors
handling has no admin-config gate, so its version claim always wins), but
`profiles` still lights up per-config exactly as before: with a `[receipt]`
signing key configured (ACDP 0.2.0), `profiles` additionally carries
`"acdp-registry-receipts"`, and so on for lifecycle/log/witnesses. The
advertised version string and the set of active capabilities are two
different axes — do not infer what a registry actually enforces from
`acdp_version` alone; check `profiles` and the response bodies instead.
`supported_did_methods` may include `"did:key"` when enabled via
`auth.did_methods`.

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

### `GET /metrics` *(FEAT-10)*

Prometheus text exposition (`Content-Type: text/plain; version=0.0.4`). Mounted
only when `metrics.enabled = true` (`404` otherwise). Deliberately outside the
ACDP auth pipeline and the `/auth/*` rate limiter so a scraper reaches it
unimpeded; when `metrics.bearer_token` is set the endpoint requires
`Authorization: Bearer <token>` and answers `401` otherwise. Exposed series:

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `acdp_registry_request_total` | counter | `route`, `method`, `status_class` | HTTP requests by **matched** route pattern (never the resolved `ctx_id`). |
| `acdp_registry_request_duration_seconds` | histogram | `route`, `method` | Request latency. |
| `acdp_registry_publish_total` | counter | `outcome` | Publishes: `inserted`, `idempotent_replay` (playground path), or a wire code (`schema_violation`, `payload_too_large`, …). |
| `acdp_registry_receipts_minted_total` | counter | — | RFC-ACDP-0010 receipts minted on accepted publishes. |
| `acdp_registry_log_leaves_total` | counter | — | RFC-ACDP-0012 transparency-log leaves appended. |
| `acdp_registry_lifecycle_event_total` | counter | `event`, `outcome` | Retract / republish outcomes. |
| `acdp_registry_witness_cosignatures_total` | counter | `outcome` | Witness cosignatures `aggregated` / `rejected` / `store_error`. |
| `acdp_registry_rate_limit_rejections_total` | counter | `scope` | 429s by scope (`auth_per_ip`, `auth_global`, `publish_per_agent`, `challenge_per_agent`, `lifecycle_per_agent`). |

Adding a handler needs no metrics-middleware change: request metrics are
automatic (from `MatchedPath`); domain counters are explicit `metrics::counter!`
calls in the handlers.

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

`anchors` (RFC-ACDP-0016, still **Draft**) is an optional array of typed,
content-addressed references from the body to external, non-ACDP artifacts.
It follows the same absent-when-empty convention as every other optional
array field — omit it entirely rather than sending `[]`. A publish carrying
`anchors` is rejected with `schema_violation` (400) unless **both**: the
registry's own advertised `acdp_version` (the value served at
`GET /.well-known/acdp.json`) is `>= 0.5.0` (RFC-ACDP-0016 §10), **and** the
request's own declared `acdp_version` is `>= 0.5.0` (RFC-ACDP-0016 §14; an
absent `acdp_version` is treated as `0.1.0` and therefore also rejected).
The check runs before signature verification and applies uniformly to every
publish path (`did:key`, playground pinned-key, and the default `did:web`
pipeline). Each anchor's `uri` is an advisory locator hint only — it is
never dereferenced by any verification code path; the binding is each
anchor's own `content_hash`, not `uri`. `uri` is stored and re-served
verbatim and is never dereferenced by this registry.

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
Visibility (RFC-ACDP-0008 §4.5) is enforced in the SQL `WHERE` clause on both
backends, and `total_estimate` is the count of §4.5-visible matches for the
caller. Tenant narrowing is post-filtered with a bounded refill loop (up to 6
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

### `GET /log/checkpoint`, `GET /log/proof`, `GET /log/entries` *(ACDP 0.3.0)*

Registry transparency log (RFC-ACDP-0012). Mounted always; a registry
without `log.enabled = true` answers `501 not_implemented` from every
`/log/*` path. There is **no `log_unavailable`** anywhere (§7.1): with the
profile advertised, every accepted publish appends its leaf in the same
storage transaction as the context row and its receipt, so the proof for a
context exists the moment its publish response does.

**`GET /log/checkpoint`** — the current signed tree head, bare:

```json
{
  "checkpoint_version": "acdp-log/1",
  "log_id": "did:web:registry.example.com/log/1",
  "tree_size": 5,
  "root_hash": "sha256:…",
  "timestamp": "2026-07-04T12:00:00.000Z",
  "signature": { "algorithm": "ed25519", "key_id": "…#receipt-key-1", "value": "…" }
}
```

Signed with the RFC-ACDP-0010 **receipt key** (§6 — no new key role);
`timestamp` is fresh per evaluation. Publicly readable wherever
capabilities are.

**Witness cosignatures (`witness_signatures`)** *(ACDP 0.4.0, RFC-ACDP-0015 §6.1).*
When the registry is configured with `[[witnesses]]` and has collected one
or more **verified** witness cosignatures over the exact
`(log_id, tree_size, root_hash)` it is serving, `GET /log/checkpoint`
returns an **envelope** that wraps the bare checkpoint under `log_checkpoint`
and adds a top-level `witness_signatures` array as a **sibling**:

```json
{
  "log_checkpoint": {
    "checkpoint_version": "acdp-log/1",
    "log_id": "did:web:registry.example.com/log/1",
    "tree_size": 5,
    "root_hash": "sha256:…",
    "timestamp": "2026-07-04T12:00:00.000Z",
    "signature": { "algorithm": "ed25519", "key_id": "…#receipt-key-1", "value": "…" }
  },
  "witness_signatures": [
    {
      "cosignature_version": "acdp-cosig/1",
      "witness_id": "did:web:witness.example.org",
      "witnessed_checkpoint": { "log_id": "…/log/1", "tree_size": 5, "root_hash": "sha256:…", "timestamp": "…" },
      "witnessed_at": "2026-07-04T12:00:03.000Z",
      "signature": { "algorithm": "ed25519", "key_id": "did:web:witness.example.org#witness-key-1", "value": "…" }
    }
  ]
}
```

`witness_signatures` is **OUTSIDE** the signed checkpoint object — it is
never inside it, never part of any `content_hash`, receipt, checkpoint, or
leaf preimage (§6.1). The embedded `log_checkpoint` is the same closed,
signed object as the bare form. When the registry has collected **no**
cosignatures for the served tuple, the response is the **bare** checkpoint
above (no envelope, no `witness_signatures`) — the array is never
fabricated or served empty, and pre-0.4.0 consumers see exactly what they
always did. A registry only serves `witness_signatures` at all once
`[[witnesses]]` is configured — that gating is unchanged. What changed
(REG-3, RFC-ACDP-0016 §10) is that `acdp_version` served at
[`GET /.well-known/acdp.json`](#get-well-knownacdpjson) no longer moves in
step with this: `acdp_version` is unconditionally `"0.5.0"` regardless of
whether `[[witnesses]]` is configured, since the anchors capability claim
always wins the version max(). A deployment with no witnesses configured
still advertises `"0.5.0"` and simply never serves `witness_signatures`;
whether witness aggregation is active is visible in the response body
(whether `witness_signatures` accompanies a checkpoint) and in
`profiles` (`"acdp-registry-transparency-log"` — witnesses are never a
distinct registry profile, RFC-ACDP-0015 §6.1), not in `acdp_version`. The
same top-level `witness_signatures` sibling is attached to
the embedded checkpoint carried by `GET /log/proof` (inclusion and
consistency modes) when cosignatures exist for that embedded checkpoint's
tuple. A consumer verifies each cosignature under the witness DID's
`assertionMethod` key and counts distinct trusted witnesses (the §8
*N-witnessed* verdict); the registry never holds a witness key, so it can
neither forge a cosignature nor make aggregation a trust dependency — a
consumer MAY always fetch direct from a witness (§6.2). See
[CONFIGURATION.md](CONFIGURATION.md#witnesses-acdp-040) for `[[witnesses]]`.

**`GET /log/proof`** — one path, two mutually exclusive parameter sets:

- *Inclusion mode:* exactly one of `?ctx_id=<ctx_id>` (the consumer
  surface — **retrieval visibility applies exactly as for
  `GET /contexts/{ctx_id}`**: an unauthorized or unlogged ctx_id is
  `404 not_found`, indistinguishable from absence) or `?leaf_index=<n>`
  (the auditor surface — positions are public, no visibility gate).
  Optional `&tree_size=<n>` requests the proof against a historical size
  (`leaf_index < tree_size ≤` current); the registry signs a checkpoint at
  that size on demand (§8.2). The response is the `log_inclusion` object
  (`log_id`, `leaf_index`, `tree_size`, `inclusion_path[]`,
  `log_checkpoint`), plus a convenience `leaf` echo **only** when the
  requester is authorized to retrieve the context — verifiers reconstruct
  the leaf from verified body + receipt material instead (§9.1 step 1).
- *Consistency mode:* `?first=<m>&second=<n>` with
  `0 < m ≤ n ≤` current size. Response: `log_id`, `first_tree_size`,
  `second_tree_size`, `consistency_path[]` (empty when `m == n`), and a
  `log_checkpoint` at the second size. The caller verifies against its own
  **retained** earlier root — that retained root is the whole point
  (§9.2). Hash-only; no visibility gate.

Mixing the parameter sets, omitting both, malformed integers, or
out-of-range positions/sizes → `400 schema_violation`.

**`GET /log/entries?start=<i>&end=<j>`** — leaves `[start, end)`
(`start < end ≤` current size). Every entry carries `leaf_index` and
`leaf_hash` unconditionally — the ordered leaf hashes alone recompute
every root, which is what makes third-party auditing possible (§8.3). The
`leaf` body is present **only** for entries whose context the requester is
authorized to retrieve (public contexts: always); otherwise it is absent,
never `null`. The page is capped at 256 entries; continue from
`start + len(entries)`.

```json
{
  "log_id": "did:web:registry.example.com/log/1",
  "start": 0,
  "entries": [
    { "leaf_index": 0, "leaf_hash": "sha256:…", "leaf": { "leaf_version": "acdp-log-leaf/1", … } },
    { "leaf_index": 1, "leaf_hash": "sha256:…" }
  ]
}
```

Visibility note (§15): leaf *hashes*, positions, and tree size are public
by design — a registry with confidentiality requirements over publication
volume/timing metadata must weigh that before enabling `[log]`.

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

Most `/admin/*` routes are bearer-gated against `auth.admin_tokens`
(constant-time compare; empty list disables every route that checks it):
`GET /admin/status`, `GET /admin/lineages/{lineage_id}/audit`,
`POST /admin/contexts/{ctx_id}/retract`, `POST /admin/contexts/{ctx_id}/republish`,
and `POST /admin/pinned-keys/reload`. See
[OPERATIONS.md](OPERATIONS.md#admin-endpoints).

**`GET /admin/contexts` is the one exception** — it does not call the admin-bearer
check at all (`crates/acdp-registry-core/src/handlers/admin.rs`'s `admin_list`
calls only `caller_from_headers` and `tenant_for_request`, the same helpers the
regular tenant-scoped read routes use). With `auth.enabled = false` it is fully
anonymous; with `auth.enabled = true` it accepts an ordinary (non-admin) auth
bearer, not an `auth.admin_tokens` value. Critically, a bearer is never
*required*: `caller_from_headers`
(`crates/acdp-registry-core/src/handlers/context.rs:1337-1339`) returns `Ok(None)`
whenever the `Authorization` header is simply absent, `auth.enabled` value
notwithstanding, and `admin_list` passes that `None` straight into
`list_contexts`, whose SQL grants every `visibility = 'public'` row to a NULL
requester (`crates/acdp-registry-pg/src/store.rs:166-169`). So a completely
unauthenticated `GET /admin/contexts` request enumerates all public contexts
regardless of `auth.enabled`. Only a well-formed `Bearer <token>` whose token
fails validation is rejected; any other header shape — including a non-`Bearer`
scheme — is treated as anonymous rather than refused
(`crates/acdp-registry-auth/src/service.rs:400-405`).
This is a pre-existing gap between the route's location under `/admin/` and
its actual authorization — not a recent change.

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

### `POST /admin/contexts/{ctx_id}/retract`, `POST /admin/contexts/{ctx_id}/republish` *(ACDP 0.3.0)*

Registry-**attested** lifecycle events (RFC-ACDP-0013 §6, "registry-initiated
events") — the policy/legal takedown path, distinct from the producer-signed
`POST /contexts/{ctx_id}/{retract,republish}`. Use when a context must be
formally withdrawn (or a withdrawal reversed) and the producer is unavailable:
the registry mints the event itself and attributes it to its **own DID**
(`capabilities.registry_did = did:web:<authority>`), not the producer.

Auth is the standard admin gate (`auth.admin_tokens` bearer). Requires
`[lifecycle] enabled` — a registry not advertising `acdp-registry-lifecycle`
answers `501 not_implemented` (after the admin gate). Always mounted.

Request body — a closed object with one optional member (the operator supplies
only the reason; the registry mints the `event_id`, `occurred_at`, `actor`, and
signature):

```json
{ "reason": "removed by policy: court order 2026-… (producer unavailable)" }
```

An empty body is accepted (`reason` is optional). Any other member →
`400 schema_violation`.

**Signing (mirrors the SDK's `record_registry_lifecycle_event` contract exactly):**

- **`[receipt]` key configured** → the event **MUST** be signed under the
  receipt key (RFC-ACDP-0013 §5; the receipts-profile MUST). `signature.key_id`
  is `did:web:<authority>#<receipt.key_id_fragment>`, verifiable against the
  registry DID document at [`/.well-known/did.json`](#-well-known-didjson-acdp-020).
- **No `[receipt]` key** → the event is recorded **unsigned but attributed**:
  `actor` still names the registry DID, and `signature` is omitted. Consumers
  weight an unsigned registry event only as far as the response transport (§5).
  This is not a refusal — it is exactly what the SDK helper permits when no
  receipt signer is present.

Downstream semantics are identical to the producer path: atomic
`commit_lifecycle_event`, the `retracted > superseded > expired > active` status
projection, the strict-alternation transition check
(`409 invalid_lifecycle_transition` on a double-retract or a republish of a
non-retracted context), byte-identical-`event_id` idempotency, and the
`context.retracted` / `context.republished` webhook (with `actor` = the registry
DID). On success returns `200` with the full-retrieval envelope (`body` +
`registry_state`), the minted event appended to
`registry_state.lifecycle_events` so its registry attribution is visible to
consumers.

**Cross-actor alternation is allowed.** RFC-ACDP-0013 §7.1 derives retraction
state from event-type *order* alone (never the actor), and §6 authorizes the
producer (`actor == agent_id`) and the registry (`actor == registry_did`)
independently. So a producer may `/republish` a context the registry retracted,
and vice versa; both events remain in the append-only history, attributed to
their distinct actors. (The RFC is silent on actor symmetry for the reversal;
allowing it is the natural reading of an actor-agnostic §7.1 and the intended
"registry retracts by policy, producer later resolves and republishes" flow.)

### `GET /admin/contexts` *(playground feature)*

Paginated dump of stored contexts for the requested tenant. Query: `limit`
(default 50), `cursor`. Returns `{ items: [...], next_cursor }`. Tenant filter
applies at the SQL level.

**Not admin-bearer gated** — see the note at the top of [Admin](#admin). Access
control here is the same tenant/caller resolution as the regular read routes,
not `auth.admin_tokens`. It is not identical, though: `list_contexts` takes no
`anonymous_public_reads` flag and unconditionally exposes `visibility = 'public'`
rows to an anonymous (`None`) requester, whereas `search`
(`crates/acdp-registry-pg/src/store.rs:1051,1110`,
`crates/acdp-registry-sqlite/src/store.rs:1152,1251`, wired at
`crates/acdp-registry-server/src/main.rs:1025`) only does that when
`auth.anonymous_public_reads = true` — `false` by default
(`crates/acdp-registry-types/src/config.rs:486`). So with the default config,
`GET /admin/contexts` hands an anonymous caller public contexts that
`GET /contexts/search` withholds from the same caller.

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
| 501 | `not_implemented` | Unimplemented protocol feature (incl. `/log/*` and lifecycle endpoints when their profiles are not enabled). |
| 502 | `key_resolution_unreachable` / `cross_registry_resolution_failed` | DID document or foreign registry unreachable (also covers SSRF-policy rejection). |
| 502 | `invalid_log_proof` | A transparency-log proof/checkpoint failed RFC-ACDP-0012 §9 verification. Emitted only when validating an *upstream's* proofs (federation); this registry's own `/log/*` handlers never raise it — their failures are `schema_violation`, `not_found`, or `not_implemented`, and there is no `log_unavailable`. |

Note: auth failures surface as `403 not_authorized`, not `401` — the registry
does not emit a `WWW-Authenticate` challenge.

[acdp-errors]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md
