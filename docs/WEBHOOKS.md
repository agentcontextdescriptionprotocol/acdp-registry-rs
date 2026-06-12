# Webhooks

When `[webhook] enabled = true`, the registry POSTs HMAC-signed JSON events to a
configured receiver. Delivery is **best-effort and non-blocking** — events go to
a bounded in-memory queue and are delivered by a background worker; the HTTP
request that triggered an event never waits on (or fails because of) webhook
delivery. Implementation: `crates/acdp-registry-webhook/src/lib.rs`; event types:
`crates/acdp-registry-types/src/event.rs`.

## Events

Three event types. Each is delivered as a flattened envelope: the variant fields
plus `event_id`, `schema_version`, and a `type` discriminator.

### `context.published`

```json
{
  "event_id": "e0f1...",
  "schema_version": "1.0",
  "type": "context_published",
  "registry_authority": "registry.example.com",
  "registry_base_url": "https://registry.example.com",
  "ctx_id": "registry.example.com/ctx_...",
  "lineage_id": "lin_...",
  "agent_id": "did:web:agents.example.com:my-agent",
  "context_type": "observation",
  "visibility": "public",
  "version": 1,
  "created_at": "2026-06-10T12:00:00Z",
  "derived_from": ["registry.example.com/ctx_parent"],
  "run_id": "run-123",
  "key_fingerprint": "sha256:139e…",
  "registry_receipt": { "registry_did": "did:web:registry.example.com", "…": "…" }
}
```

`registry_base_url` lets a federation control plane bootstrap proxy routes;
`run_id` echoes the publisher's `X-Run-Id` header (omitted if absent).

`key_fingerprint` and `registry_receipt` (ACDP 0.2.0, additive — both omitted
on a receipt-less registry) carry the RFC-ACDP-0010 §6 fingerprint of the
producer key the registry actually resolved at publish time, and the full
signed receipt, so the control plane can correlate and re-verify without
re-fetching the context.

### `context.retrieved`

```json
{
  "type": "context_retrieved",
  "registry_authority": "registry.example.com",
  "ctx_id": "registry.example.com/ctx_...",
  "requester_did": "did:web:agents.example.com:reader",
  "at": "2026-06-10T12:01:00Z"
}
```

`requester_did` is `null` for anonymous reads.

### `search.executed`

```json
{
  "type": "search_executed",
  "registry_authority": "registry.example.com",
  "query": "weather",
  "result_count": 12,
  "requester_did": null,
  "at": "2026-06-10T12:02:00Z"
}
```

## Signature scheme

Matches GitHub's exactly — receivers that already verify GitHub webhooks reuse
the same code. Headers on every delivery:

```
Content-Type:      application/json
X-ACDP-Signature:  sha256=<hex of HMAC-SHA256(webhook.secret, raw_json_body)>
X-ACDP-Event:      context.published | context.retrieved | search.executed
X-ACDP-Event-Id:   <uuid, stable across retries>
X-Tenant-Id:       <tenant, when the event is tenant-scoped>
```

Verify by recomputing the HMAC over the **raw** request body bytes (not a
re-serialization) and comparing in constant time. Reject on mismatch.

> The signing input is the exact bytes posted. Don't parse-and-reserialize
> before verifying — key ordering or whitespace differences will break the MAC.

## Delivery and retries

- Events are queued on a bounded mpsc channel of `webhook.queue_capacity`
  (default 1024). When the queue is full the event is **dropped** with a warn
  log — back-pressure never blocks the request path.
- The worker retries on `429`, `5xx`, and transport errors with exponential
  backoff starting at 250 ms, doubling, capped at 15 s, up to
  `webhook.max_retries` (default 3).
- A non-429 `4xx` is treated as a permanent failure — the worker gives up
  immediately (the receiver rejected the payload; retrying won't help).
- `2xx` is success. After exhausting retries the failure is logged and dropped
  (fire-and-forget).

Queue depth is exposed operationally at `GET /admin/status`
(`webhook.queue_in_flight` / `queue_capacity`) — see
[HTTP-API.md](HTTP-API.md#get-adminstatus).

## SSRF protection

`webhook.url` is validated at startup against the same `SsrfPolicy` as DID and
cross-registry resolution: HTTPS only, no private/internal authorities, no
redirects to such (the policy is documented in
[acdp-rs · Security Model](https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md)).
A webhook config that fails validation aborts startup rather than silently
disabling delivery.

## Configuration

```toml
[webhook]
enabled         = true
url             = "https://example.com/hooks/acdp"
secret          = "<random shared secret, non-empty>"
timeout_seconds = 5
max_retries     = 3
queue_capacity  = 1024
```

See [CONFIGURATION.md](CONFIGURATION.md#webhook) for the field reference.
