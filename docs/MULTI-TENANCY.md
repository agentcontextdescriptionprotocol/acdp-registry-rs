# Multi-tenancy

The registry can scope every operation — publish, retrieve, search, lineage,
pagination — to a **tenant**. Tenancy is off by default (V0-compatible): with no
bindings configured and `require_tenant = false`, requests run unscoped, gated
only by visibility.

Resolution is centralized in `tenant_for_request()` and `tenant_for_publish()`
(`crates/acdp-registry-core/src/handlers/context.rs`). Handlers must never
branch on tenant ad hoc — they call these functions.

## Resolution precedence

For reads (`tenant_for_request`):

```
JWT `tenant` claim  >  X-Tenant-Id header  >  None
```

- The JWT `tenant` claim is **authoritative** — it's issuer-signed. It is set
  only for agents bound via `[[auth.tenant_agents]]` (see
  [AUTHENTICATION.md](AUTHENTICATION.md#jwt-claims)).
- `X-Tenant-Id` is a **fallback**, honored only when no authoritative claim
  applies. It is spoofable, so it is never trusted once a bound token is present.
- If a bound token's claim and the header **disagree**, the request is rejected
  (`403 not_authorized`, "tenant assertion mismatch").
- `None` means "no tenant asserted" → the tenant filter is disabled (V0).

For writes (`tenant_for_publish`): publish is producer-authenticated by the
signature over `content_hash`, not a bearer. So a raw `X-Tenant-Id` must **not**
decide the write tenant — the authoritative source is the producer's
`[[auth.tenant_agents]]` binding (or a tenant-bound token claim). Otherwise any
producer could inject a context into an arbitrary tenant's namespace.

## Strict mode (`auth.require_tenant = true`)

On an enforced multi-tenant deployment:

- A request that resolves to **no tenant** is default-denied (`403
  not_authorized`) — serving it would run with the filter off and could surface
  cross-tenant rows.
- An authenticated caller's tenant comes **only** from the JWT `tenant` claim.
  An unbound token (no claim) may **not** assert a tenant via `X-Tenant-Id`.
- Configuring any `[[auth.tenant_agents]]` requires `require_tenant = true`;
  startup validation enforces this so tenancy can't be half-enabled.

In lax mode (`require_tenant = false`) an unbound caller's `X-Tenant-Id` is
still honored, preserving V0 behavior.

## The reserved `default` sentinel

`default` is the column value for untenanted rows. It is **rejected** as an
explicitly-asserted tenant from any source — header or token claim. Allowing a
caller to assert `default` would alias the entire untenanted bucket, a
cross-boundary read/write. Untenanted rows remain reachable only through the
*absence* of any tenant assertion (`None`).

## How the binding is stored and filtered

The store carries the tenant binding alongside each context:

- `set_tenant_of_ctx` / `tenant_of_ctx` / `tenants_of_ctxs` — write and read the
  binding.
- `list_contexts(tenant)` and `/admin/contexts` filter at the **SQL level**, so
  pagination pages don't short.
- Search and lineage **post-filter the tenant binding** in the handler with a
  bounded refill loop (up to 6 inner pages) — so a search page may come back
  shorter than `limit`; keep paging until `next_cursor` is absent. (Visibility
  itself is enforced in SQL and never causes short pages.)

## Configuration

```toml
[auth]
enabled        = true
require_tenant = true            # strict: deny requests that resolve to no tenant

[[auth.tenant_agents]]
agent_did = "did:web:agents.acme.example:billing-bot"
tenant_id = "acme"

[[auth.tenant_agents]]
agent_did = "did:web:agents.globex.example:ingest"
tenant_id = "globex"
```

A bound agent's tokens carry `"tenant": "acme"`; its publishes write into the
`acme` namespace regardless of any `X-Tenant-Id` header. See
[CONFIGURATION.md](CONFIGURATION.md#authtenant_agents) for the field reference.
