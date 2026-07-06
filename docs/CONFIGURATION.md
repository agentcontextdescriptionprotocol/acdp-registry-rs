# Configuration

`acdp-registry` is configured by a TOML file layered with environment-variable
overrides. There is no `clap` CLI — config loading is the `config` crate plus
env vars (same dependency-minimization principle as `acdp-rs`). The schema is
`RegistryConfig` in `crates/acdp-registry-types/src/config.rs`; a worked example
is [`config/registry.example.toml`](../config/registry.example.toml).

## Loading and precedence

```
built-in defaults  <  TOML file  <  ACDP_REGISTRY_* env vars
```

- The TOML file path comes from `ACDP_REGISTRY_CONFIG`; when unset the binary
  falls back to its defaults (dev runs use SQLite under `./data/registry.db`).
- Env overrides use `ACDP_REGISTRY_<SECTION>__<FIELD>` — a **single** underscore
  after the `ACDP_REGISTRY` prefix, then **double** underscores between nesting
  levels:

  ```bash
  export ACDP_REGISTRY_STORAGE__POSTGRES_URL="postgres://acdp:acdp@db:5432/acdp"
  export ACDP_REGISTRY_AUTH__JWT_SECRET="$(openssl rand -base64 32)"
  export ACDP_REGISTRY_AUTH__JWT_SIGNING_ALG="EdDSA"
  ```

## Startup validation

The binary validates config before serving and refuses to boot on a misconfig
(`validate_config` in `crates/acdp-registry-server/src/main.rs`). It enforces:

- **Auth** — `jwt_signing_alg` ∈ {`HS256`, `EdDSA`}. EdDSA requires a non-empty
  `jwt_private_key_pem`. HS256 with an empty `jwt_secret` requires
  `allow_ephemeral_secret = true`, otherwise it fails. A non-empty secret is
  rejected if it is the literal `changeme`, and must decode to ≥32 bytes.
- **Webhook** — when `enabled`, `url` must be non-empty and pass the SSRF policy
  (HTTPS, no private/internal authorities), and `secret` must be non-empty.
- **Multi-tenancy** — a non-empty `[[auth.tenant_agents]]` requires
  `require_tenant = true` (you can't half-enable tenancy).
- **Bind safety** — a non-loopback `bind` with neither TLS nor auth requires an
  explicit `allow_public_bind = true`.
- **TLS** — when `tls.enabled`, `cert_path` and `key_path` must exist on disk.
- **DID methods** — `auth.did_methods` entries must be `did:web` or `did:key`,
  and `did:web` must be present (RFC-ACDP-0007 §3.1).
- **Receipts** — a configured `[receipt]` key must parse (exactly one source,
  valid base64, 32 bytes), and is incompatible with `playground.enabled`
  (RFC-ACDP-0010 §7: a receipts registry has no unverified publish path).
- **0.3.0 profiles** — `receipt.head_receipts = true` requires a configured
  `[receipt]` signing key (RFC-ACDP-0011 §9: head receipts are signed with
  the receipt key). `log.enabled = true` likewise requires a `[receipt]` key
  (RFC-ACDP-0012 §11: leaves bind receipt hashes and checkpoints sign with
  the receipt key), a durable storage backend (SQLite/Postgres — the memory
  backend cannot honor the append-only history commitment), and a
  well-formed `log.instance` (`[a-z0-9-]{1,32}`). Listing
  `acdp-registry-head-receipts`, `acdp-registry-lifecycle`, or
  `acdp-registry-transparency-log` in `registry.profiles` without enabling
  the matching feature is refused as a false capability advertisement.
- **Witnesses (0.4.0)** — `[[witnesses]]` requires `log.enabled = true`
  (RFC-ACDP-0015 §6.1: there are no checkpoints to witness without a log);
  each `did` must be a `did:web` DID and each `url` must pass the SSRF
  policy (HTTPS, non-private host).

## Reference

Defaults below are the struct defaults; the example TOML may set different
values for illustration. Env var = `ACDP_REGISTRY_` + the bracketed path.

### `[registry]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `authority` | string | — | Bare lowercase DNS name. Mints `ctx_id` and is the `did:web` registry id. |
| `port` | u16 | `8443` | Listen port. |
| `bind` | string | `127.0.0.1` | Bind address. Non-loopback needs TLS/auth or `allow_public_bind`. |
| `allow_public_bind` | bool | `false` | Opt-in to bind a public interface without TLS/auth. |
| `base_url` | string | `https://{authority}` | Public URL advertised to consumers / federation control plane. |
| `profiles` | string[] | `["acdp-registry-core","acdp-registry-discovery"]` | Advertised in capabilities. |
| `cross_registry_resolution` | bool | `true` | Forward foreign `ctx_id`s to their home registry; `false` returns 404 instead. |

#### `[registry.tls]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Serve HTTPS directly via rustls. Usually terminate TLS upstream instead. |
| `cert_path` | path | — | Required when enabled. |
| `key_path` | path | — | Required when enabled. |

#### `[registry.cors]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `allowed_origins` | string[] | `[]` | Empty disables CORS (no headers sent). List your UI origin(s) to opt in. |

### `[storage]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `backend` | enum | `sqlite` | `postgres` \| `sqlite` \| `memory`. Must match the compiled storage feature. |
| `postgres_url` | string | — | Required when `backend = "postgres"`. |
| `sqlite_path` | path | `./data/registry.db` | SQLite file. |
| `max_connections` | u32 | `20` | sqlx pool size. |

> The storage backend is also chosen at **compile time** via the
> `acdp-registry-server` Cargo features (`storage-sqlite` default, `storage-pg`,
> `storage-memory`). The `backend` config key must agree with the built binary.

### `[auth]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Mounts `/auth/*` and turns on the bearer/visibility gates. |
| `did_methods` | string[] | `["did:web"]` | Allowed DID methods; advertised in capabilities. |
| `jwt_signing_alg` | string | `HS256` | `HS256` or `EdDSA`. See [AUTHENTICATION.md](AUTHENTICATION.md#signing-algorithms). |
| `jwt_secret` | string | `""` | HS256 secret — base64, ≥32 bytes. Never published. |
| `allow_ephemeral_secret` | bool | `false` | HS256 dev escape hatch: random process-lifetime key when `jwt_secret` is empty. |
| `jwt_private_key_pem` | string | `""` | EdDSA Ed25519 private key (PKCS#8 PEM). Required for EdDSA. |
| `jwt_kid` | string | `""` | Optional explicit JWKS key id; default is the public-key fingerprint. |
| `token_ttl_seconds` | u64 | `3600` | JWT lifetime. |
| `challenge_ttl_seconds` | u64 | `300` | Challenge nonce validity. |
| `token_leeway_seconds` | u64 | `30` | Clock-skew tolerance for `exp`. |
| `anonymous_public_reads` | bool | `false` | Allow unauthenticated reads of `public` contexts. Opt in for discovery hubs. |
| `require_tenant` | bool | `false` | Strict multi-tenancy: requests resolving to no tenant are denied. See [MULTI-TENANCY.md](MULTI-TENANCY.md). |
| `admin_tokens` | string[] | `[]` | Bearer tokens for `/admin/*`. Empty disables all admin routes. |

#### `[[auth.tenant_agents]]`

Repeatable. Binds a producing/consuming agent to a tenant.

| Key | Type | Notes |
|-----|------|-------|
| `agent_did` | string | Full DID of the agent. |
| `tenant_id` | string | Tenant the agent is scoped to (`default` is reserved). |

#### `[[auth.revocation_feeds]]`

Repeatable. A peer registry whose revocations this registry mirrors.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `issuer` | string | — | Peer DID; each fetched entry's `iss` must match. |
| `feed_url` | string | — | Peer's `/auth/revocations` URL. |
| `admin_token` | string | — | Bearer for the peer's feed. |
| `poll_seconds` | u64 | `300` | Poll interval. |

### `[webhook]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | |
| `url` | string | `""` | HMAC-signed POST target. SSRF-policy gated. |
| `secret` | string | `""` | HMAC-SHA256 key; must be non-empty when enabled. |
| `timeout_seconds` | u64 | `5` | Per-delivery timeout. |
| `max_retries` | u32 | `3` | Exponential backoff (250 ms → cap 15 s). |
| `queue_capacity` | usize | `1024` | Bounded in-memory queue; events drop (with a warn) when full. |

See [WEBHOOKS.md](WEBHOOKS.md).

### `[limits]`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `max_payload_bytes` | u64 | `1048576` | Publish body cap (enforced by the body-limit layer on every route). |
| `max_embedded_bytes` | u64 | `65536` | Cap on an inline `data_ref` value. |
| `idempotency_key_ttl_seconds` | u64 | `86400` | Idempotency-Key replay window; advertised in capabilities. |
| `publish_rate_per_minute` | u32 | `60` | Per-agent `POST /contexts` cap; `0` disables. In-memory, per-process. |
| `challenge_rate_per_minute` | u32 | `60` | Per-agent `POST /auth/challenge` cap; `0` disables. In-memory, per-process. |

> These are per-process in-memory token buckets — see
> [OPERATIONS.md · Rate limiting](OPERATIONS.md#rate-limiting) for the
> multi-replica caveat.

### `[playground]`

Compiled in only with the `playground` Cargo feature. **Never enable in
production** — the publish handler skips DID-signature verification.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Skip DID-signature verification for hands-on demos. |
| `pinned_only` | bool | `false` | Reject publishes from agents without a pinned key. |

#### `[[playground.pinned_keys]]`

Repeatable.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `agent_did` | string | — | Full DID. |
| `public_key_b64` | string | — | Standard base64 of the raw 32-byte key. |
| `algorithm` | string | `ed25519` | Only `ed25519` today. |
| `valid_from` | i64 | — | Unix seconds, inclusive; open-ended if omitted. |
| `valid_until` | i64 | — | Unix seconds, exclusive; open-ended if omitted. |

Hot-reload the `[playground]` section with `POST /admin/pinned-keys/reload`
(playground feature) — see [HTTP-API.md](HTTP-API.md#post-adminpinned-keysreload).

### `[receipt]` *(ACDP 0.2.0)*

Registry-receipt signing identity (RFC-ACDP-0010). Configuring a key enables
receipt minting, the `acdp-registry-receipts` profile, the `acdp_version:
0.2.0` capability claim, and `GET /.well-known/did.json`. Leave unset to stay
a 0.1.0 receipt-less registry. See [RECEIPTS.md](RECEIPTS.md) for the
operator runbook (rotation, retention, backfill policy).

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `signing_key_seed_b64` | string | `""` | Standard base64 of the raw 32-byte Ed25519 seed. Exactly one of the two key sources may be set. |
| `signing_key_path` | path | — | File (e.g. mounted secret) whose contents are that base64 string. |
| `key_id_fragment` | string | `receipt-key-1` | Fragment under the registry DID; `signature.key_id = did:web:<authority>#<fragment>`. Pick a fresh fragment per rotation. |
| `head_receipts` | bool | `false` | *(ACDP 0.3.0)* Mint a lineage-head receipt on every `GET /lineages/{id}/current` response (RFC-ACDP-0011). Requires a configured signing key (the same receipt key signs — no new key role); advertises `acdp-registry-head-receipts` and bumps the capability claim to `0.3.0`. |

#### `[[receipt.retired_keys]]`

Repeatable. Rotated-out receipt keys, published in the DID document's
`verificationMethod` only (never `assertionMethod`). **Removing an entry
bricks every receipt that key signed** — RFC-ACDP-0010 §9 retains retired
keys indefinitely; remove only on confirmed compromise.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `public_key_b64` | string | — | Standard base64 of the raw 32-byte Ed25519 **public** key. |
| `key_id_fragment` | string | — | The fragment the key was published under while active. |

### `[lifecycle]` *(ACDP 0.3.0)*

Lifecycle events & retraction (RFC-ACDP-0013). When enabled the registry
serves `POST /contexts/{ctx_id}/retract` / `/republish`, derives `status`
with the `retracted > superseded > expired > active` precedence, excludes
retracted contexts from default search and from `/current`, serves
`registry_state.lifecycle_events`, advertises `acdp-registry-lifecycle`,
and bumps the capability claim to `0.3.0`. When disabled (the default)
both endpoints answer `501 not_implemented` and neither `lifecycle_events`
nor the `retracted` status is ever emitted.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Opt into the RFC-ACDP-0013 endpoint surface and status semantics. |

`enabled` also unlocks the **registry-attested** takedown path
(`POST /admin/contexts/{ctx_id}/{retract,republish}`, RFC-ACDP-0013 §6
registry-initiated events — see [HTTP-API.md](HTTP-API.md#post-admincontextsctx_idretract-post-admincontextsctx_idrepublish-acdp-030)).
That path adds **no new knob**: it is gated by the existing `auth.admin_tokens`
bearer, and its signing is driven by whether a `[receipt]` key is configured —
with a receipt key the registry MUST sign the event under it; without one the
event is recorded unsigned but still attributed to the registry DID.

### `[log]` *(ACDP 0.3.0)*

Registry transparency log (RFC-ACDP-0012): a per-registry, append-only
RFC 6962-style Merkle tree over publish events. When enabled the registry
appends one leaf per accepted publish **in the same storage transaction as
the context row and its receipt** (§7.1 — the body, the receipt, and the
leaf commit together, or none does; a publish that cannot durably append
its leaf fails), serves `GET /log/checkpoint`, `GET /log/proof`, and
`GET /log/entries`, signs checkpoints with the `[receipt]` key (§6: no new
key role), advertises `acdp-registry-transparency-log`, and bumps the
capability claim to `0.3.0`. When disabled (the default) the three
`/log/*` endpoints answer `501 not_implemented`. There is no degraded mode
and no `log_unavailable` error.

Prerequisites (enforced at startup): a configured `[receipt]` signing key
and a durable storage backend (`sqlite` or `postgres`).

Storage: leaves live in the `log_leaves` table — dense 0-based
`leaf_index` in acceptance order, one leaf per `ctx_id`, and the **exact
JCS-canonical leaf bytes** plus their `sha256:` leaf hash, so every leaf
is byte-exactly reproducible forever. Roots and proofs are recomputed per
request from the ordered leaf hashes (O(n); the head root is cached).
Contexts published *before* enablement are not backfilled automatically;
per §7.3 their history would be time-unanchored anyway.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Opt into the RFC-ACDP-0012 log: atomic leaf appends + the three `/log/*` endpoints. |
| `instance` | string | `"1"` | The `<instance>` component of `log_id = did:web:<authority>/log/<instance>` (matches `[a-z0-9-]{1,32}`). **Change only on catastrophic tree loss** (§7.4) — a new instance is an explicit, loudly detectable history reset. |

### `[[witnesses]]` *(ACDP 0.4.0)*

Transparency-log **witness cosignature aggregation** (RFC-ACDP-0015 §6.1).
An array of independent witnesses this registry polls and whose **verified**
cosignatures it attaches to its checkpoint responses (the reserved
top-level `witness_signatures` member — see
[HTTP-API.md](HTTP-API.md#get-logcheckpoint-get-logproof-get-logentries-acdp-030)).
A consumer then gets a checkpoint **and** its witness quorum in one fetch
and verifies *N-witnessed* locally.

For each configured witness a background poller GETs
`<url>?log_id=<this registry's log_id>` over the SSRF-guarded outbound
client (HTTPS-only, DNS-rebinding-guarded, no redirects — RFC-ACDP-0008
§4.8), and for every returned cosignature runs the RFC-ACDP-0015 §8
verification procedure **against this registry's own checkpoint** at that
`tree_size`: closed parse, the witness signature under the witness DID's
`assertionMethod` key (resolved via the `did:web` resolver), and — the
load-bearing check — that the cosignature's `witnessed_checkpoint` matches
this registry's **own root** at that size. A witness cosigning a *different*
root (a fork, or a lie) is logged and **dropped** — it is never stored and
never served. Only verified cosignatures are persisted (table
`log_witness_cosignatures`, keyed by
`(log_id, tree_size, root_hash, witness_did)`; a fresh re-observation
upserts, newest wins), so serving is a single indexed read with no blocking
network call in the request path.

Aggregation is a pure convenience: the registry never holds a witness key,
so it can neither forge a cosignature nor make itself a trust dependency —
a consumer MAY always fetch direct from a witness (§6.2). There is **no new
capability flag or profile**: a registry that aggregates does so under its
existing `acdp-registry-transparency-log` profile (§10).

Prerequisites (enforced at startup): `log.enabled = true` (there are no
checkpoints to witness without a log), each `did` a `did:web` DID, and each
`url` accepted by the SSRF policy (HTTPS, non-private host). Empty (the
default) disables aggregation entirely.

```toml
[[witnesses]]
did          = "did:web:witness.example.org"
url          = "https://witness.example.org/log/witness"
poll_seconds = 60                              # default 300

[[witnesses]]
did = "did:web:witness-2.example.org"
url = "https://witness-2.example.org/log/witness"
```

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `did` | string | *(required)* | The witness's `did:web` DID. Cosignatures whose `witness_id` ≠ this value are ignored (a witness endpoint only speaks for its own DID). |
| `url` | string | *(required)* | HTTPS URL of the witness's `GET /log/witness` endpoint (RFC-ACDP-0015 §6.2). SSRF-checked at startup and at DNS time on every poll. |
| `poll_seconds` | integer | `300` | Poll interval. |
