# Authentication

The registry authenticates **agents** (clients) with a DID challenge-response
flow that mints a short-lived JWT, and authenticates **producers** (publishers)
implicitly via the signature over `content_hash` carried in the publish request.
This doc covers the first. Publish signing belongs to the protocol, not this
registry — how a producer builds and signs a `PublishRequest` is documented in
[acdp-rs · Producing][acdp-producing], and where the registry verifies it in
[ARCHITECTURE.md](ARCHITECTURE.md#publish-pipeline).

All of this lives in `crates/acdp-registry-auth/` and is mounted only when
`auth.enabled = true`. When auth is disabled, the `/auth/*` routes are not
mounted, any `Authorization` header is ignored, and every caller is treated as
anonymous (so the visibility gate runs against `None`).

## Challenge-response flow

```
client                                         registry
  │  POST /auth/challenge { agent_id }            │
  │ ────────────────────────────────────────────►│  validate did:web, mint nonce,
  │                                               │  persist ChallengeRecord(nonce, agent_id, expires_at)
  │  AuthChallenge { nonce, signing_input, ... }  │
  │ ◄──────────────────────────────────────────── │
  │                                               │
  │  sign signing_input with a DID assertionMethod key
  │                                               │
  │  POST /auth/token { agent_id, key_id, nonce,  │
  │                     expires_at, algorithm, signature }
  │ ────────────────────────────────────────────►│  consume nonce (one-shot),
  │                                               │  resolve DID doc, verify VM + signature,
  │                                               │  mint JWT, record jti as issued
  │  TokenResponse { token, token_type, expires_at }
  │ ◄──────────────────────────────────────────── │
  │                                               │
  │  GET /contexts/... Authorization: Bearer <jwt>│
  │ ────────────────────────────────────────────►│  validate_bearer (sig, exp, aud, revocation)
```

### The signing input is namespaced

```
acdp-registry-auth:v1:{nonce}:{agent_id}:{registry_authority}:{expires_at}
```

The `acdp-registry-auth:v1:` prefix and the `registry_authority` binding are
load-bearing: they stop a signature minted for one purpose or one registry from
being replayed as a challenge response elsewhere. **Do not** remove the version
prefix or the authority component (see CLAUDE.md → Conventions).

### Token issuance checks (`/auth/token`)

In order (`service.rs`):

1. Atomically **consume** the nonce — a second use of the same nonce is rejected
   (one-shot, replay-proof).
2. The request's `agent_id` and `expires_at` must match the stored challenge
   record (defeats nonce theft and tampering).
3. The challenge must not have expired.
4. `algorithm` must be supported (`ed25519` or `ecdsa-p256`).
5. `key_id` is split into a `did:web:` DID + fragment; the fragment is required.
6. The DID document is resolved via the shared `WebResolver` — HTTPS-only,
   SSRF-policy-gated, LRU-cached, the *same* resolver used for publish. Its
   defenses (IP-literal rejection, DNS-time SSRF filtering, size/redirect caps)
   are documented in [acdp-rs · Security Model][acdp-security].
7. The verification method named by the fragment must appear in the document's
   `assertionMethod` set.
8. If the verification method declares an algorithm, it must match the request's
   `algorithm` (algorithm-downgrade defense, RFC-ACDP-0001 §5.10 — enforced by
   `acdp`; see [acdp-rs · Security Model][acdp-security]).
9. The signature is verified against the resolved public key.
10. A JWT is minted and its `jti` is recorded as *issued* in the revocation
    store. If that write fails, the whole request fails — a token that can't be
    tracked is never handed out.

## JWT claims

```json
{
  "iss": "did:web:registry.example.com",
  "sub": "did:web:agents.example.com:my-agent",
  "aud": "registry.example.com",
  "jti": "<uuid-v4>",
  "iat": 1748000000,
  "exp": 1748003600,
  "acdp": {
    "registry": "registry.example.com",
    "key_id":   "did:web:agents.example.com:my-agent#key-1"
  },
  "tenant": "acme"
}
```

- `aud` and `acdp.registry` bind the token to this registry's authority — a
  token minted by a peer won't validate here.
- `exp` defaults to `iat + auth.token_ttl_seconds` (default 3600 s).
- `tenant` is present **only** for agents bound via `[[auth.tenant_agents]]`;
  it is the sole authority for an authenticated caller's tenant (see
  [MULTI-TENANCY.md](MULTI-TENANCY.md)).

### Validation

On every bearer-authenticated request the registry checks the signature, `exp`
(with `auth.token_leeway_seconds` of clock skew, default 30 s), the `aud` /
`acdp.registry` binding, and the revocation store. A revoked or expired `jti` is
rejected with `403 not_authorized`.

## Signing algorithms

JWT signing is selected by `auth.jwt_signing_alg`:

| Alg | Key material | JWKS | Use it for |
|-----|--------------|------|------------|
| `HS256` (default) | `auth.jwt_secret` — base64, ≥32 bytes, symmetric | empty key set | Single registry; backward-compatible default. |
| `EdDSA` (Ed25519) | `auth.jwt_private_key_pem` — PKCS#8 PEM, asymmetric | publishes the public key | Federation — peers verify your tokens without sharing a secret. |

In HS256 mode the secret is never published; `GET /.well-known/jwks.json`
returns `{ "keys": [] }`. In EdDSA mode the public key is published there as an
OKP/Ed25519 JWK, with `kid` derived from the key fingerprint unless
`auth.jwt_kid` overrides it.

> **Dev convenience:** with HS256 and an empty `jwt_secret`, set
> `auth.allow_ephemeral_secret = true` to boot with a random process-lifetime
> key. Tokens won't survive a restart. Never use this in production — set a real
> `jwt_secret`. The startup validator refuses the literal `changeme` and refuses
> an empty secret unless `allow_ephemeral_secret` is set.

## Token revocation

`POST /auth/token/revoke` with `{ "jti": "..." }` and a valid bearer marks a
token revoked. The caller's DID must own the `jti` (you can only revoke your own
tokens). State lives in the revocation store
(`acdp-registry-auth/src/revocation_store.rs`):

- `record_issued` — written at mint time, `revoked = false` (never downgrades an
  existing `revoked = true`).
- `revoke` — flips the flag / writes a tombstone.
- `is_revoked(jti)` — checked on every bearer validation.
- `owner_of(jti)` — enforces the ownership check on revoke.
- `evict_expired(now)` — a background task prunes tombstones past `exp` (runs on
  a ~300 s tick alongside challenge eviction).

Recording the `jti` at *issuance* (not at revoke time) is what lets the registry
reject a revoked token that was never seen again — there's always a row to flip.

## Cross-issuer revocation federation

Revocation federation is **consume-only**. This registry does not expose a
`/auth/revocations` feed; it *polls* peers' feeds and applies their revocations
locally. Configure peers with `[[auth.revocation_feeds]]`:

```toml
[[auth.revocation_feeds]]
issuer       = "did:web:peer.example.com"          # must match each entry's `iss`
feed_url     = "https://peer.example.com/auth/revocations"
admin_token  = "<bearer for the peer's feed>"
poll_seconds = 300
```

A background poller per feed (`revocation_poller.rs`) fetches
`GET {feed_url}?since={cursor_ms}&limit=...`, sanity-checks each entry's `iss`
against the configured `issuer`, and applies remote revocations to the local
store. **Durable cursors** (`get_revocation_cursor` / `set_revocation_cursor`,
unix ms) survive restarts, and the cursor advances only when an entire page
applies cleanly — a partial failure replays that page on the next tick rather
than skipping revocations.

## Where it's wired

- Routes: `build_router()` in `crates/acdp-registry-core/src/lib.rs`.
- Flow + verification: `crates/acdp-registry-auth/src/service.rs`.
- JWT sign/verify and JWKS: `crates/acdp-registry-auth/src/jwt.rs`.
- Stores: `challenge_store.rs`, `revocation_store.rs` (in-memory / SQLite / PG).
- Startup wiring (signer choice, ephemeral secret, poller spawn):
  `crates/acdp-registry-server/src/main.rs`.

[acdp-producing]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md
[acdp-security]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md
