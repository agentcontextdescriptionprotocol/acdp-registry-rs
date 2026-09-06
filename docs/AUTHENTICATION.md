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

## Presenting a bearer

Two bearer parsers coexist and they do not agree. Both are deliberate and both
are locked by tests; the difference is undocumented rather than accidental, and
it is what this section exists to state.

| Route group | Parser | Unrecognised header shape |
|---|---|---|
| `/contexts/*`, `/lineages/*`, and the other ordinary read/publish routes | `extract_bearer` (`crates/acdp-registry-auth/src/service.rs:400-405`) | treated as **anonymous** |
| `/admin/*` | `require_admin_bearer` (`crates/acdp-registry-core/src/handlers/admin.rs:679-693`) | rejected with **403** |

### Unrecognised means anonymous on the ordinary routes

`caller_from_headers` (`crates/acdp-registry-core/src/handlers/context.rs:1348-1365`)
returns `Ok(None)` — an anonymous caller — in three cases:

- `auth.enabled = false`, regardless of what the client sent;
- no `Authorization` header, or a value the HTTP layer will not hand over as a
  string — `HeaderValue::to_str` rejects any byte outside visible ASCII, which
  is broader than "not valid UTF-8" (`Bearer café` is valid UTF-8 and still
  fails);
- any value `extract_bearer` does not recognise, including a non-`Bearer` scheme.

Only a **well-formed** bearer whose token then fails validation is rejected, with
`403 not_authorized` — auth failures on this registry are `403`, never `401`, and
no `WWW-Authenticate` challenge is emitted (see
[HTTP-API.md](HTTP-API.md#error-envelope)). A client whose token merely expired sees that
explicitly rather than being silently downgraded.

The consequence worth knowing when debugging: **a typo in the scheme is not an
auth failure at all.** `Authorizaton: Bearer …` (misspelled header name),
`Basic …`, or `BEARER …` do not reach token validation — the request simply
proceeds as anonymous.

What the caller then sees depends on the route and on
`auth.anonymous_public_reads`, which ships as `false`. Anonymous access is
subject to the RFC-ACDP-0008 §4.5 visibility rules, so the same malformed header
can surface as a refusal on one route and as a short, successfully-filtered
result set on another. The invariant to hold onto while debugging is upstream of
that: the auth layer did not reject the header, it classified the caller as
anonymous. If a caller reports missing rows, or an authorization error that
names anonymity rather than a bad token, suspect the header shape before
suspecting the token.

On `/admin/*` the same inputs return `403` — absent, non-UTF-8, and unrecognised
headers are all refused, and an empty `auth.admin_tokens` list disables the routes
outright (`admin.rs:684`).

### What each parser accepts

`extract_bearer` strips `"Bearer "` or `"bearer "` and then trims the remaining
token. `require_admin_bearer` strips `"Bearer "` only, and does not trim.

Neither is case-insensitive: both hard-code their prefixes, so `BEARER` and
`BeArEr` are rejected by both.

| `Authorization` value | `/contexts/*` | `/admin/*` |
|---|---|---|
| `Bearer <token>` | `<token>` | `<token>` |
| `bearer <token>` | `<token>` | **403** |
| `Bearer  <token>` (two spaces) | `<token>` | token is `" <token>"`, so **403** |
| `Bearer <token>` + trailing space | `<token>` | **depends on protocol — see below** |
| `BEARER <token>`, `BeArEr <token>` | anonymous | 403 |
| `Bearer<TAB><token>` | anonymous | 403 |
| `Basic <token>`, bare `<token>`, empty | anonymous | 403 |

Both behaviours on the admin side are pinned by tests, so loosening either is a
deliberate reviewed change rather than a refactor: `bearer_scheme_is_case_sensitive`
(`admin.rs:854-863`) and `rejects_token_with_extra_whitespace` (`admin.rs:866-873`).

#### Trailing whitespace depends on the HTTP version

Trailing whitespace in the header *value* never reaches either parser over
HTTP/1.1: `httparse` strips trailing SP/HTAB/CR/LF from every header value while
parsing the request. Over HTTP/2, HPACK carries the value verbatim and nothing
strips it. The registry serves both.

So `Authorization: Bearer <token> ` (one trailing space) is accepted everywhere
over HTTP/1.1 — the space is gone before any handler sees it — and on HTTP/2 it
is accepted by `/contexts/*` (which trims) but **rejected by `/admin/*`** (which
does not). Only the *trailing* case is protocol-dependent; the two-space case
above is internal to the value and behaves identically on both.

The practical consequence is that an admin token configured with stray trailing
whitespace can appear to work in one environment and fail in another, depending
on whether a proxy or client negotiated HTTP/2. Startup validation now refuses
such entries outright — see [#161](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/issues/161)
and the admin-token rules in [CONFIGURATION.md](CONFIGURATION.md).

**Practical rule: send exactly `Authorization: Bearer <token>`, one space, no
surrounding whitespace.** That form is accepted everywhere. Any other spelling
works on some routes and not others.

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
