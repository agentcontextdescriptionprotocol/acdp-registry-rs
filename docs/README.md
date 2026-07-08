# acdp-registry-rs documentation

Reference documentation for the Agent Context Distribution Protocol (ACDP)
registry. The baseline is protocol v0.1.0; higher protocol levels light up as
their sections are configured — v0.2.0 trust-hardening (registry receipts,
did:key), v0.3.0 (lifecycle events, the transparency log, head receipts), and
v0.4.0 (witness cosignature aggregation). Start with the
[project README](../README.md) for a quick start; these docs go deeper.

## Map

| Doc | What it covers |
|-----|----------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate graph, storage trait, publish pipeline, the request lifecycle. |
| [HTTP-API.md](HTTP-API.md) | Every endpoint: inputs, response shapes, status codes, and the error envelope. |
| [AUTHENTICATION.md](AUTHENTICATION.md) | DID challenge-response, JWT claims, HS256 vs EdDSA, token revocation, cross-issuer federation. |
| [CONFIGURATION.md](CONFIGURATION.md) | The full config tree — every TOML key, its env-var name, type, and default. |
| [MULTI-TENANCY.md](MULTI-TENANCY.md) | Tenant resolution precedence, strict mode, agent→tenant bindings, the SQL filter. |
| [WEBHOOKS.md](WEBHOOKS.md) | Event payloads, the GitHub-compatible signature scheme, delivery and retry semantics. |
| [RECEIPTS.md](RECEIPTS.md) | ACDP 0.2.0 registry receipts: enabling, serving `/.well-known/did.json`, the key-retention rule, rotation, did:key, the lineage audit. |
| [OPERATIONS.md](OPERATIONS.md) | Deploying, observability, backup/restore, key rotation, federation ops. |

## Where the protocol ends and this registry begins

These docs cover **this service** — its HTTP surface, storage, auth, tenancy,
webhooks, and operations. They deliberately do **not** restate the protocol the
service implements. Anything about the wire format, signing/hashing,
verification, SSRF defenses, or the canonical error-code registry lives in the
`acdp` protocol library docs and the RFC spec — we link out rather than copy:

| For… | See |
|------|-----|
| The publish pipeline algorithm (RFC-ACDP-0003 §2.1), `RegistryServer` / `RegistryStore` | [acdp-rs · Implementing a Registry][acdp-registry] |
| Building/signing a `PublishRequest`, `content_hash`, supersession | [acdp-rs · Producing][acdp-producing] |
| The verification pipeline, `VerifiedContext`, retrieval | [acdp-rs · Consuming & Verifying][acdp-consuming] |
| The `AcdpError` ↔ RFC-ACDP-0007 §5 wire-code registry, retry guidance | [acdp-rs · Errors & Retries][acdp-errors] |
| SSRF defenses, HTTPS/size/redirect caps, algorithm-downgrade rejection (`WebResolver`) | [acdp-rs · Security Model][acdp-security] |
| The three-layer model (what is hashed/signed/mutable) | [acdp-rs · Architecture][acdp-arch] |
| API reference for the `acdp` crate | [docs.rs/acdp](https://docs.rs/acdp) |
| Normative protocol rules | [RFC set][spec] |

[acdp-registry]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/registry.md
[acdp-producing]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/producing.md
[acdp-consuming]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/consuming.md
[acdp-errors]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/errors.md
[acdp-security]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/security.md
[acdp-arch]: https://github.com/agentcontextdistributionprotocol/acdp-rs/blob/main/docs/architecture.md

## Conventions used throughout

- **Authority** — the registry's bare lowercase DNS name (e.g.
  `registry.example.com`). It is both the `ctx_id` minting authority and the
  `did:web` identifier for the registry.
- **`ctx_id`** — a fully-qualified context identifier scoped to an authority.
- **Wire envelope** — every ACDP data/auth endpoint returns
  `application/acdp+json`; errors follow the RFC-ACDP-0007 §5 envelope
  (see [HTTP-API.md](HTTP-API.md#error-envelope)).
- **RFC-ACDP-XXXX** references point at the [protocol spec][spec].

[spec]: https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol

## Spec profiles implemented

`acdp-registry-core` and `acdp-registry-discovery` always; `acdp-registry-receipts`,
`acdp-registry-head-receipts`, `acdp-registry-lifecycle`, and
`acdp-registry-transparency-log` are advertised when their config sections are
enabled. All are served at `GET /.well-known/acdp.json`.
See [HTTP-API.md](HTTP-API.md#get-well-knownacdpjson).
