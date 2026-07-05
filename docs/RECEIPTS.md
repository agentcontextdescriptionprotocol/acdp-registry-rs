# Registry receipts (ACDP 0.2.0 / RFC-ACDP-0010)

A **registry receipt** is the registry's signed, non-repudiable attestation of
what it did at publish time: the identifiers it assigned (`ctx_id`,
`lineage_id`), the timestamp it stamped (`created_at`), the content hash it
verified, and — critically — the **fingerprint of the producer key it actually
resolved** for signature verification. That last binding is what makes
contexts verifiable years later, after the producer has rotated keys or let
its domain lapse.

This doc is the operator runbook. The receipt wire format, signing
construction, and consumer-side verification procedure are normative in
[RFC-ACDP-0010]; the verifying client lives in `acdp-rs`
(`VerificationPolicy`, `ReceiptPolicy::Require`).

[RFC-ACDP-0010]: https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0010-registry-receipts.md

## Enabling receipts

Generate a 32-byte Ed25519 seed and configure it:

```bash
openssl rand -base64 32
```

```toml
[receipt]
signing_key_seed_b64 = "<that value>"     # or signing_key_path = "/etc/acdp/receipt-key.seed"
key_id_fragment      = "receipt-key-1"
```

Env-only deployments set `ACDP_REGISTRY_RECEIPT__SIGNING_KEY_SEED_B64`.

With a key configured the registry:

- advertises `acdp_version: "0.2.0"` and the `acdp-registry-receipts` profile
  in `/.well-known/acdp.json`;
- mints a receipt for **every** publish, **atomically** with the context row
  (one INSERT, one transaction — a context can never exist without its
  receipt, and a failed mint aborts the publish);
- returns the receipt as the top-level `registry_receipt` member of the
  publish response and of `GET /contexts/{ctx_id}` (never of
  `GET /contexts/{ctx_id}/body`);
- serves its own DID document at `GET /.well-known/did.json` (below).

Advertising the profile is a **hard commitment** — there is no
`receipt_unavailable` error and no degraded mode. That is also why
`playground.enabled` and `[receipt]` are mutually exclusive at startup: the
playground path never resolves the producer key, so any fingerprint it
attested would be false.

## Lineage-head receipts (ACDP 0.3.0 / RFC-ACDP-0011)

Registry receipts attest **publish-time** facts; a **lineage-head receipt**
attests a **serve-time** claim: "as of `as_of`, the head of `lineage_id` is
`head_ctx_id` at `head_version` with `head_status`". Enable it on top of a
configured receipt key:

```toml
[receipt]
signing_key_seed_b64 = "<seed>"
key_id_fragment      = "receipt-key-1"
head_receipts        = true              # ACDP 0.3.0 / RFC-ACDP-0011
```

With `head_receipts = true` the registry:

- advertises `acdp_version: "0.3.0"` and the `acdp-registry-head-receipts`
  profile (prerequisite: `acdp-registry-receipts` — startup validation
  refuses the flag without a signing key);
- mints a **fresh** receipt on every `GET /lineages/{id}/current` response,
  attached as the top-level `lineage_head_receipt` envelope member. `as_of`
  is the registry clock at response time, millisecond-truncated; the head
  fields are copied verbatim from the served, visibility-filtered head, so
  the RFC-ACDP-0011 §7 step-5 byte-match holds by construction;
- **never persists** head receipts (they are ephemeral evidence about one
  response instant), never attaches them to `GET /contexts/{ctx_id}/body`,
  and never mints one naming a superseded or retracted head — minting runs
  *after* head selection, and when `/current` 404s (all versions
  superseded-or-retracted) there is no head claim to attest;
- signs with the **same receipt key** — head receipts introduce no new key
  role, no new DID-document entry, and no new rotation procedure (the
  `receipt_version: "acdp-lhr/1"` member domain-separates the preimage).

Because head receipts are requester-relative (the head is selected under
the requester's visibility), `/current` responses must not be cached across
differently-authorized requesters — the existing `Cache-Control: private`
posture for non-public content covers this.

## Serving `/.well-known/did.json`

A receipt's signature references `did:web:<authority>#<fragment>`, and
`did:web:<authority>` resolves to `https://<authority>/.well-known/did.json`.
The registry generates and serves that document itself from the `[receipt]`
section — no out-of-band hosting needed, but note:

- the registry must be reachable over **HTTPS at the bare authority** it
  mints (`registry.authority`); DID resolution is HTTPS-only;
- if a CDN or proxy fronts the registry, make sure `/.well-known/did.json`
  is routed through (it is cacheable, `max-age=300`).

The active signing key appears in both `verificationMethod` and
`assertionMethod`. Retired keys appear in `verificationMethod` only.

## The key-retention rule (read before rotating)

RFC-ACDP-0010 §9 (**MUST**): every key that ever signed a receipt stays in
`verificationMethod` **indefinitely**. Rotation removes a key from
`assertionMethod` **only**. A verifier accepts a receipt key found in
`verificationMethod` even when absent from `assertionMethod` — that is what
keeps old receipts verifiable after rotation.

**Removing a retired key from `verificationMethod` bricks every receipt that
key ever signed.** The one sanctioned exception is confirmed key compromise,
where invalidation is the point; in that case re-mint affected receipts under
the successor key (they attest the original stored `created_at`, not re-mint
time).

### Rotation procedure

1. Generate a new seed; pick a **fresh** fragment (`receipt-key-2`).
2. Move the old key's **public** half into `[[receipt.retired_keys]]`:

   ```toml
   [receipt]
   signing_key_seed_b64 = "<new seed>"
   key_id_fragment      = "receipt-key-2"

   [[receipt.retired_keys]]
   public_key_b64  = "<base64 of the OLD raw 32-byte public key>"
   key_id_fragment = "receipt-key-1"
   ```

3. Restart. `did.json` now lists both keys in `verificationMethod` and only
   `receipt-key-2` in `assertionMethod`.
4. Never delete the `retired_keys` entry (see above).

## Backfill policy: none

Contexts published before receipts were enabled stay receipt-less, and their
`registry_receipt` member is simply absent. We deliberately do **not**
backfill: a receipt attests publish-time facts — above all the producer key
the registry *actually resolved at that moment* — and minting one later would
be a false attestation. (RFC-ACDP-0010 permits backfill that attests the
stored `created_at`; this implementation takes the conservative position.)

The `GET /admin/lineages/{lineage_id}/audit` report exposes
`receiptless_contexts` so you can see how much pre-receipts history a lineage
carries.

## did:key producers

Enable with:

```toml
[auth]
did_methods = ["did:web", "did:key"]
```

did:key publishes verify **offline** — the DID *is* the key, so there is no
DID-document fetch, no SSRF surface, and no `assertionMethod` check. When the
method is not advertised, a did:key publish is rejected with
`key_resolution_failed` (HTTP 400, permanent — fixture dk-003).

Receipts matter *more* for did:key producers: the DID has no document to
attest anything else, and a new key is a new identity (no rotation, so
lineage continuity ends with the key). The recommended pattern is two-tier:
organizations anchor on `did:web`, ephemeral/archival producers use
`did:key`.

## Lineage anchoring and the audit endpoint

The publish path validates a v(N+1) against the **immediate predecessor's
persisted row** (lineage anchoring, RFC-ACDP-0001 §5.6.2) instead of walking
the chain back to v1 — a deep lineage with an unretrievable intermediate can
no longer fail a publish. The full walk still exists, as an on-demand
integrity check:

```
GET /admin/lineages/{lineage_id}/audit
Authorization: Bearer <auth.admin_tokens entry>
```

It verifies version contiguity, supersedes links, the `lineage_id`
derivation from v1, producer continuity, and the single-tip invariant, and
reports receipt coverage. Run it periodically (or after restoring from
backup) — it detects storage corruption the anchored fast path would
silently inherit.

## KMS / HSM

Key loading is isolated in `acdp-registry-core::receipt` (config →
`acdp::types::receipt::ReceiptSigner`). A KMS/HSM-backed deployment plugs in
at that seam; note that today's `acdp` `ReceiptSigner` holds raw key
material, so non-extractable keys additionally need an upstream `acdp`
signer abstraction — tracked as future work, the publish path will not
change.

## Verifying end-to-end

From any machine that can reach the registry over TLS:

```rust
use acdp::client::registry::RegistryClient; // see docs.rs/acdp
use acdp::client::verified::{ReceiptPolicy, VerificationPolicy, VerifiedContext};

let policy = VerificationPolicy {
    receipts: ReceiptPolicy::Require,
    ..VerificationPolicy::default()
};
// fetch + verify body signature, then receipt signature against the
// registry's /.well-known/did.json, plus all RFC-ACDP-0010 §8 cross-checks.
```

A receipt failure does not invalidate the body — the producer signature
stands on its own; what is lost is the registry's binding of identifiers and
time. `acdp` reports the two verdicts separately.
