//! `acdp-registry` binary.
//!
//! Wires config → storage backend → registry server → auth service →
//! webhook emitter → axum router → bind. Storage backend is picked at
//! compile time via Cargo features: `storage-sqlite` (default),
//! `storage-pg`.

#[cfg(any(
    all(feature = "storage-sqlite", feature = "storage-pg"),
    all(feature = "storage-sqlite", feature = "storage-memory"),
    all(feature = "storage-pg", feature = "storage-memory"),
))]
compile_error!(
    "Enable exactly one of `storage-sqlite`, `storage-pg`, or `storage-memory`. \
     The binary's `run()` function selects the backend via cfg gates that assume \
     a single feature is on."
);

#[cfg(feature = "storage-memory")]
mod memory_ext;

use std::net::SocketAddr;
use std::sync::Arc;

use acdp::client::CrossRegistryResolver;
use acdp::did::{authority_to_did_web, WebResolver};
use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp_registry_auth::{AuthService, ChallengeStore, JwtSecret, JwtSigner, RevocationStore};
#[cfg(feature = "storage-memory")]
use acdp_registry_auth::{InMemoryChallengeStore, InMemoryRevocationStore};
use acdp_registry_core::{build_router, AppStateInner};
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{RegistryConfig, StorageBackend, REGISTRY_ADVERTISABLE_PROFILES};
use acdp_registry_webhook::WebhookEmitter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let _ = dotenvy::dotenv();

    let cfg = RegistryConfig::load(None).map_err(|e| anyhow::anyhow!("config: {e}"))?;
    // FEAT-09: surface every fixable misconfiguration BEFORE running
    // migrations or binding the socket. Discovering a bad jwt_secret on
    // first `/auth/token` request is much worse than discovering it now.
    validate_config(&cfg)?;
    tracing::info!(
        authority = %cfg.registry.authority,
        port = cfg.registry.port,
        backend = ?cfg.storage.backend,
        playground = cfg.playground.enabled,
        "starting acdp-registry"
    );

    run(cfg).await
}

/// FEAT-09: pre-bind config validation. Each check matches a runtime
/// requirement that would otherwise be discovered lazily.
fn validate_config(cfg: &RegistryConfig) -> anyhow::Result<()> {
    if cfg.auth.enabled {
        match cfg.auth.jwt_signing_alg.as_str() {
            "HS256" | "" => {}
            "EdDSA" => {
                if cfg.auth.jwt_private_key_pem.trim().is_empty() {
                    anyhow::bail!(
                        "auth.jwt_signing_alg=EdDSA but auth.jwt_private_key_pem is empty"
                    );
                }
            }
            other => anyhow::bail!(
                "auth.jwt_signing_alg must be 'HS256' or 'EdDSA' (got '{}')",
                other
            ),
        }
    }
    if cfg.auth.enabled
        && cfg.auth.jwt_signing_alg.as_str() != "EdDSA"
        && cfg.auth.jwt_secret.trim().is_empty()
        && !cfg.auth.allow_ephemeral_secret
    {
        // REG-P1-4: with auth on and HS256 selected, an empty secret would
        // otherwise fall through to an ephemeral process-lifetime key —
        // tokens silently stop validating after a restart / across replicas.
        // Fail fast unless the operator explicitly opted into ephemeral mode.
        anyhow::bail!(
            "auth.enabled with HS256 but auth.jwt_secret is empty; set \
             ACDP_REGISTRY_AUTH__JWT_SECRET (base64, ≥32 bytes) or set \
             auth.allow_ephemeral_secret=true for local dev"
        );
    }
    if cfg.auth.enabled
        && cfg.auth.jwt_signing_alg.as_str() != "EdDSA"
        && !cfg.auth.jwt_secret.is_empty()
    {
        // OPS-02 stronger guard: the docker-compose default placeholder
        // must not reach production. Run the literal check FIRST so an
        // operator who left `changeme` in place gets the actionable
        // "generate a real secret" hint instead of the generic
        // base64-length error that `JwtSecret::from_base64` would
        // surface (`changeme` happens to be valid base64 of 6 bytes).
        let trimmed = cfg.auth.jwt_secret.trim();
        if trimmed.eq_ignore_ascii_case("changeme") {
            anyhow::bail!("auth.jwt_secret is the placeholder 'changeme'; generate a real secret");
        }
        // Same decode-and-length check `JwtSecret::from_base64` performs;
        // doing it up front means a malformed secret is rejected at
        // startup rather than triggering 500s mid-flight.
        let _ = JwtSecret::from_base64(&cfg.auth.jwt_secret)
            .map_err(|e| anyhow::anyhow!("auth.jwt_secret: {e}"))?;
    }
    if cfg.webhook.enabled {
        if cfg.webhook.url.is_empty() {
            anyhow::bail!("webhook.enabled but webhook.url is empty");
        }
        acdp::safe_http::SsrfPolicy::default()
            .check_url(&cfg.webhook.url)
            .map_err(|e| anyhow::anyhow!("webhook.url rejected by SSRF policy: {e}"))?;
        if cfg.webhook.secret.trim().is_empty() {
            anyhow::bail!(
                "webhook.enabled but webhook.secret is empty — HMAC over a zero-length key \
                 accepts every signature"
            );
        }
    }
    // SEC (#17): a multi-tenant deployment must enforce tenant scoping. With
    // `tenant_agents` configured (the operator's intent is multi-tenancy) but
    // `require_tenant=false`, a request that resolves to no tenant (no header,
    // unbound caller) would run with the tenant filter disabled and read across
    // tenants. Force strict enforcement at startup rather than fail open.
    if !cfg.auth.tenant_agents.is_empty() && !cfg.auth.require_tenant {
        anyhow::bail!(
            "auth.tenant_agents is configured (multi-tenant) but auth.require_tenant=false; \
             a request resolving to no tenant would bypass the tenant filter. Set \
             auth.require_tenant=true."
        );
    }
    // #137: tenancy on the memory backend serves nothing, so refuse the
    // combination rather than starting a registry that answers every read
    // with zero rows. The guard above forces `require_tenant=true` whenever
    // `tenant_agents` is set, so this config is always strict. `MemoryStore`
    // (`memory_ext.rs`) overrides none of the three tenancy methods on
    // `ExtendedRegistryStore`, so it inherits their untenanted defaults:
    // `set_tenant_of_ctx` is a no-op and `tenant_of_ctx`/`tenants_of_ctxs`
    // report `"default"` for every row. `"default"` is `RESERVED_TENANT`,
    // which `reject_reserved_tenant` refuses to accept from a header or a
    // token claim — so no caller can ever assert the one tenant every row
    // reports, and every tenant-scoped read matches nothing. Publishes still
    // succeed — they just record no tenant — so a warning would have nothing
    // working to preserve on the read path. Note this keys on `tenant_agents`
    // only; `require_tenant` alone on this backend is the same failure and is
    // not yet refused (#156).
    if !cfg.auth.tenant_agents.is_empty() && matches!(cfg.storage.backend, StorageBackend::Memory) {
        anyhow::bail!(
            "auth.tenant_agents is configured (multi-tenant) but storage.backend=memory, \
             which is not tenancy-aware: it records no tenant for a published context and \
             reports the reserved 'default' tenant for every row, which no caller is \
             permitted to assert. Every tenant-scoped read would return zero rows. Use \
             the sqlite or postgres backend for a multi-tenant deployment."
        );
    }

    // ACDP 0.2.0: validate the DID methods this registry will advertise.
    // The publish validator gates on `supported_did_methods`, so an entry
    // the pipeline can't actually verify would advertise a capability the
    // registry silently fails to honor.
    for method in &cfg.auth.did_methods {
        match method.as_str() {
            "did:web" | "did:key" => {}
            other => anyhow::bail!(
                "auth.did_methods contains unsupported method '{other}'; \
                 this registry can verify 'did:web' and 'did:key'"
            ),
        }
    }
    if !cfg.auth.did_methods.iter().any(|m| m == "did:web") {
        anyhow::bail!("auth.did_methods must include 'did:web' (mandatory per RFC-ACDP-0007 §3.1)");
    }

    // ACDP 0.2.0: receipt signing identity (RFC-ACDP-0010). Parse the key
    // at startup — a registry must never lazily discover a bad receipt key
    // on its first publish, because advertising the receipts profile is a
    // hard commitment with no degraded mode.
    if cfg.receipt.is_configured() {
        // `playground.pinned_only=true` genuinely verifies every publish
        // against a pre-configured key (crates/acdp-registry-core/src/
        // playground.rs::enforce_pinned_signature — a non-pinned agent is
        // rejected outright, never silently accepted), producing exactly
        // the same verified (agent_did, content_hash) pair a receipt
        // attests regardless of how the key was resolved. Only the fully
        // unverified sub-mode (`pinned_only=false`, which accepts any
        // signature from a non-pinned agent with no check at all) is
        // structurally incompatible with RFC-ACDP-0010 §7's "no degraded
        // mode" — that's the case this guards against.
        if cfg.playground.enabled && !cfg.playground.pinned_only {
            anyhow::bail!(
                "playground.enabled with pinned_only=false is incompatible with [receipt]: a \
                 receipts-advertising registry has no unverified publish path (RFC-ACDP-0010 \
                 §7: no degraded mode). Set playground.pinned_only=true (every publish then \
                 verifies against a playground.pinned_keys entry) or disable playground.enabled."
            );
        }
        if cfg.playground.enabled
            && cfg.playground.pinned_only
            && cfg.playground.pinned_keys.is_empty()
        {
            anyhow::bail!(
                "playground.pinned_only=true with no playground.pinned_keys configured would \
                 reject every publish outright — add at least one pinned key or disable \
                 playground.enabled."
            );
        }
        acdp_registry_core::receipt::build_signer(&cfg.receipt, &cfg.registry.authority)
            .map_err(|e| anyhow::anyhow!("receipt: {e}"))?;
        // Also build the DID document up front: it additionally validates
        // every `[[receipt.retired_keys]]` entry. A malformed retired key
        // must fail startup, not silently 404 `/.well-known/did.json`
        // while capabilities keep advertising the receipts profile.
        acdp_registry_core::receipt::build_did_document(&cfg.receipt, &cfg.registry.authority)
            .map_err(|e| anyhow::anyhow!("receipt: {e}"))?;
    }

    // REG-5: "is this even a registry profile" logically precedes "can we
    // honor it" — run this allowlist check BEFORE the per-profile
    // backing-config guards below, so an operator with both a typo AND a
    // missing backing config sees the typo (the more fundamental,
    // actionable error) first. The allowlist is exactly the registry
    // profiles the pinned spec defines (every `profiles[].id` in the
    // spec's `registries/profiles.json` prefixed `acdp-registry-`); see
    // `REGISTRY_ADVERTISABLE_PROFILES`'s doc comment. This deliberately
    // does NOT special-case `acdp-log-witness` in the allowlist itself —
    // the prefix rule already excludes it — but DOES special-case it in
    // the error message, since a well-meaning operator confusing "runs a
    // witness" with "is a registry" is the most likely mistake here.
    for profile in &cfg.registry.profiles {
        if !REGISTRY_ADVERTISABLE_PROFILES.contains(&profile.as_str()) {
            if profile == "acdp-log-witness" {
                anyhow::bail!(
                    "registry.profiles advertises 'acdp-log-witness', but a witness is not a \
                     registry (RFC-ACDP-0015 §6.1): aggregate cosignatures under \
                     acdp-registry-transparency-log without advertising this profile. Remove \
                     'acdp-log-witness' from registry.profiles."
                );
            }
            anyhow::bail!(
                "registry.profiles advertises '{profile}', which is not a registry profile the \
                 pinned ACDP spec defines. Valid values: {:?}.",
                REGISTRY_ADVERTISABLE_PROFILES
            );
        }
    }

    // RFC-ACDP-0010 §7/§11: advertising `acdp-registry-receipts` is a hard
    // commitment to ALWAYS mint and serve receipts. An operator who lists the
    // profile in `registry.profiles` but configures no `[receipt]` key would
    // advertise a capability the registry can't honor: no signer is attached
    // so no receipt is ever minted, and `/.well-known/did.json` 404s — yet
    // capabilities still promise receipts, which consumers treat as a
    // registry fault (§7, no degraded mode). Refuse the inconsistent config
    // at startup rather than ship a false advertisement. (The reverse — a
    // receipt key with the profile omitted — is safe: `with_receipt_signer`
    // appends the profile itself. `acdp_version` itself is unaffected either
    // way — see `acdp_version_claim` below.)
    if cfg
        .registry
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-receipts")
        && !cfg.receipt.is_configured()
    {
        anyhow::bail!(
            "registry.profiles advertises 'acdp-registry-receipts' but no [receipt] signing \
             key is configured. Advertising the profile is a hard commitment to mint a \
             receipt on every publish (RFC-ACDP-0010 §7) — configure receipt.signing_key_seed_b64 \
             or receipt.signing_key_path, or remove the profile from registry.profiles."
        );
    }

    // ACDP 0.3.0 / RFC-ACDP-0011 §9: head receipts reuse the RFC-ACDP-0010
    // receipt signing key wholesale — the profile's prerequisite is
    // `acdp-registry-receipts`, so a head-receipts opt-in without a receipt
    // key has nothing to sign with and must fail startup, not 500 on the
    // first /current.
    if cfg.receipt.head_receipts && !cfg.receipt.is_configured() {
        anyhow::bail!(
            "receipt.head_receipts=true but no [receipt] signing key is configured. \
             Lineage-head receipts are signed with the RFC-ACDP-0010 receipt key \
             (RFC-ACDP-0011 §5: no new key role) — configure receipt.signing_key_seed_b64 \
             or receipt.signing_key_path, or disable receipt.head_receipts."
        );
    }
    // Same false-advertisement guard as the receipts profile: listing a
    // 0.3.0 profile in `registry.profiles` without enabling the feature
    // that honors it would advertise a capability the registry can't
    // serve (RFC-ACDP-0011 §6 / RFC-ACDP-0013 §10: no degraded mode).
    // (The reverse is safe: the `with_*` builders append the profiles.)
    if cfg
        .registry
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-head-receipts")
        && !cfg.receipt.head_receipts
    {
        anyhow::bail!(
            "registry.profiles advertises 'acdp-registry-head-receipts' but \
             receipt.head_receipts is not enabled. Advertising the profile commits the \
             registry to mint a head receipt on every /current response (RFC-ACDP-0011 §6) \
             — set receipt.head_receipts=true (with a [receipt] key) or remove the profile."
        );
    }
    if cfg
        .registry
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-lifecycle")
        && !cfg.lifecycle.enabled
    {
        anyhow::bail!(
            "registry.profiles advertises 'acdp-registry-lifecycle' but lifecycle.enabled \
             is false. Advertising the profile commits the registry to the RFC-ACDP-0013 \
             §6 endpoint surface — set lifecycle.enabled=true or remove the profile."
        );
    }

    // ACDP 0.3.0 / RFC-ACDP-0012 §11: the transparency-log profile's
    // prerequisite is `acdp-registry-receipts` — load-bearing twice over:
    // leaves bind receipt hashes (§4) and checkpoints sign with the
    // receipt key (§6). A log opt-in without a receipt key has nothing to
    // put in a leaf and nothing to sign checkpoints with.
    if cfg.log.enabled && !cfg.receipt.is_configured() {
        anyhow::bail!(
            "log.enabled=true but no [receipt] signing key is configured. The transparency \
             log's prerequisite is the receipts profile (RFC-ACDP-0012 §11: leaves bind \
             receipt hashes and checkpoints sign with the receipt key) — configure \
             receipt.signing_key_seed_b64 or receipt.signing_key_path, or disable [log]."
        );
    }
    // §7.1/§7.4: the log is a durable, append-only history commitment;
    // the ephemeral memory backend loses the tree on every restart, which
    // would force a log_id reset per §7.4 — refuse the combination.
    if cfg.log.enabled && matches!(cfg.storage.backend, StorageBackend::Memory) {
        anyhow::bail!(
            "log.enabled=true requires a durable storage backend (sqlite or postgres): the \
             transparency log is an append-only history the registry commits to across \
             restarts (RFC-ACDP-0012 §7.1/§7.4); the memory backend cannot honor that."
        );
    }
    // §6: the instance component must match [a-z0-9-]{1,32}; validate the
    // full log_id shape at startup, not on the first /log/checkpoint.
    if cfg.log.enabled {
        let log_id = format!(
            "{}/log/{}",
            authority_to_did_web(&cfg.registry.authority),
            cfg.log.instance.trim()
        );
        acdp::types::log::parse_log_id(&log_id)
            .map_err(|e| anyhow::anyhow!("log.instance: {e}"))?;
    }
    // Same false-advertisement guard as the other 0.3.0 profiles.
    if cfg
        .registry
        .profiles
        .iter()
        .any(|p| p == "acdp-registry-transparency-log")
        && !cfg.log.enabled
    {
        anyhow::bail!(
            "registry.profiles advertises 'acdp-registry-transparency-log' but log.enabled \
             is false. Advertising the profile is the RFC-ACDP-0012 §7 commitment (log every \
             accepted publish atomically, serve all three /log/* endpoints, no degraded \
             mode) — set log.enabled=true or remove the profile."
        );
    }

    // ACDP 0.4.0 / RFC-ACDP-0015 §6.1: witness-cosignature aggregation.
    // Each configured witness is polled over the SSRF-guarded client and
    // its cosignatures verified against this registry's own checkpoints.
    // Aggregation is meaningless without a log (there are no checkpoints to
    // witness), so require `log.enabled`. Validate every witness DID/URL up
    // front — a bad witness must fail startup, not silently never poll.
    if !cfg.witnesses.is_empty() && !cfg.log.enabled {
        anyhow::bail!(
            "[[witnesses]] is configured but log.enabled is false. Witness-cosignature \
             aggregation (RFC-ACDP-0015 §6.1) attaches cosignatures to this registry's \
             transparency-log checkpoints — enable [log] or remove the witnesses."
        );
    }
    for w in &cfg.witnesses {
        if !w.did.starts_with("did:web:") || w.did.len() <= "did:web:".len() {
            anyhow::bail!(
                "witness did '{}' must be a did:web DID (the only method resolvable over the \
                 network under the SSRF guard, RFC-ACDP-0015 §9)",
                w.did
            );
        }
        acdp::safe_http::SsrfPolicy::default()
            .check_url(&w.url)
            .map_err(|e| anyhow::anyhow!("witness url '{}' rejected by SSRF policy: {e}", w.url))?;
    }

    // SEC: refuse an insecure default deployment — a non-loopback bind with
    // BOTH TLS and auth disabled exposes an unauthenticated, plaintext registry
    // on every interface. Require an explicit opt-in (the operator asserting a
    // TLS-terminating, authenticating proxy fronts it on a trusted network).
    if !is_loopback_bind(&cfg.registry.bind)
        && !cfg.registry.tls.enabled
        && !cfg.auth.enabled
        && !cfg.registry.allow_public_bind
    {
        anyhow::bail!(
            "refusing to bind '{}' with TLS and auth both disabled: this exposes an \
             unauthenticated, plaintext registry on a public interface. Bind 127.0.0.1, \
             enable tls/auth, or set registry.allow_public_bind=true if a trusted proxy \
             terminates TLS and authenticates in front of it.",
            cfg.registry.bind
        );
    }
    // FEAT-06: validate the trusted-proxy CIDRs up front — a typo like
    // "10.0.0/8" must fail startup, not silently disable XFF trust (which
    // would make the registry key rate limits on the proxy IP for everyone).
    acdp_registry_core::rate_limit::TrustedProxies::parse(&cfg.rate_limit.trusted_proxies)
        .map_err(|e| anyhow::anyhow!("rate_limit.trusted_proxies: {e}"))?;
    // FEAT-06: a non-empty trusted_proxies list only makes sense with the
    // limiter enabled — otherwise XFF is parsed for nothing.
    if !cfg.rate_limit.enabled && !cfg.rate_limit.trusted_proxies.is_empty() {
        anyhow::bail!(
            "rate_limit.trusted_proxies is configured but rate_limit.enabled=false; \
             enable the limiter or drop the trusted_proxies list"
        );
    }
    // FEAT-10: reject a non-monotonic / negative histogram bucket ladder up
    // front — Prometheus requires strictly increasing positive bounds.
    if cfg.metrics.enabled {
        let b = &cfg.metrics.duration_buckets;
        if b.is_empty() {
            anyhow::bail!("metrics.duration_buckets must not be empty when metrics are enabled");
        }
        if b.iter().any(|x| !x.is_finite() || *x <= 0.0) {
            anyhow::bail!("metrics.duration_buckets must be positive, finite seconds");
        }
        if b.windows(2).any(|w| w[0] >= w[1]) {
            anyhow::bail!("metrics.duration_buckets must be strictly increasing");
        }
    }

    if cfg.registry.tls.enabled {
        let cert = cfg
            .registry
            .tls
            .cert_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tls.cert_path missing"))?;
        let key = cfg
            .registry
            .tls
            .key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("tls.key_path missing"))?;
        if !cert.exists() {
            anyhow::bail!("tls.cert_path '{}' does not exist", cert.display());
        }
        if !key.exists() {
            anyhow::bail!("tls.key_path '{}' does not exist", key.display());
        }
    }
    Ok(())
}

/// Whether `bind` is a loopback address (`127.0.0.0/8`, `::1`) or `localhost`.
/// A non-loopback bind is treated as "public" for the insecure-default guard;
/// an unparseable hostname is conservatively treated as public.
fn is_loopback_bind(bind: &str) -> bool {
    if bind.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bind.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Build the listen address from a `bind` host and `port`.
///
/// A bare IPv6 literal such as `::` (the IPv6 wildcard Railway and other
/// IPv6-native platforms recommend) is *not* valid host:port syntax once a
/// `:port` is appended — `:::8080` fails to parse. So when `bind` is a plain
/// IP literal, combine it with the port via `SocketAddr::new`, which is
/// bracket-agnostic. Only fall back to the `host:port` string form for inputs
/// that are not bare IP literals (e.g. already-bracketed `[::1]`).
fn resolve_bind_addr(bind: &str, port: u16) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = bind.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    format!("{bind}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("bind address {bind:?} port {port}: {e}"))
}

#[cfg(feature = "storage-sqlite")]
async fn run(cfg: RegistryConfig) -> anyhow::Result<()> {
    use acdp_registry_auth::{SqliteChallengeStore, SqliteRevocationStore};
    use acdp_registry_sqlite::SqliteStore;
    if !matches!(cfg.storage.backend, StorageBackend::Sqlite) {
        anyhow::bail!(
            "this build only supports SQLite; rebuild with --features storage-pg for Postgres"
        );
    }
    let path = cfg
        .storage
        .sqlite_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("storage.sqlite_path missing"))?;
    let store = SqliteStore::connect(&path, cfg.storage.max_connections).await?;
    // RFC-ACDP-0012 §7.1: with [log] enabled, every commit_publish appends
    // the leaf in the same transaction as the context row + receipt.
    let store = if cfg.log.enabled {
        store.with_transparency_log()
    } else {
        store
    };
    store.migrate().await?;
    {
        let evictor = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                if let Err(e) = evictor.evict_idempotency(chrono::Utc::now()).await {
                    tracing::warn!(error = %e, "idempotency eviction failed");
                }
            }
        });
    }
    // BUG-06 / DESIGN-02: use the DB-backed challenge store so migration
    // 003's `auth_challenges` table is actually written to, and the
    // background evictor scrubs persistent rows rather than the
    // long-dead in-memory map.
    let challenges: Arc<dyn ChallengeStore> =
        Arc::new(SqliteChallengeStore::new(store.pool().clone()));
    // SEC-01: persisted revocation list; `JwtSigner::validate` rejects
    // tokens whose jti has been tombstoned here.
    let revocations: Arc<dyn RevocationStore> =
        Arc::new(SqliteRevocationStore::new(store.pool().clone()));
    serve_with_store(cfg, store, challenges, Some(revocations)).await
}

#[cfg(all(feature = "storage-pg", not(feature = "storage-sqlite")))]
async fn run(cfg: RegistryConfig) -> anyhow::Result<()> {
    use acdp_registry_auth::{PgChallengeStore, PgRevocationStore};
    use acdp_registry_pg::PgStore;
    if !matches!(cfg.storage.backend, StorageBackend::Postgres) {
        anyhow::bail!(
            "this build only supports Postgres; rebuild with --features storage-sqlite for SQLite"
        );
    }
    let url = cfg
        .storage
        .postgres_url
        .clone()
        .ok_or_else(|| anyhow::anyhow!("storage.postgres_url missing"))?;
    let store = PgStore::connect(&url, cfg.storage.max_connections).await?;
    // RFC-ACDP-0012 §7.1: with [log] enabled, every commit_publish appends
    // the leaf in the same transaction as the context row + receipt.
    let store = if cfg.log.enabled {
        store.with_transparency_log()
    } else {
        store
    };
    store.migrate().await?;
    {
        let evictor = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                if let Err(e) = evictor.evict_idempotency(chrono::Utc::now()).await {
                    tracing::warn!(error = %e, "idempotency eviction failed");
                }
            }
        });
    }
    // BUG-06: crash-safe / multi-replica nonce store. The in-memory
    // variant breaks the handshake when an agent posts the challenge to
    // one replica and the token to another.
    let challenges: Arc<dyn ChallengeStore> = Arc::new(PgChallengeStore::new(store.pool().clone()));
    let revocations: Arc<dyn RevocationStore> =
        Arc::new(PgRevocationStore::new(store.pool().clone()));
    serve_with_store(cfg, store, challenges, Some(revocations)).await
}

#[cfg(all(
    feature = "storage-memory",
    not(feature = "storage-sqlite"),
    not(feature = "storage-pg")
))]
async fn run(cfg: RegistryConfig) -> anyhow::Result<()> {
    use crate::memory_ext::MemoryStore;
    if !matches!(cfg.storage.backend, StorageBackend::Memory) {
        anyhow::bail!("this build only supports the memory backend; rebuild with another feature");
    }
    let store = MemoryStore::new();
    store.migrate().await?;
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let revocations: Arc<dyn RevocationStore> = Arc::new(InMemoryRevocationStore::new());
    serve_with_store(cfg, store, challenges, Some(revocations)).await
}

#[cfg(not(any(
    feature = "storage-sqlite",
    feature = "storage-pg",
    feature = "storage-memory"
)))]
async fn run(_cfg: RegistryConfig) -> anyhow::Result<()> {
    anyhow::bail!(
        "no storage backend feature enabled — rebuild with one of \
         --features storage-sqlite, storage-pg, storage-memory"
    )
}

async fn serve_with_store<S: ExtendedRegistryStore + 'static>(
    cfg: RegistryConfig,
    store: S,
    challenges: Arc<dyn ChallengeStore>,
    revocations: Option<Arc<dyn RevocationStore>>,
) -> anyhow::Result<()> {
    // Capabilities + RegistryServer.
    let caps = build_capabilities(&cfg);
    let server = RegistryServer::try_new(store, caps, cfg.registry.authority.clone())
        .map_err(|e| anyhow::anyhow!("registry server: {e}"))?;
    // ACDP 0.2.0 / RFC-ACDP-0010: attach the receipt signer. From here on
    // every verified publish mints a receipt inside the store transaction,
    // and `with_receipt_signer` adds the `acdp-registry-receipts` profile
    // to the advertised capabilities (it requires the 0.2.0 version bump
    // performed by `build_capabilities` above).
    let server = if cfg.receipt.is_configured() {
        let signer =
            acdp_registry_core::receipt::build_signer(&cfg.receipt, &cfg.registry.authority)
                .map_err(|e| anyhow::anyhow!("receipt: {e}"))?;
        tracing::info!(
            registry_did = %signer.registry_did(),
            "receipt signing enabled — advertising acdp-registry-receipts"
        );
        server
            .with_receipt_signer(signer)
            .map_err(|e| anyhow::anyhow!("receipt signer: {e}"))?
    } else {
        server
    };
    // ACDP 0.3.0 / RFC-ACDP-0011: lineage-head receipts on /current.
    // `with_lineage_head_receipts` enforces its own prerequisites (a
    // configured receipt signer, acdp_version >= 0.3.0) and appends the
    // `acdp-registry-head-receipts` profile. Minting is per-response and
    // never persisted (§6).
    let server = if cfg.receipt.head_receipts {
        tracing::info!("lineage-head receipts enabled — advertising acdp-registry-head-receipts");
        server
            .with_lineage_head_receipts()
            .map_err(|e| anyhow::anyhow!("head receipts: {e}"))?
    } else {
        server
    };
    // ACDP 0.3.0 / RFC-ACDP-0013: lifecycle events & retraction.
    // `with_lifecycle` enforces acdp_version >= 0.3.0 and appends the
    // `acdp-registry-lifecycle` profile; the §7.2 status precedence,
    // §8.2 search exclusion, and §8.3 /current head exclusion are
    // implemented by the storage backends.
    let server = if cfg.lifecycle.enabled {
        tracing::info!("lifecycle events enabled — advertising acdp-registry-lifecycle");
        server
            .with_lifecycle()
            .map_err(|e| anyhow::anyhow!("lifecycle: {e}"))?
    } else {
        server
    };
    let server = Arc::new(server);

    // Auth.
    let issuer = authority_to_did_web(&cfg.registry.authority);
    let mut signer = match cfg.auth.jwt_signing_alg.as_str() {
        "EdDSA" => {
            if cfg.auth.jwt_private_key_pem.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "auth.jwt_signing_alg=EdDSA but auth.jwt_private_key_pem is empty"
                ));
            }
            let kid_override = if cfg.auth.jwt_kid.is_empty() {
                None
            } else {
                Some(cfg.auth.jwt_kid.clone())
            };
            JwtSigner::new_eddsa(
                &cfg.auth.jwt_private_key_pem,
                issuer,
                cfg.registry.authority.clone(),
                cfg.auth.token_leeway_seconds,
                kid_override,
            )
            .map_err(|e| anyhow::anyhow!("jwt_private_key_pem: {e}"))?
        }
        // Default (HS256, backward-compatible).
        _ => {
            let jwt_secret = if cfg.auth.jwt_secret.is_empty() {
                // Ephemeral secret — tokens won't survive a restart. Only
                // reachable when auth.allow_ephemeral_secret=true (REG-P1-4);
                // validate_config bails otherwise. Production MUST set
                // ACDP_REGISTRY_AUTH__JWT_SECRET.
                tracing::warn!(
                    "auth.jwt_secret not set and allow_ephemeral_secret=true — \
                     generating an ephemeral key; tokens will not survive a restart"
                );
                use rand::Rng;
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                JwtSecret::from_bytes(&bytes)
            } else {
                JwtSecret::from_base64(&cfg.auth.jwt_secret)
                    .map_err(|e| anyhow::anyhow!("jwt_secret: {e}"))?
            };
            JwtSigner::new(
                jwt_secret,
                issuer,
                cfg.registry.authority.clone(),
                cfg.auth.token_leeway_seconds,
            )
        }
    };
    if let Some(rev) = revocations.clone() {
        signer = signer.with_revocations(rev);
    }
    let resolver = Arc::new(WebResolver::new());
    let mut auth = AuthService::new(
        cfg.auth.clone(),
        challenges,
        signer,
        resolver.clone(),
        cfg.registry.authority.clone(),
    );
    // Snapshot the Arc *before* moving into AuthService — the poller
    // also needs a handle.
    let revocations_for_poller = revocations.clone();
    if let Some(rev) = revocations {
        auth = auth.with_revocations(rev);
    }
    let auth = Arc::new(auth);
    auth.spawn_evictor();

    // Cross-issuer revocation propagation (plan §9): each configured
    // peer feed is polled by an independent background task.
    if let Some(rev_store) = revocations_for_poller {
        if !cfg.auth.revocation_feeds.is_empty() {
            tracing::info!(
                count = cfg.auth.revocation_feeds.len(),
                "spawning cross-issuer revocation pollers"
            );
            acdp_registry_auth::revocation_poller::spawn_revocation_pollers(
                cfg.auth.revocation_feeds.clone(),
                rev_store,
            );
        }
    }

    // Webhook. SEC-03 / SEC-04: try_spawn validates URL + secret before
    // accepting any events.
    let webhook = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(
            WebhookEmitter::try_spawn(cfg.webhook.clone())
                .map_err(|e| anyhow::anyhow!("webhook: {e}"))?,
        )
    } else {
        None
    };

    // FEAT-01: cross-registry resolver. Defaults to enabled; operators
    // can disable via `registry.cross_registry_resolution = false`.
    let cross_registry = if cfg.registry.cross_registry_resolution {
        Some(Arc::new(CrossRegistryResolver::new()))
    } else {
        None
    };

    // Compose state + router. The constructor seeds `playground` —
    // the live-mutable cell backing `POST /admin/pinned-keys/reload`
    // (plan §2) — from `cfg.playground`.
    let state = AppStateInner::new(server, auth, webhook, cfg.clone(), cross_registry);

    // RFC-ACDP-0015 §6.1 witness-cosignature aggregation: one background
    // poller per configured witness fetches its cosignature feed over the
    // SSRF-guarded client, verifies each cosignature against THIS
    // registry's own checkpoint (rejecting any over a different root), and
    // stores the verified ones for the checkpoint handler to serve. Gated
    // on the log being enabled (aggregation is meaningless without a log)
    // and validated at startup.
    if !cfg.witnesses.is_empty() {
        match state.log.clone() {
            Some(log) => {
                tracing::info!(
                    count = cfg.witnesses.len(),
                    "spawning witness cosignature pollers (RFC-ACDP-0015 §6.1)"
                );
                acdp_registry_core::witness::spawn_witness_pollers(
                    cfg.witnesses.clone(),
                    state.server.clone(),
                    log,
                    resolver.clone(),
                );
            }
            None => tracing::warn!(
                "[[witnesses]] configured but the transparency log is not enabled; \
                 witness aggregation is disabled"
            ),
        }
    }

    let router = build_router(state);

    // Bind. TLS is optional — production typically terminates upstream.
    let addr = resolve_bind_addr(&cfg.registry.bind, cfg.registry.port)?;
    tracing::info!(addr = %addr, "listening");
    // OPS-03: graceful shutdown on SIGTERM / Ctrl-C. In-flight requests
    // get up to 30s to complete before the handle drops the listener.
    let handle = axum_server::Handle::<SocketAddr>::new();
    spawn_shutdown_watcher(handle.clone());
    if cfg.registry.tls.enabled {
        let cert = cfg
            .registry
            .tls
            .cert_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tls.cert_path missing"))?;
        let key = cfg
            .registry
            .tls
            .key_path
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tls.key_path missing"))?;
        let cfg_tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
        axum_server::bind_rustls(addr, cfg_tls)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

fn spawn_shutdown_watcher(handle: axum_server::Handle<SocketAddr>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        let term = async {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut s) = signal(SignalKind::terminate()) {
                s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term => {},
        }
        tracing::info!("shutdown signal received; draining for up to 30s");
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });
}

/// REG-3 Phase 4: the registry's independent, order-independent
/// per-feature `acdp_version` claims — replacing the four-rung ordered
/// if/else ladder that predated this phase, per OQ2's own recorded
/// follow-up (`DECISIONS.md`, 2026-08-29 entry for
/// `plans/reg2-reg5-reg6-reg8-reg9-wave4.md`'s OQ2): *"if a 5th
/// acdp_version rung is ever added, consider replacing the ordered
/// if/else ladder with an order-independent max() over per-feature
/// version claims"*. REG-3 (RFC-ACDP-0016 anchors) is that 5th rung, so
/// this phase discharges that follow-up rather than superseding OQ2's
/// decision — OQ2's conditional 0.4.0-ahead-of-0.3.0 ordering is
/// unchanged; it is simply re-expressed as one candidate claim among
/// several.
///
/// Each list entry stands entirely on its own predicate: deleting any
/// one claim only changes which OTHER still-applicable claim `max()`
/// picks next; it can never change whether a REMAINING claim's own
/// predicate fires. The base floor (`(1, "0.1.0")`) is always
/// applicable, so this list — and therefore `max_by_key` in
/// `ladder_rung_claim` / `acdp_version_claim` below — is never empty.
fn ladder_claims(cfg: &RegistryConfig) -> Vec<(u32, &'static str)> {
    [
        // RFC-ACDP-0015 §6.1: witness-cosignature aggregation is a
        // 0.4.0 wire member (`witness_signatures`); a deployment that
        // aggregates witnesses claims 0.4.0 — under-claiming 0.3.0 here
        // would serve a 0.4.0 wire member under a 0.3.0 banner. Gated on
        // `!cfg.witnesses.is_empty()` rather than `cfg.log.enabled`:
        // `validate_config` refuses startup when witnesses are
        // configured without `log.enabled` (see
        // `witnesses_require_log_and_valid_did_and_url`), so on the real
        // startup path this claim already implies the 0.3.0 claim's own
        // precondition and the ladder stays monotone; gating on
        // `log.enabled` alone would over-claim 0.4.0 for every
        // transparency-log registry that aggregates nothing.
        (!cfg.witnesses.is_empty()).then_some((4u32, "0.4.0")),
        // Lineage-head receipts (RFC-ACDP-0011 §9), lifecycle
        // (RFC-ACDP-0013 §10), and the transparency log itself all
        // require >= 0.3.0.
        (cfg.receipt.head_receipts || cfg.lifecycle.enabled || cfg.log.enabled)
            .then_some((3, "0.3.0")),
        // A receipt signing key alone claims 0.2.0 (RFC-ACDP-0010 §11).
        cfg.receipt.is_configured().then_some((2, "0.2.0")),
        // Base floor: what a bare deployment actually honors.
        Some((1, "0.1.0")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The pre-`anchors` ladder's own winner — i.e. what `acdp_version_claim`
/// below would return without the unconditional 0.5.0 anchors claim
/// folded in. Exposed as its own function *only* so
/// `capabilities_acdp_version_ladder` can keep independently falsifying
/// each of the four pre-existing rungs: once the anchors claim is folded
/// into `acdp_version_claim`, that function's own return value is
/// `"0.5.0"` for every configuration (anchors is unconditional and the
/// largest claim, so it always wins the max()) — so testing the four
/// older rungs against `build_capabilities`/`acdp_version_claim`
/// directly could no longer distinguish a correctly-implemented ladder
/// from a broken one. Testing this function instead keeps that
/// distinction alive without changing what `build_capabilities` actually
/// serves.
#[cfg(test)]
fn ladder_rung_claim(cfg: &RegistryConfig) -> &'static str {
    ladder_claims(cfg)
        .into_iter()
        .max_by_key(|(minor, _)| *minor)
        .expect("the 0.1.0 base floor claim is always present")
        .1
}

/// RFC-ACDP-0016 §10's anchors claim: `anchors` is "a body field, not a
/// registry surface" — there is **no new profile or admin-config gate**
/// to check, because unlike witness aggregation the accept / reject /
/// store / serve handling for `anchors` runs on every publish
/// unconditionally, regardless of any `[receipt]` / `[lifecycle]` /
/// `[log]` / `[[witnesses]]` setting. There is therefore no
/// "claimed-but-unexercised" state this claim could over-claim into.
///
/// Because the claim is unconditional *and* the largest value among all
/// claims, it wins `max()` for every configuration: every reachable
/// deployment of the shipped binary now advertises `acdp_version >=
/// "0.5.0"`, and the four pre-existing rungs no longer surface through
/// `build_capabilities`'s own return value (see `ladder_rung_claim`
/// above for where they remain independently observable).
///
/// This is REG-3 Phase 4's single flagged one-way-door decision
/// (`plans/reg3-anchors.md` Phase 4) — logged `UNCONFIRMED` in
/// `ASSUMPTIONS.md` pending `/reconcile` sign-off. It is cheap to
/// reverse in code (delete this constant and its use below, one
/// commit) but not cheap to reverse in the world: consumers read
/// `acdp_version` and change behavior on it, and an advertised version
/// that goes up and back down is a worse signal than one that never
/// moved.
const ANCHORS_VERSION_CLAIM: (u32, &str) = (5, "0.5.0");

/// The final advertised `acdp_version`: the max of every applicable
/// claim, pre-existing ladder rungs plus the unconditional anchors
/// floor. "Deleting the anchors claim from the max() set" (the
/// falsifiability check `capabilities_acdp_version_ladder` documents)
/// means removing `ANCHORS_VERSION_CLAIM` from the `claims` vec below,
/// which makes this function identical to `ladder_rung_claim`.
fn acdp_version_claim(cfg: &RegistryConfig) -> &'static str {
    let mut claims = ladder_claims(cfg);
    claims.push(ANCHORS_VERSION_CLAIM);
    claims
        .into_iter()
        .max_by_key(|(minor, _)| *minor)
        .expect("the 0.1.0 base floor claim is always present")
        .1
}

fn build_capabilities(cfg: &RegistryConfig) -> CapabilitiesDocument {
    CapabilitiesDocument {
        // Plan A4 / REG-3 Phase 4: each rung of the claim is gated on what
        // the deployment actually honors, exactly like the profiles (which
        // the `with_*` builders append and version-gate) — but the top-level
        // anchors claim folded in by `acdp_version_claim` is unconditional,
        // so this always advertises >= 0.5.0 regardless of config. See
        // `acdp_version_claim`'s doc comment for the full max()-over-claims
        // design.
        acdp_version: acdp_version_claim(cfg).into(),
        registry_did: authority_to_did_web(&cfg.registry.authority),
        // Advertise exactly the set the registry actually verifies. Every
        // publish path runs `acdp-server`'s validator step-5 gate, which
        // rejects `schema_violation: unsupported algorithm` for any algorithm
        // absent here — so an under-claim silently breaks otherwise-valid
        // publishes. All three verify paths honor both algorithms
        // unconditionally: the auth handshake (`AuthService` step 4, hardcoded
        // `{ed25519, ecdsa-p256}`), the pinned-key playground path
        // (`playground::enforce_pinned_signature`), and the production DID path
        // (`acdp::verify::verify_publish_request_signature`). Unlike
        // `supported_did_methods` — a genuine per-deployment choice (resolver
        // reach, SSRF surface) — algorithm support is compiled in, not
        // configurable, so it is stated here rather than read from config to
        // keep the advertisement from drifting out of sync with the code that
        // must honor it.
        supported_signature_algorithms: vec!["ed25519".into(), "ecdsa-p256".into()],
        supported_did_methods: cfg.auth.did_methods.clone(),
        profiles: {
            let mut profiles = if cfg.registry.profiles.is_empty() {
                vec![
                    "acdp-registry-core".into(),
                    "acdp-registry-discovery".into(),
                ]
            } else {
                cfg.registry.profiles.clone()
            };
            // RFC-ACDP-0012 §11: advertising the profile is the §7
            // commitment. The receipts / head-receipts / lifecycle
            // profiles are appended by the SDK's `with_*` builders; the
            // log has no SDK builder (the registry owns the endpoint
            // surface), so append it here.
            let log_profile = "acdp-registry-transparency-log";
            if cfg.log.enabled && !profiles.iter().any(|p| p == log_profile) {
                profiles.push(log_profile.into());
            }
            profiles
        },
        limits: Limits {
            max_payload_bytes: cfg.limits.max_payload_bytes,
            max_embedded_bytes: cfg.limits.max_embedded_bytes,
            // `Limits.idempotency_key_ttl_seconds` is `Option<u32>` upstream;
            // any operator value beyond u32::MAX (~136 years) is clearly a
            // misconfiguration and clamps rather than panicking.
            idempotency_key_ttl_seconds: Some(
                u32::try_from(cfg.limits.idempotency_key_ttl_seconds).unwrap_or(u32::MAX),
            ),
            // *(0.3.0)* advisory publish ceiling — not yet surfaced from
            // config; the rate limiter's ceiling can be advertised here
            // when the registry adopts the 0.3.0 capabilities surface.
            max_publish_per_minute: None,
        },
        read_authentication_methods: if cfg.auth.enabled {
            vec!["bearer-jwt".into()]
        } else {
            vec![]
        },
        anonymous_public_reads: cfg.auth.anonymous_public_reads,
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

/// OPS-04: pretty logs for local dev, JSON for production. Toggled via
/// `ACDP_LOG_FORMAT=pretty|json` (default `json`). The prior unconditional
/// JSON output was correct for production but unreadable interactively.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,acdp=info,acdp_registry=info"));
    let format = std::env::var("ACDP_LOG_FORMAT").unwrap_or_else(|_| "json".into());
    if format.eq_ignore_ascii_case("pretty") || format.eq_ignore_ascii_case("text") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_level(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_level(true)
            .json()
            .init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_registry_types::RegistryConfig;
    use base64::Engine as _;

    fn cfg_with_auth(secret: &str, allow_ephemeral: bool) -> RegistryConfig {
        let mut cfg = RegistryConfig::defaults();
        cfg.auth.enabled = true;
        cfg.auth.jwt_signing_alg = "HS256".into();
        cfg.auth.jwt_secret = secret.into();
        cfg.auth.allow_ephemeral_secret = allow_ephemeral;
        cfg
    }

    #[test]
    fn auth_enabled_empty_secret_fails_without_dev_flag() {
        let cfg = cfg_with_auth("", false);
        let err = validate_config(&cfg).expect_err("empty HS256 secret must fail startup");
        assert!(
            err.to_string().contains("jwt_secret is empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auth_enabled_empty_secret_allowed_with_dev_flag() {
        let cfg = cfg_with_auth("", true);
        assert!(
            validate_config(&cfg).is_ok(),
            "ephemeral secret should be permitted when allow_ephemeral_secret=true"
        );
    }

    #[test]
    fn auth_enabled_with_valid_secret_passes() {
        // 32 bytes base64-encoded.
        let secret = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let cfg = cfg_with_auth(&secret, false);
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn auth_disabled_empty_secret_passes() {
        let mut cfg = RegistryConfig::defaults();
        cfg.auth.enabled = false;
        cfg.auth.jwt_secret = String::new();
        assert!(validate_config(&cfg).is_ok());
    }

    // #8 — insecure-default guard.

    #[test]
    fn loopback_default_bind_passes() {
        let cfg = RegistryConfig::defaults(); // binds 127.0.0.1, auth+tls off
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn public_bind_without_tls_or_auth_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.bind = "0.0.0.0".into();
        assert!(!cfg.registry.tls.enabled && !cfg.auth.enabled);
        assert!(
            validate_config(&cfg).is_err(),
            "0.0.0.0 + no tls + no auth must be refused"
        );
    }

    #[test]
    fn public_bind_allowed_with_explicit_opt_in() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.bind = "0.0.0.0".into();
        cfg.registry.allow_public_bind = true;
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn is_loopback_bind_classification() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("::"));
        assert!(!is_loopback_bind("10.0.0.5"));
    }

    #[test]
    fn resolve_bind_addr_handles_ipv4_and_bare_ipv6() {
        // Regression: a bare IPv6 wildcard (`::`, recommended on Railway and
        // other IPv6-native hosts) must not be glued into `:::8080`, which
        // fails with "invalid socket address syntax". `SocketAddr::new` keeps
        // it valid regardless of bracketing.
        assert_eq!(
            resolve_bind_addr("0.0.0.0", 8080).unwrap().to_string(),
            "0.0.0.0:8080"
        );
        assert_eq!(
            resolve_bind_addr("127.0.0.1", 9191).unwrap().to_string(),
            "127.0.0.1:9191"
        );
        assert_eq!(
            resolve_bind_addr("::", 8080).unwrap().to_string(),
            "[::]:8080"
        );
        assert_eq!(
            resolve_bind_addr("::1", 8080).unwrap().to_string(),
            "[::1]:8080"
        );
        // Already-bracketed IPv6 still resolves via the host:port fallback.
        assert_eq!(
            resolve_bind_addr("[::1]", 8080).unwrap().to_string(),
            "[::1]:8080"
        );
        // A non-address host with no resolver yields a clear error, not a panic.
        assert!(resolve_bind_addr("not an address", 8080).is_err());
    }

    // ACDP 0.2.0 — receipt + did:key startup validation.

    #[test]
    fn receipt_with_unverified_playground_is_rejected() {
        // pinned_only=false (the default) has a genuinely unverified
        // fallback for non-pinned agents — structurally incompatible with
        // RFC-ACDP-0010 §7's "no degraded mode".
        use base64::Engine as _;
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.playground.enabled = true;
        let err =
            validate_config(&cfg).expect_err("unverified playground + receipts must be refused");
        assert!(err.to_string().contains("no degraded mode"));
        cfg.playground.enabled = false;
        assert!(validate_config(&cfg).is_ok(), "receipts alone are fine");
    }

    #[test]
    fn receipt_with_pinned_only_playground_is_accepted() {
        // pinned_only=true has no unverified fallback at all — every
        // publish either matches a pinned key (real signature check) or is
        // rejected outright — so it coexists with [receipt] fine.
        use base64::Engine as _;
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.playground.enabled = true;
        cfg.playground.pinned_only = true;
        cfg.playground
            .pinned_keys
            .push(acdp_registry_types::config::PinnedAgentKey {
                agent_did: "did:web:registry-a.playground.local:agents:rotating-publisher".into(),
                public_key_b64: base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
                algorithm: "ed25519".into(),
                valid_from: None,
                valid_until: None,
            });
        assert!(
            validate_config(&cfg).is_ok(),
            "pinned_only=true + a pinned key + receipts should be accepted"
        );
    }

    #[test]
    fn receipt_with_pinned_only_and_no_pinned_keys_is_rejected() {
        // pinned_only=true with an empty pinned_keys list would reject
        // every single publish outright — a config footgun, not a useful
        // receipts registry.
        use base64::Engine as _;
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.playground.enabled = true;
        cfg.playground.pinned_only = true;
        let err = validate_config(&cfg)
            .expect_err("pinned_only=true with no pinned_keys must be refused");
        assert!(err.to_string().contains("reject every publish outright"));
    }

    #[test]
    fn malformed_receipt_seed_fails_startup() {
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 = "not-base64!!".into();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn malformed_retired_receipt_key_fails_startup() {
        use base64::Engine as _;
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.receipt.retired_keys = vec![acdp_registry_types::RetiredReceiptKey {
            public_key_b64: "not-base64!!".into(),
            key_id_fragment: "receipt-key-0".into(),
        }];
        assert!(
            validate_config(&cfg).is_err(),
            "a bad retired key must fail startup, not silently 404 did.json"
        );
        cfg.receipt.retired_keys[0].public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode([6u8; 32]);
        cfg.receipt.retired_keys[0].key_id_fragment = "has#hash".into();
        assert!(
            validate_config(&cfg).is_err(),
            "a '#' in a retired fragment must fail startup"
        );
        cfg.receipt.retired_keys[0].key_id_fragment = "receipt-key-0".into();
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn receipts_profile_without_key_is_rejected() {
        use base64::Engine as _;
        // RFC-ACDP-0010 §7/§11: advertising the profile without a signing key
        // is a false capability claim — must fail startup.
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-core".into(), "acdp-registry-receipts".into()];
        let err = validate_config(&cfg)
            .expect_err("receipts profile without a receipt key must be refused");
        assert!(
            err.to_string().contains("acdp-registry-receipts"),
            "unexpected error: {err}"
        );
        // Configuring a key resolves the inconsistency.
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        assert!(
            validate_config(&cfg).is_ok(),
            "profile + key together are conformant"
        );
    }

    #[test]
    fn did_methods_are_validated() {
        let mut cfg = RegistryConfig::defaults();
        cfg.auth.did_methods = vec!["did:web".into(), "did:key".into()];
        assert!(validate_config(&cfg).is_ok());
        cfg.auth.did_methods = vec!["did:key".into()];
        assert!(
            validate_config(&cfg).is_err(),
            "did:web is mandatory per RFC-ACDP-0007 §3.1"
        );
        cfg.auth.did_methods = vec!["did:web".into(), "did:ion".into()];
        assert!(
            validate_config(&cfg).is_err(),
            "methods the pipeline can't verify must be refused"
        );
    }

    // RFC-ACDP-0012 — transparency-log startup validation.

    #[test]
    fn log_without_receipt_key_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.log.enabled = true;
        let err = validate_config(&cfg).expect_err("log without a receipt key must be refused");
        assert!(err.to_string().contains("RFC-ACDP-0012"), "{err}");
        // A receipt key resolves the prerequisite.
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn log_profile_without_enabled_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.registry.profiles = vec![
            "acdp-registry-core".into(),
            "acdp-registry-transparency-log".into(),
        ];
        let err = validate_config(&cfg)
            .expect_err("advertising the log profile without log.enabled must be refused");
        assert!(err.to_string().contains("transparency-log"), "{err}");
        cfg.log.enabled = true;
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn log_on_memory_backend_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.log.enabled = true;
        cfg.storage.backend = StorageBackend::Memory;
        let err =
            validate_config(&cfg).expect_err("the ephemeral memory backend cannot host a log");
        assert!(err.to_string().contains("durable"), "{err}");
    }

    #[test]
    fn log_malformed_instance_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.log.enabled = true;
        for bad in ["UPPER", "", "with space", &"a".repeat(33)] {
            cfg.log.instance = bad.into();
            assert!(
                validate_config(&cfg).is_err(),
                "instance '{bad}' must be refused (RFC-ACDP-0012 §6)"
            );
        }
        cfg.log.instance = "1".into();
        assert!(validate_config(&cfg).is_ok());
    }

    // RFC-ACDP-0015 §6.1 — witness aggregation startup validation.
    #[test]
    fn witnesses_require_log_and_valid_did_and_url() {
        use acdp_registry_types::config::WitnessConfig;
        let mut cfg = RegistryConfig::defaults();
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.witnesses = vec![WitnessConfig {
            did: "did:web:witness.example.org".into(),
            url: "https://witness.example.org/log/witness".into(),
            poll_seconds: 300,
        }];
        // Witnesses without a log are refused (nothing to witness). This
        // is also the invariant the `acdp_version` 0.4.0 rung in
        // `ladder_claims` depends on: that rung is gated on
        // `!cfg.witnesses.is_empty()` alone (not `cfg.log.enabled`), which
        // is only monotone with the 0.3.0 rung because `validate_config`
        // refuses to ever start a deployment with witnesses configured
        // and `log.enabled = false` — re-asserted here explicitly rather
        // than assumed, since `capabilities_acdp_version_ladder` calls
        // `build_capabilities` directly and cannot observe this rejection
        // itself.
        let err = validate_config(&cfg).expect_err("witnesses require log.enabled");
        assert!(err.to_string().contains("[[witnesses]]"), "{err}");

        cfg.log.enabled = true;
        assert!(
            validate_config(&cfg).is_ok(),
            "witnesses + log are conformant"
        );

        // A non-did:web witness DID is refused.
        cfg.witnesses[0].did = "did:key:z6MkExample".into();
        assert!(
            validate_config(&cfg).is_err(),
            "did:key witness must be refused"
        );
        cfg.witnesses[0].did = "did:web:witness.example.org".into();

        // A plaintext / private witness URL is refused by the SSRF policy.
        cfg.witnesses[0].url = "http://witness.example.org/log/witness".into();
        assert!(
            validate_config(&cfg).is_err(),
            "plaintext witness url must be refused"
        );
        cfg.witnesses[0].url = "https://127.0.0.1/log/witness".into();
        assert!(
            validate_config(&cfg).is_err(),
            "loopback witness url must be refused"
        );
    }

    // #17 — multi-tenant config must enforce strict tenant scoping.
    #[test]
    fn multitenant_without_require_tenant_is_rejected() {
        use acdp_registry_types::config::TenantAgentBinding;
        let mut cfg = RegistryConfig::defaults();
        cfg.auth.tenant_agents = vec![TenantAgentBinding {
            agent_did: "did:web:agents.example:a".into(),
            tenant_id: "tenant-a".into(),
        }];
        cfg.auth.require_tenant = false;
        assert!(
            validate_config(&cfg).is_err(),
            "tenant_agents without require_tenant must be refused"
        );
        cfg.auth.require_tenant = true;
        assert!(validate_config(&cfg).is_ok());
    }

    // #137 — the memory backend is not tenancy-aware, so a multi-tenant
    // config on it would serve zero rows rather than fail.
    #[test]
    fn multitenant_on_memory_backend_is_rejected() {
        use acdp_registry_types::config::TenantAgentBinding;
        let mut cfg = RegistryConfig::defaults();
        cfg.auth.tenant_agents = vec![TenantAgentBinding {
            agent_did: "did:web:agents.example:a".into(),
            tenant_id: "tenant-a".into(),
        }];
        // Set the strict flag explicitly: without it the #17 guard above
        // fires first and this test would pass for the wrong reason.
        cfg.auth.require_tenant = true;
        cfg.storage.backend = StorageBackend::Memory;
        let err = validate_config(&cfg)
            .expect_err("the memory backend cannot host a multi-tenant deployment");
        assert!(err.to_string().contains("tenancy-aware"), "{err}");

        // The same tenancy config on a durable backend still starts.
        cfg.storage.backend = StorageBackend::Sqlite;
        assert!(validate_config(&cfg).is_ok());
    }

    // The capabilities `supported_signature_algorithms` gate is enforced by
    // `acdp-server`'s publish validator (step 5): any algorithm absent from
    // this list is rejected with `schema_violation: unsupported algorithm`
    // before the signature is ever verified. The registry verifies both
    // ed25519 and ecdsa-p256 on every publish path, so both MUST be advertised
    // — a regression to ed25519-only silently 400s every P-256 publish even
    // against a correctly pinned P-256 key.
    #[test]
    fn capabilities_advertise_every_verified_algorithm() {
        let caps = build_capabilities(&RegistryConfig::defaults());
        assert!(
            caps.supports_algorithm("ed25519"),
            "ed25519 must be advertised: {:?}",
            caps.supported_signature_algorithms
        );
        assert!(
            caps.supports_algorithm("ecdsa-p256"),
            "ecdsa-p256 must be advertised — the auth handshake and pinned-key \
             path both verify it, so the publish gate must accept it: {:?}",
            caps.supported_signature_algorithms
        );
    }

    // RFC-ACDP-0015 §6.1 — witness aggregation is a 0.4.0 wire member
    // (`witness_signatures`), so a deployment that aggregates witness
    // cosignatures must independently claim "0.4.0" rather than
    // under-claim "0.3.0" (otherwise Phase 2's below-0.4.0 wire-code gate
    // is satisfiable only vacuously, since no deployment would ever claim
    // 0.4.0 in the first place).
    //
    // REG-3 Phase 4: the four assertions below test `ladder_rung_claim`
    // rather than `build_capabilities`/`acdp_version_claim` directly.
    // This is a deliberate, necessary change from how this test read
    // before Phase 4 — see `ladder_rung_claim`'s doc comment for why:
    // once the unconditional RFC-ACDP-0016 §10 anchors claim is folded
    // into `acdp_version_claim`, `build_capabilities(&cfg).acdp_version`
    // is `"0.5.0"` for every `cfg`, so it can no longer distinguish a
    // correct four-rung ladder from a broken one. `ladder_rung_claim`
    // is the pre-anchors max() this test needs to keep probing to prove
    // each of the four older rungs is still independently falsifiable.
    // The fifth assertion below is what proves the anchors claim itself
    // is wired up and reachable through the full `build_capabilities`
    // path.
    #[test]
    fn capabilities_acdp_version_ladder() {
        use acdp_registry_types::config::WitnessConfig;

        // Bare config: unchanged at 0.1.0.
        let bare = RegistryConfig::defaults();
        assert_eq!(ladder_rung_claim(&bare), "0.1.0");

        // Receipt key configured, nothing else: unchanged at 0.2.0.
        let mut receipt_only = RegistryConfig::defaults();
        receipt_only.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(ladder_rung_claim(&receipt_only), "0.2.0");

        // Witnesses configured AND log.enabled = true — the only state
        // `validate_config` allows on the real startup path (see
        // `witnesses_require_log_and_valid_did_and_url`, which re-asserts
        // that witnesses without log.enabled fail startup). Testing that
        // combination, not just `witnesses` alone, is what proves the
        // rung is correct on the real reachable state rather than merely
        // on an unvalidated config `ladder_rung_claim` itself won't reject.
        let mut witnessed = RegistryConfig::defaults();
        witnessed.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        witnessed.log.enabled = true;
        witnessed.witnesses = vec![WitnessConfig {
            did: "did:web:witness.example.org".into(),
            url: "https://witness.example.org/log/witness".into(),
            poll_seconds: 300,
        }];
        assert_eq!(
            ladder_rung_claim(&witnessed),
            "0.4.0",
            "witness aggregation (RFC-ACDP-0015 §6.1) must claim 0.4.0"
        );

        // Same config with witnesses emptied: back down to 0.3.0 (the log
        // remains enabled). Proves the rung is both reachable and truly
        // independent — since each claim in `ladder_claims` now stands on
        // its own predicate rather than living in an ordered if/else,
        // this also proves removing the 0.4.0 claim can't accidentally
        // resurrect it via some other branch: with witnesses empty the
        // 0.4.0 predicate is false regardless of what order claims are
        // considered in, so the max() naturally falls through to the
        // next-highest applicable claim, 0.3.0.
        let mut no_witnesses = witnessed.clone();
        no_witnesses.witnesses.clear();
        assert_eq!(ladder_rung_claim(&no_witnesses), "0.3.0");

        // REG-3 Phase 4 (plans/reg3-anchors.md): `anchors` support
        // (RFC-ACDP-0016 §10) is unconditional — no admin-config gate —
        // so it is the largest applicable claim for EVERY configuration,
        // including the completely bare one above (no receipt key, no
        // log, no witnesses, nothing configured). `build_capabilities`
        // therefore now always advertises >= "0.5.0": this is the one
        // new assertion this phase adds, and it is what proves "0.5.0"
        // is reachable by *some* configuration of the shipped binary
        // (acceptance criterion 1) — trivially by every configuration,
        // in fact, which is the whole point of the claim being
        // unconditional.
        //
        // Falsifiability: temporarily deleting `ANCHORS_VERSION_CLAIM`'s
        // use in `acdp_version_claim` turns ONLY this assertion red —
        // the four assertions above call `ladder_rung_claim`, which
        // never references the anchors claim, so they stay green.
        assert_eq!(build_capabilities(&bare).acdp_version, "0.5.0");
    }

    // REG-3 Phase 4 acceptance criterion 4 (plans/reg3-anchors.md): the
    // capabilities document `build_capabilities` produces for the 0.5.0
    // configuration must still pass the ACDP wire validator's own
    // `validate_capabilities`, not just informally look right. A bare
    // config is enough — Phase 4's anchors claim is unconditional, so
    // `build_capabilities(&RegistryConfig::defaults())` already advertises
    // "0.5.0" (proved above by `capabilities_acdp_version_ladder`); this
    // test is what proves that document is actually schema-valid rather
    // than merely equal to the string "0.5.0".
    #[test]
    fn capabilities_at_0_5_0_pass_validate_capabilities() {
        acdp::validation::validate_capabilities(&build_capabilities(&RegistryConfig::defaults()))
            .unwrap();
    }

    // REG-5 — `registry.profiles` allowlist (`REGISTRY_ADVERTISABLE_PROFILES`).

    #[test]
    fn witness_profile_is_rejected_with_witness_specific_message() {
        // A witness is NOT a registry (RFC-ACDP-0015 §6.1): a registry MAY
        // aggregate cosignatures under acdp-registry-transparency-log
        // without ever advertising acdp-log-witness itself. This is the
        // false-advertisement mistake this phase specifically calls out.
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-log-witness".into()];
        let err = validate_config(&cfg).expect_err("acdp-log-witness must be refused");
        let msg = err.to_string();
        assert!(msg.contains("acdp-log-witness"), "unexpected error: {msg}");
        assert!(
            msg.contains("a witness is not a registry"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn unknown_profile_is_rejected() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-typo".into()];
        let err = validate_config(&cfg).expect_err("an unknown profile string must be refused");
        assert!(
            err.to_string().contains("acdp-registry-typo"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_profile_is_rejected_before_backing_config_guards() {
        // An operator with BOTH a typo AND a missing backing config (here:
        // acdp-registry-receipts with no [receipt] key) must see the typo
        // first — the more fundamental, actionable error.
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-typo".into(), "acdp-registry-receipts".into()];
        let err = validate_config(&cfg).expect_err("must be refused");
        assert!(
            err.to_string().contains("acdp-registry-typo"),
            "the allowlist error must fire before the receipts backing-config guard: {err}"
        );
    }

    #[test]
    fn profile_acdp_registry_core_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-core".into()];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_discovery_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-discovery".into()];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_federated_alone_is_accepted() {
        // No backing-config guard exists for acdp-registry-federated
        // (explicitly out of scope for REG-5) — it only needs to clear the
        // allowlist.
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-federated".into()];
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_receipts_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-receipts".into()];
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_head_receipts_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-head-receipts".into()];
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.receipt.head_receipts = true;
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_lifecycle_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-lifecycle".into()];
        cfg.lifecycle.enabled = true;
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn profile_acdp_registry_transparency_log_alone_is_accepted() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = vec!["acdp-registry-transparency-log".into()];
        cfg.receipt.signing_key_seed_b64 =
            base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        cfg.log.enabled = true;
        // `RegistryConfig::defaults()` already sets a durable (sqlite)
        // backend, which `log.enabled` requires.
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn registry_advertisable_profiles_excludes_witness_and_consumer() {
        // Named, greppable invariant — not just an emergent property of
        // the prefix-derivation the conformance ratchet test checks.
        assert!(!REGISTRY_ADVERTISABLE_PROFILES.contains(&"acdp-log-witness"));
        assert!(!REGISTRY_ADVERTISABLE_PROFILES.contains(&"acdp-consumer"));
    }

    #[test]
    fn default_profile_list_is_advertisable() {
        // Both places this codebase substitutes a default profile list —
        // `RegistryConfig::defaults()` (config.rs) and `build_capabilities`'s
        // empty -> default substitution (main.rs, for an explicitly empty
        // `registry.profiles`) — must themselves satisfy the allowlist.
        for p in &RegistryConfig::defaults().registry.profiles {
            assert!(
                REGISTRY_ADVERTISABLE_PROFILES.contains(&p.as_str()),
                "RegistryConfig::defaults().registry.profiles advertises non-allowlisted \
                 profile '{p}'"
            );
        }

        let mut cfg = RegistryConfig::defaults();
        cfg.registry.profiles = Vec::new();
        assert!(
            validate_config(&cfg).is_ok(),
            "an empty registry.profiles has nothing to validate"
        );
        let caps = build_capabilities(&cfg);
        assert_eq!(
            caps.profiles,
            vec![
                "acdp-registry-core".to_string(),
                "acdp-registry-discovery".to_string()
            ]
        );
        for p in &caps.profiles {
            assert!(
                REGISTRY_ADVERTISABLE_PROFILES.contains(&p.as_str()),
                "build_capabilities's empty-profiles default substitution advertises \
                 non-allowlisted profile '{p}'"
            );
        }
    }
}
