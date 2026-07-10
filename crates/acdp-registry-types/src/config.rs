//! Runtime configuration loaded from TOML + environment overrides.
//!
//! The `config` crate stacks sources: defaults → TOML file →
//! `ACDP_REGISTRY_*` env vars (double-underscore separator for nesting).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level registry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    pub registry: RegistrySection,
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    /// FEAT-06: per-IP and process-global rate limiting on the `/auth/*`
    /// endpoints, on top of the per-agent `[limits]` budgets.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// FEAT-10: Prometheus `/metrics` endpoint. Off by default.
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub playground: PlaygroundConfig,
    #[serde(default)]
    pub receipt: ReceiptConfig,
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
    #[serde(default)]
    pub log: LogConfig,
    /// Transparency-log witnesses this registry polls and whose verified
    /// cosignatures it aggregates onto its checkpoint responses
    /// (RFC-ACDP-0015 §6.1). Empty (the default) disables aggregation.
    #[serde(default)]
    pub witnesses: Vec<WitnessConfig>,
}

impl RegistryConfig {
    /// Load configuration from an optional TOML file plus `ACDP_REGISTRY_*`
    /// environment variables.
    pub fn load(path: Option<&str>) -> Result<Self, config::ConfigError> {
        let mut builder =
            config::Config::builder().add_source(config::Config::try_from(&Self::defaults())?);
        if let Some(p) = path {
            builder = builder.add_source(config::File::with_name(p).required(true));
        } else if let Ok(p) = std::env::var("ACDP_REGISTRY_CONFIG") {
            builder = builder.add_source(config::File::with_name(&p).required(true));
        }
        // The prefix is joined with a single `_` (so `ACDP_REGISTRY_AUTH...`),
        // while nested keys use `__` (so `..._AUTH__JWT_SECRET`). Without
        // pinning the prefix separator, `config` reuses `separator` for both
        // and silently demands `ACDP_REGISTRY__AUTH__...`, which no
        // doc/compose/Railway env var uses — so every override was a no-op.
        //
        // Pinning the prefix separator to `_` has one edge: a prefixed var with
        // no nested `__` (e.g. `ACDP_REGISTRY_CONFIG`, the file-path selector
        // read above) maps to an unknown top-level key and trips
        // `deny_unknown_fields`. Every real override carries a `<SECTION>__<KEY>`
        // shape, so feed the source a snapshot that drops prefixed vars lacking
        // a nested `__`.
        let env_snapshot: std::collections::HashMap<String, String> = std::env::vars()
            .filter(|(k, _)| match k.strip_prefix("ACDP_REGISTRY_") {
                Some(rest) => rest.contains("__"),
                None => true,
            })
            .collect();
        builder = builder.add_source(
            config::Environment::with_prefix("ACDP_REGISTRY")
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true)
                // `did_methods` and `profiles` are the only `Vec<String>`
                // fields an operator plausibly overrides without a TOML
                // file (e.g. Railway, which has no config-file mechanism
                // for "deploy from image" services). `config`'s env source
                // only ever splits a value into a list for keys named here
                // — every other field (including base64 secrets, which may
                // itself contain no comma but shouldn't be list-eligible on
                // principle) keeps deserializing as a plain scalar.
                .list_separator(",")
                .with_list_parse_key("auth.did_methods")
                .with_list_parse_key("registry.profiles")
                .source(Some(env_snapshot)),
        );
        builder.build()?.try_deserialize()
    }

    /// Defaults suitable for local development (SQLite, no auth, no webhook).
    pub fn defaults() -> Self {
        Self {
            registry: RegistrySection {
                authority: "localhost".into(),
                port: 8443,
                bind: "127.0.0.1".into(),
                allow_public_bind: false,
                profiles: vec![
                    "acdp-registry-core".into(),
                    "acdp-registry-discovery".into(),
                ],
                tls: TlsConfig::default(),
                cross_registry_resolution: true,
                cors: CorsConfig::default(),
                base_url: String::new(),
            },
            storage: StorageConfig {
                backend: StorageBackend::Sqlite,
                postgres_url: None,
                sqlite_path: Some(PathBuf::from("./data/registry.db")),
                max_connections: 20,
            },
            auth: AuthConfig::default(),
            webhook: WebhookConfig::default(),
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            metrics: MetricsConfig::default(),
            playground: PlaygroundConfig::default(),
            receipt: ReceiptConfig::default(),
            lifecycle: LifecycleConfig::default(),
            log: LogConfig::default(),
            witnesses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySection {
    /// Bare DNS hostname. Used to mint `ctx_id` and as the `did:web` registry identifier.
    pub authority: String,
    /// TCP port to listen on.
    pub port: u16,
    /// Bind address. Defaults to `127.0.0.1` (loopback) so a registry that
    /// ships without overriding the config is not exposed on every interface.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Explicit opt-in to bind a non-loopback address while running with TLS
    /// AND auth both disabled (SEC: insecure default). Without this, such a
    /// configuration is rejected at startup — an unauthenticated, plaintext
    /// registry on a public interface is almost never intended. Set to `true`
    /// only when the registry sits behind a TLS-terminating, authenticating
    /// proxy on a trusted network.
    #[serde(default)]
    pub allow_public_bind: bool,
    /// Profiles advertised in the capabilities document.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Optional TLS configuration. When absent the server serves plain HTTP
    /// (intended for use behind a TLS-terminating proxy).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Resolve `ctx_id`s whose authority differs from this registry by
    /// forwarding to the foreign registry (RFC-ACDP-0006 §4.1). When false,
    /// foreign `ctx_id`s return 404. Defaults to true.
    #[serde(default = "default_true")]
    pub cross_registry_resolution: bool,
    /// CORS configuration. Defaults to no allowed origins (CORS disabled).
    #[serde(default)]
    pub cors: CorsConfig,
    /// Public base URL advertised to downstream consumers (the control plane
    /// uses it to route federation proxy calls). When empty, the registry
    /// derives `https://{authority}` — set this explicitly when the registry
    /// is served on a non-default port or path.
    #[serde(default)]
    pub base_url: String,
}

impl RegistrySection {
    /// Effective public base URL: the explicit `base_url` if configured,
    /// otherwise `https://{authority}`. Never carries a trailing slash.
    pub fn effective_base_url(&self) -> String {
        let raw = if self.base_url.trim().is_empty() {
            format!("https://{}", self.authority)
        } else {
            self.base_url.trim().to_string()
        };
        raw.trim_end_matches('/').to_string()
    }
}

fn default_bind() -> String {
    "127.0.0.1".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins. When empty (the default) the registry sends no
    /// CORS headers — third-party origins cannot make cross-origin
    /// requests using a visitor's stored bearer token.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// When false the binary serves plain HTTP (production typically terminates TLS upstream).
    #[serde(default)]
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Postgres,
    Sqlite,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub postgres_url: Option<String>,
    pub sqlite_path: Option<PathBuf>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_max_connections() -> u32 {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_did_methods")]
    pub did_methods: Vec<String>,
    /// Base64-encoded ≥32-byte secret used to sign JWTs.
    #[serde(default)]
    pub jwt_secret: String,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_seconds: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_seconds: u64,
    /// Clock-skew leeway (seconds) applied to JWT `exp` validation.
    #[serde(default = "default_token_leeway")]
    pub token_leeway_seconds: u64,
    /// Allow anonymous reads of `public`-visibility contexts. Defaults to
    /// `false` — CLAUDE.md: "Anonymous public reads are off by default for
    /// new registries unless the config explicitly opts in." Operators who
    /// want world-readable public contexts MUST set this to true.
    #[serde(default)]
    pub anonymous_public_reads: bool,
    /// JWT signing algorithm. `HS256` (default, backward-compatible) uses
    /// `jwt_secret`. `EdDSA` (Ed25519) uses `jwt_private_key_pem` and
    /// publishes the public key at `GET /.well-known/jwks.json` so
    /// federated peers can verify without out-of-band secret distribution.
    #[serde(default = "default_jwt_alg")]
    pub jwt_signing_alg: String,
    /// PEM-encoded Ed25519 private key (PKCS#8). Required when
    /// `jwt_signing_alg = "EdDSA"`.
    #[serde(default)]
    pub jwt_private_key_pem: String,
    /// Optional explicit key id. When empty, derived from the public-key
    /// fingerprint (stable across restarts when the key bytes are stable).
    #[serde(default)]
    pub jwt_kid: String,

    /// Permit booting with an ephemeral (process-lifetime) HS256 secret when
    /// `auth.enabled` and `jwt_secret` is empty. Defaults to `false`: a
    /// production registry with auth on but no secret fails startup rather
    /// than silently minting tokens that don't survive a restart. Set to
    /// `true` only for local dev / tests.
    #[serde(default)]
    pub allow_ephemeral_secret: bool,

    /// Cross-issuer revocation feeds the registry polls for propagated
    /// revocations (plan §9). Empty (default) = no federation; the
    /// registry trusts only its own revocation list.
    #[serde(default)]
    pub revocation_feeds: Vec<RevocationFeedConfig>,

    /// API tokens accepted on admin endpoints (currently
    /// `POST /admin/pinned-keys/reload`). Bearer the value verbatim in
    /// the `Authorization` header. Empty (the default) means the admin
    /// endpoints reject every caller — admin reload is opt-in per
    /// deployment.
    #[serde(default)]
    pub admin_tokens: Vec<String>,

    /// Agent→tenant bindings the registry stamps onto its own issued
    /// JWTs. When an agent listed here completes a `/auth/token`
    /// challenge, the resulting `BearerClaims.tenant` is set to the
    /// configured tenant id — making downstream `tenant_for_request`
    /// behave symmetrically with the CP's issuer. Empty (the default)
    /// means registry-issued tokens carry `tenant: None`, preserving
    /// V0 behavior. Plan §4.
    #[serde(default)]
    pub tenant_agents: Vec<TenantAgentBinding>,

    /// Enforce tenant scoping on every authenticated request. When `false`
    /// (the default, V0-compatible) a request that resolves to no tenant —
    /// no `X-Tenant-Id` header and a token without a `tenant` claim — runs
    /// with no tenant filter (gated only by visibility). When `true`, a
    /// multi-tenant deployment is hardened:
    ///   * a request that resolves to no tenant is rejected (default-deny);
    ///   * when a valid bearer is present, the tenant is taken ONLY from the
    ///     JWT `tenant` claim — a token the issuer did not bind to a tenant
    ///     can no longer assert one via the spoofable `X-Tenant-Id` header.
    #[serde(default)]
    pub require_tenant: bool,
}

/// Reserved tenant identifier. It is the `contexts.tenant_id` column default
/// for untenanted (V0) contexts, so it MUST NOT be assertable as a real tenant
/// via `X-Tenant-Id` or a token claim — otherwise a caller asserting `default`
/// would alias the entire untenanted bucket (a cross-boundary read/write).
pub const RESERVED_TENANT: &str = "default";

impl AuthConfig {
    /// The tenant an agent is bound to via `[[auth.tenant_agents]]`, if any.
    /// Shared by token issuance and the publish path so both resolve an
    /// agent's tenant identically. First match wins.
    pub fn tenant_for_agent(&self, agent_did: &str) -> Option<String> {
        self.tenant_agents
            .iter()
            .find(|b| b.agent_did == agent_did)
            .map(|b| b.tenant_id.clone())
    }
}

/// One agent→tenant binding for registry-issued JWTs.
///
/// Wire format (TOML):
///
///   [[auth.tenant_agents]]
///   agent_did = "did:web:agents.example:alice"
///   tenant_id = "tenant-a"
///
/// Agents not listed here mint tokens with `tenant: None`. Operators
/// who want every agent to be tenant-bound should ensure every
/// challenge-completing agent has an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAgentBinding {
    pub agent_did: String,
    pub tenant_id: String,
}

/// One peer issuer whose revocation list this registry should mirror.
///
/// Wire format (TOML):
///
/// ```toml
/// [[auth.revocation_feeds]]
/// issuer        = "did:web:control-plane.example"
/// feed_url      = "https://control-plane.example/auth/revocations"
/// admin_token   = "..."           # api key with admin role on the issuer
/// poll_seconds  = 60              # default 300
/// ```
///
/// The poller runs in the background, paged by `revoked_at_ms` cursor;
/// each propagated entry is inserted into the local revocation store
/// so existing JWT-verify code rejects the token without further
/// federation work.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationFeedConfig {
    /// Issuer `iss` the propagated entries belong to. Stamped onto each
    /// local revocation record for audit.
    pub issuer: String,
    /// Full URL of the peer's revocation feed endpoint.
    pub feed_url: String,
    /// Admin api key for the peer (peer's feed is admin-gated).
    pub admin_token: String,
    /// Poll interval. Default 300s.
    #[serde(default = "default_revocation_poll_seconds")]
    pub poll_seconds: u64,
}

fn default_revocation_poll_seconds() -> u64 {
    300
}

fn default_jwt_alg() -> String {
    "HS256".into()
}

fn default_did_methods() -> Vec<String> {
    vec!["did:web".into()]
}
fn default_token_ttl() -> u64 {
    3600
}
fn default_challenge_ttl() -> u64 {
    300
}
fn default_token_leeway() -> u64 {
    30
}
fn default_true() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            did_methods: default_did_methods(),
            jwt_secret: String::new(),
            token_ttl_seconds: default_token_ttl(),
            challenge_ttl_seconds: default_challenge_ttl(),
            token_leeway_seconds: default_token_leeway(),
            anonymous_public_reads: false,
            jwt_signing_alg: default_jwt_alg(),
            jwt_private_key_pem: String::new(),
            jwt_kid: String::new(),
            allow_ephemeral_secret: false,
            revocation_feeds: Vec::new(),
            admin_tokens: Vec::new(),
            tenant_agents: Vec::new(),
            require_tenant: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_webhook_retries")]
    pub max_retries: u32,
    /// Bounded in-memory queue capacity. Drops events (with a warn log)
    /// when the worker can't keep up, so a slow receiver can't run the
    /// server out of memory.
    #[serde(default = "default_webhook_queue_capacity")]
    pub queue_capacity: usize,
}

fn default_webhook_timeout() -> u64 {
    5
}
fn default_webhook_retries() -> u32 {
    3
}
fn default_webhook_queue_capacity() -> usize {
    1024
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            secret: String::new(),
            timeout_seconds: default_webhook_timeout(),
            max_retries: default_webhook_retries(),
            queue_capacity: default_webhook_queue_capacity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_payload_bytes")]
    pub max_payload_bytes: u64,
    #[serde(default = "default_embedded_bytes")]
    pub max_embedded_bytes: u64,
    /// Idempotency-Key cache TTL advertised in the capabilities document.
    /// Producers see this in `/.well-known/acdp.json` and replay within
    /// the window; older keys may be evicted.
    #[serde(default = "default_idempotency_ttl")]
    pub idempotency_key_ttl_seconds: u64,
    /// RFC-ACDP-0008 §4.3 (REQUIRED): max `POST /contexts` per minute per
    /// signing `agent_id`. `0` disables per-agent limiting. In-memory and
    /// per-process — front a multi-replica deployment with a shared limiter
    /// (e.g. at the gateway) for a global bound.
    #[serde(default = "default_publish_rate_per_minute")]
    pub publish_rate_per_minute: u32,
    /// Max `POST /auth/challenge` per minute per requested `agent_id`. The
    /// challenge endpoint is unauthenticated, so without a bound an attacker
    /// can flood it to amplify writes / grow the nonce store. `0` disables
    /// the limit. In-memory and per-process — same caveat as
    /// `publish_rate_per_minute`.
    #[serde(default = "default_challenge_rate_per_minute")]
    pub challenge_rate_per_minute: u32,
}

fn default_payload_bytes() -> u64 {
    1_048_576
}
fn default_embedded_bytes() -> u64 {
    65_536
}
fn default_idempotency_ttl() -> u64 {
    86_400
}
fn default_publish_rate_per_minute() -> u32 {
    60
}
fn default_challenge_rate_per_minute() -> u32 {
    60
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: default_payload_bytes(),
            max_embedded_bytes: default_embedded_bytes(),
            idempotency_key_ttl_seconds: default_idempotency_ttl(),
            publish_rate_per_minute: default_publish_rate_per_minute(),
            challenge_rate_per_minute: default_challenge_rate_per_minute(),
        }
    }
}

/// FEAT-06: per-IP and process-global rate limiting on the `/auth/*`
/// endpoints (challenge / token / revoke).
///
/// The per-agent `[limits]` budgets key on the request-supplied `agent_id`,
/// which an unauthenticated attacker controls and can rotate to defeat the
/// per-key limit. This section adds two attacker-independent bounds applied
/// as middleware over the whole `/auth/*` subrouter:
///
///   * a **per-client-IP** fixed-window budget, and
///   * a **process-global** ceiling across all IPs.
///
/// Both share the existing 60-second fixed-window limiter, so limits are
/// expressed per minute for symmetry with `[limits]`.
///
/// ## Client-IP resolution & the trusted-proxy decision (SECURITY)
///
/// The client IP is the TCP socket peer by default. `X-Forwarded-For` is a
/// caller-supplied header and is **NEVER** trusted unless the socket peer is
/// itself in one of the operator-configured `trusted_proxies` CIDR ranges —
/// otherwise any client could spoof its IP and evade the per-IP budget (or
/// frame another IP). When the peer IS a trusted proxy, the real client is
/// taken from the rightmost `X-Forwarded-For` entry that is not itself a
/// trusted proxy (walking right-to-left across a chain of trusted hops).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Master switch for the per-IP / global `/auth/*` limiter. Default
    /// `true`: the endpoints are the most attacker-controllable surface, so
    /// the bound is protective out of the box. Set `false` to fall back to
    /// the per-agent `[limits]` budgets only.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Max `/auth/*` requests per minute per resolved client IP. `0` disables
    /// the per-IP bound (the global ceiling, if set, still applies).
    #[serde(default = "default_per_ip_per_minute")]
    pub per_ip_per_minute: u32,
    /// Whole-process ceiling: max `/auth/*` requests per minute across ALL
    /// client IPs. `0` disables the global ceiling. Defends a single replica
    /// against a distributed flood that rotates source IPs.
    #[serde(default = "default_global_per_minute")]
    pub global_per_minute: u32,
    /// CIDR ranges of reverse proxies whose `X-Forwarded-For` header this
    /// registry trusts. Empty (the default) means XFF is ignored and the TCP
    /// socket peer IP is always used — the safe default. List ONLY the
    /// addresses of proxies you operate (e.g. `["10.0.0.0/8"]`); listing an
    /// untrusted range lets clients on it spoof their source IP.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

fn default_per_ip_per_minute() -> u32 {
    60
}
fn default_global_per_minute() -> u32 {
    6_000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_per_minute: default_per_ip_per_minute(),
            global_per_minute: default_global_per_minute(),
            trusted_proxies: Vec::new(),
        }
    }
}

/// FEAT-10: Prometheus `/metrics` endpoint (text exposition format).
///
/// Off by default — enabling it mounts `GET /metrics` and installs a
/// process-global recorder. The endpoint is intentionally NOT rate-limited
/// and NOT behind the ACDP auth pipeline (scrapers use bearer gating below,
/// not ACDP tokens) so a Prometheus server can scrape it unimpeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Mount `GET /metrics` and record request + domain metrics. Default
    /// `false`: metrics are pure ops ergonomics, opt-in per deployment.
    #[serde(default)]
    pub enabled: bool,
    /// When non-empty, `/metrics` requires `Authorization: Bearer <token>`
    /// matching this value. Empty (the default) leaves the endpoint open —
    /// appropriate when it is reachable only from a trusted scrape network.
    #[serde(default)]
    pub bearer_token: String,
    /// Histogram buckets (seconds) for `acdp_registry_request_duration_seconds`.
    /// Defaults to a web-latency-oriented ladder.
    #[serde(default = "default_duration_buckets")]
    pub duration_buckets: Vec<f64>,
}

fn default_duration_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: String::new(),
            duration_buckets: default_duration_buckets(),
        }
    }
}

/// Playground-mode controls.
///
/// Playground mode skips the full DID-web verification pipeline so
/// scenarios can run without standing up real DID documents. To keep
/// playground demos from accepting impostor publishes, operators can
/// configure `pinned_keys`: a list of `agent_did -> public_key_b64`
/// entries the registry MUST verify against before accepting the
/// publish.
///
/// Two enforcement modes:
///   * **lax** (default, `pinned_only = false`): pinned agents are
///     verified against their pinned key; agents not in the list are
///     still accepted. Useful while adding pinning incrementally.
///   * **strict** (`pinned_only = true`): publishes from agents NOT in
///     the pinned list are rejected outright. Useful for locked-down
///     demos.
///
/// Verification (base64 decode + Ed25519 signature check against the
/// pinned key) is performed by the handler in `acdp-registry-core` —
/// this struct is pure data so the types crate stays crypto-free.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaygroundConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Agent identities whose publish signatures must verify against a
    /// pinned public key. See [`PinnedAgentKey`] for the per-entry
    /// shape. Empty (the default) means no pinning is enforced.
    #[serde(default)]
    pub pinned_keys: Vec<PinnedAgentKey>,
    /// When true AND `pinned_keys` is non-empty, reject publishes from
    /// agents not listed in `pinned_keys`. When false (the default),
    /// unpinned agents are still accepted. Has no effect when
    /// `pinned_keys` is empty.
    #[serde(default)]
    pub pinned_only: bool,
}

/// One pinned agent identity.
///
/// `public_key_b64` MUST be the raw key material (32 bytes for
/// Ed25519), standard-base64-encoded (44 chars with padding) — the
/// format `AcdpProducer.public_key_b64` returns.
///
/// ## Key rotation with overlap windows
///
/// Multiple entries with the same `agent_did` are allowed, each
/// scoped by `valid_from` / `valid_until` (unix seconds, inclusive
/// of start, exclusive of end). [`PlaygroundConfig::pinned_for`]
/// returns whichever entry is valid at the current wall-clock
/// time, preferring the one with the latest `valid_from` so a fresh
/// key always wins over an older overlap.
///
/// Operators rotate a key by:
///   1. Adding a new entry with `valid_from = now` (or future).
///   2. Setting the old entry's `valid_until = now + overlap`.
///   3. Reloading config (deployment restart, or admin endpoint when
///      that lands).
///
/// During the overlap window, signatures from either key verify.
/// Once `valid_until` passes, only the new key is accepted.
///
/// Both bounds default to "open-ended": a `valid_from` of `None`
/// means "valid from the beginning of time"; a `valid_until` of
/// `None` means "valid forever (until explicitly revoked)".
/// Backward-compatible: existing configs without rotation fields
/// behave exactly like before.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedAgentKey {
    /// Full DID, e.g. `did:web:registry-a.playground.local:agents:alice`.
    pub agent_did: String,
    /// Standard base64 of the raw public key bytes.
    pub public_key_b64: String,
    /// Algorithm tag — currently only `ed25519` is supported. Defaulted
    /// for forward compatibility.
    #[serde(default = "default_pinned_algorithm")]
    pub algorithm: String,
    /// Unix seconds at which this key becomes valid (inclusive).
    /// `None` (the default) means "valid from the beginning of time".
    #[serde(default)]
    pub valid_from: Option<i64>,
    /// Unix seconds at which this key stops being valid (exclusive).
    /// `None` (the default) means "valid forever, until explicitly
    /// revoked or replaced by another rotation".
    #[serde(default)]
    pub valid_until: Option<i64>,
}

fn default_pinned_algorithm() -> String {
    "ed25519".into()
}

impl PinnedAgentKey {
    /// Is this entry valid at the given unix-seconds timestamp?
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.valid_from.is_none_or(|from| now >= from)
            && self.valid_until.is_none_or(|until| now < until)
    }
}

impl PlaygroundConfig {
    /// Look up the pinned entry for an agent_did at the current
    /// wall-clock time.
    ///
    /// When multiple entries exist for the same `agent_did` (the key
    /// rotation case), returns the one whose `valid_from` is latest
    /// among those currently valid — i.e. the freshest key wins
    /// during an overlap window.
    ///
    /// Returns `None` when no entry matches the DID at all OR when
    /// every matching entry is currently outside its validity window
    /// (callers can distinguish via [`Self::has_entry_for`] if they
    /// want to log "expired pin" separately from "no pin").
    pub fn pinned_for(&self, agent_did: &str) -> Option<&PinnedAgentKey> {
        self.pinned_for_at(agent_did, current_unix_seconds())
    }

    /// `pinned_for` with an explicit `now` — for tests and audit jobs
    /// that need deterministic time.
    pub fn pinned_for_at(&self, agent_did: &str, now: i64) -> Option<&PinnedAgentKey> {
        self.pinned_keys
            .iter()
            .filter(|p| p.agent_did == agent_did && p.is_valid_at(now))
            // Prefer the entry with the latest `valid_from` so a freshly
            // rotated key wins during overlap. `None` (open start) sorts
            // before any concrete timestamp so an open-ended legacy entry
            // doesn't displace a deliberately-introduced new key.
            .max_by_key(|p| p.valid_from.unwrap_or(i64::MIN))
    }

    /// True if any pinned entry exists for `agent_did`, regardless of
    /// validity window. Useful for logging an "expired pin" branch
    /// distinct from "agent not pinned".
    pub fn has_entry_for(&self, agent_did: &str) -> bool {
        self.pinned_keys.iter().any(|p| p.agent_did == agent_did)
    }
}

/// Registry-receipt signing identity (RFC-ACDP-0010, workstream A).
///
/// When a signing key is configured the registry mints a signed receipt
/// for every publish, persists it atomically with the context row, and
/// advertises `acdp_version: 0.2.0` plus the `acdp-registry-receipts`
/// profile. When NO key is configured neither is advertised — a registry
/// without a signing key must not claim the profile (RFC-ACDP-0010 §7:
/// no degraded mode).
///
/// The key is an Ed25519 seed supplied through exactly one of two
/// sources, mirroring the "file / env seed" split used for JWT secrets:
///
///   * `signing_key_seed_b64` — standard base64 of the raw 32-byte seed.
///     Env-friendly: `ACDP_REGISTRY_RECEIPT__SIGNING_KEY_SEED_B64`.
///   * `signing_key_path` — path to a file (e.g. a mounted secret)
///     whose contents are that same base64 string; surrounding
///     whitespace is tolerated.
///
/// This struct is pure data — decoding and `acdp::types::receipt::
/// ReceiptSigner` construction live in `acdp-registry-core::receipt`,
/// which is also the single seam to swap in a KMS/HSM-backed key source
/// later without touching the publish path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptConfig {
    /// Standard base64 of the raw 32-byte Ed25519 seed. Empty = unset.
    #[serde(default)]
    pub signing_key_seed_b64: String,
    /// File containing the base64 seed. `None` = unset.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,
    /// Fragment of the receipt key id under the registry DID; the full
    /// `signature.key_id` becomes `did:web:<authority>#<fragment>`.
    /// Rotations MUST pick a fresh fragment (e.g. `receipt-key-2`) so
    /// receipts minted under the old key keep resolving to the old key.
    #[serde(default = "default_receipt_key_fragment")]
    pub key_id_fragment: String,
    /// Rotated-out receipt verification keys. RFC-ACDP-0010 §9: retired
    /// keys stay in the DID document's `verificationMethod` indefinitely
    /// (they are removed from `assertionMethod` only) — dropping an entry
    /// from this list bricks every receipt that key ever signed. Remove
    /// an entry ONLY on confirmed key compromise.
    #[serde(default)]
    pub retired_keys: Vec<RetiredReceiptKey>,
    /// Lineage-head receipts (RFC-ACDP-0011, ACDP 0.3.0). When `true`
    /// (and a receipt signing key is configured — startup validation
    /// enforces the prerequisite) every `GET /lineages/{id}/current`
    /// response carries a freshly minted `lineage_head_receipt` signed
    /// with the SAME receipt key (§5: head receipts introduce no new
    /// key role), and the registry advertises the
    /// `acdp-registry-head-receipts` profile plus `acdp_version` ≥
    /// 0.3.0. Head receipts are ephemeral serve-time attestations —
    /// never persisted, never attached to body-only responses (§6).
    #[serde(default)]
    pub head_receipts: bool,
}

impl Default for ReceiptConfig {
    fn default() -> Self {
        Self {
            signing_key_seed_b64: String::new(),
            signing_key_path: None,
            key_id_fragment: default_receipt_key_fragment(),
            retired_keys: Vec::new(),
            head_receipts: false,
        }
    }
}

/// Lifecycle events & retraction (RFC-ACDP-0013, ACDP 0.3.0).
///
/// When `enabled`, the registry:
///   * serves `POST /contexts/{ctx_id}/retract` and
///     `POST /contexts/{ctx_id}/republish` (producer-signed events,
///     verified through the same DID pipeline as a publish);
///   * derives `status` with the §7.2 precedence
///     (`retracted` > `superseded` > `expired` > `active`);
///   * excludes retracted contexts from default search and from
///     `/lineages/{id}/current` (§8);
///   * serves `registry_state.lifecycle_events` on full retrieval and
///     the lineage array;
///   * advertises the `acdp-registry-lifecycle` profile plus
///     `acdp_version` ≥ 0.3.0.
///
/// When disabled (the default), both endpoints return
/// `not_implemented` (HTTP 501) and neither `lifecycle_events` nor the
/// `retracted` status is ever emitted (§6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Registry transparency log (RFC-ACDP-0012, ACDP 0.3.0).
///
/// When `enabled`, the registry:
///   * appends one §4 leaf per accepted publish, ATOMICALLY with the
///     context row and its RFC-ACDP-0010 receipt (§7.1 — the body, the
///     receipt, and the leaf commit together, or none does);
///   * serves `GET /log/checkpoint`, `GET /log/proof`, and
///     `GET /log/entries` (§8), signing checkpoints with the SAME
///     receipt key (§6: the log introduces no new key role);
///   * advertises the `acdp-registry-transparency-log` profile plus
///     `acdp_version` ≥ 0.3.0.
///
/// Prerequisite: a configured `[receipt]` signing key — the profile's
/// prerequisite is `acdp-registry-receipts` (§11: leaves bind receipt
/// hashes and checkpoints sign with the receipt key). Startup validation
/// enforces it. A durable storage backend (SQLite / Postgres) is also
/// required; the ephemeral memory backend cannot honor the append-only
/// history commitment (§7.4).
///
/// When disabled (the default), the three `/log/*` endpoints answer
/// `not_implemented` (HTTP 501) and no leaf is ever appended. There is no
/// `log_unavailable` degraded mode: an enabled log MUST log every
/// accepted publish or fail the publish (§7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The `<instance>` component of the log identifier
    /// `"<registry_did>/log/<instance>"` (§6; matches `[a-z0-9-]{1,32}`).
    /// A registry operates exactly ONE live instantiation; change this
    /// value ONLY on catastrophic tree loss (§7.4) — a new instance is an
    /// explicit, detectable history reset, and the old tree's
    /// consistency guarantees do not carry over.
    #[serde(default = "default_log_instance")]
    pub instance: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            instance: default_log_instance(),
        }
    }
}

fn default_log_instance() -> String {
    "1".into()
}

/// One transparency-log **witness** (RFC-ACDP-0015 §6.1) this registry
/// polls and whose verified cosignatures it aggregates onto its own
/// checkpoint responses (the reserved `witness_signatures` member).
///
/// Wire format (TOML):
///
/// ```toml
/// [[witnesses]]
/// did          = "did:web:witness.example.org"
/// url          = "https://witness.example.org/log/witness"
/// poll_seconds = 60              # default 300
/// ```
///
/// The background poller GETs `<url>?log_id=<this registry's log_id>`,
/// VERIFIES every returned cosignature (RFC-ACDP-0015 §8: closed parse,
/// witness-key signature under the witness DID's `assertionMethod`
/// resolved via the SSRF-guarded `did:web` resolver, and — crucially —
/// that `witnessed_checkpoint` matches THIS registry's own root at that
/// `tree_size`), and stores only the ones that pass. A witness cosigning
/// a different root (a fork, or a lie) is logged and dropped, never
/// served. Aggregation is a convenience: the registry cannot forge a
/// cosignature (it never holds a witness key), so serving them adds no
/// trust — a consumer may always go direct to the witness (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    /// The witness's DID (`did:web` — the only method resolvable over the
    /// network under the SSRF guard). Cosignatures whose `witness_id`
    /// does not equal this value are ignored (a witness endpoint only
    /// speaks for its own DID).
    pub did: String,
    /// Full HTTPS URL of the witness's `GET /log/witness` endpoint
    /// (RFC-ACDP-0015 §6.2). SSRF-checked at startup and re-checked at
    /// DNS time on every poll.
    pub url: String,
    /// Poll interval in seconds. Default 300 (aligned with the
    /// revocation-feed poller and the RFC-ACDP-0012 §7.2 freshness
    /// cadence).
    #[serde(default = "default_witness_poll_seconds")]
    pub poll_seconds: u64,
}

fn default_witness_poll_seconds() -> u64 {
    300
}

fn default_receipt_key_fragment() -> String {
    "receipt-key-1".into()
}

impl ReceiptConfig {
    /// Whether a receipt signing key source is configured. Gates the
    /// `acdp-registry-receipts` profile and the 0.2.0 capability bump.
    pub fn is_configured(&self) -> bool {
        !self.signing_key_seed_b64.trim().is_empty() || self.signing_key_path.is_some()
    }
}

/// A retired receipt verification key, published in the registry DID
/// document's `verificationMethod` (never `assertionMethod`) so receipts
/// signed before a rotation keep verifying.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredReceiptKey {
    /// Standard base64 of the raw 32-byte Ed25519 PUBLIC key.
    pub public_key_b64: String,
    /// The fragment this key was published under while active (the
    /// `signature.key_id` of receipts it signed points here).
    pub key_id_fragment: String,
}

/// Wall-clock unix seconds. Wrapped so we have one switchable point
/// if a future test harness wants to inject a clock.
fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(did: &str, b64: &str) -> PinnedAgentKey {
        PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: b64.into(),
            algorithm: default_pinned_algorithm(),
            valid_from: None,
            valid_until: None,
        }
    }

    fn pinned_window(
        did: &str,
        b64: &str,
        from: Option<i64>,
        until: Option<i64>,
    ) -> PinnedAgentKey {
        PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: b64.into(),
            algorithm: default_pinned_algorithm(),
            valid_from: from,
            valid_until: until,
        }
    }

    #[test]
    fn pinned_keys_defaults_remain_empty() {
        // Backward compat: existing configs without pinned_keys MUST still
        // deserialize and produce an empty list.
        let cfg: PlaygroundConfig = toml::from_str("enabled = true").unwrap();
        assert!(cfg.enabled);
        assert!(cfg.pinned_keys.is_empty());
        assert!(!cfg.pinned_only);
    }

    #[test]
    fn pinned_keys_round_trip_toml() {
        let toml = r#"
enabled = true
pinned_only = true

[[pinned_keys]]
agent_did = "did:web:demo.local:agents:alice"
public_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[pinned_keys]]
agent_did = "did:web:demo.local:agents:bob"
public_key_b64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
algorithm = "ed25519"
"#;
        let cfg: PlaygroundConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.pinned_keys.len(), 2);
        assert!(cfg.pinned_only);
        assert_eq!(cfg.pinned_keys[0].algorithm, "ed25519");
        assert_eq!(cfg.pinned_keys[1].algorithm, "ed25519");
    }

    #[test]
    fn pinned_for_finds_match() {
        let cfg = PlaygroundConfig {
            enabled: true,
            pinned_only: false,
            pinned_keys: vec![pinned("did:web:x", "AAAA")],
        };
        assert!(cfg.pinned_for("did:web:x").is_some());
        assert!(cfg.pinned_for("did:web:nope").is_none());
    }

    #[test]
    fn unknown_field_rejected() {
        // `deny_unknown_fields` guards against typos like `pin_keys`.
        let toml = r#"
enabled = true
pin_keys = []
"#;
        let err = toml::from_str::<PlaygroundConfig>(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pin_keys"), "unexpected error: {msg}");
    }

    // ── rotation / overlap windows ──────────────────────────────────

    #[test]
    fn is_valid_at_open_window_is_always_valid() {
        let k = pinned_window("did:web:x", "AAAA", None, None);
        assert!(k.is_valid_at(0));
        assert!(k.is_valid_at(1_000_000_000_000));
    }

    #[test]
    fn is_valid_at_respects_valid_from_inclusive() {
        let k = pinned_window("did:web:x", "AAAA", Some(100), None);
        assert!(!k.is_valid_at(99));
        assert!(k.is_valid_at(100));
        assert!(k.is_valid_at(101));
    }

    #[test]
    fn is_valid_at_respects_valid_until_exclusive() {
        let k = pinned_window("did:web:x", "AAAA", None, Some(200));
        assert!(k.is_valid_at(199));
        assert!(!k.is_valid_at(200));
        assert!(!k.is_valid_at(201));
    }

    #[test]
    fn pinned_for_at_returns_none_when_expired() {
        let cfg = PlaygroundConfig {
            enabled: true,
            pinned_only: false,
            pinned_keys: vec![pinned_window("did:web:x", "OLD", None, Some(100))],
        };
        assert!(cfg.pinned_for_at("did:web:x", 99).is_some());
        assert!(cfg.pinned_for_at("did:web:x", 150).is_none());
        // But the agent IS pinned — distinguishing from "not pinned at all".
        assert!(cfg.has_entry_for("did:web:x"));
    }

    #[test]
    fn pinned_for_at_returns_none_when_future() {
        let cfg = PlaygroundConfig {
            enabled: true,
            pinned_only: false,
            pinned_keys: vec![pinned_window("did:web:x", "NEW", Some(500), None)],
        };
        assert!(cfg.pinned_for_at("did:web:x", 100).is_none());
        assert!(cfg.pinned_for_at("did:web:x", 500).is_some());
    }

    #[test]
    fn pinned_for_at_in_overlap_window_prefers_newest_valid_from() {
        // old: valid until t=200; new: valid from t=150. Overlap = [150, 200).
        let cfg = PlaygroundConfig {
            enabled: true,
            pinned_only: false,
            pinned_keys: vec![
                pinned_window("did:web:x", "OLD", None, Some(200)),
                pinned_window("did:web:x", "NEW", Some(150), None),
            ],
        };
        // At t=120, only OLD is valid.
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 120).unwrap().public_key_b64,
            "OLD"
        );
        // At t=175 (inside overlap), NEW wins because its valid_from is later.
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 175).unwrap().public_key_b64,
            "NEW"
        );
        // At t=250, only NEW is valid.
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 250).unwrap().public_key_b64,
            "NEW"
        );
    }

    #[test]
    fn pinned_for_at_with_three_way_rotation() {
        // Sequential rotation: K1 → K2 → K3.
        let cfg = PlaygroundConfig {
            enabled: true,
            pinned_only: false,
            pinned_keys: vec![
                pinned_window("did:web:x", "K1", None, Some(100)),
                pinned_window("did:web:x", "K2", Some(80), Some(200)),
                pinned_window("did:web:x", "K3", Some(180), None),
            ],
        };
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 50).unwrap().public_key_b64,
            "K1"
        );
        // Overlap K1+K2 → K2 (newer valid_from).
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 90).unwrap().public_key_b64,
            "K2"
        );
        // Only K2.
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 150).unwrap().public_key_b64,
            "K2"
        );
        // Overlap K2+K3 → K3 (newer valid_from).
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 190).unwrap().public_key_b64,
            "K3"
        );
        // Only K3.
        assert_eq!(
            cfg.pinned_for_at("did:web:x", 500).unwrap().public_key_b64,
            "K3"
        );
    }

    #[test]
    fn rotation_round_trips_via_toml() {
        let toml = r#"
enabled = true

[[pinned_keys]]
agent_did = "did:web:demo:agents:alice"
public_key_b64 = "OLD"
valid_until = 1000

[[pinned_keys]]
agent_did = "did:web:demo:agents:alice"
public_key_b64 = "NEW"
valid_from = 900
"#;
        let cfg: PlaygroundConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.pinned_keys.len(), 2);
        assert_eq!(cfg.pinned_keys[0].valid_until, Some(1000));
        assert_eq!(cfg.pinned_keys[1].valid_from, Some(900));
        // Round-trip back through serde so we know serialize doesn't drop fields.
        let ser = toml::to_string(&cfg).unwrap();
        let back: PlaygroundConfig = toml::from_str(&ser).unwrap();
        assert_eq!(back.pinned_keys.len(), 2);
        assert_eq!(back.pinned_keys[0].valid_until, Some(1000));
        assert_eq!(back.pinned_keys[1].valid_from, Some(900));
    }

    #[test]
    fn existing_configs_without_rotation_fields_still_deserialize() {
        // The default = None on Option<i64> guarantees forward compat.
        let toml = r#"
enabled = true

[[pinned_keys]]
agent_did = "did:web:x"
public_key_b64 = "AAAA"
"#;
        let cfg: PlaygroundConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.pinned_keys[0].valid_from, None);
        assert_eq!(cfg.pinned_keys[0].valid_until, None);
    }

    // ── effective_base_url ──────────────────────────────────────────

    #[test]
    fn effective_base_url_derives_from_authority_when_unset() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.authority = "registry.example".into();
        cfg.registry.base_url = String::new();
        assert_eq!(
            cfg.registry.effective_base_url(),
            "https://registry.example"
        );
    }

    #[test]
    fn effective_base_url_prefers_explicit_and_trims_trailing_slash() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.authority = "ignored.example".into();
        cfg.registry.base_url = "https://public.example:8443/".into();
        assert_eq!(
            cfg.registry.effective_base_url(),
            "https://public.example:8443"
        );
    }

    #[test]
    fn effective_base_url_treats_whitespace_only_as_unset() {
        let mut cfg = RegistryConfig::defaults();
        cfg.registry.authority = "host.example".into();
        cfg.registry.base_url = "   ".into();
        assert_eq!(cfg.registry.effective_base_url(), "https://host.example");
    }

    // ── tenant_for_agent ────────────────────────────────────────────

    fn auth_with_bindings(bindings: &[(&str, &str)]) -> AuthConfig {
        AuthConfig {
            tenant_agents: bindings
                .iter()
                .map(|(did, tenant)| TenantAgentBinding {
                    agent_did: (*did).into(),
                    tenant_id: (*tenant).into(),
                })
                .collect(),
            ..AuthConfig::default()
        }
    }

    #[test]
    fn tenant_for_agent_returns_bound_tenant() {
        let auth = auth_with_bindings(&[("did:web:a", "tenant-a"), ("did:web:b", "tenant-b")]);
        assert_eq!(
            auth.tenant_for_agent("did:web:b"),
            Some("tenant-b".to_string())
        );
    }

    #[test]
    fn tenant_for_agent_returns_none_for_unlisted_and_empty() {
        assert_eq!(AuthConfig::default().tenant_for_agent("did:web:x"), None);
        let auth = auth_with_bindings(&[("did:web:a", "tenant-a")]);
        assert_eq!(auth.tenant_for_agent("did:web:unknown"), None);
    }

    #[test]
    fn tenant_for_agent_first_binding_wins_on_duplicate_did() {
        // First match wins — the issuance and publish paths MUST agree, so the
        // resolution order is deterministic even with a misconfigured duplicate.
        let auth = auth_with_bindings(&[("did:web:dup", "first"), ("did:web:dup", "second")]);
        assert_eq!(
            auth.tenant_for_agent("did:web:dup"),
            Some("first".to_string())
        );
    }

    // ── deserialization guards ──────────────────────────────────────

    #[test]
    fn witnesses_default_empty_and_round_trip() {
        // Backward compat: a config without [[witnesses]] deserializes to
        // an empty list (aggregation disabled).
        let cfg = RegistryConfig::defaults();
        assert!(cfg.witnesses.is_empty());

        let toml = r#"
[[witnesses]]
did = "did:web:witness.example.org"
url = "https://witness.example.org/log/witness"

[[witnesses]]
did = "did:web:witness-2.example.org"
url = "https://witness-2.example.org/log/witness"
poll_seconds = 60
"#;
        #[derive(serde::Deserialize)]
        struct Wrap {
            witnesses: Vec<WitnessConfig>,
        }
        let w: Wrap = toml::from_str(toml).unwrap();
        assert_eq!(w.witnesses.len(), 2);
        assert_eq!(w.witnesses[0].did, "did:web:witness.example.org");
        assert_eq!(w.witnesses[0].poll_seconds, 300, "default poll interval");
        assert_eq!(w.witnesses[1].poll_seconds, 60);
    }

    #[test]
    fn witness_unknown_field_rejected() {
        let toml = r#"
did = "did:web:w.example"
url = "https://w.example/log/witness"
bogus = 1
"#;
        let err = toml::from_str::<WitnessConfig>(toml).unwrap_err();
        assert!(err.to_string().contains("bogus"), "unexpected: {err}");
    }

    #[test]
    fn rate_limit_defaults_are_protective() {
        // Absent [rate_limit], the limiter is on with sane bounds.
        let cfg = RegistryConfig::defaults();
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.per_ip_per_minute, 60);
        assert_eq!(cfg.rate_limit.global_per_minute, 6_000);
        assert!(cfg.rate_limit.trusted_proxies.is_empty());
    }

    #[test]
    fn rate_limit_round_trips_and_rejects_unknown() {
        let toml = r#"
enabled = false
per_ip_per_minute = 10
global_per_minute = 500
trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
"#;
        let cfg: RateLimitConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.per_ip_per_minute, 10);
        assert_eq!(cfg.global_per_minute, 500);
        assert_eq!(cfg.trusted_proxies.len(), 2);

        let err = toml::from_str::<RateLimitConfig>("bogus = 1").unwrap_err();
        assert!(err.to_string().contains("bogus"), "unexpected: {err}");
    }

    #[test]
    fn metrics_defaults_off_and_round_trip() {
        let cfg = RegistryConfig::defaults();
        assert!(!cfg.metrics.enabled);
        assert!(cfg.metrics.bearer_token.is_empty());
        assert!(!cfg.metrics.duration_buckets.is_empty());

        let toml = r#"
enabled = true
bearer_token = "scrape-secret"
duration_buckets = [0.1, 0.5, 1.0]
"#;
        let cfg: MetricsConfig = toml::from_str(toml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bearer_token, "scrape-secret");
        assert_eq!(cfg.duration_buckets, vec![0.1, 0.5, 1.0]);

        let err = toml::from_str::<MetricsConfig>("bogus = 1").unwrap_err();
        assert!(err.to_string().contains("bogus"), "unexpected: {err}");
    }

    #[test]
    fn storage_backend_parses_known_variants() {
        let toml = r#"
backend = "postgres"
postgres_url = "postgres://localhost/acdp"
max_connections = 5
"#;
        let cfg: StorageConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.backend, StorageBackend::Postgres);
        assert_eq!(cfg.max_connections, 5);
    }

    #[test]
    fn top_level_unknown_section_is_rejected() {
        // `deny_unknown_fields` at the top level catches a mistyped section
        // name (e.g. `[storag]`) instead of silently ignoring it.
        let toml = r#"
[registry]
authority = "localhost"
port = 8443

[storag]
backend = "sqlite"
"#;
        let err = toml::from_str::<RegistryConfig>(toml).unwrap_err();
        assert!(
            err.to_string().contains("storag"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn env_overrides_use_single_underscore_prefix_and_double_underscore_nesting() {
        // Regression: the `config` crate reuses `separator` for the prefix
        // unless `prefix_separator` is pinned, which silently demanded
        // `ACDP_REGISTRY__AUTH__...`. Every doc/compose/Railway env var uses
        // the single-underscore prefix form below, so without the pin all of
        // them were no-ops (e.g. the storage backend could never be selected
        // for the Postgres-only container image). Keep this convention stable.
        //
        // Also covers the `Vec<String>` fields (`auth.did_methods`,
        // `registry.profiles`): `config`'s env source only ever splits a
        // value into a list for keys passed to `with_list_parse_key` — every
        // other field (including a comma-bearing JWT secret below) must keep
        // deserializing as a scalar even though `list_separator` is now
        // globally set on the source. Before this fix, an operator with no
        // TOML-file mechanism (e.g. Railway "deploy from image" services)
        // could not enable `did:key` at all.
        //
        // SAFETY: no other test in this crate reads or writes process env, so
        // the set/remove pair here cannot race a concurrent reader.
        let vars = [
            ("ACDP_REGISTRY_REGISTRY__AUTHORITY", "env-host"),
            ("ACDP_REGISTRY_REGISTRY__PORT", "9191"),
            ("ACDP_REGISTRY_STORAGE__BACKEND", "postgres"),
            ("ACDP_REGISTRY_AUTH__DID_METHODS", "did:web,did:key"),
            (
                "ACDP_REGISTRY_REGISTRY__PROFILES",
                "acdp-registry-core,acdp-registry-discovery",
            ),
            // Not a `with_list_parse_key` field — must stay a scalar even
            // though it contains the list separator.
            ("ACDP_REGISTRY_AUTH__JWT_SECRET", "a,b,c-not-a-list"),
            // A prefixed but un-nested var must NOT trip `deny_unknown_fields`
            // via the env source. `..._TEST_PG_URL` is the CI test harness var;
            // `ACDP_REGISTRY_CONFIG` is the same shape but is excluded here
            // because `load(None)` separately consults it as a file path.
            ("ACDP_REGISTRY_TEST_PG_URL", "postgres://ignored"),
        ];
        for (k, v) in vars {
            std::env::set_var(k, v);
        }

        let cfg = RegistryConfig::load(None).expect("config loads with env overrides");

        for (k, _) in vars {
            std::env::remove_var(k);
        }

        assert_eq!(cfg.registry.authority, "env-host");
        assert_eq!(cfg.registry.port, 9191);
        assert_eq!(cfg.storage.backend, StorageBackend::Postgres);
        assert_eq!(cfg.auth.did_methods, vec!["did:web", "did:key"]);
        assert_eq!(
            cfg.registry.profiles,
            vec!["acdp-registry-core", "acdp-registry-discovery"]
        );
        assert_eq!(cfg.auth.jwt_secret, "a,b,c-not-a-list");
    }
}
