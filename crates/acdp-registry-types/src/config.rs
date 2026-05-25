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
    #[serde(default)]
    pub playground: PlaygroundConfig,
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
        builder = builder.add_source(
            config::Environment::with_prefix("ACDP_REGISTRY")
                .separator("__")
                .try_parsing(true),
        );
        builder.build()?.try_deserialize()
    }

    /// Defaults suitable for local development (SQLite, no auth, no webhook).
    pub fn defaults() -> Self {
        Self {
            registry: RegistrySection {
                authority: "localhost".into(),
                port: 8443,
                bind: "0.0.0.0".into(),
                profiles: vec![
                    "acdp-registry-core".into(),
                    "acdp-registry-discovery".into(),
                ],
                tls: TlsConfig::default(),
                cross_registry_resolution: true,
                cors: CorsConfig::default(),
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
            playground: PlaygroundConfig::default(),
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
    /// Bind address. Defaults to `0.0.0.0`.
    #[serde(default = "default_bind")]
    pub bind: String,
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
}

fn default_bind() -> String {
    "0.0.0.0".into()
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

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: default_payload_bytes(),
            max_embedded_bytes: default_embedded_bytes(),
            idempotency_key_ttl_seconds: default_idempotency_ttl(),
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
}

fn default_pinned_algorithm() -> String {
    "ed25519".into()
}

impl PlaygroundConfig {
    /// Look up the pinned entry for an agent_did. Returns `None` when
    /// the agent isn't pinned (callers check `pinned_only` to decide
    /// whether that should be a rejection).
    pub fn pinned_for(&self, agent_did: &str) -> Option<&PinnedAgentKey> {
        self.pinned_keys.iter().find(|p| p.agent_did == agent_did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(did: &str, b64: &str) -> PinnedAgentKey {
        PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: b64.into(),
            algorithm: default_pinned_algorithm(),
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
}
