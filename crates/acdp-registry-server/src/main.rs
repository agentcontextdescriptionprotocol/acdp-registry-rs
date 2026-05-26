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
use acdp_registry_types::{RegistryConfig, StorageBackend};
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
                // Ephemeral secret — tokens won't survive a restart. Operators
                // running in production MUST set ACDP_REGISTRY_AUTH__JWT_SECRET.
                tracing::warn!("auth.jwt_secret not set — generating an ephemeral key");
                use rand::RngCore;
                let mut bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut bytes);
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
    if let Some(rev) = revocations {
        auth = auth.with_revocations(rev);
    }
    let auth = Arc::new(auth);
    auth.spawn_evictor();

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

    // Compose state + router.
    let state = AppStateInner {
        server,
        auth,
        webhook,
        config: cfg.clone(),
        cross_registry,
    };
    let router = build_router(state);

    // Bind. TLS is optional — production typically terminates upstream.
    let addr: SocketAddr = format!("{}:{}", cfg.registry.bind, cfg.registry.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("bind address: {e}"))?;
    tracing::info!(addr = %addr, "listening");
    // OPS-03: graceful shutdown on SIGTERM / Ctrl-C. In-flight requests
    // get up to 30s to complete before the handle drops the listener.
    let handle = axum_server::Handle::new();
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
            .serve(router.into_make_service())
            .await?;
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    }
    Ok(())
}

fn spawn_shutdown_watcher(handle: axum_server::Handle) {
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

fn build_capabilities(cfg: &RegistryConfig) -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: "0.1.0".into(),
        registry_did: authority_to_did_web(&cfg.registry.authority),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: cfg.auth.did_methods.clone(),
        profiles: if cfg.registry.profiles.is_empty() {
            vec![
                "acdp-registry-core".into(),
                "acdp-registry-discovery".into(),
            ]
        } else {
            cfg.registry.profiles.clone()
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
