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

use acdp::did::{authority_to_did_web, WebResolver};
use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp_registry_auth::{
    AuthService, ChallengeStore, InMemoryChallengeStore, JwtSecret, JwtSigner,
};
use acdp_registry_core::{build_router, AppStateInner};
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{RegistryConfig, StorageBackend};
use acdp_registry_webhook::WebhookEmitter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let _ = dotenvy::dotenv();

    let cfg = RegistryConfig::load(None).map_err(|e| anyhow::anyhow!("config: {e}"))?;
    tracing::info!(
        authority = %cfg.registry.authority,
        port = cfg.registry.port,
        backend = ?cfg.storage.backend,
        playground = cfg.playground.enabled,
        "starting acdp-registry"
    );

    run(cfg).await
}

#[cfg(feature = "storage-sqlite")]
async fn run(cfg: RegistryConfig) -> anyhow::Result<()> {
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
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    serve_with_store(cfg, store, challenges).await
}

#[cfg(all(feature = "storage-pg", not(feature = "storage-sqlite")))]
async fn run(cfg: RegistryConfig) -> anyhow::Result<()> {
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
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    serve_with_store(cfg, store, challenges).await
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
    serve_with_store(cfg, store, challenges).await
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
) -> anyhow::Result<()> {
    // Capabilities + RegistryServer.
    let caps = build_capabilities(&cfg);
    let server = RegistryServer::try_new(store, caps, cfg.registry.authority.clone())
        .map_err(|e| anyhow::anyhow!("registry server: {e}"))?;
    let server = Arc::new(server);

    // Auth.
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
    let issuer = authority_to_did_web(&cfg.registry.authority);
    let signer = JwtSigner::new(
        jwt_secret,
        issuer,
        cfg.registry.authority.clone(),
        cfg.auth.token_leeway_seconds,
    );
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        cfg.auth.clone(),
        challenges,
        signer,
        resolver,
        cfg.registry.authority.clone(),
    ));
    auth.spawn_evictor();

    // Webhook.
    let webhook = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(WebhookEmitter::spawn(cfg.webhook.clone()))
    } else {
        None
    };

    // Compose state + router.
    let state = AppStateInner {
        server,
        auth,
        webhook,
        config: cfg.clone(),
    };
    let router = build_router(state);

    // Bind. TLS is optional — production typically terminates upstream.
    let addr: SocketAddr = format!("{}:{}", cfg.registry.bind, cfg.registry.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("bind address: {e}"))?;
    tracing::info!(addr = %addr, "listening");
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
            .serve(router.into_make_service())
            .await?;
    } else {
        axum_server::bind(addr)
            .serve(router.into_make_service())
            .await?;
    }
    Ok(())
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

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,acdp=info,acdp_registry=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .json()
        .init();
}
