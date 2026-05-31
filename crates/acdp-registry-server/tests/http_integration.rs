//! HTTP integration tests.
//!
//! Spins up the real axum router against an in-memory SQLite store and
//! drives it via `Router::oneshot` — no network, no DID resolution.
//! Publish requests go through the playground path so the registry can
//! skip the DID-resolution step that would otherwise require a live HTTPS
//! mock.
//!
//! Coverage:
//! - `/healthz`
//! - `/.well-known/acdp.json`
//! - publish → retrieve → search round trip
//! - `/contexts/{ctx_id}/body` bare-Body response
//! - `/lineages/{id}` and `/lineages/{id}/current` (round trip + 404)
//! - visibility filtering for restricted contexts
//! - Idempotency-Key replay and collision
//! - list pagination across same-second created_at
//! - webhook absence when disabled
//! - 413 enforcement on `RequestBodyLimitLayer`
//! - playground pinned-key strict/lax/wrong-key paths

#![cfg(feature = "storage-sqlite")]

use std::sync::Arc;

use acdp::crypto::SigningKey;
use acdp::did::WebResolver;
use acdp::producer::Producer;
use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp::types::primitives::{AgentDid, ContextType, Visibility};
use acdp_registry_auth::{
    AuthService, ChallengeStore, InMemoryChallengeStore, JwtSecret, JwtSigner,
};
use acdp_registry_core::{build_router, AppStateInner};
use acdp_registry_sqlite::SqliteStore;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{
    config::PinnedAgentKey, AuthConfig, LimitsConfig, PlaygroundConfig, RegistryConfig,
    RegistrySection, StorageBackend, StorageConfig, WebhookConfig,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const AUTHORITY: &str = "registry.test";

fn caps() -> CapabilitiesDocument {
    CapabilitiesDocument {
        acdp_version: "0.1.0".into(),
        registry_did: format!("did:web:{AUTHORITY}"),
        supported_signature_algorithms: vec!["ed25519".into()],
        supported_did_methods: vec!["did:web".into()],
        profiles: vec!["acdp-registry-core".into()],
        limits: Limits {
            max_payload_bytes: 1_048_576,
            max_embedded_bytes: 65_536,
            idempotency_key_ttl_seconds: Some(86_400),
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

fn config(playground: bool) -> RegistryConfig {
    // Tests expect anonymous reads to surface published public contexts.
    // The new shipped default for `anonymous_public_reads` is `false`
    // (SEC-07 / CLAUDE.md), so opt in explicitly inside the test harness.
    let auth = AuthConfig {
        anonymous_public_reads: true,
        ..AuthConfig::default()
    };
    RegistryConfig {
        registry: RegistrySection {
            authority: AUTHORITY.into(),
            port: 8443,
            bind: "0.0.0.0".into(),
            profiles: vec!["acdp-registry-core".into()],
            tls: Default::default(),
            cross_registry_resolution: true,
            cors: Default::default(),
            base_url: String::new(),
        },
        storage: StorageConfig {
            backend: StorageBackend::Sqlite,
            postgres_url: None,
            sqlite_path: None,
            max_connections: 1,
        },
        auth,
        webhook: WebhookConfig::default(),
        limits: LimitsConfig::default(),
        playground: PlaygroundConfig {
            enabled: playground,
            ..Default::default()
        },
    }
}

/// Per-test handle that keeps the tempfile alive for the duration of
/// the test. The `Router` returned by `harness` shares a single SQLite
/// store across all routes; the tempfile is dropped (and the DB file
/// deleted) when the harness is dropped.
struct Harness {
    router: axum::Router,
    db: tempfile::NamedTempFile,
}

impl Harness {
    /// Path to the backing SQLite file, for tests that need to reach past
    /// the HTTP surface (e.g. ageing an idempotency record to simulate
    /// expiry without sleeping).
    fn db_path(&self) -> &std::path::Path {
        self.db.path()
    }
}

async fn harness(playground: bool) -> Harness {
    harness_from_config(config(playground)).await
}

async fn harness_from_config(cfg: RegistryConfig) -> Harness {
    build_harness(cfg, None).await
}

/// Like [`harness_from_config`] but wires a real `CrossRegistryResolver` so
/// federation (`GET /contexts/:foreign_ctx_id`) is exercised.
async fn harness_with_federation(cfg: RegistryConfig) -> Harness {
    build_harness(
        cfg,
        Some(Arc::new(acdp::client::CrossRegistryResolver::new())),
    )
    .await
}

async fn build_harness(
    cfg: RegistryConfig,
    cross_registry: Option<Arc<acdp::client::CrossRegistryResolver>>,
) -> Harness {
    let db = tempfile::Builder::new()
        .prefix("acdp-test-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let state = AppStateInner::new(server, auth, None, cfg, cross_registry);
    Harness {
        router: build_router(state),
        db,
    }
}

fn producer(seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(format!("did:web:agents.test:smoke-{seed}")),
        format!("did:web:agents.test:smoke-{seed}#key-1"),
    )
}

async fn body_to_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// `acdp://authority/uuid`-style ctx_ids contain `/` and `:`, which axum's
/// single-segment `:ctx_id` route param won't match unless they're percent-
/// encoded by the client. Mirror the encoding rule here (RFC 3986 §2.3).
fn pct_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[tokio::test]
async fn health_returns_ok() {
    let h = harness(true).await;
    let app = &h.router;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn jwks_returns_empty_keys_in_hs256_mode() {
    // Default harness uses HS256 — JWKS is documented to return an empty
    // key set (symmetric secrets are never published).
    let h = harness(true).await;
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some("application/jwk-set+json"),
    );
    let v = body_to_json(resp).await;
    assert_eq!(v["keys"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn jwks_publishes_eddsa_public_key_in_eddsa_mode() {
    // Mint a fresh keypair and build a harness whose signer is EdDSA.
    let db = tempfile::Builder::new()
        .prefix("acdp-test-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());

    // Build a minimal PKCS#8 v1 Ed25519 PEM from a fresh seed.
    let pem = {
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let prefix: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut der = Vec::with_capacity(prefix.len() + 32);
        der.extend_from_slice(&prefix);
        der.extend_from_slice(&sk.to_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )
    };
    let signer = JwtSigner::new_eddsa(
        &pem,
        format!("did:web:{AUTHORITY}"),
        AUTHORITY.into(),
        30,
        None,
    )
    .expect("new_eddsa");
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let state = AppStateInner::new(server, auth, None, config(true), None);
    let router = build_router(state);

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    let keys = v["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    let jwk = &keys[0];
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["alg"], "EdDSA");
    assert_eq!(jwk["use"], "sig");
    assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(jwk["x"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn capabilities_round_trips() {
    let h = harness(true).await;
    let app = &h.router;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/acdp.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // RFC-ACDP-0006 §4.2.1: capabilities are cacheable.
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=300"),
    );
    let v = body_to_json(resp).await;
    assert_eq!(v["acdp_version"], "0.1.0");
    assert_eq!(v["registry_did"], format!("did:web:{AUTHORITY}"));
    assert!(v["supports_idempotency_key"].as_bool().unwrap());
}

async fn publish(
    app: &axum::Router,
    req: &acdp::types::publish::PublishRequest,
    idem: Option<&str>,
) -> (StatusCode, Value) {
    let body = serde_json::to_vec(req).unwrap();
    let mut builder = Request::builder().method("POST").uri("/contexts");
    if let Some(k) = idem {
        builder = builder.header("Idempotency-Key", k);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let v = body_to_json(resp).await;
    (status, v)
}

async fn publish_with_tenant(
    app: &axum::Router,
    req: &acdp::types::publish::PublishRequest,
    tenant: Option<&str>,
) -> (StatusCode, Value) {
    let body = serde_json::to_vec(req).unwrap();
    let mut builder = Request::builder().method("POST").uri("/contexts");
    if let Some(t) = tenant {
        builder = builder.header("X-Tenant-Id", t);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let v = body_to_json(resp).await;
    (status, v)
}

async fn retrieve_with_tenant(
    app: &axum::Router,
    ctx_id: &str,
    tenant: Option<&str>,
) -> StatusCode {
    let mut builder =
        Request::builder().uri(format!("/contexts/{}", pct_encode_path_segment(ctx_id)));
    if let Some(t) = tenant {
        builder = builder.header("X-Tenant-Id", t);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn tenancy_stamp_and_filter_roundtrip() {
    // Publish under X-Tenant-Id=tenant-a; retrieving the same row with
    // X-Tenant-Id=tenant-a → 200, with X-Tenant-Id=tenant-b → 404
    // (same shape as not-found — no oracle that the row exists in a
    // tenant the caller doesn't belong to).
    let h = harness(true).await;
    let req = producer(11)
        .publish_request()
        .title("tenant-a-row")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish_with_tenant(&h.router, &req, Some("tenant-a")).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    // Right tenant → 200.
    assert_eq!(
        retrieve_with_tenant(&h.router, &ctx_id, Some("tenant-a")).await,
        StatusCode::OK,
    );
    // Wrong tenant → 404.
    assert_eq!(
        retrieve_with_tenant(&h.router, &ctx_id, Some("tenant-b")).await,
        StatusCode::NOT_FOUND,
    );
    // No header (V0 backward compatibility) → 200 (no tenant filter).
    assert_eq!(
        retrieve_with_tenant(&h.router, &ctx_id, None).await,
        StatusCode::OK,
    );
}

#[tokio::test]
async fn tenancy_default_when_no_publish_header() {
    // Publish without X-Tenant-Id stamps 'default'; retrieving with
    // X-Tenant-Id=default → 200, with X-Tenant-Id=tenant-a → 404.
    let h = harness(true).await;
    let req = producer(12)
        .publish_request()
        .title("default-tenant-row")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish_with_tenant(&h.router, &req, None).await;
    assert_eq!(status, StatusCode::OK);
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    assert_eq!(
        retrieve_with_tenant(&h.router, &ctx_id, Some("default")).await,
        StatusCode::OK,
    );
    assert_eq!(
        retrieve_with_tenant(&h.router, &ctx_id, Some("tenant-a")).await,
        StatusCode::NOT_FOUND,
    );
}

#[tokio::test]
async fn search_filters_by_tenant() {
    // Publish two rows under different tenants. Search with
    // X-Tenant-Id=tenant-a returns only the tenant-a row; no header
    // returns both; tenant-c returns neither.
    let h = harness(true).await;
    let req_a = producer(13)
        .publish_request()
        .title("alpha-search")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(14)
        .publish_request()
        .title("bravo-search")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish_with_tenant(&h.router, &req_a, Some("tenant-a")).await;
    publish_with_tenant(&h.router, &req_b, Some("tenant-b")).await;

    async fn search_with_tenant(app: &axum::Router, q: &str, tenant: Option<&str>) -> Value {
        let mut builder = Request::builder().uri(format!("/contexts/search?q={q}"));
        if let Some(t) = tenant {
            builder = builder.header("X-Tenant-Id", t);
        }
        let resp = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        body_to_json(resp).await
    }

    // No header → both visible (V0 backward-compat).
    let v = search_with_tenant(&h.router, "search", None).await;
    assert_eq!(v["matches"].as_array().unwrap().len(), 2);

    // tenant-a → only the alpha row.
    let v = search_with_tenant(&h.router, "search", Some("tenant-a")).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["title"], "alpha-search");

    // tenant-c → empty.
    let v = search_with_tenant(&h.router, "search", Some("tenant-c")).await;
    assert_eq!(v["matches"].as_array().unwrap().len(), 0);
}

#[cfg(feature = "playground")]
#[tokio::test]
async fn admin_list_filters_by_tenant() {
    // The playground-mode admin endpoint also honors the tenant header.
    let h = harness(true).await;
    let req_a = producer(15)
        .publish_request()
        .title("admin-alpha")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(16)
        .publish_request()
        .title("admin-bravo")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish_with_tenant(&h.router, &req_a, Some("tenant-a")).await;
    publish_with_tenant(&h.router, &req_b, Some("tenant-b")).await;

    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/contexts")
                .header("X-Tenant-Id", "tenant-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["body"]["title"], "admin-alpha");
}

#[tokio::test]
async fn publish_unverified_then_retrieve() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(1)
        .publish_request()
        .title("hello")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/contexts/{}", pct_encode_path_segment(&ctx_id)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    assert_eq!(v["body"]["title"], "hello");
}

#[tokio::test]
async fn search_returns_published_context() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(2)
        .publish_request()
        .title("findme")
        .summary("the haystack contains a needle")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, _v) = publish(app, &req, None).await;
    assert_eq!(status, StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=findme")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected one match, got {v}");
    assert_eq!(matches[0]["title"], "findme");
}

#[tokio::test]
async fn restricted_context_blocked_for_anonymous() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(3)
        .publish_request()
        .title("secret")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Restricted)
        .audience(vec![AgentDid::new("did:web:agents.test:audience-1")])
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/contexts/{}", pct_encode_path_segment(&ctx_id)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Anonymous reader against restricted context — server-side gate
    // returns NotFound rather than leaking existence.
    assert!(
        matches!(resp.status(), StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
        "unauthorized read should fail, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn idempotency_key_replays_same_response() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(4)
        .publish_request()
        .title("idem")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s1, v1) = publish(app, &req, Some("test-key-1")).await;
    let (s2, v2) = publish(app, &req, Some("test-key-1")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v1["ctx_id"], v2["ctx_id"]);
}

#[tokio::test]
async fn idempotency_key_collision_rejected() {
    let h = harness(true).await;
    let app = &h.router;
    let req_a = producer(5)
        .publish_request()
        .title("first")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(5)
        .publish_request()
        .title("second-different-body")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s1, _) = publish(app, &req_a, Some("collision-key")).await;
    let (s2, _v2) = publish(app, &req_b, Some("collision-key")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::CONFLICT, "expected 409 duplicate_publish");
}

#[tokio::test]
async fn idempotency_key_too_long_rejected() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(6)
        .publish_request()
        .title("len")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let huge = "x".repeat(256);
    let (status, _) = publish(app, &req, Some(&huge)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// REG-P1-2: the idempotency lookup checks `expires_at > now` in Rust (the
/// SQL only matches on `(agent_id, key)`). An expired record must therefore
/// be treated as a fresh publish, not a replay.
#[tokio::test]
async fn expired_idempotency_key_is_not_matched() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(11)
        .publish_request()
        .title("idem-expiry")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s1, v1) = publish(app, &req, Some("expiry-key")).await;
    assert_eq!(s1, StatusCode::OK);

    // Age the stored record so its TTL is in the past — cheaper and more
    // deterministic than sleeping out a real TTL.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", h.db_path().display()))
        .await
        .unwrap();
    let aged = sqlx::query(
        "UPDATE idempotency_records \
         SET expires_at_ms = 0, expires_at = '1970-01-01T00:00:00Z'",
    )
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(aged, 1, "expected exactly one idempotency record to age");
    pool.close().await;

    let (s2, v2) = publish(app, &req, Some("expiry-key")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_ne!(
        v1["ctx_id"], v2["ctx_id"],
        "an expired idempotency key must yield a fresh publish, not a replay"
    );
}

/// REG-P1-2: idempotency records are keyed by `(agent_id, key)` only — NOT
/// subdivided by `X-Tenant-Id`. Safe because tenant-bound tokens (#21) pin an
/// agent to a single tenant, so a key can't legitimately be reused across
/// tenants. This locks the contract: a change to per-tenant idempotency must
/// update both the key and this assertion deliberately.
#[tokio::test]
async fn idempotency_key_is_agent_scoped_not_tenant_scoped() {
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(12)
        .publish_request()
        .title("idem-tenant")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let body = serde_json::to_vec(&req).unwrap();
    let mk = |tenant: &str| {
        Request::builder()
            .method("POST")
            .uri("/contexts")
            .header("Idempotency-Key", "tenant-scope-key")
            .header("X-Tenant-Id", tenant)
            .body(Body::from(body.clone()))
            .unwrap()
    };

    let r1 = app.clone().oneshot(mk("tenant-a")).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let v1 = body_to_json(r1).await;
    let r2 = app.clone().oneshot(mk("tenant-b")).await.unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let v2 = body_to_json(r2).await;
    assert_eq!(
        v1["ctx_id"], v2["ctx_id"],
        "idempotency is (agent,key)-scoped; same key replays regardless of X-Tenant-Id"
    );
}

/// REG-P2-8: a search page whose raw rows are all hidden by the disclosure
/// filter must still advance the cursor (anchored on the last RAW row), so a
/// visible row further down the ordered scan stays reachable via pagination
/// instead of being stranded behind a premature `next_cursor: null`.
#[tokio::test]
async fn search_paginates_past_fully_hidden_pages() {
    let h = harness(true).await;
    let app = &h.router;

    // The only public context is the OLDEST; everything newer is restricted
    // (hidden from an anonymous searcher in-store). Publish the public row
    // first, then sleep so the restricted batch gets strictly-later
    // millisecond-precision `created_at` and sorts ahead of it (DESC).
    let pubreq = producer(30)
        .publish_request()
        .title("visible-oldest")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s, pub_v) = publish(app, &pubreq, None).await;
    assert_eq!(s, StatusCode::OK);
    let public_ctx = pub_v["ctx_id"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    for i in 0..4 {
        let r = producer(31)
            .publish_request()
            .title(format!("hidden-{i}"))
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Restricted)
            .audience(vec![AgentDid::new("did:web:agents.test:nobody")])
            .build()
            .unwrap();
        let (s, _) = publish(app, &r, None).await;
        assert_eq!(s, StatusCode::OK);
    }

    // Anonymous search, small page size; follow the cursor to exhaustion.
    // Page 1 is entirely restricted → matches empty; the OLD code emitted
    // next_cursor=null here and stranded the public row.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let uri = match &cursor {
            Some(c) => format!(
                "/contexts/search?limit=2&cursor={}",
                pct_encode_path_segment(c)
            ),
            None => "/contexts/search?limit=2".to_string(),
        };
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        for m in v["matches"].as_array().unwrap() {
            seen.push(m["ctx_id"].as_str().unwrap().to_string());
        }
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert!(
        seen.contains(&public_ctx),
        "public ctx must be reachable past fully-hidden pages; saw {seen:?}"
    );
    assert_eq!(
        seen.len(),
        1,
        "exactly the one public ctx should surface to anonymous; saw {seen:?}"
    );
}

/// REG-P1-3 / REG-P2-1: per-agent publish limit returns 429 + Retry-After,
/// and the limit is scoped per signing agent.
#[tokio::test]
async fn publish_rate_limited_per_agent_with_retry_after() {
    let mut cfg = config(true);
    cfg.limits.publish_rate_per_minute = 2;
    let h = harness_from_config(cfg).await;
    let app = &h.router;

    async fn send(app: &axum::Router, seed: u8, title: &str) -> axum::response::Response {
        let req = producer(seed)
            .publish_request()
            .title(title)
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        let body = serde_json::to_vec(&req).unwrap();
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/contexts")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    // Agent 20: two publishes within budget, third over budget.
    assert_eq!(send(app, 20, "a").await.status(), StatusCode::OK);
    assert_eq!(send(app, 20, "b").await.status(), StatusCode::OK);
    let limited = send(app, 20, "c").await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry = limited
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("Retry-After header present and numeric");
    assert!(
        (1..=60).contains(&retry),
        "Retry-After out of range: {retry}"
    );
    let v = body_to_json(limited).await;
    assert_eq!(v["error"]["code"], "rate_limited");

    // A different agent is unaffected by agent 20's exhausted budget.
    assert_eq!(send(app, 21, "a").await.status(), StatusCode::OK);
}

/// REG-P2-3: a foreign `ctx_id` pointing at a private/internal IP must be
/// refused by the SSRF policy on the cross-registry resolution path — never
/// fetched. The registry stays healthy, so the gateway-hop failure is a 502.
#[tokio::test]
async fn cross_registry_private_ip_authority_is_blocked() {
    let h = harness_with_federation(config(true)).await;
    let app = &h.router;
    // Authority is an RFC1918 literal; uuid is well-formed so CtxId parses.
    let foreign = "acdp://192.168.1.10/00000000-0000-4000-8000-000000000001";
    let uri = format!("/contexts/{}", pct_encode_path_segment(foreign));
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "SSRF-blocked cross-registry resolution should surface as 502"
    );
    let v = body_to_json(resp).await;
    assert_eq!(
        v["error"]["code"], "cross_registry_resolution_failed",
        "body = {v}"
    );
}

/// REG-P2-5: federation is public-only and opt-in. With cross-registry
/// resolution DISABLED, a foreign `ctx_id` is never proxied — it returns a
/// plain 404 (indistinguishable from a missing local context), so a restricted
/// remote context can't be reached through this registry.
#[tokio::test]
async fn cross_registry_disabled_does_not_proxy_foreign_ctx() {
    // Default harness wires cross_registry = None.
    let h = harness(true).await;
    let app = &h.router;
    let foreign = "acdp://other.example.com/00000000-0000-4000-8000-000000000002";
    let uri = format!("/contexts/{}", pct_encode_path_segment(foreign));
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"]["code"], "not_found", "body = {v}");
}

#[tokio::test]
async fn search_filters_by_schema_uri() {
    let h = harness(true).await;
    let app = &h.router;
    let req_a = producer(7)
        .publish_request()
        .title("schema-a")
        .schema_uri("https://example.com/schemas/a.json")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(7)
        .publish_request()
        .title("schema-b")
        .schema_uri("https://example.com/schemas/b.json")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish(app, &req_a, None).await;
    publish(app, &req_b, None).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?schema_uri=https%3A%2F%2Fexample.com%2Fschemas%2Fa.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one schema match, got {v}"
    );
    assert_eq!(matches[0]["title"], "schema-a");
}

#[tokio::test]
async fn auth_routes_absent_when_disabled() {
    let h = harness(true).await;
    let app = &h.router;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/challenge")
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"agent_id": "did:web:x"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "auth routes should be unmounted when auth.enabled = false"
    );
}

#[tokio::test]
async fn search_visibility_filter_narrows_results() {
    // FEAT-07: ?visibility=public must drop a published-restricted row
    // from the same producer's search results, even though the requester
    // (anonymous in this test) is already gated by the disclosure rules.
    let h = harness(true).await;
    let app = &h.router;
    let req_pub = producer(20)
        .publish_request()
        .title("filterable-public")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_restricted = producer(20)
        .publish_request()
        .title("filterable-restricted")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Restricted)
        .audience(vec![AgentDid::new("did:web:agents.test:audience-x")])
        .build()
        .unwrap();
    publish(app, &req_pub, None).await;
    publish(app, &req_restricted, None).await;

    // Anonymous caller, no visibility filter: only the public row passes
    // disclosure (the restricted one is filtered by the store predicate).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=filterable")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(
        matches.len(),
        1,
        "anonymous disclosure dropped the restricted row"
    );
    assert_eq!(matches[0]["title"], "filterable-public");

    // Same query with ?visibility=public — same result.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=filterable&visibility=public")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);

    // ?visibility=private must yield zero (anonymous can never see private).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=filterable&visibility=private")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    assert_eq!(v["matches"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn health_503_when_storage_pool_closed() {
    // BUG-05: /healthz returns 503 + status "degraded" when the storage
    // health check fails. Realised by closing the SQLite pool out from
    // under the running server.
    let db = tempfile::Builder::new()
        .prefix("acdp-degraded-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    // Close the pool: subsequent health() calls will fail.
    store.pool().close().await;

    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let state = AppStateInner::new(server, auth, None, config(true), None);
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "load balancers gate traffic on 503; degraded must not return 200"
    );
    let v = body_to_json(resp).await;
    assert_eq!(v["status"], "degraded");
    assert_eq!(v["storage"], false);
}

#[tokio::test]
async fn revoke_returns_503_when_revocations_not_configured() {
    // Doc contract on `revoke_token`: 503 when the registry started
    // without a revocation store. Default builds always wire one, so
    // this path needs a custom harness that mounts /auth/* but skips
    // `AuthService::with_revocations`.
    let db = tempfile::Builder::new()
        .prefix("acdp-no-rev-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig {
            enabled: true,
            anonymous_public_reads: true,
            ..AuthConfig::default()
        },
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let mut cfg = config(true);
    cfg.auth.enabled = true;
    let state = AppStateInner::new(server, auth, None, cfg, None);
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/token/revoke")
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"jti": "anything"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "revoke endpoint must signal 503 when the feature isn't wired, not 500"
    );
    let v = body_to_json(resp).await;
    assert_eq!(v["error"]["code"], "service_unavailable");
}

#[tokio::test]
async fn search_and_tokens_intersect() {
    // FTS5 query semantics: `q=foo bar` should match documents that contain
    // BOTH `foo` and `bar`, matching Postgres `plainto_tsquery` behavior.
    let h = harness(true).await;
    let app = &h.router;

    let both = producer(11)
        .publish_request()
        .title("foo bar baz")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let only_foo = producer(11)
        .publish_request()
        .title("foo only here")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish(app, &both, None).await;
    publish(app, &only_foo, None).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=foo%20bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(
        matches.len(),
        1,
        "AND-of-tokens: only the 'foo bar baz' doc should match, got {v}"
    );
    assert_eq!(matches[0]["title"], "foo bar baz");
}

#[tokio::test]
async fn retrieve_body_returns_bare_body() {
    // `/contexts/{ctx_id}/body` returns the producer-signed Body directly
    // (not wrapped in a FullContext envelope). Regression-guards against
    // accidentally serving FullContext from the body route, which would
    // leak registry_state and inflate the response.
    let h = harness(true).await;
    let app = &h.router;
    let req = producer(31)
        .publish_request()
        .title("body-target")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .summary("body only")
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/contexts/{}/body",
                    pct_encode_path_segment(&ctx_id)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    assert_eq!(v["title"], "body-target");
    assert_eq!(v["summary"], "body only");
    assert_eq!(v["ctx_id"], ctx_id);
    assert!(
        v.get("registry_state").is_none(),
        "/body must return the bare Body, not a FullContext envelope: {v}"
    );
}

#[tokio::test]
async fn lineage_round_trip_lists_versions_and_returns_current() {
    // Publish v1 → publish v2 superseding v1 → GET /lineages/{id} returns
    // both versions; GET /lineages/{id}/current returns v2. Exercises the
    // two lineage HTTP routes end-to-end, which had no direct coverage.
    let h = harness(true).await;
    let app = &h.router;
    let p = producer(40);

    let v1_req = p
        .publish_request()
        .title("v1")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &v1_req, None).await;
    assert_eq!(status, StatusCode::OK, "v1 publish body = {v}");
    let v1_ctx_id = v["ctx_id"].as_str().unwrap().to_string();
    let lineage_id = v["lineage_id"].as_str().unwrap().to_string();

    // Fetch v1 body and chain v2 from it — `supersede_body` propagates
    // version + expected_lineage_id, matching what a real producer does.
    let v1_body_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/contexts/{}/body",
                    pct_encode_path_segment(&v1_ctx_id)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v1_body_json = body_to_json(v1_body_resp).await;
    let v1_body: acdp::types::body::Body = serde_json::from_value(v1_body_json).unwrap();

    let v2_req = p
        .supersede_body(&v1_body)
        .title("v2")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &v2_req, None).await;
    assert_eq!(status, StatusCode::OK, "v2 publish body = {v}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/lineages/{}",
                    pct_encode_path_segment(&lineage_id)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let items = body_to_json(resp).await;
    let arr = items.as_array().expect("lineage returns array");
    assert_eq!(arr.len(), 2, "expected 2 versions, got {items}");
    let titles: Vec<&str> = arr
        .iter()
        .map(|i| i["body"]["title"].as_str().unwrap())
        .collect();
    assert!(
        titles.contains(&"v1") && titles.contains(&"v2"),
        "got {titles:?}"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/lineages/{}/current",
                    pct_encode_path_segment(&lineage_id)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cur = body_to_json(resp).await;
    assert_eq!(cur["body"]["title"], "v2");
    assert_eq!(cur["body"]["version"], 2);
}

#[tokio::test]
async fn lineage_unknown_id_returns_404() {
    let h = harness(true).await;
    let app = &h.router;
    // /current is the route that returns 404 on a missing lineage (the
    // bare /lineages/{id} returns an empty array). Pick a syntactically
    // valid lineage id with no matching row.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/lineages/{}/current",
                    pct_encode_path_segment("acdp://registry.test/no-such-lineage")
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"]["code"], "not_found");
}

#[tokio::test]
async fn publish_payload_above_limit_rejected() {
    // The router applies a uniform `RequestBodyLimitLayer` driven by
    // `limits.max_payload_bytes`. Build a harness with a tiny cap and
    // verify the layer rejects an over-sized POST with 413 — including
    // for non-publish routes that share the same limit.
    let db = tempfile::Builder::new()
        .prefix("acdp-payload-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let mut cfg = config(true);
    cfg.limits.max_payload_bytes = 1024;
    let state = AppStateInner::new(server, auth, None, cfg, None);
    let app = build_router(state);

    let big = vec![b'x'; 4096];
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/contexts")
                .header("Content-Type", "application/json")
                .body(Body::from(big))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "publish payload above limit must return 413, not 400/500"
    );
}

#[tokio::test]
async fn playground_strict_mode_rejects_unknown_agent() {
    // SEC-08: pinned_only=true forbids any agent_did not in pinned_keys.
    // Reaches the same enforcement path the unit tests cover, but through
    // the real router so the error envelope shape is exercised too.
    let known = SigningKey::from_bytes(&[7u8; 32]);
    let known_did = "did:web:agents.test:smoke-pinned";
    let known_pub_b64 = B64.encode(known.verifying_key_bytes());

    let unknown_producer = producer(8);

    let h = harness_with_playground(PlaygroundConfig {
        enabled: true,
        pinned_keys: vec![PinnedAgentKey {
            agent_did: known_did.into(),
            public_key_b64: known_pub_b64,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        }],
        pinned_only: true,
    })
    .await;
    let app = &h.router;

    let req = unknown_producer
        .publish_request()
        .title("nope")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "strict pinned_only must 403 for unknown agents, got {v}"
    );
    assert_eq!(v["error"]["code"], "key_not_authorized");
}

#[tokio::test]
async fn playground_pinned_agent_with_matching_key_publishes() {
    // Positive case: a pinned agent publishes with the correct key — the
    // Ed25519 verifier accepts and the row lands in storage. Confirms the
    // happy-path wire integration of `enforce_pinned_signature`.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let did = "did:web:agents.test:smoke-pinned-ok";
    let pub_b64 = B64.encode(key.verifying_key_bytes());
    let p = Producer::new(key, AgentDid::new(did), format!("{did}#key-1"));

    let h = harness_with_playground(PlaygroundConfig {
        enabled: true,
        pinned_keys: vec![PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        }],
        pinned_only: true,
    })
    .await;
    let app = &h.router;

    let req = p
        .publish_request()
        .title("pinned-ok")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "pinned publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    // Retrieve to confirm the row actually persisted, not just that the
    // response 200'd.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/contexts/{}", pct_encode_path_segment(&ctx_id)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn playground_pinned_agent_with_wrong_key_rejected() {
    // Negative case: a pinned agent publishes with a *different* signing
    // key than the one pinned in config. The verifier MUST reject — this
    // is the whole reason pinned_keys exists.
    let real_key = SigningKey::from_bytes(&[10u8; 32]);
    let did = "did:web:agents.test:smoke-pinned-bad";
    let p = Producer::new(real_key, AgentDid::new(did), format!("{did}#key-1"));

    // Pin a *different* key — verification must fail.
    let other = SigningKey::from_bytes(&[11u8; 32]);
    let other_pub_b64 = B64.encode(other.verifying_key_bytes());

    let h = harness_with_playground(PlaygroundConfig {
        enabled: true,
        pinned_keys: vec![PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: other_pub_b64,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        }],
        pinned_only: false,
    })
    .await;
    let app = &h.router;

    let req = p
        .publish_request()
        .title("wrong-key")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(app, &req, None).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "pinned agent signing with a non-pinned key must be rejected, got 200 with {v}"
    );
}

/// Build a harness with a fully-specified PlaygroundConfig so tests can
/// inject pinned_keys / pinned_only. The default `harness(playground)`
/// helper only flips the `enabled` flag, which isn't enough for the
/// pinned-signature suite.
async fn harness_with_playground(playground: PlaygroundConfig) -> Harness {
    let db = tempfile::Builder::new()
        .prefix("acdp-pin-")
        .suffix(".sqlite")
        .tempfile()
        .unwrap();
    let store = SqliteStore::connect(db.path(), 1).await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let mut cfg = config(true);
    cfg.playground = playground;
    let state = AppStateInner::new(server, auth, None, cfg, None);
    Harness {
        router: build_router(state),
        db,
    }
}
