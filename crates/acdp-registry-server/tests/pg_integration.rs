//! Postgres-backed integration tests.
//!
//! Mirrors `tests/http_integration.rs` but against `PgStore`. Each test
//! starts by truncating the registry tables — so the suite is gated on
//! `#[serial_test::serial]` to avoid races, and the whole file is gated
//! on the `storage-pg` Cargo feature. When `ACDP_REGISTRY_TEST_PG_URL`
//! is unset, every test prints a skip line and returns success so the
//! suite is a no-op in environments without Postgres.
//!
//! Run locally:
//! ```bash
//! docker run --rm -d --name acdp-test-pg -p 5433:5432 \
//!   -e POSTGRES_USER=acdp -e POSTGRES_PASSWORD=acdp -e POSTGRES_DB=acdp_registry \
//!   postgres:16-alpine
//! ACDP_REGISTRY_TEST_PG_URL=postgres://acdp:acdp@localhost:5433/acdp_registry \
//!   cargo test -p acdp-registry-server --no-default-features --features storage-pg \
//!   --test pg_integration
//! ```

#![cfg(feature = "storage-pg")]

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
use acdp_registry_pg::PgStore;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{
    AuthConfig, LimitsConfig, PlaygroundConfig, RegistryConfig, RegistrySection, StorageBackend,
    StorageConfig, WebhookConfig,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use serial_test::serial;
use tower::ServiceExt;

const AUTHORITY: &str = "registry.test";

fn pg_url_or_skip() -> Option<String> {
    match std::env::var("ACDP_REGISTRY_TEST_PG_URL") {
        Ok(u) => Some(u),
        Err(_) => {
            eprintln!("ACDP_REGISTRY_TEST_PG_URL unset; skipping pg integration");
            None
        }
    }
}

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
    let auth = AuthConfig {
        anonymous_public_reads: true,
        ..AuthConfig::default()
    };
    RegistryConfig {
        registry: RegistrySection {
            authority: AUTHORITY.into(),
            port: 8443,
            bind: "0.0.0.0".into(),
            allow_public_bind: false,
            profiles: vec!["acdp-registry-core".into()],
            tls: Default::default(),
            cross_registry_resolution: true,
            cors: Default::default(),
            base_url: String::new(),
        },
        storage: StorageConfig {
            backend: StorageBackend::Postgres,
            postgres_url: None,
            sqlite_path: None,
            max_connections: 4,
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

/// Wipe registry state so every test starts from a clean slate. The
/// migrations are idempotent (`CREATE TABLE IF NOT EXISTS`), so running
/// `migrate()` per test is cheap. We TRUNCATE rather than drop/recreate
/// the database to avoid needing CREATEDB privileges.
async fn truncate(pool: &sqlx::PgPool) {
    // `IF EXISTS` guards against the very first run on a fresh DB,
    // where the migrator might race with the truncate.
    sqlx::query(
        "DO $$
         BEGIN
           IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'contexts') THEN
             TRUNCATE TABLE contexts, lineages, idempotency_records, auth_challenges
             RESTART IDENTITY CASCADE;
           END IF;
         END $$;",
    )
    .execute(pool)
    .await
    .expect("truncate");
}

async fn harness(playground: bool, url: &str) -> axum::Router {
    let store = PgStore::connect(url, 4).await.unwrap();
    store.migrate().await.unwrap();
    // Reach into the underlying pool to truncate via a fresh connection.
    let pool = sqlx::PgPool::connect(url).await.unwrap();
    truncate(&pool).await;
    pool.close().await;

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
    let state = AppStateInner::new(server, auth, None, config(playground), None);
    build_router(state)
}

fn producer(seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(format!("did:web:agents.test:pg-{seed}")),
        format!("did:web:agents.test:pg-{seed}#key-1"),
    )
}

async fn body_to_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// `acdp://authority/uuid` ctx_ids contain `/` and `:`, which axum's
/// `:ctx_id` single-segment route param won't match without percent
/// encoding. Mirror RFC 3986 §2.3.
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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_health_returns_ok() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let resp = app
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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_capabilities_round_trips() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/acdp.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_json(resp).await;
    assert_eq!(v["acdp_version"], "0.1.0");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_publish_then_retrieve() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req = producer(1)
        .publish_request()
        .title("pg-hello")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, v) = publish(&app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let resp = app
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
    assert_eq!(v["body"]["title"], "pg-hello");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_search_returns_published_context() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req = producer(2)
        .publish_request()
        .title("findme-pg")
        .summary("haystack with needle")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish(&app, &req, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/contexts/search?q=findme-pg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(resp).await;
    let matches = v["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1, "expected one match, got {v}");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_restricted_context_blocked_for_anonymous() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req = producer(3)
        .publish_request()
        .title("pg-secret")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Restricted)
        .audience(vec![AgentDid::new("did:web:agents.test:audience-1")])
        .build()
        .unwrap();
    let (status, v) = publish(&app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/contexts/{}", pct_encode_path_segment(&ctx_id)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        matches!(resp.status(), StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
        "unauthorized read should fail, got {}",
        resp.status()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_idempotency_replays_same_response() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req = producer(4)
        .publish_request()
        .title("pg-idem")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s1, v1) = publish(&app, &req, Some("pg-key-1")).await;
    let (s2, v2) = publish(&app, &req, Some("pg-key-1")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v1["ctx_id"], v2["ctx_id"]);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_idempotency_collision_rejected() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req_a = producer(5)
        .publish_request()
        .title("pg-first")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(5)
        .publish_request()
        .title("pg-second-different-body")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (s1, _) = publish(&app, &req_a, Some("pg-collision-key")).await;
    let (s2, _) = publish(&app, &req_b, Some("pg-collision-key")).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_search_filters_by_schema_uri() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let req_a = producer(7)
        .publish_request()
        .title("pg-schema-a")
        .schema_uri("https://example.com/schemas/a.json")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_b = producer(7)
        .publish_request()
        .title("pg-schema-b")
        .schema_uri("https://example.com/schemas/b.json")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    publish(&app, &req_a, None).await;
    publish(&app, &req_b, None).await;

    let resp = app
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
    assert_eq!(matches[0]["title"], "pg-schema-a");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_auth_routes_absent_when_disabled() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
    let resp = app
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
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_search_and_tokens_intersect() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness(true, &url).await;
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
    publish(&app, &both, None).await;
    publish(&app, &only_foo, None).await;

    let resp = app
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
        "Postgres plainto_tsquery should AND tokens; got {v}"
    );
    assert_eq!(matches[0]["title"], "foo bar baz");
}
