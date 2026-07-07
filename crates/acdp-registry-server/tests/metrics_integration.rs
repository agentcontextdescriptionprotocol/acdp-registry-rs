//! FEAT-10: Prometheus `/metrics` integration tests.
//!
//! These run in their own test binary (separate process) so the
//! process-global `metrics` recorder is isolated from other integration
//! tests. All assertions live in a single `#[tokio::test]` so accumulated
//! counter values are deterministic within the process.

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
    AuthConfig, LimitsConfig, MetricsConfig, PlaygroundConfig, RateLimitConfig, RegistryConfig,
    RegistrySection, StorageBackend, StorageConfig, WebhookConfig,
};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use std::net::SocketAddr;
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
            max_publish_per_minute: None,
        },
        read_authentication_methods: vec![],
        anonymous_public_reads: true,
        supports_idempotency_key: true,
        extensions: Default::default(),
    }
}

fn metrics_config() -> RegistryConfig {
    let auth = AuthConfig {
        enabled: true,
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
            cross_registry_resolution: false,
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
        limits: LimitsConfig {
            // Disable the per-agent challenge limiter; the per-IP limiter is
            // what we drive to prove rate-limit rejections are counted.
            challenge_rate_per_minute: 0,
            ..LimitsConfig::default()
        },
        rate_limit: RateLimitConfig {
            enabled: true,
            per_ip_per_minute: 1,
            global_per_minute: 0,
            trusted_proxies: vec![],
        },
        metrics: MetricsConfig {
            enabled: true,
            bearer_token: String::new(),
            ..MetricsConfig::default()
        },
        playground: PlaygroundConfig {
            enabled: true,
            ..Default::default()
        },
        receipt: Default::default(),
        lifecycle: Default::default(),
        log: Default::default(),
        witnesses: Vec::new(),
    }
}

struct Harness {
    router: axum::Router,
    _db: tempfile::NamedTempFile,
}

async fn harness(cfg: RegistryConfig) -> Harness {
    let db = tempfile::Builder::new()
        .prefix("acdp-metrics-")
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
    let state = AppStateInner::new(server, auth, None, cfg, None);
    Harness {
        router: build_router(state),
        _db: db,
    }
}

fn producer(seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(format!("did:web:agents.test:m-{seed}")),
        format!("did:web:agents.test:m-{seed}#key-1"),
    )
}

async fn publish(app: &axum::Router, req: &acdp::types::publish::PublishRequest) -> StatusCode {
    let body = serde_json::to_vec(req).unwrap();
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
        .status()
}

async fn scrape(app: &axum::Router) -> (StatusCode, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, ct, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Sum the values of every exposition line whose series contains all of
/// `needles` (metric name + label fragments).
fn metric_sum(text: &str, needles: &[&str]) -> f64 {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| needles.iter().all(|n| l.contains(n)))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.parse::<f64>().ok())
        .sum()
}

#[tokio::test]
async fn metrics_endpoint_exposes_request_and_domain_series() {
    let h = harness(metrics_config()).await;

    // Two accepted publishes.
    for seed in [10u8, 11u8] {
        let req = producer(seed)
            .publish_request()
            .title("m")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .unwrap();
        assert_eq!(publish(&h.router, &req).await, StatusCode::OK);
    }

    // A malformed publish → schema_violation outcome.
    let bad = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/contexts")
                .body(Body::from("{ not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Drive the per-IP limiter to a rejection: per_ip_per_minute = 1, so the
    // second challenge from one IP is 429.
    let chal = |xff_ip: &str| {
        let addr: SocketAddr = format!("{xff_ip}:5000").parse().unwrap();
        let mut req = Request::builder()
            .method("POST")
            .uri("/auth/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"agent_id": "did:web:agents.test:flooder"}).to_string(),
            ))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    };
    assert_eq!(
        h.router
            .clone()
            .oneshot(chal("203.0.113.7"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        h.router
            .clone()
            .oneshot(chal("203.0.113.7"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // Scrape.
    let (status, ct, text) = scrape(&h.router).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ct.starts_with("text/plain") && ct.contains("version=0.0.4"),
        "unexpected content-type: {ct}"
    );

    // Request-level metrics exist and carry the MATCHED route pattern
    // (`/contexts`), never a resolved ctx_id.
    assert!(
        text.contains("acdp_registry_request_total"),
        "missing request counter:\n{text}"
    );
    assert!(
        text.contains("acdp_registry_request_duration_seconds"),
        "missing request histogram"
    );
    assert!(
        metric_sum(
            &text,
            &["acdp_registry_request_total", "route=\"/contexts\""]
        ) >= 3.0,
        "expected >=3 /contexts requests counted"
    );

    // Domain counters.
    assert_eq!(
        metric_sum(
            &text,
            &["acdp_registry_publish_total", "outcome=\"inserted\""]
        ),
        2.0,
        "two accepted publishes\n{text}"
    );
    assert_eq!(
        metric_sum(
            &text,
            &[
                "acdp_registry_publish_total",
                "outcome=\"schema_violation\""
            ]
        ),
        1.0,
        "one malformed publish"
    );
    assert_eq!(
        metric_sum(
            &text,
            &[
                "acdp_registry_rate_limit_rejections_total",
                "scope=\"auth_per_ip\""
            ]
        ),
        1.0,
        "one per-IP rejection counted"
    );
}

#[tokio::test]
async fn metrics_absent_when_disabled() {
    let mut cfg = metrics_config();
    cfg.metrics.enabled = false;
    let h = harness(cfg).await;
    let (status, _, _) = scrape(&h.router).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/metrics must 404 when disabled"
    );
}

#[tokio::test]
async fn metrics_bearer_gate_enforced() {
    let mut cfg = metrics_config();
    cfg.metrics.bearer_token = "scrape-secret".into();
    let h = harness(cfg).await;

    // No token → 401.
    let (status, _, _) = scrape(&h.router).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Correct token → 200.
    let resp = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .header("authorization", "Bearer scrape-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
