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
use acdp::{AnchorEntry, ContentHash};
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
        // Mirror the binary: both algorithms the registry actually verifies.
        supported_signature_algorithms: vec!["ed25519".into(), "ecdsa-p256".into()],
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
        rate_limit: Default::default(),
        metrics: Default::default(),
        playground: PlaygroundConfig {
            enabled: playground,
            ..Default::default()
        },
        receipt: Default::default(),
        lifecycle: Default::default(),
        log: Default::default(),
        witnesses: Vec::new(),
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
    harness_with_caps(playground, url, caps()).await
}

/// REG-3 Phase 5 (plans/reg3-anchors.md): 0.5.0 capabilities document —
/// the §10 half of the anchors version gate. Mirrors `http_integration.rs`'s
/// `caps_050()`.
fn caps_050() -> CapabilitiesDocument {
    let mut c = caps();
    c.acdp_version = "0.5.0".into();
    c
}

/// Like [`harness`] but with a caller-supplied capabilities document — used
/// by the anchors round-trip tests to reach `acdp_version >= 0.5.0` on the
/// registry-advertised side of the gate.
async fn harness_with_caps(
    playground: bool,
    url: &str,
    caps: CapabilitiesDocument,
) -> axum::Router {
    let store = PgStore::connect(url, 4).await.unwrap();
    store.migrate().await.unwrap();
    // Reach into the underlying pool to truncate via a fresh connection.
    let pool = sqlx::PgPool::connect(url).await.unwrap();
    truncate(&pool).await;
    pool.close().await;

    let server = Arc::new(RegistryServer::try_new(store, caps, AUTHORITY).unwrap());
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

/// Playground-on, 0.5.0-advertising harness — the §10 half of the REG-3
/// anchors version gate. Mirrors `http_integration.rs`'s `harness_050`.
async fn harness_050(playground: bool, url: &str) -> axum::Router {
    harness_with_caps(playground, url, caps_050()).await
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
/// `{ctx_id}` single-segment route param won't match without percent
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

// ─── ACDP 0.2.0: receipt atomicity + concurrent idempotency stress (Postgres) ───

/// D4 stress (Postgres): N concurrent publishes sharing one
/// (agent_id, Idempotency-Key) must yield exactly ONE persisted context;
/// the losers replay the winner's response. Unlike the in-process SQLite
/// variant, this runs against a real multi-connection Postgres pool, so
/// the racers genuinely interleave inside the ON CONFLICT claim gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn pg_concurrent_duplicate_publishes_yield_one_context() {
    use acdp::registry::store::{
        PendingIdempotencyCommit, PublishCommit, PublishCommitOutcome, RegistryStore,
    };

    let Some(url) = pg_url_or_skip() else { return };
    let store = PgStore::connect(&url, 8).await.unwrap();
    store.migrate().await.unwrap();
    truncate(store.pool()).await;
    let store = Arc::new(store);

    let p = Producer::new(
        SigningKey::from_bytes(&[71u8; 32]),
        AgentDid::new("did:web:agents.test:pg-race".to_string()),
        "did:web:agents.test:pg-race#key-1".to_string(),
    );
    let req = p
        .publish_request()
        .title("pg-race")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let req = req.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            store.commit_publish(PublishCommit {
                req: &req,
                authority: AUTHORITY,
                idempotency: Some(PendingIdempotencyCommit {
                    key: "pg-race-key",
                    ttl: chrono::Duration::hours(1),
                }),
                tenant: None,
                receipt_minter: None,
            })
        }));
    }
    let mut inserted = 0usize;
    let mut ctx_ids = std::collections::HashSet::new();
    for h in handles {
        let outcome = h.await.unwrap().expect("every racer resolves cleanly");
        match outcome {
            PublishCommitOutcome::Inserted(r) => {
                inserted += 1;
                ctx_ids.insert(r.ctx_id.as_str().to_string());
            }
            PublishCommitOutcome::IdempotentReplay(r) => {
                ctx_ids.insert(r.ctx_id.as_str().to_string());
            }
        }
    }
    assert_eq!(inserted, 1, "exactly one racer inserts");
    assert_eq!(ctx_ids.len(), 1, "all racers resolve to the same ctx_id");

    let page = store.list_contexts(100, None, None, None).await.unwrap();
    assert_eq!(page.items.len(), 1, "one context row persisted");
}

/// RFC-ACDP-0010 §7 on Postgres: the receipt is minted inside the commit
/// transaction and round-trips through the publish response and `get`;
/// a failing minter aborts the whole publish (no row, no idempotency
/// record).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn pg_receipt_atomicity_and_round_trip() {
    use acdp::registry::store::{
        PendingIdempotencyCommit, PublishCommit, PublishCommitOutcome, RegistryStore,
    };

    let Some(url) = pg_url_or_skip() else { return };
    let store = PgStore::connect(&url, 4).await.unwrap();
    store.migrate().await.unwrap();
    truncate(store.pool()).await;
    let store = Arc::new(store);

    let p = Producer::new(
        SigningKey::from_bytes(&[72u8; 32]),
        AgentDid::new("did:web:agents.test:pg-rcpt".to_string()),
        "did:web:agents.test:pg-rcpt#key-1".to_string(),
    );

    // 1. Failing minter → nothing persists.
    let doomed = p
        .publish_request()
        .title("pg-rcpt-doomed")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let failing = |_: &acdp::types::body::Body| {
        Err(acdp::error::AcdpError::RegistryInternal(
            "simulated KMS outage".into(),
        ))
    };
    let s = store.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        s.commit_publish(PublishCommit {
            req: &doomed,
            authority: AUTHORITY,
            idempotency: Some(PendingIdempotencyCommit {
                key: "pg-mintfail",
                ttl: chrono::Duration::hours(1),
            }),
            tenant: None,
            receipt_minter: Some(&failing),
        })
    })
    .await
    .unwrap();
    assert!(outcome.is_err(), "minting failure fails the publish");
    let page = store.list_contexts(100, None, None, None).await.unwrap();
    assert!(page.items.is_empty(), "no row survives a failed mint");
    assert_eq!(store.count_idempotency_records().await.unwrap(), Some(0));

    // 2. Working minter → receipt rides the row and round-trips on get().
    let req = p
        .publish_request()
        .title("pg-rcpt-ok")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let minter = |body: &acdp::types::body::Body| {
        Ok(json!({
            "ctx_id": body.ctx_id.as_str(),
            "lineage_id": body.lineage_id.as_str(),
        }))
    };
    let s = store.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        s.commit_publish(PublishCommit {
            req: &req,
            authority: AUTHORITY,
            idempotency: None,
            tenant: None,
            receipt_minter: Some(&minter),
        })
    })
    .await
    .unwrap()
    .expect("publish ok");
    let response = match outcome {
        PublishCommitOutcome::Inserted(r) => r,
        other => panic!("expected Inserted, got {other:?}"),
    };
    let receipt = response
        .registry_receipt
        .clone()
        .expect("response carries the minted receipt");
    assert_eq!(receipt["ctx_id"], response.ctx_id.as_str());

    let s = store.clone();
    let ctx_id = response.ctx_id.clone();
    let fetched = tokio::task::spawn_blocking(move || s.get(&ctx_id))
        .await
        .unwrap()
        .unwrap()
        .expect("context exists");
    assert_eq!(fetched.registry_receipt, Some(receipt));
}

// ─── REG-3 Phase 5: byte-exact round-trip (Postgres) ───
//
// `plans/reg3-anchors.md` Phase 5: mirrors `http_integration.rs`'s sqlite
// leg exactly, against `PgStore`. **Mandatory, not optional** — the plan is
// explicit that this is the phase's real risk: sqlite stores the body as
// `TEXT` (`serde_json::to_string`), Postgres as `JSONB`
// (`serde_json::to_value`), and JSONB is a normalizing representation
// (number re-rendering, key dedup/reorder) where TEXT is not. That
// asymmetry is already latent for every arbitrary-JSON field this repo
// stores (`metadata`, and now `AnchorEntry.extensions`) and has apparently
// never been pinned by a cross-backend byte-exactness test before this.

async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let v = body_to_json(resp).await;
    (status, v)
}

/// Two anchors: the first mirrors anc-001's shape
/// (spec schemas/conformance/anc-001-well-formed-anchor.json, not present
/// in this repo) but adds a `uri` and a flattened extension key
/// (`AnchorEntry.extensions`) so Postgres's JSONB normalization has real
/// surface to bite on; the second has a different scheme/hash and no
/// optional fields, so array ORDER is meaningfully exercised (acceptance
/// criterion 3). anc-001's anchor `content_hash` literal is reused only for
/// shape — an arbitrary-but-valid external digest, unrelated to this
/// request's own freshly computed top-level `content_hash` (anc-001's own
/// placeholders are NOT replayed; see its `input.notes`).
fn anchors_for_round_trip() -> Vec<AnchorEntry> {
    let mut ext = serde_json::Map::new();
    ext.insert("commitment_id".into(), json!("cmt-782"));
    ext.insert("sealed_amount".into(), json!(478231));
    // Numeric-normalization probe: `1e-7` is a value Postgres's `jsonb`
    // type is known to re-render differently (in text form) from what
    // `serde_json` produces — unlike the plain positive integer above,
    // which round-trips through JSONB unchanged either way. Without this,
    // the round-trip proof only demonstrates field *presence*, not
    // resilience to JSONB's number normalization, which is the actual risk
    // this phase is about.
    ext.insert("normalization_probe".into(), json!(1e-7));
    let first = AnchorEntry {
        scheme: "macp.commitment".to_string(),
        content_hash: ContentHash::parse(
            "sha256:fa8fe6b9143b469866d31de09b81928cc44d226ed935162cd346ae80d14fd200",
        )
        .unwrap(),
        uri: Some("https://example.test/commitments/782".to_string()),
        extensions: ext,
    };
    let second = AnchorEntry {
        // Deliberately sorts BEFORE `first.scheme` ("macp.commitment")
        // alphabetically, so a "helpful" ascending sort by `scheme` (or by
        // the first serialized field) is not a no-op on this fixture and
        // would actually change the served order — which
        // `pg_anchors_two_entries_preserve_order` below would then catch.
        scheme: "aaa.artifact".to_string(),
        content_hash: ContentHash::parse(format!("sha256:{}", "9".repeat(64))).unwrap(),
        uri: None,
        extensions: Default::default(),
    };
    vec![first, second]
}

fn assert_anchors_round_trip_byte_exact(
    label: &str,
    served_body: &Value,
    sent_anchors: &[AnchorEntry],
    expected_content_hash: &ContentHash,
) {
    let sent_anchors_json = serde_json::to_value(sent_anchors).unwrap();
    assert_eq!(
        served_body["anchors"], sent_anchors_json,
        "{label}: served anchors must be order-preserving deep-equal (raw JSON) to what was sent"
    );
    let served_anchors: Vec<AnchorEntry> =
        serde_json::from_value(served_body["anchors"].clone()).unwrap();
    assert_eq!(
        &served_anchors, sent_anchors,
        "{label}: served anchors must be deep-equal on the typed struct too"
    );

    // The assertion that actually proves byte-exactness (not PartialEq on a
    // deserialized struct, which the plan explicitly rejects as
    // insufficient): recompute content_hash over the served body — read
    // back from Postgres's JSONB column — and confirm it reproduces the
    // content_hash that was actually published.
    let recomputed = acdp::crypto::compute_content_hash(served_body).unwrap();
    assert_eq!(
        &recomputed, expected_content_hash,
        "{label}: compute_content_hash over the served (Postgres-JSONB-round-tripped) body \
         must reproduce the published content_hash"
    );
}

/// Acceptance criteria 2 + 3 (Postgres) + the mandatory Postgres leg of
/// criterion 4's mutation check. Identical assertions to
/// `http_integration.rs`'s `anchors_round_trip_byte_exact_sqlite`, run
/// against `PgStore` — proving the sqlite leg's green result isn't hiding a
/// JSONB-specific normalization divergence.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_anchors_round_trip_byte_exact() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness_050(true, &url).await;

    let anchors = anchors_for_round_trip();
    let req = producer(230)
        .publish_request()
        .title("pg anchors byte-exact round trip")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .acdp_version("0.5.0")
        .anchors(anchors.clone())
        .build()
        .unwrap();
    let (status, v) = publish(&app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let (status, full) = get_json(
        &app,
        &format!("/contexts/{}", pct_encode_path_segment(&ctx_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{full}");
    let served_full_body = full["body"].clone();

    let (status, bare) = get_json(
        &app,
        &format!("/contexts/{}/body", pct_encode_path_segment(&ctx_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bare}");

    assert_anchors_round_trip_byte_exact(
        "pg: GET /contexts/{ctx_id} (nested body)",
        &served_full_body,
        &anchors,
        &req.content_hash,
    );
    assert_anchors_round_trip_byte_exact(
        "pg: GET /contexts/{ctx_id}/body (bare)",
        &bare,
        &anchors,
        &req.content_hash,
    );

    // ── Live mutation check (criterion 4), Postgres leg ──
    // Simulate `anchors` being dropped from the served (JSONB-round-tripped)
    // value and confirm the hash-recompute assertion actually goes RED —
    // otherwise this Postgres leg would not be measuring byte-exactness at
    // all, only that JSON deserialization succeeds.
    let mut mutated = served_full_body.clone();
    mutated
        .as_object_mut()
        .expect("served body is a JSON object")
        .remove("anchors");
    let mutated_hash = acdp::crypto::compute_content_hash(&mutated).unwrap();
    assert_ne!(
        &mutated_hash, &req.content_hash,
        "pg mutation check: dropping anchors from the served body must change the recomputed \
         hash — if it doesn't, the round-trip assertion above is not exercising anchors"
    );
}

/// Acceptance criterion 3, isolated: a two-anchor body preserves array
/// ORDER specifically across a fresh publish -> retrieve, independent of
/// the byte-exactness assertions above — reordering changes the JCS
/// preimage (and therefore the recomputed hash), which is exactly what
/// `pg_anchors_round_trip_byte_exact` already proves; this test pins the
/// order check on its own so a future refactor of that combined test can't
/// silently drop order coverage.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pg_anchors_two_entries_preserve_order() {
    let Some(url) = pg_url_or_skip() else { return };
    let app = harness_050(true, &url).await;

    let anchors = anchors_for_round_trip();
    assert_eq!(anchors[0].scheme, "macp.commitment");
    assert_eq!(anchors[1].scheme, "aaa.artifact");

    let req = producer(231)
        .publish_request()
        .title("pg anchors order preserved")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .acdp_version("0.5.0")
        .anchors(anchors.clone())
        .build()
        .unwrap();
    let (status, v) = publish(&app, &req, None).await;
    assert_eq!(status, StatusCode::OK, "publish body = {v}");
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    let (status, bare) = get_json(
        &app,
        &format!("/contexts/{}/body", pct_encode_path_segment(&ctx_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bare}");
    let served = bare["anchors"].as_array().expect("anchors array served");
    assert_eq!(served.len(), 2, "both anchors served");
    assert_eq!(
        served[0]["scheme"], "macp.commitment",
        "first anchor must stay first (order-sensitive, not a set)"
    );
    assert_eq!(
        served[1]["scheme"], "aaa.artifact",
        "second anchor must stay second — a 'helpful' sort would silently reorder this \
         (its scheme sorts alphabetically BEFORE the first anchor's, so an ascending sort \
         would actually move it and get caught here)"
    );
}
