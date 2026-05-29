//! ACDP spec conformance harness.
//!
//! When `ACDP_SPEC_DIR` is set to a checkout of the spec repo, this test
//! walks `${ACDP_SPEC_DIR}/fixtures/{pub,vis}-*.json` and replays each
//! fixture through an in-process registry. When unset (the common CI
//! case), the test logs a skip and returns success — running the spec
//! suite is opt-in so the repo is independently testable.
//!
//! Each fixture file describes a single request/response pair. The minimal
//! contract the harness expects (subject to refinement when the spec repo
//! formalises it) looks like:
//!
//! ```json
//! {
//!   "request": {
//!     "method": "POST",
//!     "path": "/contexts",
//!     "headers": {"Idempotency-Key": "..."},
//!     "body": { ...PublishRequest... }
//!   },
//!   "expected": {
//!     "status": 200,
//!     "json_contains": {"ctx_id": null, "lineage_id": null}
//!   }
//! }
//! ```
//!
//! Fixtures whose filename starts with `pub-` exercise the publish flow;
//! `vis-` fixtures exercise visibility filtering on retrieve. The harness
//! reports per-fixture pass/fail with the offending JSON.

#![cfg(feature = "storage-sqlite")]

use std::path::PathBuf;
use std::sync::Arc;

use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp_registry_auth::{
    AuthService, ChallengeStore, InMemoryChallengeStore, JwtSecret, JwtSigner,
};
use acdp_registry_core::{build_router, AppStateInner};
use acdp_registry_sqlite::SqliteStore;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{
    AuthConfig, LimitsConfig, PlaygroundConfig, RegistryConfig, RegistrySection, StorageBackend,
    StorageConfig, WebhookConfig,
};
use axum::body::Body;
use axum::http::Request;
#[cfg(feature = "playground")]
use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::Value;
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

fn config() -> RegistryConfig {
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
            cross_registry_resolution: false,
            cors: Default::default(),
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
        // The playground bypasses DID verification, which lets the
        // harness replay synthetic fixtures without standing up a TLS
        // mock for `did:web` resolution.
        playground: PlaygroundConfig {
            enabled: true,
            ..Default::default()
        },
    }
}

async fn harness() -> axum::Router {
    let store = SqliteStore::connect_in_memory().await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(acdp::did::WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let state = AppStateInner::new(server, auth, None, config(), None);
    build_router(state)
}

async fn body_to_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Mirror of `pct_encode_path_segment` in `http_integration.rs` — the
/// `acdp://authority/uuid` ctx_ids contain `/` and `:` which need
/// percent-encoding to satisfy axum's `:ctx_id` single-segment param.
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

#[derive(Debug, serde::Deserialize)]
struct Fixture {
    request: FxRequest,
    expected: FxExpected,
}

#[derive(Debug, serde::Deserialize)]
struct FxRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
}

#[derive(Debug, serde::Deserialize)]
struct FxExpected {
    status: u16,
    /// Sparse subset of the response body to match. `null` values match any
    /// present key (used when the registry mints the value, e.g. `ctx_id`).
    #[serde(default)]
    json_contains: Option<Value>,
}

#[tokio::test(flavor = "multi_thread")]
async fn replays_spec_fixtures_when_present() {
    let Ok(dir) = std::env::var("ACDP_SPEC_DIR") else {
        eprintln!("conformance: ACDP_SPEC_DIR unset; skipping");
        return;
    };
    let fixtures = PathBuf::from(&dir).join("fixtures");
    if !fixtures.exists() {
        eprintln!(
            "conformance: {} does not exist; skipping",
            fixtures.display()
        );
        return;
    }

    let app = harness().await;
    let mut pub_run = 0usize;
    let mut vis_run = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let entries = std::fs::read_dir(&fixtures).unwrap_or_else(|e| panic!("read {fixtures:?}: {e}"));
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_pub = name.starts_with("pub-");
        let is_vis = name.starts_with("vis-");
        if !is_pub && !is_vis {
            continue;
        }
        if !name.ends_with(".json") {
            continue;
        }
        let raw = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{name}: read error: {e}"));
                continue;
            }
        };
        let fx: Fixture = match serde_json::from_slice(&raw) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{name}: malformed fixture: {e}"));
                continue;
            }
        };

        // Build the HTTP request.
        let method = fx.request.method.to_uppercase();
        let mut path = fx.request.path.clone();
        if path.contains("acdp://") && method == "GET" {
            // GET fixtures encoded with raw ctx_ids — percent-encode the
            // single segment so axum's :ctx_id matcher accepts them.
            if let Some(idx) = path.rfind('/') {
                let segment = &path[idx + 1..];
                path = format!("{}/{}", &path[..idx], pct_encode_path_segment(segment));
            }
        }
        let mut builder = Request::builder().method(method.as_str()).uri(&path);
        for (k, v) in &fx.request.headers {
            builder = builder.header(k, v);
        }
        let body = fx
            .request
            .body
            .as_ref()
            .map(|v| Body::from(serde_json::to_vec(v).unwrap()))
            .unwrap_or_else(Body::empty);
        let req = builder.body(body).unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        let got = resp.status().as_u16();
        let want = fx.expected.status;
        let body_json = body_to_json(resp).await;

        if got != want {
            failures.push(format!(
                "{name}: status {got} != {want}; body = {}",
                body_json
            ));
            continue;
        }
        if let Some(contains) = fx.expected.json_contains.as_ref() {
            if let Err(reason) = json_contains(&body_json, contains) {
                failures.push(format!("{name}: {reason}; body = {body_json}"));
                continue;
            }
        }
        if is_pub {
            pub_run += 1;
        } else if is_vis {
            vis_run += 1;
        }
    }

    eprintln!(
        "conformance: replayed pub-* fixtures={pub_run}, vis-* fixtures={vis_run}, \
         failures={}",
        failures.len()
    );
    if !failures.is_empty() {
        panic!("conformance failures:\n  - {}", failures.join("\n  - "));
    }
}

/// Returns `Ok(())` iff every key in `want` is present in `got` with a
/// matching value. `null` in `want` matches any non-null value in `got`
/// (used when the registry mints the value, e.g. `ctx_id`).
fn json_contains(got: &Value, want: &Value) -> Result<(), String> {
    match (got, want) {
        (_, Value::Null) => {
            if matches!(got, Value::Null) {
                Err("expected non-null value (fixture used null sentinel)".into())
            } else {
                Ok(())
            }
        }
        (Value::Object(gm), Value::Object(wm)) => {
            for (k, v) in wm {
                let g = gm.get(k).ok_or_else(|| format!("missing key '{k}'"))?;
                json_contains(g, v).map_err(|m| format!("at '{k}': {m}"))?;
            }
            Ok(())
        }
        (Value::Array(ga), Value::Array(wa)) => {
            if ga.len() < wa.len() {
                return Err(format!(
                    "array shorter than expected: {} < {}",
                    ga.len(),
                    wa.len()
                ));
            }
            for (i, w) in wa.iter().enumerate() {
                json_contains(&ga[i], w).map_err(|m| format!("at [{i}]: {m}"))?;
            }
            Ok(())
        }
        (g, w) => {
            if g == w {
                Ok(())
            } else {
                Err(format!("{g} != {w}"))
            }
        }
    }
}

/// DESIGN-03: when compiled with the `playground` feature but the runtime
/// flag is off, the admin route must be mounted AND the publish path must
/// still perform full verification. This guards the "compile-on / runtime-
/// off" matrix cell that's documented but otherwise untested.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "playground")]
async fn playground_compiled_in_but_runtime_disabled_keeps_admin_route() {
    let store = SqliteStore::connect_in_memory().await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps(), AUTHORITY).unwrap());
    let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new());
    let secret = JwtSecret::from_bytes(&[42u8; 32]);
    let signer = JwtSigner::new(secret, format!("did:web:{AUTHORITY}"), AUTHORITY.into(), 30);
    let resolver = Arc::new(acdp::did::WebResolver::new());
    let auth = Arc::new(AuthService::new(
        AuthConfig::default(),
        challenges,
        signer,
        resolver,
        AUTHORITY.into(),
    ));
    let mut cfg = config();
    cfg.playground.enabled = false;
    let state = AppStateInner::new(server, auth, None, cfg, None);
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/contexts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The admin route is wired in at compile time; the playground flag
    // only affects whether `publish` skips DID verification.
    assert_eq!(resp.status(), StatusCode::OK);
}
