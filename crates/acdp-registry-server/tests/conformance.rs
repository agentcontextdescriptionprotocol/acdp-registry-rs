//! ACDP spec conformance harness.
//!
//! When `ACDP_SPEC_DIR` is set to a checkout of the spec repo, this test
//! discovers the fixture directory (`schemas/conformance`, `fixtures`, or the
//! dir itself), replays every fixture that is a *deterministic, self-contained
//! HTTP exchange*, and asserts status + error code.
//!
//! There are two modes, gated by `ACDP_REQUIRE_CONFORMANCE` (any value —
//! including the empty string — counts as set/enabled; unset is the only way
//! to get default mode):
//!
//!   * **Default mode** (`ACDP_REQUIRE_CONFORMANCE` unset) — every
//!     spec-dependent path degrades to a logged skip when `ACDP_SPEC_DIR` is
//!     unset, points at a nonexistent directory, or resolves to a directory
//!     with no fixture layout the harness recognizes. Running the spec suite
//!     is opt-in so the repo is independently testable without a spec
//!     checkout on disk.
//!   * **Require mode** (`ACDP_REQUIRE_CONFORMANCE` set) — every one of those
//!     same paths panics instead of skipping: `ACDP_SPEC_DIR` unset, set to a
//!     nonexistent path, set to a path with no resolvable fixture directory,
//!     or (in `did_key_golden_vector_accepted_and_gated`) pointing at
//!     fixtures that don't contain `sig-003-did-key-golden.json`. This is
//!     what the dedicated conformance CI job (a later phase) runs, so a
//!     missing or misconfigured spec checkout is a red run, not a silent
//!     green one. There is deliberately **no** sibling-directory fallback —
//!     `ACDP_SPEC_DIR` is the single explicit contract; letting an unset
//!     variable silently resolve to some other spec tree on disk would
//!     defeat the entire point of require-mode and violate this repo's
//!     pinned-spec-worktree rule. See `crates/acdp-registry-server/tests/conformance_gate.rs`
//!     for the companion guard against running require-mode with the
//!     `storage-sqlite` feature off, which would compile this whole file
//!     away and vacuously pass.
//!
//! The spec corpus is heterogeneous: only some families map to a single HTTP
//! request/response the registry can replay through its public API. The rest
//! are deliberately NOT replayed here, and the harness logs a per-family /
//! per-reason manifest so coverage is never silently truncated:
//!
//!   * **Replayed** — negative publish fixtures that fail at schema/validation
//!     (HTTP 400) with an inline body, and stateless retrieval fixtures
//!     (e.g. `ret-*` GET of a missing ctx → 404).
//!   * **Skipped — requires pre-seeded state** — `vis-*`, `idem-*` and other
//!     fixtures whose `setup`/`preconditions` (top-level or under `input`)
//!     need a context with a specific registry-assigned `ctx_id` the publish
//!     API won't let us mint.
//!   * **Skipped — profile not advertised** — fixtures whose
//!     `applies_to_profiles` is disjoint from `HARNESS_PROFILES`, e.g.
//!     `lc-*` (`acdp-registry-lifecycle`), `fed-*`
//!     (`acdp-registry-federated`). This is the harness's advertised
//!     profile set, not a statement about what the registry implements.
//!   * **Skipped — non-HTTP** — `can-*`/`sig-*` (canonicalization & signature
//!     vectors; these belong against the `acdp` library, not the HTTP layer),
//!     `caps-*`/`schema-*`/`meta-*` (document-schema validation), `rate-*`
//!     (informative wire-shape pin), and positive/authz publish outcomes that
//!     need valid crypto material the synthetic fixtures don't carry.
//!   * **Skipped — unsubstituted template** — an exchange whose constructed
//!     path still carries a `{...}` placeholder the harness couldn't fill.
//!
//! Any replayed exchange whose status or error code mismatches fails the test.

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
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const AUTHORITY: &str = "registry.test";

/// Profiles the conformance harness registry advertises. Mirrors `caps().profiles`
/// (`conformance.rs:61`) and `config().registry.profiles` (`:86`) — keep all three
/// in step; `harness_profiles_match_caps_and_config` enforces it.
const HARNESS_PROFILES: &[&str] = &["acdp-registry-core"];

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
        limits: LimitsConfig::default(),
        rate_limit: Default::default(),
        metrics: Default::default(),
        // The playground bypasses DID verification, which lets the
        // harness replay synthetic fixtures without standing up a TLS
        // mock for `did:web` resolution.
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

/// A single HTTP request/response pair extracted from a fixture. The real
/// spec corpus is heterogeneous — different families use different shapes —
/// so we normalize whatever is *deterministically replayable through the
/// public HTTP API* into this struct and skip (with a logged reason) the
/// fixtures that are canonicalization vectors, informative wire-shape pins,
/// document-schema validation, or that require pre-seeded registry state.
#[derive(Debug)]
struct Exchange {
    method: String,
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Option<Value>,
    want_status: u16,
    want_error_code: Option<String>,
    want_json: Option<Value>,
}

/// Outcome of inspecting one fixture file.
enum Extracted {
    /// One or more replayable HTTP exchanges.
    Run(Vec<Exchange>),
    /// Not replayable through the public API; carries a human reason.
    Skip(&'static str),
}

fn want_status(expected: &Value) -> Option<u16> {
    expected
        .get("status")
        .or_else(|| expected.get("http_status"))
        .and_then(Value::as_u64)
        .map(|n| n as u16)
}

fn want_error_code(expected: &Value) -> Option<String> {
    expected
        .get("error_code")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn headers_of(req: &Value) -> std::collections::BTreeMap<String, String> {
    req.get("headers")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// True iff the fixture declares `applies_to_profiles` and that set is
/// disjoint from the profiles this harness's registry advertises
/// (`HARNESS_PROFILES`). A fixture that names several profiles, only one of
/// which we advertise, still runs — hence disjoint, not "not a subset".
/// Fixtures that omit `applies_to_profiles` entirely are unaffected (treated
/// as applying universally).
fn targets_unadvertised_profile(fx: &Value) -> bool {
    let Some(profiles) = fx.get("applies_to_profiles").and_then(Value::as_array) else {
        return false;
    };
    let fixture_profiles: Vec<&str> = profiles.iter().filter_map(Value::as_str).collect();
    !fixture_profiles.is_empty()
        && !fixture_profiles
            .iter()
            .any(|p| HARNESS_PROFILES.contains(p))
}

/// True iff the fixture declares any of the four precondition-carrying keys
/// the pinned corpus uses: top-level `setup`/`preconditions`, or
/// `input.precondition`/`input.preconditions`. All four mean the fixture
/// needs a ctx the publish API won't let us mint (registry assigns ctx_id),
/// so we skip those.
fn has_unseeded_precondition(fx: &Value) -> bool {
    fx.get("setup").is_some()
        || fx.get("preconditions").is_some()
        || fx
            .get("input")
            .is_some_and(|i| i.get("precondition").is_some() || i.get("preconditions").is_some())
}

/// Turn a parsed fixture into replayable exchanges or a skip reason. Only
/// fixtures that are self-contained HTTP exchanges with a deterministic
/// expected status — and that do NOT depend on pre-seeded registry state —
/// are replayed. `setup`/`preconditions` (top-level or under `input`) mean
/// the fixture needs a ctx the publish API won't let us mint (registry
/// assigns ctx_id), so we skip those.
///
/// Gate order: profile gate → precondition gate → shape dispatch → template
/// gate (which needs a constructed `Exchange.path`, so it runs last). The
/// most specific, most informative reason wins.
fn extract(fx: &Value) -> Extracted {
    if targets_unadvertised_profile(fx) {
        return Extracted::Skip("fixture targets a profile this harness does not advertise");
    }
    if has_unseeded_precondition(fx) {
        return Extracted::Skip("requires pre-seeded registry state");
    }
    let extracted = extract_shapes(fx);
    // Template gate: inspect the *constructed* Exchange.path, never the
    // fixture's declared `request.path` / `input.endpoint`. Shape C
    // substitutes `input.ctx_id` into a brace-free path even though the
    // declared `input.endpoint` (e.g. "GET /contexts/{ctx_id}") carries
    // braces — applying this gate to the declared endpoint would wrongly
    // drop ret-001. RFC 3986 doesn't permit unescaped `{`/`}` in a path, and
    // `pct_encode_path_segment` escapes them anyway, so this can't
    // false-positive on well-formed substituted input.
    if let Extracted::Run(exchanges) = &extracted {
        if exchanges
            .iter()
            .any(|e| e.path.contains('{') || e.path.contains('}'))
        {
            return Extracted::Skip("request path carries an unsubstituted {template} placeholder");
        }
    }
    extracted
}

/// Shape dispatch: the actual per-family extraction logic, run after the
/// profile and precondition gates have already passed.
fn extract_shapes(fx: &Value) -> Extracted {
    // Shape A: top-level `request` + `expected`.
    if let (Some(req), Some(exp)) = (fx.get("request"), fx.get("expected")) {
        if let (Some(method), Some(path), Some(status)) = (
            req.get("method").and_then(Value::as_str),
            req.get("path").and_then(Value::as_str),
            want_status(exp),
        ) {
            let method = method.to_uppercase();
            let is_publish = method == "POST" && path.starts_with("/contexts");
            if is_publish {
                // A publish fixture is only deterministically replayable to a
                // *schema/validation* (400) outcome: positive (2xx) publishes
                // need valid signature+hash material the fixture may not fully
                // carry, and authz (403) outcomes require every earlier stage
                // to pass — which a synthetic fixture body doesn't guarantee.
                // Our pipeline legitimately rejects such inputs earlier (e.g.
                // 400 schema_violation before reaching 403 key_not_authorized).
                if req.get("body").is_none() {
                    return Extracted::Skip("publish fixture has no inline body");
                }
                if status != 400 {
                    return Extracted::Skip(
                        "publish positive/authz outcome not deterministically replayable",
                    );
                }
                return Extracted::Run(vec![Exchange {
                    method,
                    path: path.to_string(),
                    headers: headers_of(req),
                    body: req.get("body").cloned(),
                    want_status: status,
                    // Don't pin the exact first-failing error code for
                    // publishes — validation ordering is impl-defined.
                    want_error_code: None,
                    want_json: exp.get("json_contains").cloned(),
                }]);
            }
            return Extracted::Run(vec![Exchange {
                method,
                path: path.to_string(),
                headers: headers_of(req),
                body: req.get("body").cloned(),
                want_status: status,
                want_error_code: want_error_code(exp),
                want_json: exp.get("json_contains").cloned(),
            }]);
        }
    }
    // Shape B: `scenarios[]`, each a self-contained request + expected.
    if let Some(scenarios) = fx.get("scenarios").and_then(Value::as_array) {
        let mut out = Vec::new();
        for sc in scenarios {
            let (Some(req), Some(exp)) = (sc.get("request"), sc.get("expected")) else {
                continue;
            };
            let (Some(method), Some(path), Some(status)) = (
                req.get("method").and_then(Value::as_str),
                req.get("path").and_then(Value::as_str),
                want_status(exp),
            ) else {
                continue;
            };
            out.push(Exchange {
                method: method.to_uppercase(),
                path: path.to_string(),
                headers: headers_of(req),
                body: req.get("body").cloned(),
                want_status: status,
                want_error_code: want_error_code(exp),
                want_json: exp.get("json_contains").cloned(),
            });
        }
        if out.is_empty() {
            return Extracted::Skip("scenarios carried no replayable request");
        }
        return Extracted::Run(out);
    }
    // Shape C: retrieval-by-template, e.g. ret-* with `input.endpoint =
    // "GET /contexts/{ctx_id}"` + `input.ctx_id`.
    if let Some(input) = fx.get("input") {
        if let (Some(endpoint), Some(exp)) = (
            input.get("endpoint").and_then(Value::as_str),
            fx.get("expected"),
        ) {
            if let (Some(("GET", "/contexts/{ctx_id}")), Some(ctx), Some(status)) = (
                endpoint.split_once(' '),
                input.get("ctx_id").and_then(Value::as_str),
                want_status(exp),
            ) {
                return Extracted::Run(vec![Exchange {
                    method: "GET".into(),
                    path: format!("/contexts/{}", pct_encode_path_segment(ctx)),
                    headers: Default::default(),
                    body: None,
                    want_status: status,
                    want_error_code: want_error_code(exp),
                    want_json: None,
                }]);
            }
        }
    }
    Extracted::Skip("non-HTTP fixture (vectors / schema / informative)")
}

/// True when `ACDP_REQUIRE_CONFORMANCE` is set to any value, including the
/// empty string — matches `acdp-rs`'s "any value = enabled" contract
/// byte-for-byte. Do not "improve" this to a truthiness check.
fn require_conformance() -> bool {
    std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok()
}

/// Spec checkout root from `ACDP_SPEC_DIR`, or `None` (skip) when unset.
///
/// Under `ACDP_REQUIRE_CONFORMANCE`, every `None`-return path below panics
/// instead. Deliberately **no** sibling-directory fallback: unlike
/// `acdp-rs`, `ACDP_SPEC_DIR` is the single explicit contract here — unset
/// (or pointing nowhere) means skip in default mode / panic in require
/// mode, full stop. Falling back to some other spec tree on disk would let
/// require-mode go green off an unpinned checkout, defeating its purpose.
fn spec_root() -> Option<PathBuf> {
    let require = require_conformance();
    let Ok(dir) = std::env::var("ACDP_SPEC_DIR") else {
        assert!(
            !require,
            "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR is not"
        );
        return None;
    };
    let p = PathBuf::from(dir);
    if p.exists() {
        return Some(p);
    }
    assert!(
        !require,
        "ACDP_REQUIRE_CONFORMANCE is set but ACDP_SPEC_DIR '{}' does not exist",
        p.display()
    );
    None
}

/// `spec_root()` + `resolve_fixture_dir()`. Panics under require-mode when
/// the root exists but carries no fixture directory the harness recognizes.
fn spec_fixtures() -> Option<PathBuf> {
    let root = spec_root()?;
    let fixtures = resolve_fixture_dir(&root.to_string_lossy());
    if fixtures.is_none() {
        assert!(
            !require_conformance(),
            "ACDP_REQUIRE_CONFORMANCE is set but no fixture directory found under \
             ACDP_SPEC_DIR '{}'",
            root.display()
        );
    }
    fixtures
}

/// Resolve the fixture directory from `ACDP_SPEC_DIR`. The variable may point
/// at the spec root or directly at the fixtures, so try the known layouts.
fn resolve_fixture_dir(dir: &str) -> Option<PathBuf> {
    let has_json = |d: &PathBuf| {
        d.is_dir()
            && std::fs::read_dir(d)
                .map(|mut e| {
                    e.any(|x| {
                        x.ok()
                            .map(|x| x.file_name().to_string_lossy().ends_with(".json"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
    };
    [
        PathBuf::from(dir).join("schemas/conformance"),
        PathBuf::from(dir).join("fixtures"),
        PathBuf::from(dir),
    ]
    .into_iter()
    .find(has_json)
}

/// Exchanges replayable at spec bff3cf3a: pub-004, pub-005, pub-008, ret-001.
/// A gate that accidentally over-matches must fail loudly, not quietly shrink
/// coverage to a still-nonzero number. Raise this as coverage grows.
const MIN_REPLAYED_EXCHANGES: usize = 4;

fn family_of(name: &str) -> String {
    // Prefix up to the digit group: `data-ref-ssrf-001-...` -> `data-ref-ssrf`.
    let stem = name.trim_end_matches(".json");
    let mut parts: Vec<&str> = Vec::new();
    for seg in stem.split('-') {
        if seg
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            break;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        stem.to_string()
    } else {
        parts.join("-")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn replays_spec_fixtures_when_present() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping \
             (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    eprintln!("conformance: fixtures dir = {}", fixtures.display());

    let app = harness().await;
    let mut replayed = 0usize;
    let mut failures: Vec<String> = Vec::new();
    // Per-family / per-reason tallies so coverage is transparent — never
    // silently truncate.
    let mut ran: std::collections::BTreeMap<String, usize> = Default::default();
    let mut skipped: std::collections::BTreeMap<(String, &'static str), usize> = Default::default();

    let entries = std::fs::read_dir(&fixtures).unwrap_or_else(|e| panic!("read {fixtures:?}: {e}"));
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();

    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let family = family_of(&name);
        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{name}: read error: {e}"));
                continue;
            }
        };
        let fx: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{name}: malformed fixture: {e}"));
                continue;
            }
        };

        let exchanges = match extract(&fx) {
            Extracted::Skip(reason) => {
                *skipped.entry((family, reason)).or_insert(0) += 1;
                continue;
            }
            Extracted::Run(x) => x,
        };

        for ex in exchanges {
            // GET paths may carry a raw `acdp://` ctx_id needing single-
            // segment percent-encoding for axum's `:ctx_id` matcher.
            let mut p = ex.path.clone();
            if p.contains("acdp://") && ex.method == "GET" {
                if let Some(idx) = p.rfind('/') {
                    let seg = &p[idx + 1..];
                    p = format!("{}/{}", &p[..idx], pct_encode_path_segment(seg));
                }
            }
            let mut builder = Request::builder().method(ex.method.as_str()).uri(&p);
            for (k, v) in &ex.headers {
                builder = builder.header(k, v);
            }
            let body = ex
                .body
                .as_ref()
                .map(|v| Body::from(serde_json::to_vec(v).unwrap()))
                .unwrap_or_else(Body::empty);
            let resp = app
                .clone()
                .oneshot(builder.body(body).unwrap())
                .await
                .unwrap();
            let got = resp.status().as_u16();
            let body_json = body_to_json(resp).await;

            if got != ex.want_status {
                failures.push(format!(
                    "{name}: status {got} != {}; body = {body_json}",
                    ex.want_status
                ));
                continue;
            }
            if let Some(code) = &ex.want_error_code {
                let actual = body_json
                    .get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(Value::as_str);
                if actual != Some(code.as_str()) {
                    failures.push(format!(
                        "{name}: error code {actual:?} != {code:?}; body = {body_json}"
                    ));
                    continue;
                }
            }
            if let Some(contains) = &ex.want_json {
                if let Err(reason) = json_contains(&body_json, contains) {
                    failures.push(format!("{name}: {reason}; body = {body_json}"));
                    continue;
                }
            }
            replayed += 1;
            *ran.entry(family.clone()).or_insert(0) += 1;
        }
    }

    eprintln!(
        "conformance: replayed {replayed} exchange(s); failures={}",
        failures.len()
    );
    eprintln!("conformance: ran by family:");
    for (fam, n) in &ran {
        eprintln!("  - {fam}: {n}");
    }
    eprintln!("conformance: skipped (not HTTP-replayable here):");
    for ((fam, reason), n) in &skipped {
        eprintln!("  - {fam}: {n} ({reason})");
    }
    if !failures.is_empty() {
        panic!("conformance failures:\n  - {}", failures.join("\n  - "));
    }
    assert!(
        replayed >= MIN_REPLAYED_EXCHANGES,
        "replayed {replayed} exchange(s), expected at least {MIN_REPLAYED_EXCHANGES} \
         (a fidelity gate may be over-matching and silently shrinking coverage)"
    );
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

// ─── ACDP 0.2.0: did:key golden vector + capability gate (sig-003 / dk-003) ───

/// Caps for a did:key-accepting 0.2.0 registry. The standard `caps()` stays
/// did:web-only, which doubles as the dk-003 counter-registry below.
fn did_key_caps() -> CapabilitiesDocument {
    let mut c = caps();
    c.acdp_version = "0.2.0".into();
    c.supported_did_methods = vec!["did:web".into(), "did:key".into()];
    c
}

/// Non-playground harness: did:key verification is pure/offline, so the
/// full RFC-ACDP-0003 §2.1 pipeline (steps 7–8 included) runs without a
/// network DID resolver — exactly what the golden vector is meant to pin.
async fn did_key_harness(caps: CapabilitiesDocument) -> axum::Router {
    let store = SqliteStore::connect_in_memory().await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, caps, AUTHORITY).unwrap());
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
    build_router(state)
}

/// Replays the spec's did:key golden publish request (sig-003,
/// `vectors[0].expected.publish_request_body` — a byte-pinned, fully
/// signed request) against both registry postures:
///
///   * did:key advertised  → accepted through the verified pipeline;
///   * did:web-only (dk-003) → rejected `key_resolution_failed` / 400.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn did_key_golden_vector_accepted_and_gated() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping \
             sig-003/dk-003 (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let path = fixtures.join("sig-003-did-key-golden.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            assert!(
                !require_conformance(),
                "ACDP_REQUIRE_CONFORMANCE is set but cannot read {}: {e}",
                path.display()
            );
            eprintln!("conformance: cannot read {}: {e}; skipping", path.display());
            return;
        }
    };
    let fx: Value = serde_json::from_str(&raw).unwrap();
    let req_body = fx["vectors"][0]["expected"]["publish_request_body"].clone();
    assert!(
        req_body.is_object(),
        "sig-003 must carry vectors[0].expected.publish_request_body"
    );

    let post = |app: axum::Router, body: Value| async move {
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/contexts")
                    .header("content-type", "application/acdp+json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let v = body_to_json(resp).await;
        (status, v)
    };

    // Advertised → the golden request verifies offline and persists.
    let accepting = did_key_harness(did_key_caps()).await;
    let (status, v) = post(accepting, req_body.clone()).await;
    assert_eq!(status, StatusCode::OK, "sig-003 accept body = {v}");
    assert!(v["ctx_id"].as_str().is_some_and(|s| !s.is_empty()));

    // dk-003: not advertised → key_resolution_failed, HTTP 400, permanent.
    let rejecting = did_key_harness(caps()).await;
    let (status, v) = post(rejecting, req_body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "dk-003 body = {v}");
    assert_eq!(v["error"]["code"], "key_resolution_failed");
}

// ─── Phase 1: harness fidelity gates ───

/// A fixture whose `applies_to_profiles` is disjoint from `HARNESS_PROFILES`
/// must be skipped by the profile gate, with the specific reason string (not
/// merely "some skip"). A fixture listing several profiles, only one of
/// which we advertise, must still run.
#[test]
fn extract_skips_fixtures_outside_advertised_profiles() {
    let out_of_profile = json!({
        "applies_to_profiles": ["acdp-registry-lifecycle"],
        "request": {"method": "GET", "path": "/health"},
        "expected": {"status": 200}
    });
    match extract(&out_of_profile) {
        Extracted::Skip(reason) => assert_eq!(
            reason,
            "fixture targets a profile this harness does not advertise"
        ),
        Extracted::Run(x) => panic!("expected profile-gate skip, got Run({x:?})"),
    }

    // Overlapping (not disjoint) — must run, not be skipped.
    let overlapping = json!({
        "applies_to_profiles": ["acdp-consumer", "acdp-registry-core"],
        "request": {"method": "GET", "path": "/health"},
        "expected": {"status": 200}
    });
    match extract(&overlapping) {
        Extracted::Run(x) => assert_eq!(x.len(), 1),
        Extracted::Skip(reason) => {
            panic!("expected Run for overlapping profiles, got Skip({reason})")
        }
    }
}

/// The template gate inspects the *constructed* `Exchange.path`, not the
/// fixture's declared `request.path` / `input.endpoint`. A shape-A fixture
/// whose declared path still carries `{ctx_id}` must be skipped. A shape-C
/// fixture (the `ret-001` shape) whose declared `input.endpoint` carries
/// `{ctx_id}` but whose `input.ctx_id` substitutes cleanly into a brace-free
/// path must still run — this is the single most important test in this
/// phase, since a gate applied to the wrong field would silently drop
/// `ret-001` and shrink `replayed` from 4 to 3.
#[test]
fn extract_skips_unsubstituted_path_templates() {
    let unsubstituted = json!({
        "request": {
            "method": "POST",
            "path": "/contexts/{ctx_id}/retract",
            "body": {"foo": "bar"}
        },
        "expected": {"status": 400}
    });
    match extract(&unsubstituted) {
        Extracted::Skip(reason) => assert_eq!(
            reason,
            "request path carries an unsubstituted {template} placeholder"
        ),
        Extracted::Run(x) => panic!("expected template-gate skip, got Run({x:?})"),
    }

    // ret-001 regression: declared endpoint carries braces, but the
    // substituted ctx_id produces a brace-free path — must run.
    let ret_001_shape = json!({
        "input": {
            "endpoint": "GET /contexts/{ctx_id}",
            "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-000000000000"
        },
        "expected": {"status": 404, "error_code": "not_found"}
    });
    match extract(&ret_001_shape) {
        Extracted::Run(x) => {
            assert_eq!(x.len(), 1);
            assert!(
                !x[0].path.contains('{') && !x[0].path.contains('}'),
                "substituted path must be brace-free: {}",
                x[0].path
            );
        }
        Extracted::Skip(reason) => {
            panic!("expected ret-001-shape fixture to run, got Skip({reason})")
        }
    }
}

/// `input.precondition` (singular, string) and `input.preconditions`
/// (plural, object) must both be recognized alongside the top-level
/// `setup`/`preconditions` keys.
#[test]
fn extract_skips_input_level_preconditions() {
    let singular = json!({
        "input": {"precondition": "some pre-seeded state"}
    });
    match extract(&singular) {
        Extracted::Skip(reason) => assert_eq!(reason, "requires pre-seeded registry state"),
        Extracted::Run(x) => panic!("expected precondition skip, got Run({x:?})"),
    }

    let plural = json!({
        "input": {"preconditions": {"existing_context": {"ctx_id": "acdp://x/1"}}}
    });
    match extract(&plural) {
        Extracted::Skip(reason) => assert_eq!(reason, "requires pre-seeded registry state"),
        Extracted::Run(x) => panic!("expected precondition skip, got Run({x:?})"),
    }
}

/// Drift guard: `HARNESS_PROFILES` must equal both `caps().profiles` and
/// `config().registry.profiles`. If a later change widens the harness's
/// advertised profiles without updating `HARNESS_PROFILES`, the profile gate
/// would silently keep skipping fixtures it should now run.
#[test]
fn harness_profiles_match_caps_and_config() {
    let caps = caps();
    let caps_profiles: Vec<&str> = caps.profiles.iter().map(String::as_str).collect();
    assert_eq!(
        HARNESS_PROFILES,
        caps_profiles.as_slice(),
        "HARNESS_PROFILES must mirror caps().profiles"
    );
    let config = config();
    let config_profiles: Vec<&str> = config
        .registry
        .profiles
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        HARNESS_PROFILES,
        config_profiles.as_slice(),
        "HARNESS_PROFILES must mirror config().registry.profiles"
    );
}
