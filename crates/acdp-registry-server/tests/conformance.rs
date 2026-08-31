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
//!     what the dedicated `conformance` CI job runs (see
//!     `.github/workflows/ci.yml`), so a missing or misconfigured spec
//!     checkout is a red run, not a silent green one. There is deliberately **no** sibling-directory fallback —
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
//!
//! ## Coverage ratchet (`KNOWN_FAMILIES` / `EXCUSED`)
//!
//! `KNOWN_FAMILIES` is the honest claim "we have looked at every fixture
//! family the pinned spec declares" — all 29 keys of `registries/
//! profiles.json`'s `fixture_families` object, each with fixtures on disk,
//! each classified by the manifest above as replayed or skipped-with-reason.
//! `all_conformance_fixtures_are_bucketed_into_known_families` is the ratchet
//! itself: a 30th family (new fixture id prefix the spec adds later) fails
//! the build until a human looks at it and adds it here.
//!
//! `EXCUSED` is a strict subset of `KNOWN_FAMILIES` naming the families this
//! repo asserts don't need HTTP-replay coverage at all, each with a prose
//! reason. An excuse is legitimate only when **both** hold:
//!
//!   1. **Spec-grounded** — no fixture in the family appears in
//!      `registries/profiles.json`'s `acdp-registry-core` profile's
//!      `required_fixtures`, nor anywhere in its `conditional_fixtures`
//!      (fixtures required whenever this repo's advertised capabilities
//!      satisfy the entry's condition — e.g. `dk-*` when `did:key` is
//!      advertised, `idem-*` when idempotency-key support is advertised).
//!      If the spec requires the family of the profile this repo
//!      advertises — unconditionally or conditionally — it cannot be
//!      excused, full stop — no amount of "obviously a pure library vector"
//!      overrides this.
//!   2. **Structural** — every fixture in the family is either a pure golden
//!      vector over a library the server delegates to (no top-level
//!      `request`, no `scenarios`, no `input.endpoint`), or declares
//!      `applies_to_profiles` disjoint from `acdp-registry-core`.
//!
//! `no_excused_family_is_required_by_our_profile` mechanically enforces rule
//! 1 by reading the spec's own `required_fixtures` AND `conditional_fixtures`
//! and rejecting any excuse that contradicts either — this is what gives
//! `EXCUSED` real teeth (unlike `acdp-rs`'s equivalent list, which is
//! unenforced prose).
//!
//! When the ratchet trips, a contributor has exactly two options: add
//! dedicated test coverage for the new family, or add a spec-grounded excuse
//! to `EXCUSED` — and the latter is mechanically rejected if the spec
//! requires the family of `acdp-registry-core`.
//!
//! `wit-*` remains classified "non-HTTP fixture" by the replay harness
//! above (`extract()`'s fallback) and is not itself `EXCUSED` — RFC-ACDP-0015
//! §8 witness-cosignature verification is a pure library check over a
//! witness DID document and an independently-held checkpoint, not a
//! registry HTTP endpoint. `wit-001` (golden) and `wit-004` (wrong-key
//! rejection) now have DIRECT non-HTTP coverage via
//! `wit004_key_mismatch_cosignature_is_rejected_and_wit001_golden_is_accepted`,
//! which drives `acdp::client::verify_witness_cosignature_value` and
//! `evaluate_witness_quorum` in-process — beside, not instead of, the HTTP
//! replayer's skip manifest below.
//!
//! `anc-*` (RFC-ACDP-0016 anchors) is likewise a family the generic replayer
//! cannot reach at any pin: `anc-001` expects a positive (2xx) publish
//! outcome with a placeholder, non-recomputable signature -- `extract_shapes`'s
//! Shape A refuses any non-400 publish outcome by design -- and `anc-002`/
//! `anc-003` carry only an `input.anchor_under_test` fragment, no full body.
//! `anc-001`/`anc-002`/`anc-003` (the three registry-surface members of the
//! family -- anchors schema acceptance at publish time) now have DIRECT
//! fixture-driven coverage via `anc001_well_formed_anchor_is_accepted_and_round_trips`,
//! `anc002_malformed_anchor_content_hash_is_rejected`, and
//! `anc003_empty_anchors_array_is_rejected_with_established_ordering`, which
//! splice each fixture's own anchor data into a freshly-signed body and
//! publish it in-process -- beside, not instead of, the HTTP replayer's skip
//! manifest below, which still (correctly) shows `anc` as non-HTTP-replayed.
//! `anc-004` (a pure hash-computation golden vector over `acdp-crypto`'s
//! JCS/hash pipeline, which this repo delegates to) and `anc-005` (consumer-
//! side scheme-unaware-verifier tolerance -- a registry has no verifier role)
//! are deliberately out of scope; see the doc-comments on the three tests
//! above and the CHANGELOG for the full reasoning.

#![cfg(feature = "storage-sqlite")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp::types::primitives::{AgentDid, ContextType, Visibility};
use acdp::types::publish::PublishRequest;
use acdp::AnchorEntry;
use acdp_registry_auth::{
    AuthService, ChallengeStore, InMemoryChallengeStore, JwtSecret, JwtSigner,
};
use acdp_registry_core::{build_router, AppStateInner};
use acdp_registry_sqlite::SqliteStore;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{
    AuthConfig, LimitsConfig, PlaygroundConfig, RegistryConfig, RegistrySection, StorageBackend,
    StorageConfig, WebhookConfig, REGISTRY_ADVERTISABLE_PROFILES,
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
/// percent-encoding to satisfy axum's `{ctx_id}` single-segment param.
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

/// Exchanges replayable at spec 417211f: pub-004, pub-005, pub-008, ret-001.
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

/// Reads + parses a JSON file, panicking (naming the path) on any failure
/// (missing file, invalid JSON). A spec checkout with an unparseable JSON
/// file under it is not a usable spec checkout, so this is not a skip path.
fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

/// Reads `registries/profiles.json` under `root` and returns its
/// `fixture_families` object's keys. `None` when the file is absent (the
/// bare-fixtures-dir layout, where `ACDP_SPEC_DIR` points straight at
/// `schemas/conformance` with no `registries/` sibling).
fn spec_families(root: &Path) -> Option<Vec<String>> {
    let profiles_path = root.join("registries/profiles.json");
    if !profiles_path.exists() {
        return None;
    }
    let profiles = read_json(&profiles_path);
    let keys = profiles
        .get("fixture_families")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "{} missing 'fixture_families' object",
                profiles_path.display()
            )
        })
        .keys()
        .cloned()
        .collect();
    Some(keys)
}

/// Longest-prefix match of a fixture `id` against a family list, mirroring
/// `acdp-rs`'s `tests/conformance.rs::bucket_family`, which in turn mirrors
/// the spec's own `scripts/check-consistency.py::check_families`: sort
/// candidates by length descending and take the first one that is a true
/// `-`-delimited prefix of `id`. A naive split-on-first-hyphen would
/// mis-bucket `data-ref-ssrf-001` as `data` (or `data-ref`).
fn bucket_family<'a>(id: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let mut ordered: Vec<&str> = candidates.to_vec();
    ordered.sort_by_key(|fam| std::cmp::Reverse(fam.len()));
    ordered
        .into_iter()
        .find(|fam| id.starts_with(&format!("{fam}-")))
}

/// Bucket a fixture into its spec-declared family. Prefers the fixture's own
/// `id` and a longest-prefix match against the spec's declared families;
/// falls back to the filename-stem heuristic only when `registries/
/// profiles.json` is not reachable (`ACDP_SPEC_DIR` may point straight at a
/// bare fixtures directory), or when the `id` doesn't match any declared
/// family (`all_conformance_fixtures_are_bucketed_into_known_families` below
/// is what turns that into a hard failure, not this helper — the manifest
/// must still get *a* label).
fn fixture_family(fx: &Value, path: &Path, spec_families: Option<&[&str]>) -> String {
    let id = fx
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture {} missing string 'id'", path.display()));
    let filename_stem = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    match spec_families {
        Some(candidates) => bucket_family(id, candidates)
            .map(str::to_string)
            .unwrap_or_else(|| family_of(&filename_stem)),
        None => family_of(&filename_stem),
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

    // Spec-declared families, when reachable, so fixture bucketing is keyed
    // on the fixture's own `id` (via `fixture_family`) rather than a bare
    // filename heuristic. `spec_root()` cannot be `None` here: `fixtures`
    // above only resolves once `spec_root()` has already resolved.
    let root = spec_root().expect("spec_fixtures() resolved implies spec_root() resolves");
    let spec_fams = spec_families(&root);
    let spec_fam_refs: Option<Vec<&str>> = spec_fams
        .as_ref()
        .map(|v| v.iter().map(String::as_str).collect());

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
        let family = fixture_family(&fx, &path, spec_fam_refs.as_deref());

        let exchanges = match extract(&fx) {
            Extracted::Skip(reason) => {
                *skipped.entry((family, reason)).or_insert(0) += 1;
                continue;
            }
            Extracted::Run(x) => x,
        };

        for ex in exchanges {
            // GET paths may carry a raw `acdp://` ctx_id needing single-
            // segment percent-encoding for axum's `{ctx_id}` matcher.
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

/// wit-004 (RFC-ACDP-0015 §8 step 2, §10): a witness cosignature whose
/// `signature.value` was produced by the WRONG key must fail consumer
/// verification with `InvalidWitnessCosignature`, and the error must name
/// the actual signature-verification failure — not merely match the
/// variant, since every failure mode of `verify_witness_cosignature_value`
/// returns that same variant. The rejected cosignature must NOT count
/// toward the N-witnessed quorum. wit-001 (the paired golden vector: same
/// witness key, same underlying cosignature body, correct signature) is
/// the positive control — without it, wit-004 failing would prove nothing,
/// since a broken test can "fail correctly" for the wrong reason.
///
/// `wit-*` is classified "non-HTTP fixture" by the replay harness above
/// (`extract()` / the module doc-comment's "Coverage ratchet" section) —
/// §8 verification is a pure library check over a witness DID document
/// and an independently-held checkpoint, not a registry HTTP endpoint.
/// This test drives `acdp::client::verify_witness_cosignature_value` and
/// `evaluate_witness_quorum` directly instead of going through HTTP, and
/// deliberately does NOT use the registry's internal
/// `verify_cosignature_against_own_log` — that path first reconstructs
/// the checkpoint from a log store, which for a synthetic/empty store
/// would yield `InvalidWitnessCosignature` for the WRONG reason (missing
/// checkpoint, not bad signature).
#[test]
fn wit004_key_mismatch_cosignature_is_rejected_and_wit001_golden_is_accepted() {
    use acdp::client::{evaluate_witness_quorum, verify_witness_cosignature_value, WitnessPolicy};
    use acdp::types::log::LogCheckpoint;
    use acdp::types::Signature;
    use acdp::AcdpError;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use std::collections::{HashMap, HashSet};

    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping \
             wit-001/wit-004 (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };

    let read_fixture = |name: &str| -> Option<Value> {
        let path = fixtures.join(name);
        match std::fs::read_to_string(&path) {
            Ok(s) => Some(serde_json::from_str(&s).unwrap()),
            Err(e) => {
                assert!(
                    !require_conformance(),
                    "ACDP_REQUIRE_CONFORMANCE is set but cannot read {}: {e}",
                    path.display()
                );
                eprintln!("conformance: cannot read {}: {e}; skipping", path.display());
                None
            }
        }
    };

    let (Some(wit004), Some(wit001)) = (
        read_fixture("wit-004-cosignature-key-mismatch.json"),
        read_fixture("wit-001-cosignature-golden.json"),
    ) else {
        return;
    };

    // Cross-check: both fixtures are about the same witness key and the
    // same underlying cosignature body (independent proof they pair up).
    let wit004_key_hex = wit004["witness_did_document"]["assertion_method_key_public_hex"]
        .as_str()
        .expect("wit-004 carries witness_did_document.assertion_method_key_public_hex");
    let wit001_key_hex = wit001["witness_test_keypair"]["public_key_hex"]
        .as_str()
        .expect("wit-001 carries witness_test_keypair.public_key_hex");
    assert_eq!(
        wit004_key_hex, wit001_key_hex,
        "wit-004 and wit-001 must pin the same witness assertionMethod key"
    );
    let wit004_cosig_hash = wit004["expected"]["cosignature_hash"]
        .as_str()
        .expect("wit-004 carries expected.cosignature_hash");
    let wit001_cosig_hash = wit001["vectors"][0]["expected"]["cosignature_hash"]
        .as_str()
        .expect("wit-001 carries vectors[0].expected.cosignature_hash");
    assert_eq!(
        wit004_cosig_hash, wit001_cosig_hash,
        "wit-004 and wit-001 must pin the same underlying cosignature body hash"
    );

    // Build witness A's DID document from wit-004's OWN fixture data (not
    // a hardcoded seed): witness_did_document is {note, id,
    // assertion_method_key_public_hex}, not a full DID document.
    let witness_id = wit004["witness_did_document"]["id"]
        .as_str()
        .expect("wit-004 carries witness_did_document.id");
    let key_bytes = hex::decode(wit004_key_hex).expect("wit-004 key hex decodes");
    let vm_id = format!("{witness_id}#witness-key-1");
    let doc = json!({
        "id": witness_id,
        "verificationMethod": [{
            "id": vm_id,
            "type": "Ed25519VerificationKey2020",
            "controller": witness_id,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(&key_bytes),
            }
        }],
        "assertionMethod": [vm_id],
    });

    // The expected checkpoint, built from the cosignature's own
    // `witnessed_checkpoint` tuple. Deliberately NOT
    // `LogCheckpoint::from_value` — it enforces a closed parse requiring
    // `signature.key_id` under the log_id's registry DID, which this
    // synthetic checkpoint has no reason to satisfy. The verification
    // function below only cross-checks the tuple, never the checkpoint's
    // own signature, so the placeholder `signature` field is harmless.
    let wc = &wit004["cosignature"]["witnessed_checkpoint"];
    let checkpoint = LogCheckpoint {
        checkpoint_version: "acdp-log/1".to_string(),
        log_id: wc["log_id"].as_str().unwrap().to_string(),
        tree_size: wc["tree_size"].as_u64().unwrap(),
        root_hash: wc["root_hash"].as_str().unwrap().to_string(),
        timestamp: chrono::Utc::now(),
        signature: Signature {
            algorithm: "ed25519".to_string(),
            key_id: "did:web:registry.example.com#placeholder".to_string(),
            value: String::new(),
        },
    };

    // wit-004: the wrong-key cosignature MUST fail verification, and the
    // error MUST name the actual §8 step 2 signature-verification
    // failure — not merely match the variant.
    let err =
        verify_witness_cosignature_value(&wit004["cosignature"], &doc, &checkpoint, None, None)
            .expect_err("wit-004: wrong-key cosignature must fail verification");
    assert!(
        matches!(err, AcdpError::InvalidWitnessCosignature(_)),
        "wit-004 error must be InvalidWitnessCosignature, got {err:?}"
    );
    assert!(
        err.to_string().contains("signature verification failed"),
        "wit-004 error must name the actual signature-verification failure (§8 step 2), \
         got: {err}"
    );

    // Positive control: wit-001's golden cosignature — nested at
    // vectors[0].expected.log_cosignature, a DIFFERENT JSON path than
    // wit-004's top-level `cosignature` — verified under the SAME DID
    // document and checkpoint → Ok. Without this, wit-004 failing proves
    // nothing: the test could pass because everything fails.
    let wit001_cosig = &wit001["vectors"][0]["expected"]["log_cosignature"];
    verify_witness_cosignature_value(wit001_cosig, &doc, &checkpoint, None, None)
        .expect("wit-001: golden cosignature must verify under the same witness key");

    // The rejected wit-004 cosignature does NOT count toward the
    // N-witnessed quorum; the accepted wit-001 one does, and it is
    // attributed exactly once in `witnesses` (not left empty, not
    // double-counted).
    let mut docs = HashMap::new();
    docs.insert(witness_id.to_string(), doc.clone());
    let trusted: HashSet<String> = [witness_id.to_string()].into_iter().collect();

    let report_alone = evaluate_witness_quorum(
        &[wit004["cosignature"].clone()],
        &docs,
        &trusted,
        &checkpoint,
        &WitnessPolicy::default(),
        None,
    );
    assert_eq!(
        report_alone.witnessed_count, 0,
        "wit-004 alone must not count toward N-witnessed"
    );

    let report_both = evaluate_witness_quorum(
        &[wit001_cosig.clone(), wit004["cosignature"].clone()],
        &docs,
        &trusted,
        &checkpoint,
        &WitnessPolicy::default(),
        None,
    );
    assert_eq!(
        report_both.witnessed_count, 1,
        "only wit-001's cosignature counts toward N-witnessed"
    );
    assert_eq!(
        report_both.witnesses,
        vec![witness_id.to_string()],
        "the one verifying cosignature must appear exactly once in `witnesses` \
         (wit-001 and wit-004 share a witness DID, so this pins the reported \
         identifier — the witness DID, not its verification-method id — and \
         its consistency with witnessed_count; it cannot discriminate which \
         of the two witnesses verified)"
    );
}

// ─── REG-3 Phase 7 (plans/reg3-anchors.md): anc-001/002/003 direct,
// fixture-driven coverage ───
//
// None of anc-001/002/003 is replayable through `extract_shapes` at any pin
// (Context Correction 5 in the plan): anc-001 expects a *positive* publish
// outcome carrying a content_hash/signature its own `input.notes` calls
// placeholders that do not recompute over the fixture's own body —
// `extract_shapes`'s Shape A (`:389-393` above) refuses any non-400 publish
// outcome by design, for exactly that reason — and anc-002/anc-003 carry
// only an `input.anchor_under_test` fragment, no full body. So, following
// the same precedent as
// `wit004_key_mismatch_cosignature_is_rejected_and_wit001_golden_is_accepted`
// and `did_key_golden_vector_accepted_and_gated` above, these three tests
// consume the fixtures' own data directly and drive the registry in-process
// instead of going through the generic replayer. They run BESIDE the
// replayer, not instead of it — the skip manifest in
// `replays_spec_fixtures_when_present` still (correctly) shows `anc` as
// non-HTTP-replayed, because the replayer itself still doesn't replay any
// anc-* fixture.
//
// anc-004 and anc-005 are deliberately OUT OF SCOPE for this phase (see the
// CHANGELOG entry for the same reasoning):
//   * anc-004 is a pure hash-computation golden vector (top-level `vectors`,
//     no `expected.http_status`, no endpoint, no request) over
//     `acdp-crypto`'s JCS/hash pipeline, which this repo delegates to via
//     the `acdp` dependency and does not own. `anchors_round_trip_byte_exact_sqlite`
//     / `pg_anchors_round_trip_byte_exact` (REG-3 Phase 5,
//     `http_integration.rs` / `pg_integration.rs`) already prove that
//     pipeline handles anchors correctly *through this repo's own
//     storage*, which is the part this repo is accountable for. Duplicating
//     anc-004 here would just re-test an upstream crate's own golden vector.
//   * anc-005 is consumer-side behavioral (a scheme-unaware verifier
//     tolerating an unknown scheme) — this registry has no verifier role,
//     and the pinned spec places all five anc-* fixtures in
//     `acdp-consumer`'s `required_fixtures`, never in any
//     `acdp-registry-*` profile's `required_fixtures` or
//     `conditional_fixtures`.

/// Capabilities for a `0.5.0`-advertising registry, built LOCALLY for the
/// three anc-* tests below — do NOT mutate the shared `caps()` (`:142`,
/// `"0.1.0"`), which `replays_spec_fixtures_when_present` (and other tests)
/// depend on. Mirrors `did_key_caps()` (`:877`)'s pattern of cloning
/// `caps()` and bumping the one field under test.
fn anc_caps_050() -> CapabilitiesDocument {
    let mut c = caps();
    c.acdp_version = "0.5.0".into();
    c
}

/// A `0.5.0`-advertising harness, playground on (so a freshly-signed
/// synthetic producer identity can publish without a live DID resolver) —
/// the same shape as the file's shared `harness()` (`:205`) except for the
/// swapped-in capabilities document, built locally the same way
/// `did_key_harness()` (`:887`) builds its own isolated harness rather than
/// touching the shared one.
async fn anc_harness_050() -> axum::Router {
    let store = SqliteStore::connect_in_memory().await.unwrap();
    store.migrate().await.unwrap();
    let server = Arc::new(RegistryServer::try_new(store, anc_caps_050(), AUTHORITY).unwrap());
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

/// A signing producer identity for the anc-* tests, isolated from any other
/// test's seed space — mirrors `http_integration.rs`'s `producer()`.
fn anc_producer(seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(format!("did:web:agents.test:anc-{seed}")),
        format!("did:web:agents.test:anc-{seed}#key-1"),
    )
}

/// POST `req` to `/contexts` on `app` and return `(status, parsed body)`.
async fn anc_publish(app: &axum::Router, req: &PublishRequest) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/contexts")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let v = body_to_json(resp).await;
    (status, v)
}

/// GET `uri` on `app` and return `(status, parsed body)`. A small local
/// mirror of `http_integration.rs`'s `get_json` — this file has no such
/// helper yet.
async fn anc_get(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let v = body_to_json(resp).await;
    (status, v)
}

/// Resolve a fixture by its own `id` field via the same directory-scan
/// mechanism `replays_spec_fixtures_when_present` / `bucketed_fixtures` use
/// (`fixtures` must already be a resolved `spec_fixtures()` directory),
/// rather than hardcoding a filename. Returns `None` only via a LOUD path:
/// under `ACDP_REQUIRE_CONFORMANCE`, "no fixture with this id" is a hard
/// panic naming both the id and the searched directory — a
/// silently-skipped conformance test is exactly the failure mode this
/// repo's whole ratchet exists to prevent.
fn find_fixture_by_id(fixtures: &Path, id: &str) -> Option<Value> {
    let entries = std::fs::read_dir(fixtures).unwrap_or_else(|e| panic!("read {fixtures:?}: {e}"));
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();
    for path in &paths {
        let fx = read_json(path);
        if fx.get("id").and_then(Value::as_str) == Some(id) {
            return Some(fx);
        }
    }
    assert!(
        !require_conformance(),
        "ACDP_REQUIRE_CONFORMANCE is set but no fixture with id \"{id}\" was found under {}",
        fixtures.display()
    );
    eprintln!(
        "conformance: no fixture with id \"{id}\" found under {}; skipping",
        fixtures.display()
    );
    None
}

/// anc-001 (RFC-ACDP-0016 §4/§5): a publish body carrying one well-formed
/// `anchors` entry must be accepted, served intact, and its recomputed
/// `content_hash` must match. `extract_shapes`'s Shape A (`:389-393`)
/// refuses this fixture by design — it is a *positive* publish outcome, and
/// anc-001's own `content_hash`/`signature` are placeholders (per its
/// `input.notes`) that don't recompute over its own body. So this test
/// lifts only `input.body.anchors`'s SHAPE and splices it into a body it
/// signs itself via `anc_producer` (reusing REG-3 Phase 5's
/// test-body-construction technique), publishing on the locally-built
/// `anc_harness_050()` — NOT the shared `caps()`/`harness()` pair
/// `replays_spec_fixtures_when_present` uses. This repo's `POST /contexts`
/// returns HTTP 200 on success, not the fixture's own literal
/// `expected.http_status: 201` — established by REG-3 Phases 3-6 and
/// reconfirmed here.
#[tokio::test(flavor = "multi_thread")]
async fn anc001_well_formed_anchor_is_accepted_and_round_trips() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping anc-001 \
             (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "anc-001") else {
        return;
    };
    let anchors_json = fx["input"]["body"]["anchors"].clone();
    assert!(
        anchors_json.as_array().is_some_and(|a| !a.is_empty()),
        "anc-001 must carry a non-empty input.body.anchors array: {fx}"
    );
    let anchors: Vec<AnchorEntry> = serde_json::from_value(anchors_json).unwrap_or_else(|e| {
        panic!("anc-001 input.body.anchors did not parse as Vec<AnchorEntry>: {e}")
    });

    let req = anc_producer(240)
        .publish_request()
        .title("anc-001 well-formed anchor")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .acdp_version("0.5.0")
        .anchors(anchors)
        .build()
        .unwrap();

    let app = anc_harness_050().await;
    let (status, v) = anc_publish(&app, &req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "anc-001: this repo's POST /contexts returns 200 on success (not the fixture's own \
         literal 201); body = {v}"
    );
    let ctx_id = v["ctx_id"].as_str().unwrap().to_string();

    // Post-publish invariant 1 (anc-001's own `expected.post_publish_invariants[0]`):
    // GET returns the body with anchors present, byte-identical to what was signed.
    let (status, served) = anc_get(
        &app,
        &format!("/contexts/{}/body", pct_encode_path_segment(&ctx_id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anc-001 GET body = {served}");
    let sent_anchors_json = serde_json::to_value(&req.anchors).unwrap();
    assert_eq!(
        served["anchors"], sent_anchors_json,
        "anc-001 invariant 1: served anchors must be byte-identical to what was signed"
    );

    // Post-publish invariant 2 (anc-001's own `expected.post_publish_invariants[1]`):
    // content_hash recomputed over the retrieved body (anchors included)
    // matches the stored content_hash.
    let recomputed = acdp::crypto::compute_content_hash(&served).unwrap();
    assert_eq!(
        &recomputed, &req.content_hash,
        "anc-001 invariant 2: compute_content_hash over the served body must reproduce the \
         published content_hash"
    );
}

/// anc-002 (RFC-ACDP-0016 §4): `anchors[].content_hash` failing the
/// `sha256:` + 64-lowercase-hex shape must be rejected `schema_violation`.
///
/// IMPORTANT — this test exercises INHERITED (upstream) behavior, not this
/// repo's own code: the check that actually fires here is
/// `acdp_validation::validate_anchors`'s `ContentHash::parse` call, inside
/// the `acdp` 0.8.2 dependency this repo bumped to in REG-3 Phase 2 — NOT
/// this repo's own Phase 3 version gate (RFC-ACDP-0016 §10/§14), which runs
/// earlier in `publish_inner` and only ever inspects the acdp_version pair,
/// never anchor *content*. (`ContentHash`'s `Deserialize` impl is
/// permissive — any string deserializes — so the malformed hash survives
/// wire deserialization and is only caught by this later, explicit shape
/// check.) This is a regression net worth having for an inherited
/// behavior, labelled honestly as such rather than implied to be this
/// repo's own gate.
#[tokio::test(flavor = "multi_thread")]
async fn anc002_malformed_anchor_content_hash_is_rejected() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping anc-002 \
             (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "anc-002") else {
        return;
    };
    let anchor_json = fx["input"]["anchor_under_test"].clone();
    assert!(
        anchor_json.is_object(),
        "anc-002 must carry input.anchor_under_test as an object: {fx}"
    );
    let malformed: AnchorEntry = serde_json::from_value(anchor_json).unwrap_or_else(|e| {
        panic!("anc-002 input.anchor_under_test did not parse as AnchorEntry: {e}")
    });

    // `.anchors(vec![malformed]).build()` would refuse this client-side —
    // `RequestBuilder::build()` runs the SDK's own `validate_publish_request`
    // (which calls `validate_anchors`) before ever returning, so it would
    // reject the malformed content_hash before a request exists to send.
    // Same technique as `gate_fires_before_sdk_empty_vec_check_on_sub_0_5_0_registry`
    // in `http_integration.rs`: build a valid, anchors-free base request,
    // then patch the malformed anchor onto the struct literal so the
    // malformed body actually reaches the wire.
    let base = anc_producer(241)
        .publish_request()
        .title("anc-002 malformed anchor content_hash")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let req = PublishRequest {
        anchors: Some(vec![malformed]),
        ..base
    };

    let app = anc_harness_050().await;
    let (status, v) = anc_publish(&app, &req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "anc-002 body = {v}");
    assert_eq!(v["error"]["code"], "schema_violation");
}

/// anc-003 (RFC-ACDP-0016 §4): `anchors: []` must be rejected
/// `schema_violation` — the absent-when-empty convention. Also pins the
/// ORDERING already established by `http_integration.rs`'s
/// `gate_fires_before_sdk_empty_vec_check_on_sub_0_5_0_registry` /
/// `empty_anchors_still_rejected_downstream_once_gate_passes` (REG-3 Phase
/// 3): on a sub-0.5.0 registry this repo's OWN §10 version gate fires
/// first (it runs at the very top of `publish_inner`, before the SDK's
/// validator ever sees the body); on a 0.5.0-advertising registry the gate
/// passes and the SDK's own `validate_anchors` empty-vec rule fires
/// instead. Both outcomes are 400/`schema_violation` at the HTTP level, so
/// this test distinguishes them by the specific error MESSAGE — exactly as
/// the two `http_integration.rs` tests above do — so a future reordering of
/// the two checks would flip which message appears and be caught here.
#[tokio::test(flavor = "multi_thread")]
async fn anc003_empty_anchors_array_is_rejected_with_established_ordering() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping anc-003 \
             (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "anc-003") else {
        return;
    };
    let anchor_under_test = fx["input"]["anchor_under_test"].clone();
    assert_eq!(
        anchor_under_test,
        json!([]),
        "anc-003 must carry input.anchor_under_test == [] (empty array): {fx}"
    );

    // Sub-0.5.0 registry: this repo's own §10 version gate fires first.
    let sub_050_app = harness().await; // shared caps(): acdp_version "0.1.0"
    let base_sub = anc_producer(242)
        .publish_request()
        .title("anc-003 empty anchors, sub-0.5.0 registry")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let req_sub = PublishRequest {
        anchors: Some(vec![]),
        ..base_sub
    };
    let (status, v) = anc_publish(&sub_050_app, &req_sub).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "anc-003 (sub-0.5.0) body = {v}"
    );
    assert_eq!(v["error"]["code"], "schema_violation");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("\u{a7}10"),
        "anc-003 on a sub-0.5.0 registry: the version gate, not the SDK's empty-vec check, \
         must fire first: {msg}"
    );
    assert!(
        !msg.contains("MUST be omitted entirely"),
        "anc-003 on a sub-0.5.0 registry: the SDK's empty-vec message must not be the one \
         surfaced here: {msg}"
    );

    // 0.5.0 registry: the gate passes, so the SDK's own empty-vec rule fires.
    let app_050 = anc_harness_050().await;
    let base_050 = anc_producer(243)
        .publish_request()
        .title("anc-003 empty anchors, 0.5.0 registry")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .acdp_version("0.5.0")
        .build()
        .unwrap();
    let req_050 = PublishRequest {
        anchors: Some(vec![]),
        ..base_050
    };
    let (status, v) = anc_publish(&app_050, &req_050).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "anc-003 (0.5.0) body = {v}"
    );
    assert_eq!(v["error"]["code"], "schema_violation");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("MUST be omitted entirely"),
        "anc-003 on a 0.5.0 registry: once the gate passes, the SDK's own empty-vec check \
         must fire: {msg}"
    );
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

// ─── Phase 3: unified fixture bucketing (`bucket_family` / `fixture_family`) ───

/// Direct test of `bucket_family`'s longest-prefix behavior: `data-ref-ssrf-001`
/// must bucket as `data-ref-ssrf`, not `data-ref` — the case that motivates
/// sorting candidates by length descending instead of taking the first match.
#[test]
fn fixture_family_bucketing_prefers_longest_match() {
    let candidates = ["data-ref", "data-ref-ssrf", "lc"];
    assert_eq!(
        bucket_family("data-ref-ssrf-001", &candidates),
        Some("data-ref-ssrf")
    );
    assert_eq!(bucket_family("data-ref-001", &candidates), Some("data-ref"));
    assert_eq!(bucket_family("lc-001", &candidates), Some("lc"));
    assert_eq!(bucket_family("unrelated-001", &candidates), None);
}

/// `fixture_family` must bucket from the fixture's `id`, not its filename —
/// constructed so the two heuristics disagree: `id` "ret-001" prefix-matches
/// "ret" in the spec family list, while the filename stem's split-until-digit
/// heuristic on a deliberately unrelated filename would produce a different
/// label entirely.
#[test]
fn fixture_family_prefers_id_over_filename() {
    let fx = json!({"id": "ret-001", "description": "x"});
    let path = Path::new("/tmp/totally-different-001-desc.json");
    let spec_fams = ["ret", "pub"];
    assert_eq!(fixture_family(&fx, path, Some(&spec_fams)), "ret");
    // Confirm the filename-based heuristic really would have disagreed, so
    // this test is actually discriminating between the two code paths.
    assert_eq!(
        family_of("totally-different-001-desc.json"),
        "totally-different"
    );
}

/// `spec_families = None` (bare-fixtures-dir layout, no `registries/` sibling
/// to read) must route to the filename-stem `family_of` fallback regardless
/// of what the fixture's `id` says.
#[test]
fn fixture_family_falls_back_without_spec_families() {
    let fx = json!({"id": "ret-001", "description": "x"});
    let path = Path::new("/tmp/pub-005-desc.json");
    assert_eq!(fixture_family(&fx, path, None), "pub");
}

/// A fixture `id` that matches no declared family must NOT panic here — this
/// helper only produces manifest labels; turning "unaccounted family" into a
/// hard failure is `all_conformance_fixtures_are_bucketed_into_known_families`'s
/// job. The label falls back to the filename-stem heuristic.
#[test]
fn fixture_family_id_matching_no_family_falls_back_without_panicking() {
    let fx = json!({"id": "totally-unknown-001", "description": "x"});
    let path = Path::new("/tmp/totally-unknown-001-desc.json");
    let spec_fams = ["ret", "pub"];
    assert_eq!(
        fixture_family(&fx, path, Some(&spec_fams)),
        "totally-unknown"
    );
}

/// A fixture missing `id` must panic naming the file path, not silently fall
/// back to filename-based bucketing — the coverage ratchet below could
/// otherwise be defeated by simply omitting `id`.
#[test]
#[should_panic(expected = "no-id-fixture.json")]
fn fixture_family_panics_naming_file_when_id_missing() {
    let fx = json!({"description": "no id here"});
    let path = Path::new("/tmp/no-id-fixture.json");
    fixture_family(&fx, path, None);
}

// ─── Phase 4: family-coverage ratchet (`KNOWN_FAMILIES` / `EXCUSED`) ───

/// All 29 fixture families the pinned spec (`registries/profiles.json`'s
/// `fixture_families` object) declares, as of SHA `417211f`. Every one has
/// fixtures on disk and is classified (replayed or skipped-with-reason) by
/// this harness. Listing all 29 — not just the ones we replay — is the
/// honest statement "we have looked at every family"; a 30th family (the
/// spec adding a new fixture prefix) is what turns
/// `all_conformance_fixtures_are_bucketed_into_known_families` red.
///
/// `anc` (RFC-ACDP-0016 anchors) stays classified "non-HTTP fixture" by the
/// generic replay harness (`extract_shapes`'s Shape A refuses `anc-001`'s
/// positive/placeholder-signature publish outcome by design, and
/// `anc-002`/`anc-003` carry no full body) — but `anc-001`/`anc-002`/
/// `anc-003` now have DIRECT fixture-driven coverage (REG-3 Phase 7,
/// `plans/reg3-anchors.md`) via `anc001_well_formed_anchor_is_accepted_and_round_trips`,
/// `anc002_malformed_anchor_content_hash_is_rejected`, and
/// `anc003_empty_anchors_array_is_rejected_with_established_ordering`, same
/// precedent as `wit`. `anc`'s *classification* here is unchanged — it was
/// never `EXCUSED` and still isn't; only its *coverage* changed.
const KNOWN_FAMILIES: &[&str] = &[
    "anc",
    "body",
    "can",
    "caps",
    "cur",
    "data-ref",
    "data-ref-ssrf",
    "did-ssrf",
    "dk",
    "err",
    "fed",
    "fp",
    "idem",
    "lc",
    "lhr",
    "lin",
    "log",
    "meta",
    "pub",
    "rate",
    "rcpt",
    "ret",
    "rev",
    "rot",
    "schema",
    "sig",
    "status",
    "vis",
    "wit",
];

/// Families excused from needing HTTP-replay coverage, each with a prose
/// reason. An excuse is legitimate only when BOTH hold: (1) spec-grounded —
/// no fixture in the family appears in `acdp-registry-core`'s
/// `required_fixtures` or anywhere in its `conditional_fixtures`,
/// mechanically checked by `no_excused_family_is_required_by_our_profile`;
/// and (2) structural —
/// every fixture in the family is a pure golden vector over a library the
/// server delegates to, or declares `applies_to_profiles` disjoint from
/// `acdp-registry-core`. See the module doc-comment's "Coverage ratchet"
/// section for the full rule.
const EXCUSED: &[(&str, &str)] = &[
    (
        "fp",
        "Key-fingerprint encoding vectors (RFC-ACDP-0010 \u{a7}6): a pure acdp-crypto \
         surface. 0/1 fixtures carry an HTTP request shape and none is in \
         acdp-registry-core's required_fixtures or conditional_fixtures.",
    ),
    (
        "data-ref-ssrf",
        "applies_to_profiles = [acdp-consumer] on all 5 fixtures: DataRef location \
         fetching is a consumer fetch-time duty (RFC-ACDP-0008 \u{a7}4.9). This registry \
         never dereferences data_refs[].location, and none of the 5 is in \
         acdp-registry-core's required_fixtures or conditional_fixtures.",
    ),
    (
        "fed",
        "applies_to_profiles = [acdp-registry-federated, acdp-consumer] on all 10 \
         fixtures. This repo does not implement or advertise the \
         acdp-registry-federated profile itself -- no crate under crates/ implements \
         federated resolution (the profile name appears only in fixture data and in \
         this excuse) -- and none of the 10 is in acdp-registry-core's \
         required_fixtures or conditional_fixtures.",
    ),
    (
        "rot",
        "applies_to_profiles = [acdp-registry-receipts, acdp-consumer], and none of \
         its 1 fixture is in acdp-registry-core's required_fixtures or \
         conditional_fixtures -- same structural shape as lc (a profile this harness \
         doesn't advertise), but excused on a substantive ground lc is not: RFC-ACDP-0010 \
         \u{a7}10 assigns historical producer-key verification to the consumer holding \
         the receipt, not to the issuing registry, so no harness configuration change \
         would make this registry responsible for it.",
    ),
];

/// Returns the `acdp-registry-core` profile object from `registries/
/// profiles.json`'s `profiles[]` array, panicking (naming the checked path)
/// if the file is unreadable/malformed, `profiles` isn't an array, or no
/// entry's `id` is `"acdp-registry-core"`. The excuse rule loses its
/// grounding without this profile, so absence is a hard failure, not a skip.
fn core_profile(root: &Path) -> Value {
    let profiles_path = root.join("registries/profiles.json");
    let doc = read_json(&profiles_path);
    let profiles = doc
        .get("profiles")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{} missing 'profiles' array", profiles_path.display()));
    profiles
        .iter()
        .find(|p| p.get("id").and_then(Value::as_str) == Some("acdp-registry-core"))
        .unwrap_or_else(|| {
            panic!(
                "{} has no profile entry with id == \"acdp-registry-core\"",
                profiles_path.display()
            )
        })
        .clone()
}

/// Returns every `profiles[].id` in `registries/profiles.json` under `root`
/// whose id starts with `acdp-registry-` — i.e. the *registry* profiles the
/// pinned spec defines, as opposed to the two non-registry profile ids it
/// also declares (`acdp-log-witness`, `acdp-consumer`). Panics (naming the
/// checked path) if the file is unreadable/malformed, `profiles` isn't an
/// array, or any entry's `id` is missing/non-string — same "malformed spec
/// data is a hard failure, not a skip" discipline as `core_profile`.
fn spec_registry_profile_ids(root: &Path) -> Vec<String> {
    let profiles_path = root.join("registries/profiles.json");
    let doc = read_json(&profiles_path);
    let profiles = doc
        .get("profiles")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{} missing 'profiles' array", profiles_path.display()));
    profiles
        .iter()
        .map(|p| {
            p.get("id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| {
                    panic!(
                        "{} has a profiles[] entry with a missing/non-string 'id': {p}",
                        profiles_path.display()
                    )
                })
                .to_string()
        })
        .filter(|id| id.starts_with("acdp-registry-"))
        .collect()
}

/// Reads `acdp-registry-core`'s `required_fixtures` array, panicking (naming
/// the path) if it is absent or not an array — the excuse rule cannot be
/// silently vacuous.
fn core_required_fixtures(root: &Path) -> Vec<String> {
    let profiles_path = root.join("registries/profiles.json");
    let profile = core_profile(root);
    profile
        .get("required_fixtures")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "{} acdp-registry-core profile missing 'required_fixtures' array",
                profiles_path.display()
            )
        })
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "{} required_fixtures contains a non-string entry: {v}",
                        profiles_path.display()
                    )
                })
                .to_string()
        })
        .collect()
}

/// Reads `acdp-registry-core`'s `conditional_fixtures` array and flattens
/// every entry's `fixtures` array into one list, panicking (naming the path)
/// if the top-level key is absent or malformed. Shape, confirmed by reading
/// the pinned spec's `registries/profiles.json` directly (not guessed): an
/// array of objects, each carrying a `fixtures` array of fixture ids plus
/// descriptive `required_when` / `capability_key` / `capability_match`
/// fields this helper doesn't need, e.g.:
///
/// ```json
/// {
///   "fixtures": ["dk-001-wrong-multicodec-prefix", "dk-002-malformed-multibase", ...],
///   "required_when": "supported_did_methods includes \"did:key\" (0.2.0)",
///   "capability_key": "supported_did_methods",
///   "capability_match": "did:key"
/// }
/// ```
///
/// This deliberately does NOT filter by whether the harness's own
/// capabilities document currently satisfies each entry's condition — the
/// point of the caller (`no_excused_family_is_required_by_our_profile`) is
/// to reject an excuse that would contradict the spec under *any*
/// capability posture the profile allows, not just the one this harness
/// happens to advertise today (`EXCUSED` growing to cover, say, `idem`
/// should fail loudly regardless of whether `supports_idempotency_key` is
/// currently `true` in `caps()`).
///
/// Unlike `required_fixtures`, `conditional_fixtures` is not conceptually
/// mandatory on every profile — a profile with no capability-gated fixtures
/// could legitimately omit it. But the pinned spec's `acdp-registry-core`
/// entry does carry one (verified above), so on this specific profile its
/// absence would mean a spec regression or a parsing bug, not a legitimate
/// empty case. Treating that silently as `Vec::new()` would let the caller's
/// non-empty assertion (mirroring `required_fixtures`'s) go vacuously easy,
/// so this panics instead, exactly like `core_required_fixtures`.
fn core_conditional_fixtures(root: &Path) -> Vec<String> {
    let profiles_path = root.join("registries/profiles.json");
    let profile = core_profile(root);
    let entries = profile
        .get("conditional_fixtures")
        .and_then(Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "{} acdp-registry-core profile missing 'conditional_fixtures' array \
                 (expected present per the pinned spec; if the spec legitimately \
                 dropped it, update this helper's expectations deliberately rather \
                 than silently returning an empty list)",
                profiles_path.display()
            )
        });
    entries
        .iter()
        .flat_map(|entry| {
            entry
                .get("fixtures")
                .and_then(Value::as_array)
                .unwrap_or_else(|| {
                    panic!(
                        "{} conditional_fixtures entry missing 'fixtures' array: {entry}",
                        profiles_path.display()
                    )
                })
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "{} conditional_fixtures entry's 'fixtures' array contains a \
                                 non-string entry: {v}",
                                profiles_path.display()
                            )
                        })
                        .to_string()
                })
                .collect::<Vec<String>>()
        })
        .collect()
}

/// Shared skip gate for all four ratchet tests below: resolves the fixtures
/// directory and the spec's own declared families, then buckets every
/// on-disk fixture's `id` into its family via `fixture_family` (the same
/// helper `replays_spec_fixtures_when_present` uses). Returns `None` — the
/// signal to skip, not panic — when `ACDP_SPEC_DIR` is unset/nonexistent, no
/// fixture directory is resolvable under it, or `registries/profiles.json`
/// isn't reachable (the bare-fixtures-dir layout `resolve_fixture_dir`
/// supports). This is a deliberate divergence from `acdp-rs`'s equivalent
/// test, which unconditionally `expect()`s both to exist because `acdp-rs`
/// has no bare-dir layout to support; this repo does, so all four tests here
/// degrade to a clean skip in that case rather than a panic.
fn bucketed_fixtures() -> Option<(PathBuf, Vec<(String, String)>)> {
    let fixtures = spec_fixtures()?;
    let root = spec_root().expect("spec_fixtures() resolved implies spec_root() resolves");
    let spec_fams = spec_families(&root)?;
    let spec_fam_refs: Vec<&str> = spec_fams.iter().map(String::as_str).collect();

    let entries = std::fs::read_dir(&fixtures).unwrap_or_else(|e| panic!("read {fixtures:?}: {e}"));
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();

    let out = paths
        .into_iter()
        .map(|path| {
            let fx = read_json(&path);
            let id = fx
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("fixture {} missing string 'id'", path.display()))
                .to_string();
            let family = fixture_family(&fx, &path, Some(&spec_fam_refs));
            (id, family)
        })
        .collect();
    Some((fixtures, out))
}

/// Every fixture on disk must bucket into a family `KNOWN_FAMILIES`
/// declares. Skips (does not panic) when the spec, its fixtures directory, or
/// `registries/profiles.json` isn't reachable.
#[tokio::test(flavor = "multi_thread")]
async fn all_conformance_fixtures_are_bucketed_into_known_families() {
    let Some((fixtures, ids_and_families)) = bucketed_fixtures() else {
        eprintln!(
            "conformance: spec unavailable (ACDP_SPEC_DIR unset, no fixture dir, or no \
             registries/profiles.json); skipping \
             all_conformance_fixtures_are_bucketed_into_known_families"
        );
        return;
    };
    assert!(
        !ids_and_families.is_empty(),
        "expected at least one fixture under {}",
        fixtures.display()
    );
    for (id, fam) in &ids_and_families {
        assert!(
            KNOWN_FAMILIES.contains(&fam.as_str()),
            "fixture id \"{id}\" bucketed into family \"{fam}\", which is not in \
             KNOWN_FAMILIES"
        );
    }
}

/// `KNOWN_FAMILIES` must equal exactly the spec's own `fixture_families` keys
/// (`registries/profiles.json`) at the pinned SHA — not merely a subset. That
/// exact-equality is the honest claim "we have classified every family the
/// spec declares, and only those." Skips when the spec isn't reachable.
#[tokio::test(flavor = "multi_thread")]
async fn known_families_are_declared_by_the_spec() {
    let Some(root) = spec_root() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or nonexistent; skipping \
             known_families_are_declared_by_the_spec"
        );
        return;
    };
    let Some(spec_fams) = spec_families(&root) else {
        eprintln!(
            "conformance: no registries/profiles.json under {}; skipping \
             known_families_are_declared_by_the_spec",
            root.display()
        );
        return;
    };

    let mut spec_sorted = spec_fams.clone();
    spec_sorted.sort();
    let mut known_sorted: Vec<String> = KNOWN_FAMILIES.iter().map(|s| s.to_string()).collect();
    known_sorted.sort();

    assert_eq!(
        known_sorted, spec_sorted,
        "KNOWN_FAMILIES must equal exactly the spec's fixture_families keys"
    );
}

/// Every `(family, reason)` in `EXCUSED` must be well-formed: `family` is in
/// `KNOWN_FAMILIES`, at least one fixture on disk buckets into it, and
/// `reason` is non-empty. Catches a stale excuse (family renamed/removed) or
/// a placeholder reason. Skips when the spec isn't reachable.
#[tokio::test(flavor = "multi_thread")]
async fn excused_families_are_known_and_present() {
    let Some((fixtures, ids_and_families)) = bucketed_fixtures() else {
        eprintln!(
            "conformance: spec unavailable (ACDP_SPEC_DIR unset, no fixture dir, or no \
             registries/profiles.json); skipping excused_families_are_known_and_present"
        );
        return;
    };

    for (family, reason) in EXCUSED {
        assert!(
            KNOWN_FAMILIES.contains(family),
            "EXCUSED family \"{family}\" is not in KNOWN_FAMILIES"
        );
        assert!(
            !reason.trim().is_empty(),
            "EXCUSED family \"{family}\" has an empty reason"
        );
        let present = ids_and_families.iter().any(|(_, fam)| fam == family);
        assert!(
            present,
            "EXCUSED family \"{family}\" has zero fixtures on disk under {}",
            fixtures.display()
        );
    }
}

/// Every fixture id named in one of `ids` must bucket (via `bucket_family`)
/// into a family, and that family must not be in `excused_families`. Shared
/// by `no_excused_family_is_required_by_our_profile`'s two signals —
/// `required_fixtures` and `conditional_fixtures` — so a failure's message
/// names which spec key (`source`) caught it.
fn assert_no_id_buckets_into_excused_family(
    ids: &[String],
    spec_fam_refs: &[&str],
    excused_families: &[&str],
    source: &str,
) {
    for id in ids {
        let fam = bucket_family(id, spec_fam_refs).unwrap_or_else(|| {
            panic!(
                "acdp-registry-core.{source} entry \"{id}\" does not bucket \
                 into any spec-declared family"
            )
        });
        assert!(
            !excused_families.contains(&fam),
            "acdp-registry-core.{source} contains \"{id}\", which buckets into \
             excused family \"{fam}\" -- the spec requires this family of the profile \
             this repo advertises (via {source}), so it cannot be in EXCUSED"
        );
    }
}

/// The assertion that gives `EXCUSED` real teeth: no fixture in
/// `acdp-registry-core`'s `required_fixtures` OR anywhere in its
/// `conditional_fixtures` may bucket into an excused family. If the spec
/// requires the family of the profile this repo advertises — unconditionally
/// via `required_fixtures`, or conditionally (gated on an advertised
/// capability, e.g. `dk-*` behind `did:key`, `idem-*` behind
/// `supports_idempotency_key`) via `conditional_fixtures` — it cannot be
/// excused. This test mechanically rejects such an excuse rather than
/// relying on a human re-reading the spec by hand every time `EXCUSED`
/// grows; a failure names both the offending fixture id and which of the two
/// spec keys (`required_fixtures` vs `conditional_fixtures`) caught it.
/// Skips when the spec isn't reachable.
#[tokio::test(flavor = "multi_thread")]
async fn no_excused_family_is_required_by_our_profile() {
    let Some(root) = spec_root() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or nonexistent; skipping \
             no_excused_family_is_required_by_our_profile"
        );
        return;
    };
    let Some(spec_fams) = spec_families(&root) else {
        eprintln!(
            "conformance: no registries/profiles.json under {}; skipping \
             no_excused_family_is_required_by_our_profile",
            root.display()
        );
        return;
    };
    let spec_fam_refs: Vec<&str> = spec_fams.iter().map(String::as_str).collect();
    let excused_families: Vec<&str> = EXCUSED.iter().map(|(fam, _)| *fam).collect();

    let required = core_required_fixtures(&root);
    assert!(
        !required.is_empty(),
        "acdp-registry-core.required_fixtures resolved empty; the excuse rule \
         would be vacuously true, which is not the intent"
    );
    assert_no_id_buckets_into_excused_family(
        &required,
        &spec_fam_refs,
        &excused_families,
        "required_fixtures",
    );

    let conditional = core_conditional_fixtures(&root);
    assert!(
        !conditional.is_empty(),
        "acdp-registry-core.conditional_fixtures resolved empty; the excuse rule \
         would be vacuously true for this signal, which is not the intent"
    );
    assert_no_id_buckets_into_excused_family(
        &conditional,
        &spec_fam_refs,
        &excused_families,
        "conditional_fixtures",
    );
}

/// REG-5: `REGISTRY_ADVERTISABLE_PROFILES` (`acdp-registry-types`'s
/// `registry.profiles` allowlist, enforced at startup by
/// `acdp-registry-server`'s `validate_config`) must equal — exactly, as a
/// set — every `profiles[].id` in the pinned spec's `registries/
/// profiles.json` that starts with `acdp-registry-`. This is the property
/// that makes the allowlist "derived by rule, not hand-maintained": if the
/// spec adds an eighth registry profile, or renames/removes one of the
/// current seven, this test goes red rather than the allowlist silently
/// drifting. Skips when the pinned spec isn't reachable (`ACDP_SPEC_DIR`
/// unset/nonexistent) in default mode; panics in require mode (via
/// `spec_root()`).
#[tokio::test(flavor = "multi_thread")]
async fn registry_advertisable_profiles_matches_spec_derived_set() {
    let Some(root) = spec_root() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or nonexistent; skipping \
             registry_advertisable_profiles_matches_spec_derived_set"
        );
        return;
    };

    let mut spec_ids = spec_registry_profile_ids(&root);
    spec_ids.sort();
    spec_ids.dedup();

    let mut const_ids: Vec<String> = REGISTRY_ADVERTISABLE_PROFILES
        .iter()
        .map(|s| s.to_string())
        .collect();
    const_ids.sort();
    const_ids.dedup();

    assert_eq!(
        const_ids, spec_ids,
        "REGISTRY_ADVERTISABLE_PROFILES must equal exactly the pinned spec's \
         acdp-registry-* profile ids (registries/profiles.json). If the spec added, \
         removed, or renamed a registry profile, update REGISTRY_ADVERTISABLE_PROFILES \
         in crates/acdp-registry-types/src/config.rs to match."
    );

    // Named invariant, not just an emergent property of the prefix filter
    // both sides apply: the two non-registry profile ids the spec also
    // declares must not sneak into either side.
    assert!(
        !const_ids.iter().any(|id| id == "acdp-log-witness"),
        "a witness is not a registry (RFC-ACDP-0015 §6.1) -- acdp-log-witness must never \
         appear in REGISTRY_ADVERTISABLE_PROFILES"
    );
    assert!(
        !const_ids.iter().any(|id| id == "acdp-consumer"),
        "acdp-consumer is not a registry profile -- it must never appear in \
         REGISTRY_ADVERTISABLE_PROFILES"
    );
}
