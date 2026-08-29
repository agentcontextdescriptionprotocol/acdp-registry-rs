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
//! family the pinned spec declares" — all 28 keys of `registries/
//! profiles.json`'s `fixture_families` object, each with fixtures on disk,
//! each classified by the manifest above as replayed or skipped-with-reason.
//! `all_conformance_fixtures_are_bucketed_into_known_families` is the ratchet
//! itself: a 29th family (new fixture id prefix the spec adds later) fails
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

#![cfg(feature = "storage-sqlite")]

use std::path::{Path, PathBuf};
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

/// Exchanges replayable at spec 31cf874: pub-004, pub-005, pub-008, ret-001.
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

/// All 28 fixture families the pinned spec (`registries/profiles.json`'s
/// `fixture_families` object) declares, as of SHA `31cf874`. Every one has
/// fixtures on disk and is classified (replayed or skipped-with-reason) by
/// this harness. Listing all 28 — not just the ones we replay — is the
/// honest statement "we have looked at every family"; a 29th family (the
/// spec adding a new fixture prefix) is what turns
/// `all_conformance_fixtures_are_bucketed_into_known_families` red.
const KNOWN_FAMILIES: &[&str] = &[
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
