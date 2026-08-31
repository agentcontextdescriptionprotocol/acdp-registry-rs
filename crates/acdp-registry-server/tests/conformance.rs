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
//!     (HTTP 400) with an inline body, stateless retrieval fixtures
//!     (e.g. `ret-*` GET of a missing ctx → 404), and (REG-10 Phase 8, widened
//!     Phase 9a) the `vis-*` fixtures whose `setup` + scenario(s) Shape D can
//!     fully pre-seed, sign, and verify end-to-end: `vis-006` (single
//!     exchange, Phase 8's proof fixture), `vis-001` (5 scenarios), and
//!     `vis-004` (4 scenarios) — the last two include a per-scenario
//!     `context_subset_for_test.contributors`, folded into the seed at seed
//!     time (see [`parse_shape_d`]'s fold step doc comment for why that's
//!     faithful to the fixture's "mutate the seeded row" framing).
//!   * **Skipped — requires pre-seeded state** — `idem-*` and other
//!     fixtures whose `setup`/`preconditions` (top-level or under `input`)
//!     need a context with a specific registry-assigned `ctx_id` the publish
//!     API won't let us mint, PLUS the `vis-*`/`ret-*` fixtures whose
//!     `setup` shape Shape D doesn't recognize at all (`setup.lineages` —
//!     `vis-008`, `ret-002`). As of Phase 9a, `vis-001`, `vis-004`, and
//!     `vis-006` have escaped this bucket via Shape D (below).
//!   * **Skipped — Shape D: unrecognized scenario/expected key** — the rest
//!     of `vis-*` (`vis-002`, `vis-005`, `vis-007`, `vis-009`): Shape D CAN
//!     seed these (their `setup` fully parses) but at least one scenario or
//!     `expected` key is outside its allowlist (`matches_ctx_ids`,
//!     `total_estimate`, …). A distinct reason from the bucket above so a
//!     future widening of the allowlist (Phase 9c) is auditable: it's the
//!     scenario shape, not the seeding, blocking these.
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
//! `extract_shapes` (below) dispatches every fixture through exactly one of
//! four shapes, tried in this order:
//!
//!   * **Shape A** — top-level `request` + `expected`: one self-contained
//!     exchange (`pub-*` negative publishes, most singleton fixtures).
//!   * **Shape D** — `setup` present AND (`scenarios` present OR (`input` +
//!     top-level `expected` present)): a *stateful* fixture that needs
//!     pre-seeded registry state before it can replay at all (REG-10 Phase
//!     8). Dispatched **ahead of Shape B**, deliberately: a `setup`-carrying
//!     fixture's `scenarios[]` (e.g. `vis-001`) also satisfies Shape B's own
//!     predicate (`request` + `expected` per scenario), and Shape B has no
//!     seeding step — if it ran first it would silently replay such a
//!     fixture against an empty store, turning "context doesn't exist yet"
//!     404s into false-negative passes. Shape D seeds `setup.context_published`
//!     / `setup.contexts_published` through the real publish API (substituting
//!     the fixture's unmintable literal `ctx_id`s and any non-`did:web`
//!     `agent_id`s — see [`replay_shape_d`] and its `SeedContext`/`did_map`
//!     handling), mints a per-scenario bearer from `effective_requester_did`
//!     (no `Authorization` header when it's `null`), and rebuilds the router
//!     when a scenario's `registry_capabilities_subset` overrides
//!     `anonymous_public_reads`. A fixture whose seeding shape or scenario
//!     assertions Shape D doesn't yet recognize (`setup.lineages`,
//!     `matches_ctx_ids`, `context_subset_for_test`, …) is deliberately left
//!     to `unseeded_precondition_reason`'s skip path rather than partially
//!     replayed — see [`parse_shape_d`]. Each Shape D fixture gets its own
//!     fresh in-memory store ([`common::SeededHarness`]), never the shared
//!     `app` Shapes A/B/C replay against.
//!   * **Shape B** — `scenarios[]`, each a self-contained `request` +
//!     `expected` (multi-scenario fixtures Shape D doesn't yet claim).
//!   * **Shape C** — retrieval-by-template: `input.endpoint =
//!     "GET /contexts/{ctx_id}"` + `input.ctx_id` (`ret-*`).
//!
//! Shapes A, B, and C are unmodified by Phase 8 — Shape D takes precedence
//! purely by trying its (narrower, `setup`-gated) predicate first.
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
//!
//! `can-*` (RFC-ACDP-0001 canonicalization & hashing vectors) is likewise
//! not HTTP-replayable -- the family carries no request/response shape at
//! all, just JCS canonicalization/hash golden vectors (`can-*.json`'s
//! `vectors[]`) and, for `can-007` alone, a registry-clock-truncation
//! table with no `input`/hash at all. REG-10 Phase 7 gives it DIRECT
//! fixture-driven coverage, same precedent as `anc`/`wit` above:
//! `can_vectors_reproduce_canonical_form_and_hash` drives `acdp::crypto`'s
//! public JCS surface (`canonicalize_value`, `canonical_preimage`,
//! `derive_lineage_id`) against 30 of the family's 35 vectors, and
//! `can007_registry_created_at_millisecond_truncation` drives this repo's
//! own `acdp::time::trunc_ms` -- the function `acdp-registry-sqlite`/
//! `acdp-registry-pg` actually call when minting `created_at` -- against
//! the remaining 5. As with `anc-004` above, most of `can`'s vectors
//! re-test `acdp-crypto`'s own golden vectors rather than this repo's
//! code; `can_vectors_reproduce_canonical_form_and_hash`'s own doc comment
//! records the counter-argument (the coverage ratchet makes `can`
//! mechanically inexcusable, and the conformance claim is about the
//! binary as shipped, not about which crate owns the tested code). `can`'s
//! *classification* here is unchanged -- it was never `EXCUSED` and still
//! isn't (all 12 ids sit in `acdp-registry-core`'s `required_fixtures`,
//! see `KNOWN_FAMILIES`'s doc comment) -- only its *coverage* changed.
//!
//! `vis-003` (RFC-ACDP-0005 §2.2 search response field-naming) is likewise
//! not reachable through the generic replay loop -- it carries no `setup`
//! (only `background`), and its `scenarios[]` use `input.endpoint` /
//! `input.received_response`, not `request.method`/`request.path`, so it
//! matches neither Shape D (no `setup`) nor Shape B (no `request` at all;
//! it falls through Shape B's own scenario loop to
//! `"scenarios carried no replayable request"`, the family's manifest
//! classification here). REG-10 Phase 9a gives its one registry-side
//! scenario (index 0: registry MUST emit `matches`, MUST NOT emit
//! `results`) DIRECT coverage via
//! `vis003_search_response_emits_matches_not_results`, which drives a real
//! `GET /contexts/search` and asserts on the real response body -- beside,
//! not instead of, the replay manifest above, same precedent as `anc`/`wit`/
//! `can`. Its other two scenarios (indices 1-2) are consumer-side
//! obligations (`expected.consumer_behavior` /
//! `expected.minimum_diagnostic_content`) a registry implementation cannot
//! satisfy or violate by construction -- they describe how a CONSUMER of
//! this registry's response must behave, not this registry's own behavior --
//! and are recorded not-applicable, with this reasoning, in that same test's
//! doc comment rather than silently dropped.

#![cfg(feature = "storage-sqlite")]

mod common;

use std::path::{Path, PathBuf};
#[cfg(feature = "playground")]
use std::sync::Arc;

use common::{body_to_json, body_to_json_lenient, pct_encode_path_segment};

use acdp::crypto::SigningKey;
use acdp::producer::Producer;
#[cfg(feature = "playground")]
use acdp::registry::RegistryServer;
use acdp::types::capabilities::{CapabilitiesDocument, Limits};
use acdp::types::primitives::{AgentDid, ContentHash, ContextType, CtxId, Visibility};
use acdp::types::publish::PublishRequest;
use acdp::AnchorEntry;
#[cfg(feature = "playground")]
use acdp_registry_auth::{
    AuthService, ChallengeStore, InMemoryChallengeStore, JwtSecret, JwtSigner,
};
#[cfg(feature = "playground")]
use acdp_registry_core::{build_router, AppStateInner};
#[cfg(feature = "playground")]
use acdp_registry_sqlite::SqliteStore;
#[cfg(feature = "playground")]
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{
    AuthConfig, LimitsConfig, PlaygroundConfig, RegistryConfig, RegistrySection, StorageBackend,
    StorageConfig, WebhookConfig, REGISTRY_ADVERTISABLE_PROFILES,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
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

/// Shape D's own `RegistryConfig`, layered on [`config()`]: identical
/// except `auth.enabled = true`.
///
/// GAP 1 fixer-pass finding: `config()`'s `auth.enabled` is left at its
/// default `false` (Shapes A/B/C's shared, stateless `harness()` never
/// needs caller identity), but `acdp-registry-core`'s
/// `caller_from_headers` gates bearer parsing behind exactly that flag --
/// `if !state.config.auth.enabled { return Ok(None); }`. Shape D mints a
/// real per-scenario bearer from `effective_requester_did`
/// ([`replay_shape_d`]) specifically so restricted/private/audience
/// visibility checks (RFC-ACDP-0008 §4.5) can distinguish producer vs.
/// audience vs. outsider -- with `auth.enabled` left `false`, every one of
/// those bearers would be silently ignored and every Shape D scenario
/// would replay anonymously regardless of `effective_requester_did`,
/// which would make GAP 1's `did_map` bug (and its fix) unobservable
/// through HTTP replay -- exactly the failure mode the GAP 1 write-up
/// describes ("Scenario 1... would then get a bearer sub =
/// shape-d-2... 1 match instead of 2") requires a *working* bearer path
/// to even manifest. Scoped to Shape D's own harness only -- `config()`
/// itself, and therefore Shapes A/B/C's shared `app`/`harness()`, is
/// unchanged.
fn shape_d_config() -> RegistryConfig {
    let mut cfg = config();
    cfg.auth.enabled = true;
    cfg
}

async fn harness() -> axum::Router {
    common::build_harness_with_webhook(
        config(),
        caps(),
        AUTHORITY,
        common::StoreMode::Memory,
        None,
        None,
    )
    .await
    .router
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
    /// A *stateful* fixture Shape D fully understands: pre-seed, then
    /// replay one or more scenarios against the seeded store. See
    /// [`replay_shape_d`] and the module doc-block's Shape D writeup.
    RunStateful(ShapeDPlan),
    /// Not replayable through the public API; carries a human reason.
    Skip(&'static str),
}

// ── Shape D (REG-10 Phase 8): `setup` + (`scenarios` OR (`input` +
// `expected`)) ───────────────────────────────────────────────────────────
//
// Everything below builds and executes a `ShapeDPlan`. See the module
// doc-block for the high-level writeup and `extract_shapes`'s Shape D
// dispatch block for *why* it runs ahead of Shape B.

/// One `setup.context_published` / one element of `setup.contexts_published`
/// — the two seeding shapes this phase handles. `setup.lineages` (`vis-008`)
/// is deliberately NOT modeled here; see [`parse_seed_plan`].
#[derive(Debug, Clone)]
struct SeedContext {
    /// The fixture's own literal `ctx_id` — never mintable as-is
    /// (`pub-013` proves the registry must reject a producer-supplied
    /// `ctx_id`), so every request path referencing it must be rewritten
    /// through the substitution map [`replay_shape_d`] builds.
    fixture_ctx_id: String,
    /// Literal fixture `agent_id`, if the seed shape carries one at all
    /// (`contexts_published` entries in `vis-002`/`vis-005`/`vis-009` do
    /// not). `None` gets a harness-minted `did:web` default.
    agent_id: Option<String>,
    title: Option<String>,
    visibility: String,
    audience: Vec<String>,
    /// Contributors folded onto this seed from any scenario's
    /// `request.context_subset_for_test.contributors` (REG-10 Phase 9a —
    /// `vis-001` scenario 5, `vis-004` scenario 4). Empty for every seed
    /// shape Phase 8 handled; never populated by `setup` itself (no fixture
    /// carries `contributors` there). See [`parse_shape_d`]'s fold step for
    /// why applying it at seed time is faithful to the fixture's own
    /// "per-scenario mutation of the seeded row" framing rather than an
    /// identity swap.
    contributors: Vec<String>,
}

/// One HTTP exchange inside a Shape D plan: either one element of a
/// fixture's `scenarios[]`, or the fixture's own single `input` +
/// top-level `expected` (`vis-006`'s shape — no `scenarios` at all).
#[derive(Debug, Clone)]
struct ShapeDScenario {
    method: String,
    path: String,
    /// `None` ⇒ send no `Authorization` header at all (anonymous).
    effective_requester_did: Option<String>,
    /// `Some(b)` when the scenario's `registry_capabilities_subset`
    /// overrides `anonymous_public_reads`; forces a router rebuild.
    anonymous_public_reads_override: Option<bool>,
    want_status: u16,
    want_error_code: Option<String>,
    want_matches_count: Option<u64>,
    want_match_summary_contains: Option<Value>,
    /// This scenario's own `request.context_subset_for_test.contributors`
    /// (REG-10 Phase 9a), if any -- purely a parse-time carrier.
    /// [`parse_shape_d`] drains this into the (single) seed's
    /// [`SeedContext::contributors`] before replay ever starts; by the time
    /// [`replay_shape_d`] runs, this field is inert. Always empty for the
    /// single-exchange (`vis-006`) shape, which has no `request` at all.
    contributors_for_seed: Vec<String>,
}

/// A fully-parsed, fully-understood Shape D fixture: every `setup` entry
/// and every scenario used only keys this phase recognizes. Built by
/// [`parse_shape_d`]; replayed by [`replay_shape_d`].
#[derive(Debug, Clone)]
struct ShapeDPlan {
    seeds: Vec<SeedContext>,
    scenarios: Vec<ShapeDScenario>,
}

/// The CORRECTED Shape D dispatch predicate (see the Phase 8 plan
/// correction — the original "`setup` and `scenarios`" wording can never
/// match `vis-006`, the proof fixture, which has no `scenarios` at all):
/// `setup` present AND (`scenarios` present OR (`input` AND `expected`
/// present)).
fn is_shape_d_candidate(fx: &Value) -> bool {
    fx.get("setup").is_some()
        && (fx.get("scenarios").is_some()
            || (fx.get("input").is_some() && fx.get("expected").is_some()))
}

/// Parse one `context_published` / `contexts_published` element. `None`
/// when the object carries any key outside the recognized set — this is
/// the mechanism that keeps Shape D from silently half-seeding a shape it
/// doesn't fully understand yet.
fn parse_seed_context(v: &Value) -> Option<SeedContext> {
    let obj = v.as_object()?;
    const KNOWN: &[&str] = &["ctx_id", "agent_id", "title", "visibility", "audience"];
    if obj.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return None;
    }
    let fixture_ctx_id = obj.get("ctx_id")?.as_str()?.to_string();
    let visibility = obj.get("visibility")?.as_str()?.to_string();
    let agent_id = obj
        .get("agent_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let title = obj.get("title").and_then(Value::as_str).map(str::to_string);
    let audience = obj
        .get("audience")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(SeedContext {
        fixture_ctx_id,
        agent_id,
        title,
        visibility,
        audience,
        // Never populated from `setup` itself -- only [`parse_shape_d`]'s
        // fold step (from a scenario's `context_subset_for_test`) fills
        // this in, after this function returns.
        contributors: Vec::new(),
    })
}

/// Parse `setup` into seed contexts. `None` when `setup` carries anything
/// other than exactly one of `context_published` (object) /
/// `contexts_published` (array) — in particular `setup.lineages`
/// (`vis-008`), which is Phase 9c's job and must keep skipping via
/// `unseeded_precondition_reason` until then.
fn parse_seed_plan(setup: &Value) -> Option<Vec<SeedContext>> {
    let obj = setup.as_object()?;
    const KNOWN: &[&str] = &["context_published", "contexts_published"];
    if obj.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return None;
    }
    match (obj.get("context_published"), obj.get("contexts_published")) {
        (Some(single), None) => Some(vec![parse_seed_context(single)?]),
        (None, Some(Value::Array(list))) => list.iter().map(parse_seed_context).collect(),
        _ => None,
    }
}

/// The parts of an `expected` object Shape D actually asserts on. Returned
/// by [`parse_expected`] instead of a tuple (clippy's `type_complexity`).
struct ParsedExpected {
    status: u16,
    error_code: Option<String>,
    matches_count: Option<u64>,
    match_summary_contains: Option<Value>,
}

/// Parse an `expected` object shared by both scenario forms. Returns
/// `None` when it carries any key outside the recognized assertable /
/// purely-descriptive set — e.g. `total_estimate`, `matches_ctx_ids`,
/// `match_visibility_field_disposition`, `response_body_constraints`.
/// This allowlist is precisely what keeps Phase 8 scoped to `vis-006`
/// alone: every other `vis-*` fixture's `expected` uses at least one key
/// outside it. `match_visibility`, `outcome`, `rationale`,
/// `implementer_note`, and `notes` are recognized but purely descriptive
/// (never asserted) — `match_summary_contains` already covers the
/// disclosure assertion `match_visibility` restates.
fn parse_expected(expected: &Value) -> Option<ParsedExpected> {
    let obj = expected.as_object()?;
    const RECOGNIZED: &[&str] = &[
        "status",
        "http_status",
        "error_code",
        "matches_count",
        "match_summary_contains",
        "match_visibility",
        "outcome",
        "rationale",
        "implementer_note",
        "notes",
    ];
    if obj.keys().any(|k| !RECOGNIZED.contains(&k.as_str())) {
        return None;
    }
    let status = want_status(expected)?;
    Some(ParsedExpected {
        status,
        error_code: want_error_code(expected),
        matches_count: expected.get("matches_count").and_then(Value::as_u64),
        match_summary_contains: expected.get("match_summary_contains").cloned(),
    })
}

/// Parse `vis-006`'s single-exchange shape: top-level `input` + top-level
/// `expected`, no `scenarios` at all.
fn parse_single_exchange_scenario(fx: &Value) -> Option<ShapeDScenario> {
    let input = fx.get("input")?.as_object()?;
    const KNOWN: &[&str] = &["endpoint", "effective_requester_did"];
    if input.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return None;
    }
    let (method, path) = input.get("endpoint")?.as_str()?.split_once(' ')?;
    let effective_requester_did = match input.get("effective_requester_did") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return None,
    };
    let expected = parse_expected(fx.get("expected")?)?;
    Some(ShapeDScenario {
        method: method.to_uppercase(),
        path: path.to_string(),
        effective_requester_did,
        anonymous_public_reads_override: None,
        want_status: expected.status,
        want_error_code: expected.error_code,
        want_matches_count: expected.matches_count,
        want_match_summary_contains: expected.match_summary_contains,
        contributors_for_seed: Vec::new(),
    })
}

/// Parse a `scenarios[]` array (the `vis-001`-style multi-scenario shape).
/// `None` (via `Option`'s `FromIterator`) as soon as any single scenario
/// carries a request field Shape D doesn't handle yet. As of REG-10 Phase
/// 9a, `request.context_subset_for_test` IS recognized — `{"contributors":
/// [...]}`, and only that shape (`vis-001` scenario 5, `vis-004` scenario
/// 4): the DIDs listed become part of the SEEDED row's `contributors` (see
/// [`parse_shape_d`]'s fold step), never a per-request override. Any other
/// key inside `context_subset_for_test`, or any request key outside
/// `KNOWN_REQUEST`, still fails the whole fixture's parse.
fn parse_scenarios_array(scenarios: &[Value]) -> Option<Vec<ShapeDScenario>> {
    scenarios
        .iter()
        .map(|sc| {
            const KNOWN_SCENARIO: &[&str] = &["name", "request", "expected", "notes"];
            if sc
                .as_object()?
                .keys()
                .any(|k| !KNOWN_SCENARIO.contains(&k.as_str()))
            {
                return None;
            }
            let req = sc.get("request")?.as_object()?;
            const KNOWN_REQUEST: &[&str] = &[
                "method",
                "path",
                "effective_requester_did",
                "registry_capabilities_subset",
                "context_subset_for_test",
            ];
            if req.keys().any(|k| !KNOWN_REQUEST.contains(&k.as_str())) {
                return None;
            }
            let method = req.get("method")?.as_str()?.to_uppercase();
            let path = req.get("path")?.as_str()?.to_string();
            let effective_requester_did = match req.get("effective_requester_did") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                _ => return None,
            };
            let anonymous_public_reads_override = match req.get("registry_capabilities_subset") {
                None => None,
                Some(v) => {
                    let obj = v.as_object()?;
                    if obj.len() != 1 {
                        return None;
                    }
                    obj.get("anonymous_public_reads")?.as_bool()
                }
            };
            // `context_subset_for_test`: exactly `{"contributors": [..]}` --
            // any other shape (a future fixture using a different key
            // inside it) still fails the parse rather than being silently
            // ignored.
            let contributors_for_seed = match req.get("context_subset_for_test") {
                None => Vec::new(),
                Some(v) => {
                    let obj = v.as_object()?;
                    if obj.len() != 1 {
                        return None;
                    }
                    obj.get("contributors")?
                        .as_array()?
                        .iter()
                        .map(|d| d.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()?
                }
            };
            let expected = parse_expected(sc.get("expected")?)?;
            Some(ShapeDScenario {
                method,
                path,
                effective_requester_did,
                anonymous_public_reads_override,
                want_status: expected.status,
                want_error_code: expected.error_code,
                want_matches_count: expected.matches_count,
                want_match_summary_contains: expected.match_summary_contains,
                contributors_for_seed,
            })
        })
        .collect()
}

/// Fully parse a Shape D candidate into a plan, or `None` when any part of
/// it (the seed shape, or any one scenario) uses a key this phase doesn't
/// recognize. `unseeded_precondition_reason` calls this to decide whether a
/// `setup`-carrying fixture escapes the generic pre-seeded-state skip;
/// `extract_shapes` calls it again to build the plan it actually replays.
/// A fixture only ever reaches [`replay_shape_d`] once both call sites
/// agree it parses.
fn parse_shape_d(fx: &Value) -> Option<ShapeDPlan> {
    let mut seeds = parse_seed_plan(fx.get("setup")?)?;
    // `contexts_published: []` parses to `Some(vec![])` in `parse_seed_plan`
    // -- that shape is a syntactically valid (if useless) seed list, not a
    // parse failure. But `replay_shape_d` asserts its `ctx_map` is
    // non-empty afterward, so a plan with zero seeds must never reach it:
    // treat it the same as an unrecognized seed shape here (`None`), which
    // routes the fixture to `extract()`'s skip path with its own distinct
    // reason instead of panicking mid-replay.
    if seeds.is_empty() {
        return None;
    }
    let scenarios = if let Some(arr) = fx.get("scenarios").and_then(Value::as_array) {
        parse_scenarios_array(arr)?
    } else if fx.get("input").is_some() && fx.get("expected").is_some() {
        vec![parse_single_exchange_scenario(fx)?]
    } else {
        return None;
    };
    if scenarios.is_empty() {
        return None;
    }

    // REG-10 Phase 9a: fold any scenario's `context_subset_for_test.
    // contributors` onto the seed it targets, applied at seed time (the
    // registry's only write path is `POST /contexts`, which mints a NEW
    // ctx_id per call -- there is no in-place "update contributors on this
    // existing ctx_id" endpoint, so a true "mutate the row immediately
    // before firing this one scenario" is not expressible through the
    // public HTTP API at all). Applying it at seed time is observably
    // identical to that framing for every fixture this reaches: `vis-001`
    // and `vis-004` are both single-seed, and `contributors` never affects
    // any OTHER scenario's status/error_code (RFC-ACDP-0002 §7 /
    // RFC-ACDP-0008 §4.5 -- contributors carries attribution, not
    // retrieval/search authorization: `can_retrieve` and
    // `can_surface_in_search` branch only on visibility / agent_id /
    // audience / anonymous_public_reads), so no earlier scenario in the
    // same fixture can observe the row having gained a contributor it
    // didn't ask about.
    //
    // SCOPE, and do NOT carry this reasoning further than it goes: the
    // claim holds on the RETRIEVAL and SEARCH axis only. `contributors`
    // DOES gate authorization on the supersession producer-continuity
    // path (`prev_contributors.contains(&req.agent_id)` in the sqlite/pg
    // stores and in handlers/admin.rs). These two fixtures are
    // retrieval-only, so seed-time folding is sound here. A future
    // publish/supersede fixture folded the same way WOULD change
    // authorization, and must not reuse this justification.
    //
    // Second bound: the fold pools contributors from every scenario onto
    // the single seed. Correct while the single-seed guard below holds --
    // a fixture with two DIFFERING `context_subset_for_test` scenarios
    // would hand scenario A's row scenario B's contributor, and the guard
    // would not fire on it.
    // Fail closed (`None`) rather than guess when more than one seed
    // exists -- Shape D doesn't yet know which seed a multi-seed fixture's
    // `context_subset_for_test` would target, and no pinned fixture at this
    // pin needs that (both current uses are single-seed).
    let extra_contributors: Vec<String> = scenarios
        .iter()
        .flat_map(|s| s.contributors_for_seed.iter().cloned())
        .collect();
    if !extra_contributors.is_empty() {
        if seeds.len() != 1 {
            return None;
        }
        for c in extra_contributors {
            if !seeds[0].contributors.contains(&c) {
                seeds[0].contributors.push(c);
            }
        }
    }

    Some(ShapeDPlan { seeds, scenarios })
}

/// A signing producer whose `agent_id` is exactly `did` -- used both for a
/// fixture literal `agent_id` that's already `did:web` (no substitution
/// needed, e.g. `vis-006`/`vis-007`'s `did:web:agents.example.com:test-producer`)
/// and for a freshly-minted substitute (`did:web:agents.test:shape-d-{seed}`).
/// `seed` only needs to be distinct per producer within one fixture replay.
fn shape_d_producer(did: &str, seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(did.to_string()),
        format!("{did}#key-1"),
    )
}

/// Parse a fixture's literal `visibility` string into [`Visibility`].
/// Panics on an unrecognized value -- `parse_seed_context` already
/// requires the key to be present and a string, so an unrecognized value
/// here means the pinned spec introduced a fourth visibility level, which
/// is worth failing loudly on rather than silently mis-seeding.
fn shape_d_visibility(s: &str) -> Visibility {
    serde_json::from_value(json!(s))
        .unwrap_or_else(|e| panic!("Shape D: unrecognized visibility {s:?}: {e}"))
}

/// Rewrite every occurrence of a fixture's literal `ctx_id` in `path` (raw
/// or single-segment percent-encoded, matching how `request.path` /
/// `input.ctx_id` each appear across the corpus) with its minted
/// replacement. Used both to build the actual request path and, by the
/// caller, to assert no un-substituted literal ctx_id survives into it.
fn substitute_ctx_ids_in_path(
    path: &str,
    ctx_map: &std::collections::BTreeMap<String, String>,
) -> String {
    let mut out = path.to_string();
    for (fixture_ctx, minted_ctx) in ctx_map {
        let encoded_fixture = pct_encode_path_segment(fixture_ctx);
        let encoded_minted = pct_encode_path_segment(minted_ctx);
        if out.contains(&encoded_fixture) {
            out = out.replace(&encoded_fixture, &encoded_minted);
        } else if out.contains(fixture_ctx.as_str()) {
            out = out.replace(fixture_ctx.as_str(), minted_ctx.as_str());
        }
    }
    out
}

/// Result of replaying one Shape D plan: how many scenario exchanges
/// matched their expectation, every mismatch found (empty ⇒ full pass),
/// and the substitution maps built while seeding -- exposed so the
/// dedicated `vis-006` proof test can assert on them directly (the Phase 8
/// plan's Correction 3: completeness, not non-emptiness, since the DID map
/// is legitimately empty for `vis-006`).
#[derive(Debug)]
struct ShapeDResult {
    ran: usize,
    failures: Vec<String>,
    ctx_map: std::collections::BTreeMap<String, String>,
    did_map: std::collections::BTreeMap<String, String>,
}

/// Replay one Shape D plan end-to-end.
///
/// 1. **Isolation**: a fresh in-memory [`common::SeededHarness`] -- never
///    the shared `app` Shapes A/B/C replay against.
/// 2. **Seed**: publish every `setup` context through the real publish API
///    (never a direct store write), substituting each fixture's unmintable
///    literal `ctx_id` (`ctx_map`) and, for any seeded `agent_id` that
///    isn't already `did:web` (`caps().supported_did_methods`), minting a
///    substitute `did:web` producer this harness holds the key for
///    (`did_map`). `audience` entries pass through the SAME `did_map`
///    lookup as requester DIDs (falling back to the literal string when
///    absent) so an audience-membership check stays consistent with
///    whichever bearer `sub` a scenario presents -- `contributors` would be
///    exempt from this entirely (per the plan), but no seed shape Phase 8
///    handles carries any. A seed publish that does not return 200 PANICS
///    -- never skips -- per the plan's edge-case note: a mis-seeded
///    fixture that silently skipped would be indistinguishable from a
///    genuinely passing one.
/// 3. **Replay**: mint a bearer per scenario from `effective_requester_did`
///    (no `Authorization` header at all when it's `null`), rebuilding the
///    router whenever a scenario's `anonymous_public_reads_override`
///    differs from the router's current setting. Per-scenario assertion
///    mismatches are collected into `failures` rather than panicking, so
///    the mutation proof (a deliberately-broken `vis-006` copy) can
///    observe a non-empty `failures` without aborting the whole test
///    binary.
async fn replay_shape_d(name: &str, plan: &ShapeDPlan) -> ShapeDResult {
    let mut harness = common::SeededHarness::new(shape_d_config(), caps(), AUTHORITY).await;

    let mut ctx_map = std::collections::BTreeMap::new();
    let mut did_map = std::collections::BTreeMap::new();

    // Pass 1: mint every non-`did:web` literal `agent_id` exactly ONCE,
    // before any seed is published. Two seeds can legitimately share one
    // literal `agent_id` (e.g. `vis-005`'s two `contexts_published`
    // entries both carry `did:agent:owner`) -- minting inline, per-seed,
    // as the loop below used to do would silently overwrite the first
    // mint's `did_map` entry with a second, DIFFERENT minted DID, leaving
    // the first-seeded context "owned" by a DID no longer reachable
    // through `did_map` (see the module doc-block / REG-10 Phase 8 GAP 1
    // writeup). `did_map.entry(..).or_insert_with(..)` makes the mapping
    // idempotent: however many seeds name the same literal agent, they
    // all resolve to the SAME minted `did:web`. Doing this as its own
    // pass, ahead of any publish, also means pass 2's `audience`
    // resolution below can never race a seed whose `agent_id` is only
    // minted by a LATER seed in `plan.seeds` -- every literal agent DID
    // this plan will ever mint is already in `did_map` before pass 2
    // starts.
    let mut mint_seq: u8 = 1;
    for seed in &plan.seeds {
        let literal_agent = seed
            .agent_id
            .clone()
            .unwrap_or_else(|| "did:web:agents.test:shape-d-default".to_string());
        if !literal_agent.starts_with("did:web:") {
            did_map.entry(literal_agent).or_insert_with(|| {
                let minted = format!("did:web:agents.test:shape-d-{mint_seq}");
                mint_seq = mint_seq.wrapping_add(1);
                minted
            });
        }
    }

    // Pass 2: publish every seed, resolving both its own `agent_id` and
    // every `audience` entry against the now-complete `did_map` built
    // above.
    let mut seed_seq: u8 = 1;
    for seed in &plan.seeds {
        let literal_agent = seed
            .agent_id
            .clone()
            .unwrap_or_else(|| "did:web:agents.test:shape-d-default".to_string());
        let seeded_agent = did_map
            .get(&literal_agent)
            .cloned()
            .unwrap_or(literal_agent);
        assert!(
            seeded_agent.starts_with("did:web:"),
            "{name}: every seeded agent_id must be did:web (caps().supported_did_methods); \
             got {seeded_agent}"
        );
        let producer = shape_d_producer(&seeded_agent, seed_seq);
        seed_seq = seed_seq.wrapping_add(1);

        // An `audience` entry resolves through `did_map` ONLY when it
        // matches some seed's own literal `agent_id` elsewhere in this
        // plan (pass 1 above minted a substitute for every such literal,
        // regardless of seeding order -- the two-pass fix). Most audience
        // DIDs name a pure consumer identity that never publishes
        // anything itself (e.g. `vis-001`'s `did:agent:authorized_consumer`)
        // and so never appears in `did_map` at all -- those pass through
        // UNCHANGED, exactly like the requester-bearer `sub` resolution
        // below (`did_map.get(did).unwrap_or_else(|| did.clone())`), so
        // audience membership and bearer identity stay consistent with
        // each other even for a literal, non-`did:web` DID.
        let audience: Vec<AgentDid> = seed
            .audience
            .iter()
            .map(|a| AgentDid::new(did_map.get(a).cloned().unwrap_or_else(|| a.clone())))
            .collect();

        // `contributors` (REG-10 Phase 9a) is exempt from `did_map`
        // substitution entirely, same as the module doc-block already
        // established for the pre-existing `pub-010` coverage: contributors
        // is attribution metadata, not an authorization identity, so it
        // never needs to be a `did:web` DID this harness holds a key for.
        let contributors: Vec<AgentDid> = seed
            .contributors
            .iter()
            .cloned()
            .map(AgentDid::new)
            .collect();

        let mut builder = producer
            .publish_request()
            .title(
                seed.title
                    .clone()
                    .unwrap_or_else(|| format!("Shape D seed ({name})")),
            )
            .context_type(ContextType::DataSnapshot)
            .visibility(shape_d_visibility(&seed.visibility));
        if !audience.is_empty() {
            builder = builder.audience(audience);
        }
        if !contributors.is_empty() {
            builder = builder.contributors(contributors);
        }
        let req = builder
            .build()
            .unwrap_or_else(|e| panic!("{name}: Shape D seed request failed to build: {e}"));

        let (status, body) = common::publish(&harness.router, &req, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{name}: Shape D seed publish for fixture ctx_id {} MUST succeed -- a failed seed \
             panics, it never skips; body = {body}",
            seed.fixture_ctx_id
        );
        let minted_ctx = body["ctx_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: seed publish response carried no ctx_id: {body}"))
            .to_string();
        ctx_map.insert(seed.fixture_ctx_id.clone(), minted_ctx);
    }
    assert!(
        !ctx_map.is_empty(),
        "{name}: Shape D ctx_id substitution map must be non-empty for every `vis` fixture"
    );

    let mut current_anon = shape_d_config().auth.anonymous_public_reads;
    let mut ran = 0usize;
    let mut failures = Vec::new();

    for sc in &plan.scenarios {
        let desired_anon = sc.anonymous_public_reads_override.unwrap_or(current_anon);
        if desired_anon != current_anon {
            let mut cfg = shape_d_config();
            cfg.auth.anonymous_public_reads = desired_anon;
            // `anonymous_public_reads` is authorization-relevant behavior
            // (`RegistryServer::search`/`::retrieve` gate off `caps`, not
            // off `RegistryConfig` -- see `SeededHarness::rebuild`'s doc
            // comment / GAP 3), so the `CapabilitiesDocument` passed to
            // `rebuild` must carry the override too, not just `cfg`.
            let mut new_caps = caps();
            new_caps.anonymous_public_reads = desired_anon;
            harness.rebuild(cfg, new_caps);
            current_anon = desired_anon;
        }

        let mut path = substitute_ctx_ids_in_path(&sc.path, &ctx_map);
        // GET paths may carry a raw `acdp://` ctx_id needing single-segment
        // percent-encoding for axum's `{ctx_id}` matcher -- mirrors the
        // main replay loop's own handling for Shapes A/B/C.
        if path.contains("acdp://") && sc.method == "GET" {
            if let Some(idx) = path.rfind('/') {
                let seg = &path[idx + 1..];
                path = format!("{}/{}", &path[..idx], pct_encode_path_segment(seg));
            }
        }
        for fixture_ctx in ctx_map.keys() {
            assert!(
                !path.contains(fixture_ctx.as_str()),
                "{name}: fixture ctx_id {fixture_ctx} leaked into request path unsubstituted: {path}"
            );
        }

        let mut builder = Request::builder().method(sc.method.as_str()).uri(&path);
        if let Some(did) = &sc.effective_requester_did {
            let sub = did_map.get(did).cloned().unwrap_or_else(|| did.clone());
            let bearer = common::forged_bearer(&sub, &format!("{name}-{sub}"), 300);
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let resp = harness
            .router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let got_status = resp.status().as_u16();
        let body_json = body_to_json_lenient(resp).await;

        let mut mismatch = None;
        if got_status != sc.want_status {
            mismatch = Some(format!(
                "{name}: status {got_status} != {}; body = {body_json}",
                sc.want_status
            ));
        } else if let Some(code) = &sc.want_error_code {
            let actual = body_json
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_str);
            if actual != Some(code.as_str()) {
                mismatch = Some(format!(
                    "{name}: error code {actual:?} != {code:?}; body = {body_json}"
                ));
            }
        }
        if mismatch.is_none() {
            if let Some(n) = sc.want_matches_count {
                let got_n = body_json
                    .get("matches")
                    .and_then(Value::as_array)
                    .map(|a| a.len() as u64);
                if got_n != Some(n) {
                    mismatch = Some(format!(
                        "{name}: matches_count {got_n:?} != {n}; body = {body_json}"
                    ));
                }
            }
        }
        if mismatch.is_none() {
            if let Some(contains) = &sc.want_match_summary_contains {
                let first = body_json
                    .get("matches")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first());
                match first {
                    None => {
                        mismatch = Some(format!(
                            "{name}: match_summary_contains asserted but matches[] is empty; \
                             body = {body_json}"
                        ))
                    }
                    Some(m) => {
                        if let Err(reason) = json_contains(m, contains) {
                            mismatch = Some(format!("{name}: {reason}; body = {body_json}"));
                        }
                    }
                }
            }
        }

        match mismatch {
            Some(f) => failures.push(f),
            None => ran += 1,
        }
    }

    ShapeDResult {
        ran,
        failures,
        ctx_map,
        did_map,
    }
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

/// The skip reason for a fixture that carries an unseeded precondition, or
/// `None` when Shape D fully understands the fixture (it should be
/// replayed, not skipped). All four of the pinned corpus's
/// precondition-carrying keys — top-level `setup`/`preconditions`, or
/// `input.precondition`/`input.preconditions` — mean the fixture needs a
/// ctx the publish API won't let us mint (registry assigns `ctx_id`), so we
/// skip those UNLESS Shape D (REG-10 Phase 8) fully understands how to
/// pre-seed and replay it — narrowed, not deleted, per the Phase 8 plan.
/// `is_shape_d_candidate` alone is not enough (it's deliberately broad —
/// see the module doc-block); `parse_shape_d(fx).is_some()` is what
/// actually proves every `setup` entry and every scenario used only
/// recognized keys.
///
/// A Shape D candidate that fails to fully parse gets one of two DISTINCT
/// reasons, so a future widening of Shape D's allowlist (Phase 9a/9c) is
/// auditable rather than lumped into one catch-all bucket:
///
///   * its `setup` shape itself is unrecognized (e.g. `setup.lineages` —
///     `vis-008`, `ret-002`) — Shape D cannot even SEED these yet, so they
///     keep the generic `"requires pre-seeded registry state"` reason;
///   * its `setup` parses fine (Shape D COULD seed it) but some
///     scenario/expected key is outside the allowlist (e.g. `vis-007`'s
///     `total_estimate`, `vis-002`'s `matches_ctx_ids`) — these get
///     `"Shape D: unrecognized scenario/expected key"`, naming precisely
///     what's blocking them: the scenario shape, not the seeding. (As of
///     REG-10 Phase 9a, `vis-001` and `vis-004` no longer land here —
///     `context_subset_for_test.contributors` is now recognized; see
///     [`parse_scenarios_array`] and [`parse_shape_d`]'s fold step.)
///
/// An empty `contexts_published: []` seed list is its own third reason
/// (`parse_shape_d` treats it as unparseable — see its doc comment — so it
/// never reaches [`replay_shape_d`] and panics on an empty `ctx_map`).
fn unseeded_precondition_reason(fx: &Value) -> Option<&'static str> {
    if is_shape_d_candidate(fx) {
        if parse_shape_d(fx).is_some() {
            return None;
        }
        if let Some(seeds) = fx.get("setup").and_then(parse_seed_plan) {
            return Some(if seeds.is_empty() {
                "Shape D: empty contexts_published seed list"
            } else {
                "Shape D: unrecognized scenario/expected key"
            });
        }
        // else: `setup` itself didn't parse (e.g. `setup.lineages`) — fall
        // through to the generic reason below.
    }
    if fx.get("setup").is_some()
        || fx.get("preconditions").is_some()
        || fx
            .get("input")
            .is_some_and(|i| i.get("precondition").is_some() || i.get("preconditions").is_some())
    {
        return Some("requires pre-seeded registry state");
    }
    None
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
    if let Some(reason) = unseeded_precondition_reason(fx) {
        return Extracted::Skip(reason);
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
// Sibling note to Shape A's non-400-publish refusal below (the "A publish
// fixture is only deterministically replayable to a *schema/validation*
// (400) outcome" comment, just inside the `is_publish` branch): that
// refusal applies only to fixtures replayed as an HTTP *exchange* through
// `extract_shapes`'s own generic path. Shape D's seeding step
// ([`replay_shape_d`]) never goes through `extract_shapes` at all -- it
// calls `common::publish` directly with a request THIS harness signs
// itself (title/visibility/audience lifted from `setup.context_published`
// / `.contexts_published`, everything else supplied fresh), the same
// technique the `anc-*`/`wit-*` direct-coverage tests already use
// elsewhere in this file. A seeded publish is therefore expected to
// succeed (200), not merely tolerated as a 400 — and per the Phase 8 plan,
// a seed publish that does NOT return 200 is a hard bug in the harness's
// own request construction, so `replay_shape_d` panics on it rather than
// skipping or recording it as a fixture mismatch.
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
    // Shape D: `setup` present AND (`scenarios` present OR (`input` +
    // `expected` present)) -- REG-10 Phase 8. Dispatched HERE, ahead of
    // Shape B: a `setup`-carrying fixture's `scenarios[]` (e.g. `vis-001`)
    // also satisfies Shape B's own predicate (`request` + `expected` per
    // scenario), and Shape B has no seeding step at all -- if it ran first
    // it would silently replay such a fixture against an empty store,
    // turning "context doesn't exist yet" 404s into false-negative passes.
    // See the module doc-block for the full writeup. Shapes A (above) and
    // B/C (below) are unmodified by this phase -- Shape D wins purely by
    // trying its narrower, `setup`-gated predicate first.
    if is_shape_d_candidate(fx) {
        let plan = parse_shape_d(fx).expect(
            "extract_shapes is only reached once extract()'s unseeded_precondition_reason() gate \
             has already confirmed is_shape_d_candidate(fx) && parse_shape_d(fx).is_some()",
        );
        return Extracted::RunStateful(plan);
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

/// Exchanges replayable at spec 417211f: pub-004, pub-005, pub-008, ret-001
/// (Shapes A/C: 4), plus vis-006's 1 scenario (Shape D, REG-10 Phase 8's
/// proof fixture), plus (REG-10 Phase 9a) vis-001's 5 scenarios and
/// vis-004's 4 scenarios -- 4 + 1 + 5 + 4 = 14. A gate that accidentally
/// over-matches must fail loudly, not quietly shrink coverage to a
/// still-nonzero number. Raise this as coverage grows.
const MIN_REPLAYED_EXCHANGES: usize = 14;

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
            Extracted::RunStateful(plan) => {
                let result = replay_shape_d(&name, &plan).await;
                eprintln!(
                    "conformance: {name} replayed via Shape D ({} exchange(s), {} failure(s))",
                    result.ran,
                    result.failures.len()
                );
                failures.extend(result.failures);
                replayed += result.ran;
                *ran.entry(family.clone()).or_insert(0) += result.ran;
                continue;
            }
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
            let body_json = body_to_json_lenient(resp).await;

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

/// REG-10 Phase 8 regression canary. The gravest failure mode of this phase
/// is Shape D over-matching and capturing a fixture Shape A or C already
/// handles — dispatching Shape D ahead of Shape B (`extract_shapes`, right
/// before the "Shape B: `scenarios[]`" comment) exists specifically to
/// avoid that. This proves it directly, not by inference from a green
/// suite: `extract()` on each of the four exchanges replayed before this
/// phase (`pub-004`, `pub-005`, `pub-008` via Shape A; `ret-001` via Shape
/// C) still returns `Extracted::Run` (never `RunStateful`), and the
/// extracted `Exchange`'s fields still match the fixture content
/// field-for-field, exactly as they did before Shape D existed.
#[tokio::test(flavor = "multi_thread")]
async fn four_pre_existing_exchanges_still_use_original_shapes() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping regression \
             canary (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };

    // pub-004, pub-005, pub-008: Shape A, publish branch.
    for id in ["pub-004", "pub-005", "pub-008"] {
        let Some(fx) = find_fixture_by_id(&fixtures, id) else {
            return;
        };
        assert!(
            !is_shape_d_candidate(&fx),
            "{id} carries no `setup`, so it must not even be a Shape D candidate"
        );
        let Extracted::Run(exchanges) = extract(&fx) else {
            panic!("{id} must still extract via Shape A (Extracted::Run)");
        };
        assert_eq!(
            exchanges.len(),
            1,
            "{id}: Shape A yields exactly one exchange"
        );
        let ex = &exchanges[0];
        assert_eq!(
            ex.method,
            fx["request"]["method"].as_str().unwrap().to_uppercase(),
            "{id}: method"
        );
        assert_eq!(
            ex.path,
            fx["request"]["path"].as_str().unwrap(),
            "{id}: path"
        );
        assert_eq!(
            ex.body,
            fx["request"].get("body").cloned(),
            "{id}: body must still be the fixture's own request.body"
        );
        assert_eq!(
            ex.want_status,
            fx["expected"]["status"].as_u64().unwrap() as u16,
            "{id}: want_status"
        );
        assert!(
            ex.want_error_code.is_none(),
            "{id}: Shape A's publish branch never pins an error code (validation ordering is \
             impl-defined) -- this must still hold"
        );
    }

    // ret-001: Shape C, retrieval-by-template.
    let Some(fx) = find_fixture_by_id(&fixtures, "ret-001") else {
        return;
    };
    assert!(
        !is_shape_d_candidate(&fx),
        "ret-001 carries no `setup`, so it must not even be a Shape D candidate"
    );
    let Extracted::Run(exchanges) = extract(&fx) else {
        panic!("ret-001 must still extract via Shape C (Extracted::Run)");
    };
    assert_eq!(
        exchanges.len(),
        1,
        "ret-001: Shape C yields exactly one exchange"
    );
    let ex = &exchanges[0];
    assert_eq!(ex.method, "GET");
    assert_eq!(
        ex.path,
        format!(
            "/contexts/{}",
            pct_encode_path_segment(fx["input"]["ctx_id"].as_str().unwrap())
        ),
        "ret-001: path must still be Shape C's substituted /contexts/{{ctx_id}}"
    );
    assert_eq!(ex.want_status, 404);
    assert_eq!(ex.want_error_code.as_deref(), Some("not_found"));
}

/// REG-10 Phase 8's proof fixture. `vis-006` is the only single-exchange
/// `vis` fixture (`setup.context_published` + `input` + top-level
/// `expected`, no `scenarios`), so it exercises all five Shape D
/// capabilities (ctx_id substitution, the DID substitution table, `setup`
/// handling, per-scenario identity, and per-fixture isolation) in one
/// fixture. Driven directly through `extract`/`replay_shape_d` rather than
/// via the shared replay loop, so the mutation proof below can inspect
/// `ShapeDResult::failures` without panicking this whole test binary.
#[tokio::test(flavor = "multi_thread")]
async fn vis006_search_match_public_visibility_disclosure_replays_via_shape_d() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping vis-006 \
             Shape D proof (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "vis-006") else {
        return;
    };

    assert!(
        is_shape_d_candidate(&fx),
        "vis-006 must satisfy the corrected Shape D predicate: setup present AND (scenarios \
         present OR (input AND expected present)) -- it has no `scenarios`, only input+expected"
    );
    let plan = parse_shape_d(&fx).expect("vis-006 is Shape D's proof fixture and must fully parse");
    assert_eq!(plan.seeds.len(), 1, "vis-006 seeds exactly one context");
    assert_eq!(
        plan.scenarios.len(),
        1,
        "vis-006 is the single-exchange input+expected form, not scenarios[]"
    );

    let result = replay_shape_d("vis-006", &plan).await;
    assert!(
        result.failures.is_empty(),
        "vis-006 must replay cleanly via Shape D: {:?}",
        result.failures
    );
    assert_eq!(result.ran, 1);

    // Correction 3 (the Phase 8 plan): the ctx_id map is non-empty for
    // every `vis` fixture.
    assert_eq!(
        result.ctx_map.len(),
        1,
        "vis-006's ctx_id substitution map must contain exactly its one seeded context"
    );
    // ...but the DID map is legitimately EMPTY here: vis-006 already seeds
    // `did:web:agents.example.com:test-producer`, which needs no
    // substitution at all (unlike vis-001/004/005/008's `did:agent:owner`).
    // Asserting it non-empty would be unsatisfiable on this fixture.
    assert!(
        result.did_map.is_empty(),
        "vis-006 seeds an already-did:web agent_id; the DID map must be empty here, not \
         merely non-empty-somewhere-else: {:?}",
        result.did_map
    );

    // Mutation proof: an in-memory-only clone of the fixture (never
    // written to the spec checkout -- the whole point is to never touch
    // it) with the seeded context's visibility flipped to `restricted`
    // must FAIL vis-006's own expectation (a public match disclosing
    // `visibility: "public"`). This proves the harness is exercising the
    // registry's real visibility-scoping logic, not trivially returning
    // green regardless of what's seeded. `restricted` requires a non-empty
    // `audience` (the SDK's own publish-request builder enforces this --
    // seeding would otherwise panic as a hard seed-build failure, not a
    // soft replay mismatch), so the mutation also adds one audience DID
    // that is deliberately NOT vis-006's search requester
    // (`did:agent:any-authenticated-or-anonymous`) -- the seeded context
    // still publishes cleanly, but now sits outside the searcher's
    // visibility, and the search's own `matches_count: 1` expectation
    // must fail.
    let mut mutated = fx.clone();
    mutated["setup"]["context_published"]["visibility"] = json!("restricted");
    mutated["setup"]["context_published"]["audience"] = json!(["did:agent:someone-else"]);
    let mutated_plan =
        parse_shape_d(&mutated).expect("mutated vis-006 must still parse as Shape D");
    let mutated_result = replay_shape_d("vis-006-mutated", &mutated_plan).await;
    assert!(
        !mutated_result.failures.is_empty(),
        "mutating vis-006's seeded visibility to `restricted` MUST fail replay -- if it \
         doesn't, Shape D isn't actually checking anything: {mutated_result:?}"
    );
    // Pin the KIND of failure, not just its presence: a bare
    // `!failures.is_empty()` would pass on ANY mismatch (e.g. a status-code
    // regression elsewhere), which wouldn't actually prove the harness is
    // exercising visibility scoping. The mutated context must specifically
    // drop out of the search's `matches_count`, since it's no longer public.
    assert!(
        mutated_result
            .failures
            .iter()
            .any(|f| f.contains("matches_count")),
        "mutating vis-006's seeded visibility must fail specifically on a matches_count \
         mismatch (the once-public match must disappear from the search results), not on \
         some other, unrelated failure: {:?}",
        mutated_result.failures
    );
}

/// REG-10 Phase 9a: `vis-001` (RFC-ACDP-0008 §4.5 restricted-visibility
/// existence-leak prevention) through Shape D. 5 scenarios against ONE
/// seeded restricted context, each a different requester identity: producer
/// (200), audience member (200), outsider (404 not_found), a request
/// targeting a genuinely NONEXISTENT ctx_id (404 not_found, byte-
/// indistinguishable from the outsider case), and a listed *contributor*
/// who is NOT in `audience` (404 not_found -- contributors carries
/// attribution, not retrieval authorization; see [`parse_shape_d`]'s fold
/// step for how `context_subset_for_test.contributors` reaches the seed,
/// and for why that reasoning stops at the retrieval/search axis).
///
/// This is the first fixture in this file whose scenarios require the
/// bearer path to genuinely DISTINGUISH requester identities against the
/// SAME seeded ctx_id (`vis-006`, Phase 8's proof fixture, does not: its
/// requester is `did:agent:any-authenticated-or-anonymous` against a
/// PUBLIC context, so it behaves identically with auth on or off). If
/// Phase 8's GAP 2 fix (`shape_d_config().auth.enabled = true`) ever
/// regressed, every request here would replay anonymously and scenarios 0
/// (producer, want 200) and 1 (audience member, want 200) would both
/// mismatch against the anonymous-gets-404 outcome -- so this fixture
/// passing with zero failures IS the proof the bearer path works, not an
/// inference from a green suite elsewhere.
#[tokio::test(flavor = "multi_thread")]
async fn vis001_restricted_denied_as_404_replays_via_shape_d() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping vis-001 \
             Shape D proof (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "vis-001") else {
        return;
    };

    // Shape A must never capture this fixture unseeded: it carries no
    // top-level `request` at all, only `setup` + `scenarios`.
    assert!(
        fx.get("request").is_none(),
        "vis-001 must carry no top-level `request` -- otherwise Shape A could capture it \
         ahead of Shape D and replay it against an empty store"
    );
    assert!(
        is_shape_d_candidate(&fx),
        "vis-001 must satisfy the Shape D dispatch predicate"
    );

    let plan =
        parse_shape_d(&fx).expect("vis-001 must fully parse as Shape D as of REG-10 Phase 9a");
    assert_eq!(
        plan.seeds.len(),
        1,
        "vis-001 seeds exactly one restricted context"
    );
    assert_eq!(plan.scenarios.len(), 5, "vis-001 carries 5 scenarios");

    // The contributor scenario's `context_subset_for_test.contributors`
    // DID must have been folded onto the (only) seed.
    assert_eq!(
        plan.seeds[0].contributors,
        vec!["did:agent:listed_contributor".to_string()],
        "vis-001 scenario 5's context_subset_for_test.contributors must be folded onto the \
         seed, not dropped: {:?}",
        plan.seeds[0].contributors
    );

    // Concrete evidence the fixture actually requires identity
    // differentiation (see doc comment above): the producer scenario wants
    // 200 from one requester DID, the outsider scenario wants 404 from a
    // DIFFERENT requester DID against the exact same seeded ctx_id.
    assert_eq!(plan.scenarios[0].want_status, 200);
    assert_eq!(plan.scenarios[2].want_status, 404);
    assert_ne!(
        plan.scenarios[0].effective_requester_did, plan.scenarios[2].effective_requester_did,
        "the 200-vs-404 split must come from different requester identities, not path/method"
    );

    let result = replay_shape_d("vis-001", &plan).await;
    assert!(
        result.failures.is_empty(),
        "vis-001 must replay cleanly via Shape D: {:?}",
        result.failures
    );
    assert_eq!(result.ran, 5);

    // Edge case 1 (REG-10 Phase 9a): scenario 4 targets a genuinely
    // NONEXISTENT ctx_id (`...000000000000`, distinct from the seeded
    // `...000000000001`). It must NOT have been seeded and must NOT have
    // gained a substitution entry -- the ctx_id map must contain ONLY the
    // one context this fixture actually seeded.
    assert_eq!(
        result.ctx_map.len(),
        1,
        "vis-001's ctx_id substitution map must contain exactly its one seeded context, not \
         the nonexistent ctx_id scenario 4 targets: {:?}",
        result.ctx_map
    );
    assert!(
        result
            .ctx_map
            .contains_key("acdp://registry.example.com/00000000-0000-4000-8000-000000000001"),
        "the seeded ctx_id must be present in the substitution map: {:?}",
        result.ctx_map
    );
    assert!(
        !result
            .ctx_map
            .contains_key("acdp://registry.example.com/00000000-0000-4000-8000-000000000000"),
        "the NONEXISTENT ctx_id scenario 4 targets must never gain a substitution entry -- it \
         was never seeded, and must reach the registry as the literal, unmintable string: {:?}",
        result.ctx_map
    );
}

/// REG-10 Phase 9a: `vis-004` (RFC-ACDP-0008 §4.5 / RFC-ACDP-0002 §7
/// private/audience retrieval asymmetry) through Shape D. 4 scenarios
/// against ONE seeded private context with `audience: [did:agent:
/// audience_member]`: producer (200), audience member (200), outsider (404
/// not_found), and a listed *contributor* who is NOT in `audience` (404
/// not_found -- same contributors-is-not-authorization proof as vis-001's
/// scenario 5, via the same `context_subset_for_test.contributors` fold).
#[tokio::test(flavor = "multi_thread")]
async fn vis004_private_audience_retrieval_allowed_replays_via_shape_d() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping vis-004 \
             Shape D proof (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "vis-004") else {
        return;
    };

    assert!(
        fx.get("request").is_none(),
        "vis-004 must carry no top-level `request` -- otherwise Shape A could capture it \
         ahead of Shape D and replay it against an empty store"
    );
    assert!(
        is_shape_d_candidate(&fx),
        "vis-004 must satisfy the Shape D dispatch predicate"
    );

    let plan =
        parse_shape_d(&fx).expect("vis-004 must fully parse as Shape D as of REG-10 Phase 9a");
    assert_eq!(
        plan.seeds.len(),
        1,
        "vis-004 seeds exactly one private context"
    );
    assert_eq!(plan.scenarios.len(), 4, "vis-004 carries 4 scenarios");
    assert_eq!(
        plan.seeds[0].contributors,
        vec!["did:agent:listed_contributor".to_string()],
        "vis-004 scenario 4's context_subset_for_test.contributors must be folded onto the \
         seed, not dropped: {:?}",
        plan.seeds[0].contributors
    );
    assert_eq!(
        plan.seeds[0].audience,
        vec!["did:agent:audience_member".to_string()]
    );

    let result = replay_shape_d("vis-004", &plan).await;
    assert!(
        result.failures.is_empty(),
        "vis-004 must replay cleanly via Shape D: {:?}",
        result.failures
    );
    assert_eq!(result.ran, 4);
    assert_eq!(
        result.ctx_map.len(),
        1,
        "vis-004's ctx_id substitution map must contain exactly its one seeded context: {:?}",
        result.ctx_map
    );

    // Mutation proof: an in-memory-only clone of the fixture (never written
    // to the spec checkout) with the seeded context's visibility flipped
    // from `private` to `public`. Scenario 3 (the outsider, who is neither
    // producer nor in `audience`) expects 404 not_found specifically
    // because the context is private; under `public` visibility an outsider
    // CAN retrieve it (200), so this MUST fail replay -- proving the
    // harness is exercising the registry's real private/audience scoping,
    // not trivially returning green regardless of what's seeded. `audience`
    // must be cleared too -- the SDK's publish-request builder itself
    // rejects `visibility: public` with a non-empty `audience` (schema
    // violation), so leaving it in place would fail at SEED time (a hard
    // panic, per Shape D's "a failed seed panics" rule) rather than
    // demonstrating the intended REPLAY mismatch.
    let mut mutated = fx.clone();
    mutated["setup"]["context_published"]["visibility"] = json!("public");
    mutated["setup"]["context_published"]["audience"] = json!([]);
    let mutated_plan =
        parse_shape_d(&mutated).expect("mutated vis-004 must still parse as Shape D");
    let mutated_result = replay_shape_d("vis-004-mutated", &mutated_plan).await;
    assert!(
        !mutated_result.failures.is_empty(),
        "mutating vis-004's seeded visibility to `public` MUST fail replay -- if it doesn't, \
         Shape D isn't actually checking anything: {mutated_result:?}"
    );
    assert!(
        mutated_result.failures.iter().any(|f| f.contains("!= 404")),
        "mutating vis-004's seeded visibility to `public` must fail specifically on a \
         404-expected-but-not-gotten mismatch (the outsider scenario, no longer blocked by \
         privacy), not on some other, unrelated failure: {:?}",
        mutated_result.failures
    );
}

/// REG-10 Phase 8 GAP 1 / GAP 2 regression proof: a synthetic, in-test-only
/// fixture (never read from the spec checkout -- this exercises a shape no
/// pinned fixture currently reaches, since `vis-002`/`vis-005`/`vis-009`
/// are all still excluded by `parse_expected`'s allowlist) whose
/// `setup.contexts_published` carries THREE entries: two share one
/// non-`did:web` literal `agent_id` (mirroring `vis-005`'s two
/// `did:agent:owner` entries exactly -- the shape that will trip GAP 1 the
/// moment `vis-005` itself is admitted in a later phase), and a third
/// names a DIFFERENT agent that only the SECOND entry's `audience`
/// forward-references (proving the two-pass mint/seed fix, not just the
/// `did_map.entry` dedup).
///
/// Before the fix: seeding entry 1 (private, owned by `did:agent:owner`)
/// minted `shape-d-1` and recorded it in `did_map`; seeding entry 2 (also
/// `did:agent:owner`) minted a SECOND, different DID `shape-d-2` and
/// OVERWROTE `did_map["did:agent:owner"]` with it. The owner-search
/// scenario below then resolved its own bearer `sub` through the
/// (now-overwritten) `did_map` and got `shape-d-2` -- which does not own
/// entry 1 -- so entry 1 (privately scoped, agent_id-only search
/// visibility) silently dropped out of the owner's own search results:
/// `matches_count` was 1, not 2. After the fix, both entries resolve
/// through the SAME `did_map` entry, and the owner's search correctly
/// finds both.
#[tokio::test(flavor = "multi_thread")]
async fn shape_d_seeding_maps_one_shared_literal_agent_to_one_minted_did() {
    let fx = json!({
        "id": "shape-d-test-shared-agent-two-pass",
        "setup": {
            "contexts_published": [
                {
                    "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-0000000000f1",
                    "agent_id": "did:agent:owner",
                    "title": "Gap1owner secret",
                    "visibility": "private",
                    "audience": ["did:agent:later-seeded"]
                },
                {
                    "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-0000000000f2",
                    "agent_id": "did:agent:owner",
                    "title": "Gap1owner public",
                    "visibility": "public"
                },
                {
                    "ctx_id": "acdp://registry.example.com/00000000-0000-4000-8000-0000000000f3",
                    "agent_id": "did:agent:later-seeded",
                    "title": "Gap1 later-seeded agent's own context",
                    "visibility": "public"
                }
            ]
        },
        "scenarios": [
            {
                "name": "Owner (agent_id) searches and sees both of their own contexts",
                "request": {
                    "method": "GET",
                    "path": "/contexts/search?q=Gap1owner",
                    "effective_requester_did": "did:agent:owner"
                },
                "expected": {"status": 200, "matches_count": 2}
            },
            {
                "name": "Later-seeded agent (audience of entry 1, seeded 3rd) retrieves it by ctx_id",
                "request": {
                    "method": "GET",
                    "path": "/contexts/acdp%3A%2F%2Fregistry.example.com%2F00000000-0000-4000-8000-0000000000f1",
                    "effective_requester_did": "did:agent:later-seeded"
                },
                "expected": {"status": 200}
            }
        ]
    });

    assert!(
        is_shape_d_candidate(&fx),
        "synthetic fixture must satisfy the Shape D dispatch predicate"
    );
    let plan =
        parse_shape_d(&fx).expect("synthetic shared-agent fixture must fully parse as Shape D");
    assert_eq!(plan.seeds.len(), 3, "three contexts_published entries");
    assert_eq!(plan.seeds[0].agent_id.as_deref(), Some("did:agent:owner"));
    assert_eq!(
        plan.seeds[1].agent_id.as_deref(),
        Some("did:agent:owner"),
        "entries 0 and 1 MUST share one literal, non-did:web agent_id -- this is the exact \
         shape that trips GAP 1"
    );

    let result = replay_shape_d("shape-d-test-shared-agent-two-pass", &plan).await;
    assert!(
        result.failures.is_empty(),
        "GAP 1 AFTER the fix: both contexts_published entries sharing `did:agent:owner` \
         must resolve to ONE minted producer DID, so the owner's own search sees both \
         (matches_count: 2) and the later-seeded audience member's retrieval succeeds. A \
         non-empty failures list here means the did_map overwrite bug (or the ordering bug) \
         is back: {:?}",
        result.failures
    );
    assert_eq!(
        result.ran, 2,
        "both scenarios (owner search, later-seeded audience retrieval) must pass"
    );

    // Structural proof, not just behavioral: `did_map` holds exactly one
    // entry per distinct literal non-did:web agent (2: `did:agent:owner`,
    // `did:agent:later-seeded`) -- never one per seed (3).
    assert_eq!(
        result.did_map.len(),
        2,
        "did_map must hold exactly one entry per distinct literal agent, not one per seed \
         that names it: {:?}",
        result.did_map
    );
    assert!(
        result.did_map.contains_key("did:agent:owner"),
        "did_map must carry the shared literal agent: {:?}",
        result.did_map
    );
    assert!(
        result.did_map.contains_key("did:agent:later-seeded"),
        "did_map must resolve the forward-referenced (seeded 3rd, audience-referenced in \
         seed 1) agent too -- this is the two-pass fix: {:?}",
        result.did_map
    );

    // Both seeded contexts under the shared literal agent are present in
    // ctx_map (all 3 seeds published successfully).
    assert_eq!(result.ctx_map.len(), 3);
}

/// REG-10 Phase 8 GAP 3 regression proof: [`common::SeededHarness::rebuild`]
/// is wired into `replay_shape_d` (for a scenario's
/// `registry_capabilities_subset` override) but no pinned fixture reaches
/// it yet. This proves `rebuild` directly, against the one endpoint
/// `anonymous_public_reads` actually gates (keyword search -- RFC-ACDP-0005
/// §2.5.5 / RFC-ACDP-0008 §6.3; direct retrieval by known `ctx_id` is NOT
/// gated by this flag, only by visibility itself, so a GET-by-`ctx_id`
/// probe would prove nothing here -- see `vis-009`): (a) it actually
/// changes the router's behavior (an anonymous search that succeeded
/// before rebuilding with `anonymous_public_reads: false` must be refused
/// after), and (b) it PRESERVES already-seeded store state across the
/// rebuild (the whole point of `SeededHarness` holding
/// `Arc<RegistryServer>`/`Arc<AuthService>` rather than tearing down and
/// re-seeding) -- proven by an AUTHENTICATED search still finding the
/// pre-rebuild context afterward (authenticated search is never gated by
/// `anonymous_public_reads`, so this isolates "is the state still there"
/// from "does the flag apply to this requester").
#[tokio::test(flavor = "multi_thread")]
async fn seeded_harness_rebuild_changes_router_behavior_and_preserves_seeded_state() {
    let mut harness = common::SeededHarness::new(shape_d_config(), caps(), AUTHORITY).await;

    let producer_did = "did:web:agents.test:rebuild-proof";
    let producer = shape_d_producer(producer_did, 200);
    let req = producer
        .publish_request()
        .title("Rebuildproof context")
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .unwrap();
    let (status, body) = common::publish(&harness.router, &req, None).await;
    assert_eq!(status, StatusCode::OK, "seed publish must succeed: {body}");
    let ctx_id = body["ctx_id"]
        .as_str()
        .expect("seed publish response carried no ctx_id")
        .to_string();

    async fn search(router: &axum::Router, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut builder = Request::builder().uri("/contexts/search?q=Rebuildproof");
        if let Some(b) = bearer {
            builder = builder.header("authorization", format!("Bearer {b}"));
        }
        let resp = router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        (status, body_to_json_lenient(resp).await)
    }

    // `shape_d_config()` sets `anonymous_public_reads: true`, so an
    // anonymous search finds the public context before any rebuild.
    let (before_status, before_body) = search(&harness.router, None).await;
    assert_eq!(
        before_status,
        StatusCode::OK,
        "anonymous search must succeed before rebuild: {before_body}"
    );
    assert_eq!(
        before_body["matches"].as_array().map(|a| a.len()),
        Some(1),
        "anonymous search must find the seeded public context before rebuild: {before_body}"
    );

    let mut cfg = shape_d_config();
    cfg.auth.anonymous_public_reads = false;
    let mut new_caps = caps();
    new_caps.anonymous_public_reads = false;
    harness.rebuild(cfg, new_caps);

    // (a) Behavior actually changed: the same anonymous search must now be
    // refused outright (RFC-ACDP-0008 §6.3: `not_authorized`, no
    // matches/total_estimate leak), not merely return zero matches.
    let (after_status, after_body) = search(&harness.router, None).await;
    assert_ne!(
        after_status,
        StatusCode::OK,
        "rebuild must actually take effect: anonymous_public_reads: false must refuse the \
         same anonymous search that succeeded before rebuild: {after_body}"
    );

    // (b) State survived: the context seeded BEFORE rebuild is still
    // findable AFTER it, via an AUTHENTICATED search (never gated by
    // anonymous_public_reads) as its own producer.
    let bearer = common::forged_bearer(producer_did, "seeded-harness-rebuild-proof", 300);
    let (authed_status, authed_body) = search(&harness.router, Some(&bearer)).await;
    assert_eq!(
        authed_status,
        StatusCode::OK,
        "authenticated search must succeed after rebuild: {authed_body}"
    );
    assert_eq!(
        authed_body["matches"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|m| m["ctx_id"].as_str()),
        Some(ctx_id.as_str()),
        "rebuild must preserve already-seeded store state -- the context published before \
         rebuild must still be findable (authenticated) after it: {authed_body}"
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

// ─── REG-10 Phase 9a: vis-003 (search response field-naming) ─────────────

/// vis-003 (RFC-ACDP-0005 §2.2): the search response's wrapping array MUST
/// be named `matches`; a registry MUST NOT emit `results` (or any other
/// alternative spelling). Neither Shape D (no `setup`, only `background`)
/// nor Shape B (scenarios use `input.endpoint`/`input.received_response`,
/// never `request.method`/`request.path`) can reach this fixture — see the
/// module doc-block's `vis-003` paragraph. This test drives it DIRECTLY,
/// same precedent as `anc-*`/`wit-*`/`can-*` elsewhere in this file:
///
///   * **Scenario 0 ("registry-side")** is the one this registry can
///     actually be checked against: a REAL `GET /contexts/search` fired at
///     the shared harness, asserting the fixture's own
///     `expected.response_body_constraints` on the REAL response body --
///     `matches` MUST be present, `results` (and every listed alternate
///     spelling) MUST NOT be. Read directly off the fixture rather than
///     hand-duplicated, so a spec-side rewording of the constraint keys
///     would fail this test's own parsing rather than silently going stale.
///   * **Scenarios 1-2 ("consumer-side")** are recorded NOT APPLICABLE, in
///     this doc comment, with a reason, rather than silently dropped: both
///     carry `expected.consumer_behavior` (scenario 1: a consumer MUST NOT
///     silently coerce `results` to `matches`) and scenario 2 additionally
///     carries `expected.minimum_diagnostic_content` (a consumer SHOULD
///     surface an observable diagnostic naming the misuse). Both describe
///     obligations on a CONSUMER of a (deliberately non-conformant, per the
///     fixture's own `background`) response -- not on this registry's own
///     behavior. A registry has no consumer role to exercise here, so there
///     is no HTTP exchange, in-process call, or assertion this repo could
///     make that would exercise either scenario; the assertions below only
///     confirm the two scenarios are still shaped exactly the way this
///     analysis depends on, so a future fixture edit that changed their
///     meaning would fail loudly here rather than the reasoning silently
///     going stale.
#[tokio::test(flavor = "multi_thread")]
async fn vis003_search_response_emits_matches_not_results() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping vis-003 \
             (set ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "vis-003") else {
        return;
    };
    assert!(
        fx.get("setup").is_none(),
        "vis-003 must carry no `setup` -- confirms it can never reach Shape D"
    );
    let scenarios = fx["scenarios"]
        .as_array()
        .expect("vis-003 must carry a scenarios[] array");
    assert_eq!(scenarios.len(), 3, "vis-003 must carry exactly 3 scenarios");

    // Scenario 0: registry-side, the only HTTP-replayable one.
    let sc0 = &scenarios[0];
    assert!(
        sc0.get("request").is_none(),
        "vis-003 scenario 0 must carry no `request` key -- confirms Shape B's own predicate \
         (request + expected) cannot reach it either"
    );
    let endpoint = sc0["input"]["endpoint"]
        .as_str()
        .expect("vis-003 scenario 0 must carry input.endpoint");
    let (method, path) = endpoint
        .split_once(' ')
        .expect("input.endpoint must be \"METHOD path\"");
    assert_eq!(method, "GET");
    let want_status = sc0["expected"]["http_status"]
        .as_u64()
        .expect("vis-003 scenario 0 must carry expected.http_status") as u16;
    let constraints = &sc0["expected"]["response_body_constraints"];
    let must_have_key = constraints["MUST_have_key"]
        .as_str()
        .expect("vis-003 scenario 0 must carry response_body_constraints.MUST_have_key");
    let must_not_have_key = constraints["MUST_NOT_have_key"]
        .as_str()
        .expect("vis-003 scenario 0 must carry response_body_constraints.MUST_NOT_have_key");
    let must_not_have_alternates: Vec<&str> = constraints["MUST_NOT_have_key_alternates"]
        .as_array()
        .expect(
            "vis-003 scenario 0 must carry response_body_constraints.MUST_NOT_have_key_alternates",
        )
        .iter()
        .map(|v| v.as_str().expect("alternate key must be a string"))
        .collect();
    assert!(
        !must_not_have_alternates.is_empty(),
        "vis-003's MUST_NOT_have_key_alternates must be non-empty"
    );

    let app = harness().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let got_status = resp.status().as_u16();
    let body = body_to_json_lenient(resp).await;
    assert_eq!(
        got_status, want_status,
        "vis-003 scenario 0: GET {path} status; body = {body}"
    );
    let obj = body.as_object().unwrap_or_else(|| {
        panic!("vis-003 scenario 0: search response must be a JSON object: {body}")
    });
    assert!(
        obj.contains_key(must_have_key),
        "vis-003 scenario 0: search response MUST have key \"{must_have_key}\": {body}"
    );
    assert!(
        !obj.contains_key(must_not_have_key),
        "vis-003 scenario 0: search response MUST NOT have key \"{must_not_have_key}\": {body}"
    );
    for alt in &must_not_have_alternates {
        assert!(
            !obj.contains_key(*alt),
            "vis-003 scenario 0: search response MUST NOT have alternate key \"{alt}\": {body}"
        );
    }

    // Scenarios 1-2: consumer-side, not applicable to a registry -- see
    // this test's doc comment for the full reasoning. Assert their SHAPE
    // only, so this reasoning cannot silently go stale.
    for (idx, expect_diagnostic) in [(1usize, false), (2usize, true)] {
        let sc = &scenarios[idx];
        assert!(
            sc.get("request").is_none()
                && sc.get("input").and_then(|i| i.get("endpoint")).is_none(),
            "vis-003 scenario {idx} must carry no replayable HTTP request -- it is consumer-side"
        );
        assert_eq!(
            sc["expected"]["outcome"].as_str(),
            Some("failure"),
            "vis-003 scenario {idx} must describe a consumer-observed failure outcome"
        );
        assert!(
            sc["expected"]["consumer_behavior"].is_string(),
            "vis-003 scenario {idx} must carry expected.consumer_behavior -- confirms it's a \
             consumer-side obligation, not a registry one"
        );
        assert_eq!(
            sc["expected"]["minimum_diagnostic_content"].is_array(),
            expect_diagnostic,
            "vis-003 scenario {idx}: minimum_diagnostic_content presence must match the known \
             fixture shape (only scenario 2 carries it)"
        );
    }
    eprintln!(
        "conformance: vis-003 scenarios 1-2 (consumer_behavior / minimum_diagnostic_content) \
         are consumer-side obligations a registry cannot satisfy or violate; not applicable, \
         see vis003_search_response_emits_matches_not_results's doc comment"
    );
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
    let mut cfg = config();
    cfg.playground.enabled = false;
    common::build_harness_with_webhook(cfg, caps, AUTHORITY, common::StoreMode::Memory, None, None)
        .await
        .router
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
    common::build_harness_with_webhook(
        config(),
        anc_caps_050(),
        AUTHORITY,
        common::StoreMode::Memory,
        None,
        None,
    )
    .await
    .router
}

/// A signing producer identity for the anc-* tests, isolated from any other
/// test's seed space — mirrors `http_integration.rs`'s `producer()`.
fn anc_producer(seed: u8) -> Producer {
    common::producer("anc", seed)
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

// ─── REG-10 Phase 7 (plans/reg10-conformance-and-ci-hygiene.md): can-*
// canonicalization & hashing vector coverage ───
//
// None of the 12 can-* fixtures is HTTP-replayable (no request/response
// shape at all -- see the module doc-comment's `can-*` paragraph), yet all
// 12 ids sit in the pinned spec's `acdp-registry-core.required_fixtures`,
// which makes `can` mechanically inexcusable under `EXCUSED`'s rule 1
// (`no_excused_family_is_required_by_our_profile`, below). So, following
// the same "direct, fixture-driven, in-process" precedent as `anc`/`wit`
// above, the two tests in this section consume every can-* fixture's own
// data directly instead of going through the generic replayer.
//
// TENSION, recorded rather than left implicit (per the phase plan): the
// anc-004/anc-005 paragraph above argues AGAINST re-testing an upstream
// crate's own golden vectors -- "Duplicating anc-004 here would just
// re-test an upstream crate's own golden vector." That objection applies
// just as much to can-001..006/008..012: they are `acdp-crypto`'s own JCS/
// hash golden vectors (`acdp-crypto-0.8.4/src/hash.rs`'s and
// `acdp-jcs-0.8.4/src/lib.rs`'s own `#[cfg(test)]` modules already cover
// several of the same values, e.g. `lineage_id_golden`). The counter,
// which is why this phase exists anyway: unlike anc-004/anc-005 (excused
// on a *spec-grounded* basis -- neither is in any acdp-registry-core
// required/conditional fixture list), all 12 can-* ids ARE required by
// this repo's own advertised profile, so `EXCUSED` mechanically refuses an
// excuse here regardless of how compelling the "pure library vector"
// argument sounds. A conformance claim made about this binary has to cover
// every fixture the binary's own profile requires -- who else in the
// dependency chain already tested the same value is a cost/duplication
// argument, not a coverage argument, and the ratchet is deliberately deaf
// to cost/duplication arguments.

/// can-* vector count pinned at spec `417211f` (REG-10 Phase 7): **35**
/// total across all 12 can-* fixtures. Split into two constants because
/// can-007 alone carries no `input`/hash at all (see
/// `can007_registry_created_at_millisecond_truncation`'s doc comment) and
/// is therefore asserted by a separate test:
/// `EXPECTED_CAN_HASH_VECTOR_COUNT` is the other 11 fixtures' 30
/// canonical-form/hash vectors, and can-007's own 5 are asserted as
/// `EXPECTED_CAN_VECTOR_COUNT - EXPECTED_CAN_HASH_VECTOR_COUNT` rather than
/// a third bare literal, so the two constants can't silently drift apart.
/// Either test's vector count shrinking without this constant moving is
/// the vacuous-pass failure mode this pair exists to catch.
const EXPECTED_CAN_VECTOR_COUNT: usize = 35;
const EXPECTED_CAN_HASH_VECTOR_COUNT: usize = 30;

/// Parse an RFC 3339 timestamp string as `DateTime<Utc>`, panicking
/// (naming `ctx`) on failure. can-007's fixture-supplied timestamps are
/// trusted, spec-pinned input -- a parse failure here means the fixture
/// itself changed shape, which must be loud, not silently skipped.
fn parse_rfc3339_utc(s: &str, ctx: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("{ctx}: {s:?} did not parse as RFC 3339: {e}"))
        .with_timezone(&chrono::Utc)
}

/// Assert `bytes` (a raw JCS canonicalization) and `hash` (its SHA-256,
/// `sha256:`-prefixed) both reproduce `expected`'s pinned values. Shared by
/// every can-* vector shape that carries a hash. Also asserts
/// `expected.content_hash_field_value` when present (11 of the 12 can-*
/// fixtures carry it) -- it is the same digest with its wire `sha256:`
/// prefix, i.e. the exact string RFC-ACDP-0001 §5.7 says would be stored
/// in `Body.content_hash`, so checking it is free coverage of the wire
/// format beyond the bare hex digest the plan calls out by name.
fn assert_canonical_bytes_and_hash(bytes: Vec<u8>, hash: ContentHash, expected: &Value, ctx: &str) {
    let got_form = String::from_utf8(bytes)
        .unwrap_or_else(|e| panic!("{ctx}: canonical form is not valid UTF-8: {e}"));
    let want_form = expected["canonical_form"].as_str().unwrap_or_else(|| {
        panic!("{ctx}: expected.canonical_form missing or not a string: {expected}")
    });
    assert_eq!(got_form, want_form, "{ctx}: canonical_form mismatch");

    let want_hex = expected["sha256_hex"].as_str().unwrap_or_else(|| {
        panic!("{ctx}: expected.sha256_hex missing or not a string: {expected}")
    });
    let got_hex = hash
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("{ctx}: computed hash has no 'sha256:' prefix: {hash}"));
    assert_eq!(got_hex, want_hex, "{ctx}: sha256_hex mismatch");

    if let Some(want_field) = expected
        .get("content_hash_field_value")
        .and_then(Value::as_str)
    {
        assert_eq!(
            hash.as_str(),
            want_field,
            "{ctx}: content_hash_field_value mismatch"
        );
    }
}

/// The Body/ProducerContent path: `canonical_preimage` strips the
/// RFC-ACDP-0001 §5.7 EXCLUDE set (`content_hash`, `signature`, `ctx_id`,
/// `lineage_id`, `origin_registry`, `created_at`) by name, JCS-
/// canonicalizes, and SHA-256 hashes in one call. Safe for every can-*
/// vector that genuinely represents a (Producer)Content-shaped body -- none
/// of their `input` objects carry an EXCLUDE-set key name.
fn assert_body_hash_vector(input: &Value, expected: &Value, ctx: &str) {
    let (bytes, hash) = acdp::crypto::canonical_preimage(input)
        .unwrap_or_else(|e| panic!("{ctx}: canonical_preimage failed: {e}"));
    assert_canonical_bytes_and_hash(bytes, hash, expected, ctx);
}

/// The no-hash shape: only `expected.canonical_form` exists (can-001's
/// number-formatting / array-order / null-vs-absent vectors). Uses the raw
/// `canonicalize_value` JCS API directly rather than the Body-shaped
/// `canonical_preimage` -- there is no hash to check, so there is no
/// reason to route through the content_hash-specific function at all.
fn assert_canonical_form_only(input: &Value, expected: &Value, ctx: &str) {
    let bytes = acdp::crypto::canonicalize_value(input);
    let got_form = String::from_utf8(bytes)
        .unwrap_or_else(|e| panic!("{ctx}: canonical form is not valid UTF-8: {e}"));
    let want_form = expected["canonical_form"].as_str().unwrap_or_else(|| {
        panic!("{ctx}: expected.canonical_form missing or not a string: {expected}")
    });
    assert_eq!(got_form, want_form, "{ctx}: canonical_form mismatch");
}

/// can-001's `{lineage_id}`-only vectors: `lineage_id = "lin:sha256:" +
/// lowercase_hex(SHA-256(utf8(ctx_id)))` (RFC-ACDP-0001 §5.6), computed
/// directly via `derive_lineage_id` rather than any hash-equality loop
/// over `sha256_hex` -- these vectors carry no `sha256_hex` at all.
fn assert_lineage_vector(input: &Value, expected: &Value, ctx: &str) {
    let ctx_id_str = input["ctx_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: input.ctx_id missing or not a string: {input}"));
    let lineage = acdp::crypto::derive_lineage_id(&CtxId(ctx_id_str.to_string()));
    let want = expected["lineage_id"].as_str().unwrap_or_else(|| {
        panic!("{ctx}: expected.lineage_id missing or not a string: {expected}")
    });
    assert_eq!(lineage.as_str(), want, "{ctx}: lineage_id mismatch");
}

/// can-011's vectors: bare `{"values": [...]}` JSON objects, NOT ACDP
/// bodies -- `canonicalize_value` (raw JCS), not `canonical_preimage`'s
/// Body/content_hash path, is the semantically correct API. The hash is
/// still obtained without adding a `sha2` dependency: `canonical_preimage`
/// is called too, and its canonical bytes are asserted byte-identical to
/// `canonicalize_value`'s own output BEFORE its hash is trusted -- proving,
/// per vector, that none of can-011's EXCLUDE-set-free `values` arrays
/// happened to collide with a §5.7 exclusion-set key name, i.e. that
/// reusing `canonical_preimage`'s hash here is provably equivalent to
/// hashing the raw JCS bytes directly, not an accident of today's fixture
/// contents.
fn assert_raw_jcs_hash_vector(input: &Value, expected: &Value, ctx: &str) {
    let raw_bytes = acdp::crypto::canonicalize_value(input);
    let (preimage_bytes, hash) = acdp::crypto::canonical_preimage(input)
        .unwrap_or_else(|e| panic!("{ctx}: canonical_preimage failed: {e}"));
    assert_eq!(
        raw_bytes, preimage_bytes,
        "{ctx}: canonical_preimage produced different bytes than raw canonicalize_value -- an \
         RFC-ACDP-0001 §5.7 EXCLUDE-set key name must have leaked into this vector's input, \
         which would make reusing canonical_preimage's hash here unsound (can-011's vectors \
         are bare numeric-formatting objects, not ACDP bodies)"
    );
    assert_canonical_bytes_and_hash(raw_bytes, hash, expected, ctx);
}

/// can-001..006/008..012's 30 canonicalization/hashing vectors (of the
/// family's 35 total -- can-007 is covered separately below). can-001
/// alone packs THREE distinct `expected` shapes into its 7 vectors: 1 Body
/// `{canonical_form, sha256_hex}`, 3 `{lineage_id}`-only, and 3
/// `{canonical_form}`-only with no hash at all -- a single hash-equality
/// loop would silently cover only the first of the seven, which is exactly
/// the vacuous-pass failure mode this whole phase exists to close.
#[test]
fn can_vectors_reproduce_canonical_form_and_hash() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping can-* \
             canonicalization/hash vectors (set ACDP_REQUIRE_CONFORMANCE to make this a hard \
             failure)"
        );
        return;
    };

    let mut asserted = 0usize;

    // can-001: three shapes, dispatched per-vector on which `expected` key
    // is present.
    if let Some(fx) = find_fixture_by_id(&fixtures, "can-001") {
        let vectors = fx["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("can-001: vectors missing or not an array: {fx}"));
        assert_eq!(
            vectors.len(),
            7,
            "can-001 must carry exactly 7 vectors at spec pin 417211f: {fx}"
        );
        for (i, v) in vectors.iter().enumerate() {
            let ctx = format!("can-001 vector {i} ({})", v["name"].as_str().unwrap_or("?"));
            let expected = &v["expected"];
            if expected.get("lineage_id").is_some() {
                assert_lineage_vector(&v["input"], expected, &ctx);
            } else if expected.get("sha256_hex").is_some() {
                assert_body_hash_vector(&v["input"], expected, &ctx);
            } else {
                assert!(
                    expected.get("canonical_form").is_some(),
                    "{ctx}: expected has none of lineage_id, sha256_hex, canonical_form: {v}"
                );
                assert_canonical_form_only(&v["input"], expected, &ctx);
            }
            asserted += 1;
        }
    }

    // can-011: raw JCS numeric-formatting vectors -- see
    // assert_raw_jcs_hash_vector's own comment for why they take a
    // different API than the Body vectors below.
    if let Some(fx) = find_fixture_by_id(&fixtures, "can-011") {
        let vectors = fx["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("can-011: vectors missing or not an array: {fx}"));
        assert_eq!(
            vectors.len(),
            6,
            "can-011 must carry exactly 6 vectors at spec pin 417211f: {fx}"
        );
        for (i, v) in vectors.iter().enumerate() {
            let ctx = format!("can-011 vector {i} ({})", v["name"].as_str().unwrap_or("?"));
            assert_raw_jcs_hash_vector(&v["input"], &v["expected"], &ctx);
            asserted += 1;
        }
    }

    // can-006: two vectors are the SAME logical instant at different
    // sub-second precisions. Beyond each vector's own hash matching
    // (below), explicitly assert they DIVERGE from each other -- per the
    // fixture's own description, that divergence (not either vector in
    // isolation) is the whole point.
    if let Some(fx) = find_fixture_by_id(&fixtures, "can-006") {
        let vectors = fx["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("can-006: vectors missing or not an array: {fx}"));
        assert_eq!(
            vectors.len(),
            2,
            "can-006 must carry exactly 2 vectors at spec pin 417211f: {fx}"
        );
        let forms: Vec<String> = vectors
            .iter()
            .map(|v| {
                String::from_utf8(acdp::crypto::canonicalize_value(&v["input"]))
                    .expect("can-006: canonical form is not valid UTF-8")
            })
            .collect();
        let hashes: Vec<String> = vectors
            .iter()
            .map(|v| {
                acdp::crypto::compute_content_hash(&v["input"])
                    .expect("can-006: compute_content_hash failed")
                    .as_str()
                    .to_string()
            })
            .collect();
        assert_ne!(
            forms[0], forms[1],
            "can-006: the nanosecond- and millisecond-precision vectors must have DIFFERENT \
             canonical_form -- that divergence is the fixture's whole point"
        );
        assert_ne!(
            hashes[0], hashes[1],
            "can-006: the nanosecond- and millisecond-precision vectors must have DIFFERENT \
             content_hash"
        );
        let compliances: Vec<&str> = vectors
            .iter()
            .map(|v| {
                v["producer_compliance"]
                    .as_str()
                    .unwrap_or_else(|| panic!("can-006: producer_compliance missing: {v}"))
            })
            .collect();
        assert_eq!(
            compliances,
            vec!["non-conformant", "conformant"],
            "can-006: vector 0 (nanosecond) must be labelled non-conformant and vector 1 \
             (millisecond-truncated) conformant"
        );
        for (i, v) in vectors.iter().enumerate() {
            let ctx = format!("can-006 vector {i} ({})", v["name"].as_str().unwrap_or("?"));
            assert_body_hash_vector(&v["input"], &v["expected"], &ctx);
            asserted += 1;
        }
    }

    // The remaining 8 fixtures each carry only the single Body
    // {canonical_form, sha256_hex, content_hash_field_value} shape.
    for (id, expected_len) in [
        ("can-002", 1),
        ("can-003", 1),
        ("can-004", 1),
        ("can-005", 2),
        ("can-008", 1),
        ("can-009", 1),
        ("can-010", 1),
        ("can-012", 7),
    ] {
        let Some(fx) = find_fixture_by_id(&fixtures, id) else {
            continue;
        };
        let vectors = fx["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: vectors missing or not an array: {fx}"));
        assert_eq!(
            vectors.len(),
            expected_len,
            "{id} must carry exactly {expected_len} vector(s) at spec pin 417211f: {fx}"
        );
        for (i, v) in vectors.iter().enumerate() {
            let ctx = format!("{id} vector {i} ({})", v["name"].as_str().unwrap_or("?"));
            assert_body_hash_vector(&v["input"], &v["expected"], &ctx);
            asserted += 1;
        }
    }

    assert_eq!(
        asserted, EXPECTED_CAN_HASH_VECTOR_COUNT,
        "expected exactly {EXPECTED_CAN_HASH_VECTOR_COUNT} can-* canonical-form/hash vectors at \
         spec pin 417211f across 11 of the 12 can-* fixtures (can-007 has no input/hash at all \
         and is covered separately by can007_registry_created_at_millisecond_truncation) -- a \
         silently-shrinking count here is exactly the vacuous-pass failure mode this ratchet \
         exists to prevent"
    );
}

/// can-007 (registry `created_at` millisecond-truncation table): unlike
/// every other can-* fixture, this one carries no `input`/`sha256_hex` at
/// all -- its `expected` is `{registry_compliance, rationale}`, keyed off
/// `example_created_at` (+, for 2 of 5 vectors, `registry_clock_at_acceptance`).
/// It isn't a JCS/hash golden vector, so it's asserted separately from
/// `can_vectors_reproduce_canonical_form_and_hash` above -- and, unlike
/// that test's re-tested `acdp-crypto` golden vectors (see the TENSION
/// note above this section), this one genuinely exercises code THIS repo
/// owns and calls on the publish path: `acdp::time::trunc_ms`, the exact
/// function `acdp-registry-sqlite`/`acdp-registry-pg`'s stores call when
/// minting `created_at` (`crates/acdp-registry-sqlite/src/store.rs:1001`,
/// `crates/acdp-registry-pg/src/store.rs:897`) -- reachable here as a pure
/// function of a `DateTime<Utc>`, with no server/store/auth needed.
///
/// Per vector: truncate `registry_clock_at_acceptance` (or, when absent,
/// `example_created_at` itself -- for those vectors the pinned timestamp
/// IS the un-truncated "registry clock reading") with `trunc_ms`, and
/// compare against `example_created_at`. `"conformant"` vectors must
/// truncate back to exactly `example_created_at`; `"non-conformant"`
/// vectors must NOT -- proving both that `trunc_ms` reproduces the
/// canonical form a conformant registry emits, and that it floors rather
/// than rounds (vector 5: `.1235` truncates to `.123`, never rounds up to
/// the vector's own, non-conformant `.124`).
#[test]
fn can007_registry_created_at_millisecond_truncation() {
    let Some(fixtures) = spec_fixtures() else {
        eprintln!(
            "conformance: ACDP_SPEC_DIR unset or no fixtures resolvable; skipping can-007 (set \
             ACDP_REQUIRE_CONFORMANCE to make this a hard failure)"
        );
        return;
    };
    let Some(fx) = find_fixture_by_id(&fixtures, "can-007") else {
        return;
    };
    let vectors = fx["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("can-007: vectors missing or not an array: {fx}"));
    let expected_len = EXPECTED_CAN_VECTOR_COUNT - EXPECTED_CAN_HASH_VECTOR_COUNT;
    assert_eq!(
        vectors.len(),
        expected_len,
        "can-007 must carry exactly {expected_len} vectors at spec pin 417211f: {fx}"
    );

    for (i, v) in vectors.iter().enumerate() {
        let ctx = format!("can-007 vector {i} ({})", v["name"].as_str().unwrap_or("?"));
        let example_str = v["example_created_at"]
            .as_str()
            .unwrap_or_else(|| panic!("{ctx}: example_created_at missing or not a string: {v}"));
        let example = parse_rfc3339_utc(example_str, &ctx);
        let clock_reading_str = v
            .get("registry_clock_at_acceptance")
            .and_then(Value::as_str)
            .unwrap_or(example_str);
        let clock_reading = parse_rfc3339_utc(clock_reading_str, &ctx);
        let truncated = acdp::time::trunc_ms(clock_reading);

        let compliance = v["expected"]["registry_compliance"]
            .as_str()
            .unwrap_or_else(|| panic!("{ctx}: expected.registry_compliance missing: {v}"));
        match compliance {
            "conformant" => assert_eq!(
                truncated, example,
                "{ctx}: trunc_ms(registry clock reading) must reproduce example_created_at for \
                 a conformant vector"
            ),
            "non-conformant" => assert_ne!(
                truncated, example,
                "{ctx}: trunc_ms(registry clock reading) must NOT reproduce example_created_at \
                 for a non-conformant vector -- the vector's own timestamp is the wrong-\
                 precision or wrong-rounding form a conformant registry must never emit"
            ),
            other => panic!("{ctx}: unrecognized registry_compliance {other:?}: {v}"),
        }
    }
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
        Extracted::RunStateful(_) => panic!("expected profile-gate skip, got RunStateful"),
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
        Extracted::RunStateful(_) => {
            panic!("expected Run for overlapping profiles, got RunStateful")
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
        Extracted::RunStateful(_) => panic!("expected template-gate skip, got RunStateful"),
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
        Extracted::RunStateful(_) => {
            panic!("expected ret-001-shape fixture to run via Shape C, got RunStateful")
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
        Extracted::RunStateful(_) => panic!("expected precondition skip, got RunStateful"),
    }

    let plural = json!({
        "input": {"preconditions": {"existing_context": {"ctx_id": "acdp://x/1"}}}
    });
    match extract(&plural) {
        Extracted::Skip(reason) => assert_eq!(reason, "requires pre-seeded registry state"),
        Extracted::Run(x) => panic!("expected precondition skip, got Run({x:?})"),
        Extracted::RunStateful(_) => panic!("expected precondition skip, got RunStateful"),
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
///
/// `can` (RFC-ACDP-0001 canonicalization & hashing) is the same story:
/// still classified "non-HTTP fixture" by the generic replay harness (no
/// can-* fixture carries a request/response shape), but now has DIRECT
/// fixture-driven coverage (REG-10 Phase 7,
/// `plans/reg10-conformance-and-ci-hygiene.md`) via
/// `can_vectors_reproduce_canonical_form_and_hash` (30 of the family's 35
/// vectors, across 11 of its 12 fixtures) and
/// `can007_registry_created_at_millisecond_truncation` (the remaining 5,
/// can-007's registry-clock-truncation table). `can` was never `EXCUSED`
/// either — all 12 of its ids sit in `acdp-registry-core`'s
/// `required_fixtures`, which makes it mechanically inexcusable under rule
/// 1 below — so again only its *coverage* changed, not its classification.
///
/// `vis` (RFC-ACDP-0008 §4.5 visibility scoping) was never `EXCUSED` and
/// never classified "non-HTTP" — it is squarely `acdp-registry-core`'s own
/// business, and REG-10 Phase 8/9a's whole point is widening how much of it
/// this harness can replay for real. As of Phase 9a: `vis-001` (5
/// scenarios) and `vis-004` (4 scenarios) join `vis-006` (Phase 8) as
/// genuinely REPLAYED via Shape D — including, for both, a per-scenario
/// `context_subset_for_test.contributors` folded onto the seed (see
/// [`parse_shape_d`]'s fold step). `vis-003` stays classified
/// "scenarios carried no replayable request" by the generic harness (its
/// scenarios use `input.endpoint`, never `request.method`/`request.path`,
/// so no shape's predicate matches) but now has DIRECT coverage, same
/// `anc`/`can` precedent, via `vis003_search_response_emits_matches_not_results`.
/// `vis-002`/`vis-005`/`vis-007`/`vis-009` remain "Shape D: unrecognized
/// scenario/expected key" (`matches_ctx_ids`, `total_estimate`, multi-seed
/// / capability-toggling shapes — Phase 9b/9c); `vis-008`
/// (`setup.lineages`) remains "requires pre-seeded registry state" (Phase
/// 9c). Only `vis`'s *coverage* changed here, never its classification.
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
