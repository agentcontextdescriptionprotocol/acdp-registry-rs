# Changelog

All notable changes to this project will be documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

<!-- REG-11 Phase 9 (Lane B) -->

- **`GET /healthz` now reports the running build** (`REG-11` Phase 9,
  `#117`): the body carries a top-level `version` alongside `status` and
  `storage`, on both the `200` and the `503`/degraded response — build
  identity matters most when the service is unhealthy, which is also the
  precedent `acdp-control-plane` sets in its own health tests.

  The frozen contract is one field, not a body shape:

  > `GET /healthz` MUST include a top-level `"version"`: a non-empty,
  > human-readable identifier of the running build. It SHOULD begin with
  > the package's SemVer and MAY carry SemVer build metadata
  > (`+g<shortsha>`). **Consumers MUST treat it as opaque** — display or
  > equality at most, never parsing.

  The value is composed as `CARGO_PKG_VERSION` plus an optional
  `+g<shortsha>`, because every workspace crate still carries a
  placeholder `0.1.0` and the package version alone would not distinguish
  two builds. CI injects the commit through a new `ACDP_BUILD_SHA` build
  ARG in `docker/Dockerfile`, fed from `.github/workflows/docker.yml`.
  **Outside `docker.yml` — a local `cargo run`, or any other image build —
  `ACDP_BUILD_SHA` is unset and `version` degrades to the bare `0.1.0`,
  which does not uniquely identify a build.** The unique-identification
  property holds for images built by `docker.yml`, not universally. No new
  dependency and no `build.rs`: `.dockerignore` excludes `.git/`, so a
  `git describe` at build time could not work.

  The ARG is declared *after* the `cargo chef cook` layer. Its value
  changes every commit, so declaring it earlier would invalidate the
  dependency cache the two-stage build exists for; the final layer
  rebuilds each commit regardless, so it costs nothing there.
  `docker.yml`'s smoke step now asserts the running image's `version`
  carries the commit it was built from, so the injection path is covered
  by CI rather than assumed.

- **`GET /admin/status` gains a `build` group** (`REG-11` Phase 9,
  `#117`): `version` (the same string `/healthz` serves), `commit`, and
  `storage_impl`. Coarse identity stays public; the finer detail is
  disclosed only behind the existing admin bearer. The endpoint's other
  groups are unchanged and it remains bearer-gated.

  `commit` is **omitted entirely** when `ACDP_BUILD_SHA` was unset. That
  absence is meaningful rather than an error: it is how an operator tells
  a `docker.yml`-built image from any other build without reading docs.

  `storage_impl` reports the compiled-in store *type* (from
  `std::any::type_name`), not a `storage-*` Cargo feature name. It is an
  **opaque diagnostic identifier**: `type_name` output carries no
  stability guarantee and may change across compiler versions, so it must
  be displayed rather than parsed or branched on. This deviates from the
  REG-11 plan, which specified a `storage_feature` string — those
  features are declared on `acdp-registry-server`, not on
  `acdp-registry-core` where the handler lives, so `cfg!(feature =
  "storage-sqlite")` there does not merely evaluate false, it fails to
  compile under the `-D unexpected-cfgs` implied by CI's `-D warnings`.
  `acdp-registry-core` is generic over `S: ExtendedRegistryStore`
  precisely so it need not know about storage backends.

  Closing `#117` unblocks `acdp-ui-console#64`; it does not by itself
  make that console display a live registry version, which needs its own
  change there.

<!-- end REG-11 Phase 9 -->

- **A coverage-completeness ratchet closes the gap Phases 7-10 left open**
  (`REG-10` Phase 11): the existing four `KNOWN_FAMILIES`/`EXCUSED` ratchet
  tests fail only on an *unclassified* family or an *illegitimate excuse* —
  never on zero coverage, which is exactly how `vis`/`idem` sat uncovered
  before Phases 8-10, and how `caps`/`lin`/`lc` (#115) and 15 more families
  (#130) still do today. Two new consts and two new tests in
  `crates/acdp-registry-server/tests/conformance.rs` close it:
  - **`COVERED: &[(&str, &[CoverageMechanism])]`** models the two legitimate
    coverage mechanisms a family can claim — `Replayed` (produced >= 1
    exchange in `replays_spec_fixtures_when_present`'s own per-family
    tally) and `Direct(&[fn_names])` (named in-process test functions).
    Modelling both, rather than deriving `COVERED` purely from replay
    results as originally preferred, is load-bearing: `anc`, `can`,
    `idem`, and `wit` are genuinely covered by direct tests and produce
    **zero** replayed exchanges, so a replay-only derivation would have
    branded all four uncovered — including `can` (Phase 7) and `idem`
    (Phase 10), the two families this very effort added. `vis` claims
    both mechanisms (it clears `MIN_REPLAYED_EXCHANGES`, currently
    confirmed still 30, AND carries 10 dedicated per-fixture test
    functions).
  - **`DEFERRED: &[(&str, &str, u32)]`** lists the 18 families with no
    coverage yet, each with a non-empty reason and an open tracking-issue
    number: `caps`/`lin`/`lc` cite #115; the remaining 15
    (`body`/`schema`/`sig`/`dk`/`did-ssrf`/`data-ref`/`cur`/`err`/`meta`/
    `rate`/`status`/`rcpt`/`lhr`/`log`/`rev`) cite #130.
  - **`known_families_partition_into_covered_excused_or_deferred`** is the
    new fifth ratchet test, and the one point of this phase: it asserts
    `KNOWN_FAMILIES == COVERED ∪ EXCUSED ∪ DEFERRED` as a set. Unlike the
    four existing ratchet tests, it is deliberately **unconditional** — it
    touches no spec data, so it does not skip when `ACDP_SPEC_DIR` is
    unset. The required `tests` CI job runs `cargo test --workspace` with
    no spec configured, so this is what actually blocks a merge; verified
    directly by temporarily adding an unclassified 30th family and
    confirming only this test goes red under that exact job configuration.
  - **`covered_direct_families_have_present_test_functions`** is the
    mutation-proof half for `Direct`-mechanism families: it scans this
    file's own compiled-in source (`include_str!`) for each named test
    function, confirming it still exists with a test attribute directly
    above it. This is deliberately an EXISTENCE check, not a correctness
    check — the honest limit of what a spec-independent, self-inspecting
    const can verify; documented as such rather than overclaimed, including
    the two evasions it cannot catch (`#[ignore]` written above `#[test]`,
    and the whole function wrapped in a `/* ... */` block comment).
    Verified by temporarily stripping a `#[test]` attribute and observing
    the expected failure, then reverting.
  - The `Replayed` half of the same mutation proof lives inside
    `replays_spec_fixtures_when_present` itself: every family claiming
    `CoverageMechanism::Replayed` must have produced >= 1 exchange in that
    very run's tally, checked against the spec at the pinned SHA.
  - **Required-checks decision, recorded but not executed** (a repo-admin
    action, out of scope for this diff): `conformance (spec fixtures)`
    should join `rustfmt`/`clippy`/`tests` as a required branch-protection
    context. Confirmed directly against this repo's branch protection that
    it is not currently required. Leaving it advisory means only the
    spec-independent half of this ratchet (the set-equality test and the
    direct-mechanism scan) can ever block a merge; a regression that
    silently drops a family's replayed exchanges while its `COVERED` entry
    and direct tests stay intact would go unnoticed by required checks
    alone. Flagged as a follow-up for a human with repo-admin access.

- **`idem-001` through `idem-005` (RFC-ACDP-0003 §6 idempotency-key
  lifecycle) now have DIRECT, fixture-driven coverage** (`REG-10` Phase 10).
  These five fixtures don't fit Shape D — their top-level key is
  `preconditions` (an existing idempotency record, never a literal
  `ctx_id`), not `setup`, and `idem-005`'s `input` is a bare array of
  publish descriptors, not `scenarios[]` — and none of Shape D's seeding
  machinery has anything to seed here: the object under test IS the
  publish response itself. So, same precedent as `anc`/`can`/`vis-003`/
  `vis-007`: two direct tests, run beside the generic replayer (which
  still, correctly, shows all five as unreached — "requires pre-seeded
  state"). `idem001_004_publish_idempotency_key_lifecycle_and_restart_durability`
  runs the full, mutually-dependent `idem-001`→`idem-002`→`idem-003`→
  `idem-004` sequence against one shared, file-backed harness: `idem-001`
  (fresh publish), a genuine registry-restart proof (reconnect to the same
  on-disk SQLite file as a NEW `SqliteStore`/`RegistryServer`/`Router`,
  proving the idempotency record — not just the context row — survives),
  `idem-002` (same key + hash → byte-identical stored response returned,
  not re-executed), `idem-003` (same key, different hash → 409
  `duplicate_publish`, with a mutation proof that `idem-001`'s record is
  unmodified AND that the rejected body was never persisted), and
  `idem-004` (new key, same content → a fresh `ctx_id` AND `lineage_id`
  despite byte-identical content). `idem005_no_support_ignores_idempotency_key_header`
  runs against a SEPARATE, non-playground harness (a did:key producer
  through the SDK's verified publish path) that genuinely does not
  advertise `supports_idempotency_key`, proven by reading it back off
  `GET /.well-known/acdp.json`, and asserts two independent publishes with
  the same key both succeed with DIFFERENT `ctx_id`s. This repo's
  `POST /contexts` returns HTTP **200** on success, not the fixtures' own
  literal `201`, and never sets a `Location` header at all — both
  deviations are recorded in a doc comment following the `anc-001`
  precedent, not "fixed". `idem-002`'s `registry_must_not` clause (no
  re-DID-resolution, no re-signature-verification) is stated honestly as
  un-observable to a black-box HTTP assertion — the full-response-body
  equality is the closest indirect evidence available, not a claim of
  having observed the internals. `idem-006` (a concurrency-race fixture)
  and `idem-007` (a capabilities-document validation check gated on
  `acdp_version >= 0.3.0`) are recorded not-owed with their real reasons:
  `idem-006` sits in the pinned spec's `tolerated_outcomes` — a THIRD
  obligation category this repo's model didn't previously name, alongside
  `required_fixtures`/`conditional_fixtures` — not a strict requirement;
  `idem-007`'s version gate never fires against this harness's advertised
  `0.1.0`. `MIN_REPLAYED_EXCHANGES` is unchanged at 30 — neither test
  replays through the generic harness.
  **Finding recorded, not fixed (out of this phase's scope — test file and
  CHANGELOG only):** `acdp-registry-core`'s playground publish branch
  (`crates/acdp-registry-core/src/handlers/context.rs`, the manual
  idempotency lookup/record dance around `publish_unverified_for_tests`)
  honors ANY `Idempotency-Key` header whenever one is present, with no
  check of `supports_idempotency_key` anywhere in that branch — unlike
  every other publish path (verified did:web, did:key, pinned-verified),
  which routes through the upstream `acdp-server` SDK's own
  `RegistryServer::commit_via_store` and gates correctly. It is
  unreachable in a deployed registry, though not for the reason one might
  assume: the playground publish branch carries no
  `#[cfg(feature = "playground")]` (only the admin router does), so it
  compiles into a stock build and activates on the runtime toggle alone.
  What actually makes the divergence unrealizable is that
  `crates/acdp-registry-server/src/main.rs:1026` hardcodes
  `supports_idempotency_key: true` with no config knob, so the shipped
  binary can never advertise `false` — the state in which honoring the
  header would be wrong. It becomes live the moment that field is made
  config-driven, as every other capability already is. Filed as an issue
  rather than fixed here; it meant `idem-005` had to be
  built against a non-playground, did:key harness instead of the shared
  playground harness `idem-001`..`004` use — see the doc comment on
  `idem005_no_support_ignores_idempotency_key_header` for the full
  write-up.

- **`vis-008` (5 scenarios) — the last parked `vis` seed shape,
  `setup.lineages` — now replays end-to-end through Shape D** (`REG-10`
  Phase 9c). `MIN_REPLAYED_EXCHANGES` rises from 25 to 30. This is the last
  fixture needing a THIRD substitution table, `fixture_lineage_id ->
  minted_lineage_id`, built alongside the existing ctx_id and DID tables
  (`SeedLineage`/`SeedLineageVersion`, `parse_seed_lineages`) rather than
  special-cased outside the substitution layer. `vis-008` seeds two
  two-version lineages (`a1 -> a2`, both `restricted`, same audience/owner;
  `b1` `public` -> `b2` **`private`**, same owner — the head is private
  while v1 stays public) through REAL `Producer::supersede_body()`-chained
  publishes, in ascending `version`-field order (the fixture carries no
  explicit `supersedes` key), never a direct store write. `status`
  (`active`/`superseded`) is never a seed input — `PublishRequest` has no
  such field — it is asserted as the registry COMPUTES it from the
  supersession, cross-checked against the fixture's own `status` literal
  per lineage version; at pin `417211f` the registry's computed status
  matches every one of the fixture's four literals exactly, so no
  `anc-001`-style deviation note was needed. Two response shapes no earlier
  phase needed: `GET /lineages/{lineage_id}` returns a bare JSON array
  (scenario 0's `stranger on a fully-restricted lineage gets 200 + []`, not
  404 — asserted via an EXPLICIT `body == []` equality check, not inferred
  from `matches_ctx_ids` being an empty set, because an unsubstituted or
  unknown `lineage_id` also 200s with an empty array); `GET
  /lineages/{lineage_id}/current` returns a single `FullContext` object
  with singular `ctx_id` and a nested `registry_state.status` (scenario 4).
  A new `assert_substitution_sound` helper generalizes the existing
  raw-and-percent-encoded substitution-occurred proof (previously inline
  and ctx_id-specific) so it covers the lineage_id table too — closing the
  one place a wrong-but-200 answer could otherwise read as correct.
  Mutation-proven: `vis008_mutated_lineage_version_order_fails_replay`
  swaps the `version` field between lineage b's two entries (nothing
  else), which reverses which version publishes first and flips the
  lineage's real head from private to public — scenario 3 then gets 200
  instead of its expected 404, failing the replay. `ret-002` (also
  `setup.lineages`) was checked deliberately and does NOT become
  replayable as a side effect: its lineage versions carry no `visibility`
  key and one carries `expires_at`, both outside
  `parse_seed_lineage_version`'s recognized set, and its first lineage
  requires an "abnormal state: every version is superseded" that a real
  publish sequence cannot produce (publishing v2 always makes v2, not v1,
  the active head) — it remains classified `requires pre-seeded registry
  state`, unchanged from before this phase.

- **`vis-002` (4 scenarios), `vis-005` (4 scenarios), and `vis-009` (3
  scenarios) — multi-context, capability-toggling visibility fixtures — now
  replay end-to-end through Shape D, and `vis-007` gets direct in-process
  coverage** (`REG-10` Phase 9b). `MIN_REPLAYED_EXCHANGES` rises from 14 to
  25 (14 + `vis-002`'s 4 + `vis-005`'s 4 + `vis-009`'s 3). Two Shape D
  capabilities Phase 8 built and proved only synthetically are exercised
  against real fixtures for the first time: a per-scenario router rebuild
  driven by `registry_capabilities_subset.anonymous_public_reads`
  (`vis-002` scenarios 2/3 toggle `true`→`false` back-to-back against the
  identical anonymous requester; `vis-009` toggles `false`→`true`→`false`
  across all three scenarios), and ctx_id substitution reaching QUERY
  STRINGS in both raw and percent-encoded form (`vis-005` scenario 2's
  `search?derived_from=<percent-encoded private ctx_id>`). The
  substitution-occurred check inside `replay_shape_d` was strengthened
  alongside this: previously it only asserted no *raw* literal ctx_id
  leaked into the built request path, which would have silently missed a
  failed *query-string* substitution (the percent-encoded literal would
  sit unnoticed in the path); it now also asserts, positively, that
  whenever a scenario's original path referenced a fixture ctx_id at all,
  the built path carries the MINTED replacement — catching exactly the
  "substitution silently failed, empty result reads as a legitimate
  negative" failure mode the Phase 8/9b plans both flag. `expected`
  parsing gains two new assertable (not merely recognized) keys,
  `total_estimate` and `matches_ctx_ids` — the latter translated through
  the fixture's ctx_id substitution map at replay time, so a search that
  returns the right *count* but the wrong *identity* (exactly what
  `vis-005`'s two same-`did:agent:owner` seeds could produce if the Phase
  8 `did_map` two-pass fix ever regressed) is caught, not just an
  off-by-one. `vis-005`'s two seeds sharing one literal `agent_id` is the
  exact shape Phase 8's GAP 1 (`did_map` overwrite on a shared literal
  agent) was fixed for but never exercised by a real fixture until now;
  `vis005_private_audience_search_excluded_via_derived_from` asserts
  `did_map.len() == 1` on it directly. Across `vis-002` (3), `vis-005` (4),
  `vis-007` (1, direct coverage), and `vis-009` (2), the pinned spec
  fixtures carry exactly 10 `expected.total_estimate` occurrences; 9 of the
  10 are asserted on their exact value, alongside `matches_count`. The
  tenth — `vis-005` scenario 2, `search?derived_from=<private ctx_id>` — is
  **not** a conformance divergence: the spec explicitly licenses an
  approximate `total_estimate` ("May be approximate; not guaranteed to be
  exact", `schemas/json/acdp-search-response.schema.json`; "SHOULD NOT be
  relied upon for exact counts", `rfcs/RFC-ACDP-0005-discovery.md:219`; the
  spec's own `examples/search/empty-page-post-filter-response.json` ships
  the identical shape — an empty post-filtered page with a non-zero
  estimate). One genuine, pre-existing registry characteristic surfaced
  while building this: `total_estimate` (both `acdp-registry-sqlite` and
  `acdp-registry-pg`, `DESIGN-01`) is computed from the same SQL scan that
  applies RFC-ACDP-0008 §4.5 visibility, but `derived_from` (like
  `status`/`tags`) is a documented *post*-SQL refinement applied afterward
  in Rust — so it is a pre-refinement upper bound for a `derived_from`-
  filtered search, not the post-filter count `vis-005` scenario 2's fixture
  happens to pin at `0`; that `0` is one of several conformant values, and
  this registry emits another. Verified live: `matches` correctly scopes to
  empty (proving both the `derived_from` filter and the ctx_id substitution
  work), while `total_estimate` returns the harmless pre-refinement scan
  count instead. Exact-value assertion is therefore skipped for that one
  `derived_from`-filtered scenario (see the carve-out in
  `parse_scenarios_array`, and the corpus-wide tripwire
  `derived_from_carve_out_matches_exactly_one_corpus_scenario`, which fails
  loudly if a second such fixture ever appears); every other scenario
  across all four fixtures keeps the full exact-value assertion. What the
  carve-out does *not* skip: leak-invariance (RFC-ACDP-0005 §2.5.5 Q2's
  MUST that a registry "avoid leaking their existence via per-requester
  variance in the estimate") is asserted directly against a live registry
  response in `vis005_private_audience_search_excluded_via_derived_from` —
  the audience member and an outsider get the identical `total_estimate` on
  the same `derived_from` query, both strictly below the producer's.
  `anonymous_public_reads: false`
  is NOT an unconditional "403" rule: `vis-009` scenario 2 sets the flag
  `false` but expects a *successful* search because its requester is
  authenticated — the flag gates anonymous reads only, and both the
  `vis-002`/`vis-009` dedicated tests assert this directly rather than
  the naive stricter reading. `vis-007` cannot reach Shape D at all: its
  scenario 2 (`expected: {outcome:
  "registry_must_not_emit_this_response", rationale}`) carries no `status`
  whatsoever, so `parse_expected` fails on it and, by Shape D's
  parse-all-or-nothing rule, the whole fixture stays unparseable there —
  `vis007_search_match_restricted_visibility_disposition` seeds the one
  restricted context directly and replays scenarios 0 and 1 for real
  (`status`/`matches_count`/`total_estimate` all asserted), same
  direct-coverage precedent as `vis-003`; only the MAY-shaped
  `match_visibility_field_disposition`/`consumer_invariant` keys and
  scenario 2 wholesale are recorded not-assertable. Mutation proofs (an
  in-memory-only fixture clone, never written to the spec checkout) on
  both `vis-002` (restricted context flipped to `public`) and `vis-005`
  (the private seed flipped to `public`) fail replay specifically on a
  `matches_count`/`matches_ctx_ids` mismatch. Shapes A, B, and C remain
  textually unchanged.

- **`vis-001` (5 scenarios) and `vis-004` (4 scenarios) — single-context
  restricted/private visibility fixtures — now replay end-to-end through
  Shape D, and `vis-003` (search response field-naming) gets direct
  in-process coverage** (`REG-10` Phase 9a). `MIN_REPLAYED_EXCHANGES` rises
  from 5 to 14 (4 pre-existing + `vis-006`'s 1 + `vis-001`'s 5 + `vis-004`'s
  4). `vis-001` (RFC-ACDP-0008 §4.5 existence-leak prevention) seeds one
  `restricted` context and exercises producer / audience-member / outsider
  / genuinely-nonexistent-ctx_id / non-audience-contributor across five
  requester identities against the same ctx_id — the first fixture in this
  file to require the bearer path to actually distinguish requesters (Phase
  8's proof fixture, `vis-006`, is requester-identity-agnostic by
  construction: `did:agent:any-authenticated-or-anonymous` against a public
  context behaves the same with auth on or off). `vis-004` (RFC-ACDP-0008
  §4.5 / RFC-ACDP-0002 §7 private/audience retrieval asymmetry) seeds one
  `private` context with an `audience` and covers the same four-way split.
  Both fixtures carry a scenario with
  `request.context_subset_for_test.contributors` — a per-scenario mutation
  of the seeded row's `contributors` list, not a requester swap, and
  exactly the key Phase 8's allowlist excluded them on. Shape D is widened
  to fold it onto the (single) seed at seed time rather than left
  unsupported: the registry's only write path (`POST /contexts`) mints a
  new `ctx_id` per call, so there is no in-place "update contributors on
  this existing row" endpoint to genuinely mutate mid-replay, and applying
  it at seed time is observably identical to that framing here since
  `contributors` never affects any other scenario's status/error_code —
  `can_retrieve` and `can_surface_in_search` branch only on visibility,
  `agent_id`, `audience` and `anonymous_public_reads`, so contributors
  carries attribution rather than retrieval authorization — and both
  fixtures are single-seed and retrieval-only. That scoping is deliberate:
  `contributors` *does* gate authorization on the supersession
  producer-continuity path, so the same seed-time fold applied to a
  publish/supersede fixture would change authorization rather than preserve
  it. `parse_shape_d` fails closed (returns `None`, routing to
  the existing skip path) rather than guess which seed a *multi*-seed
  fixture's `context_subset_for_test` would target. `vis-001` scenario 4's
  genuinely nonexistent ctx_id (`…-000000000000`, distinct from the seeded
  `…-000000000001`) needed no special-casing — it was never seeded, gains
  no substitution-table entry, and a dedicated test
  (`vis001_restricted_denied_as_404_replays_via_shape_d`) asserts the
  ctx_id map contains exactly the one context that actually was seeded.
  `vis-003` has no `setup` (only `background`) and its scenarios use
  `input.endpoint`/`input.received_response`, never
  `request.method`/`request.path`, so it matches neither Shape D nor Shape
  B; `vis003_search_response_emits_matches_not_results` drives a real `GET
  /contexts/search` and asserts the fixture's own
  `response_body_constraints` (`matches` present, `results` and its listed
  alternates absent) directly against the real response body — same
  precedent as the existing `anc`/`wit`/`can` direct-coverage tests. Its
  other two scenarios (`expected.consumer_behavior` /
  `expected.minimum_diagnostic_content`) are consumer-side obligations a
  registry cannot satisfy or violate by construction; recorded
  not-applicable, with reasoning, in that test's own doc comment rather
  than silently dropped. `vis-004`'s own mutation proof (seeded visibility
  flipped `private` → `public` on an in-memory-only fixture clone, never
  written to the spec checkout) fails replay specifically on the
  outsider/contributor scenarios' now-wrong 404 expectation, alongside the
  pre-existing `vis-006` mutation proof — together demonstrating Shape D
  exercises the registry's real visibility-scoping logic rather than
  trivially passing. Shapes A, B, and C remain textually unchanged.

- **The conformance replayer gains a fourth shape ("Shape D") that seeds
  registry state before replaying, and `vis-006` (RFC-ACDP-0005 §2.2
  public-visibility search disclosure) is now the fifth exchange it
  proves live** (`REG-10` Phase 8). Previously the replayer's three shapes
  (`conformance.rs`'s `extract_shapes`) only handled self-contained
  exchanges; every fixture carrying `setup` — all of `vis-*`, `idem-*` and
  friends — was a blanket skip ("requires pre-seeded registry state"),
  because the registry mints its own `ctx_id` and the fixtures' literal
  ones (`pub-013` proves a producer-supplied `ctx_id` is rejected) can't
  be replayed against directly. Shape D closes that gap for the shapes it
  understands: it seeds `setup.context_published` / `.contexts_published`
  through the real publish API (never a direct store write), building a
  `fixture_ctx_id -> minted_ctx_id` substitution table and, for any seeded
  `agent_id` that isn't already `did:web` (this registry only advertises
  `did:web`, and `pub-008` proves it rejects anything else), a
  `did:agent:* -> did:web:*` substitution table for a producer identity
  the harness holds the key for — `audience` entries and requester DIDs
  route through the same table so an audience check stays consistent with
  whichever bearer `sub` a scenario presents. It mints a per-scenario
  bearer from `effective_requester_did` (no `Authorization` header at all
  when it's `null`). Shape D runs under its own `shape_d_config()` with
  `auth.enabled = true`: the shared `config()` Shapes A/B/C use leaves auth
  off, which is right for them since they need no caller identity, but with
  auth off `caller_from_headers` returns `None` unconditionally, so every
  bearer Shape D minted was being discarded. Without that one line the
  per-scenario bearer is inert and any identity-sensitive assertion built on
  it would pass for the wrong reason. When a scenario's
  `registry_capabilities_subset` overrides `anonymous_public_reads`, the
  harness reconstructs the `RegistryServer` with the new capabilities
  document rather than only rebuilding the router around it: `search` and
  `retrieve` gate that flag on the server's own baked-in `caps`, not on
  `RegistryConfig`, so rebuilding the router alone left the override
  silently inert. Seeded state survives because `SqliteStore` is
  `SqlitePool`-backed and the pool is an `Arc`, so the clone shares the same
  in-memory database. Every Shape D fixture gets its own
  fresh in-memory store, isolated from the shared store Shapes A/B/C
  replay against. Dispatched deliberately **ahead of** Shape B (not after
  the fallback, as an earlier draft of this phase's plan had it): a
  `setup`-carrying fixture's `scenarios[]` also satisfies Shape B's own
  predicate, and Shape B has no seeding step — letting it capture such a
  fixture first would silently replay it against an empty store and read
  the resulting 404s as legitimate negative results. Shapes A, B, and C
  are textually unchanged. A fixture whose seed shape or scenario
  assertions Shape D doesn't recognize yet (`setup.lineages`,
  `matches_ctx_ids`, `total_estimate`, `context_subset_for_test`, …) still
  falls through to the narrowed — not deleted — `unseeded_precondition_reason`
  skip path rather than being partially replayed; this is what keeps this
  phase scoped to exactly one fixture (`vis-006`, the only single-exchange
  `vis` fixture) even though the rest of `vis-*` structurally satisfies
  Shape D's dispatch predicate. A dedicated regression test,
  `four_pre_existing_exchanges_still_use_original_shapes`, asserts the
  four exchanges replayed before this phase (`pub-004`, `pub-005`,
  `pub-008`, `ret-001`) still extract via their original shapes with
  identical fields — the gravest failure mode this phase could introduce
  is Shape D silently over-matching one of them. A second dedicated test
  proves Shape D end-to-end on `vis-006` and then, against an in-memory-only
  mutated copy of the fixture (never written to the spec checkout) whose
  seeded context's visibility is flipped to `restricted`, proves the
  replay now fails — demonstrating the harness exercises the registry's
  real visibility-scoping logic rather than trivially passing. A failed
  seed publish panics rather than skips, so a broken substitution can't
  quietly read as "fixture not applicable". Two further tests cover paths no
  fixture reaches yet, using synthetic in-test fixtures rather than spec
  reads: `shape_d_seeding_maps_one_shared_literal_agent_to_one_minted_did`
  pins the multi-seed `contexts_published` path, where two seeds sharing one
  literal `agent_id` must resolve to a single minted DID — seeding is
  two-pass for this reason, minting every distinct agent before any publish,
  so a repeat cannot overwrite an earlier mint and an `audience` naming a
  later-seeded agent still resolves; and
  `seeded_harness_rebuild_changes_router_behavior_and_preserves_seeded_state`
  pins both halves of the rebuild — that the anonymous-read posture actually
  changes, and that the seeded rows survive it. Note `vis-006` itself does
  not exercise the bearer path: its requester is
  `did:agent:any-authenticated-or-anonymous` against a public context, so it
  behaves identically with auth on or off. The bearer and rebuild mechanisms
  are proven by the synthetic tests, not by the replayed fixture. `MIN_REPLAYED_EXCHANGES`
  rises from 4 to 5.

- **`can-*` (RFC-ACDP-0001 canonicalization & hashing) moves from zero
  coverage to direct, fixture-driven coverage of all 35 vectors across all
  12 fixtures** (`REG-10` Phase 7). None of `can-*` is HTTP-replayable —
  the family carries no request/response shape at all — yet all 12 ids sit
  in the pinned spec's `acdp-registry-core.required_fixtures`, which makes
  `can` mechanically inexcusable under this file's `EXCUSED` ratchet. Two
  new tests in `conformance.rs` consume every fixture's own data directly,
  same precedent as `anc`/`wit`:
  `can_vectors_reproduce_canonical_form_and_hash` covers 30 of the 35
  vectors (can-001 through can-006, can-008 through can-012) by driving
  `acdp::crypto`'s public JCS surface directly —
  `canonical_preimage` for the Body/`content_hash`-shaped vectors,
  `canonicalize_value` for can-011's bare numeric-formatting objects (not
  ACDP bodies, so the Body-specific exclusion-set path is the wrong tool)
  and can-001's three `canonical_form`-only vectors, and
  `derive_lineage_id` for can-001's three `lineage_id`-only vectors. `can-001`
  alone packs three distinct `expected` shapes into its 7 vectors; a naive
  hash-equality loop would have silently covered only one of them.
  `can-006`'s two divergent-precision vectors are additionally asserted to
  produce different `canonical_form`/hash from each other, not just to
  each independently match their own pinned value. The second new test,
  `can007_registry_created_at_millisecond_truncation`, covers the
  remaining 5 — can-007 alone carries no `input`/hash at all, just a
  `registry_compliance` table keyed off example timestamps — by driving
  `acdp::time::trunc_ms` directly, the actual function
  `acdp-registry-sqlite`/`acdp-registry-pg` call when minting
  `created_at`, proving both that it reproduces the canonical millisecond
  form and that it floors rather than rounds. An explicit
  `EXPECTED_CAN_HASH_VECTOR_COUNT`/`EXPECTED_CAN_VECTOR_COUNT` pair (30 and
  35) guards against the vacuous-pass failure mode where a loop silently
  iterates zero vectors and passes green; proven by mutation on three
  fixtures (can-001, can-002, can-011), each of which fails when its
  `sha256_hex` is corrupted and passes again once restored. Both new tests'
  doc comments record the tension with this file's own anc-004 precedent
  (`conformance.rs`'s module doc-comment already argues against re-testing
  an upstream crate's golden vectors): most of `can`'s vectors do exactly
  that, but the coverage ratchet makes `can` inexcusable regardless, and
  the conformance claim is about this binary, not about which crate owns
  the tested code. No new dependency: `acdp::crypto` already re-exports
  `acdp_crypto`'s `canonicalize_value`/`canonical_preimage`/
  `derive_lineage_id`, and `acdp::time::trunc_ms` was already reachable.
  `KNOWN_FAMILIES`'s doc comment and the module doc-comment both gain a
  `can` paragraph mirroring the existing `anc` one — classification
  unchanged (still "non-HTTP fixture"), only coverage changed.

- **The witness aggregator's reject-then-no-write path is now directly
  tested** (`REG-10` Phase 4, GitHub issue #112). `witness.rs`'s
  `verify_and_store` was split at the point right after DID resolution:
  it now resolves the witness DID document and tail-calls a new private
  `verify_and_store_resolved(store, log, witness_did, doc_value,
  cosig_value) -> bool`, a verbatim lift of the verify-then-store half
  (the `verify_cosignature_against_own_log` match through the
  `upsert_witness_cosignature` call and the three metric-labeled early
  returns). This is a no-behavior-change refactor — `verify_and_store`'s
  signature, visibility, and callers are untouched — that makes the
  store-writing half callable directly against a real `SqliteStore`
  without a live witness endpoint. Two new tests exercise it:
  `rejected_cosignature_is_not_persisted_by_the_store_path` (a forged-root
  cosignature is reported unstored, and leaves no row at either the
  forged or the honest checkpoint tuple) and
  `verified_cosignature_is_persisted_by_the_store_path` (the positive
  control — a genuine cosignature is reported stored and reads back).
  Previously only the pre-store verification helper had forward-guard
  assertions; nothing exercised the actual persistence path.

- **`.github/workflows/bump-spec.yml`, a manual and dispatch-driven
  replacement for hand-written spec-pin bumps** (`REG-10` Phase 3, GitHub
  issue #110). It delegates to acdp-ci's reusable `bump-spec-ref.yml@v1`
  workflow, mirroring the existing `bump-acdp.yml` pattern: `with: file:
  .github/workflows/ci.yml` names the file whose single spec-pin anchor gets
  rewritten, `sha` picks the target commit (on `workflow_dispatch`, the
  input — blank meaning spec HEAD; on `repository_dispatch`, the event
  payload's SHA), and `secrets: inherit` supplies `ACDP_BOT_APP_ID` and
  `ACDP_BOT_PRIVATE_KEY`, already proven available in this repo via
  `notify-website.yml`. The reusable workflow hard-fails on zero or more
  than one spec-pin anchor in the named file, rewrites only the `ref:`
  following that anchor, asserts the rewrite landed, and opens a PR on
  branch `deps/spec-<sha:0:12>` for review — it never auto-merges, and it
  opens no PR when the target SHA already matches the current pin. Two
  triggers are wired: `workflow_dispatch`, runnable from the Actions tab
  today with an optional explicit `sha` input; and `repository_dispatch` on
  `spec-released`, which stays inert until the spec repo's
  `notify-spec-consumers.yml` adds this repo to its consumer matrix (as of
  this writing that matrix lists only `acdp-rs` and `acdp-verifier-py`).
  `CONTRIBUTING.md`'s conformance-pin paragraph now points at this workflow
  as an alternative to bumping the pin by hand.

- **`anc-001`/`anc-002`/`anc-003` move from "skipped as non-HTTP by the
  generic replayer" to direct, fixture-driven coverage, and require-mode CI
  is confirmed green at spec pin `417211f`** (`REG-3` Phase 7 — the closing
  phase of `plans/reg3-anchors.md`). None of `anc-001/002/003` is replayable
  through `crates/acdp-registry-server/tests/conformance.rs`'s generic
  `extract_shapes` at any pin: `anc-001` expects a *positive* (2xx) publish
  outcome carrying a `content_hash`/`signature` its own `input.notes` calls
  placeholders that don't recompute over the fixture's own body (Shape A
  refuses any non-400 publish outcome by design), and `anc-002`/`anc-003`
  carry only an `input.anchor_under_test` fragment, not a full body. So,
  following the same precedent already established for `wit-001`/`wit-004`
  and the did:key golden vector, three new in-process tests —
  `anc001_well_formed_anchor_is_accepted_and_round_trips`,
  `anc002_malformed_anchor_content_hash_is_rejected`,
  `anc003_empty_anchors_array_is_rejected_with_established_ordering` — read
  each fixture's own data via the existing `spec_fixtures()`/`read_json`
  helpers (resolved by the fixture's own `id` field through a directory
  scan, not a hardcoded filename), splice it into a freshly-signed body
  built with the same producer/`RequestBuilder` technique REG-3 Phase 5
  uses, and publish it against a **locally-built** capabilities document
  advertising `acdp_version: "0.5.0"` (`anc_caps_050`/`anc_harness_050` —
  the shared `caps()`, which stays `"0.1.0"` for
  `replays_spec_fixtures_when_present`, is never mutated). `anc-001`
  asserts HTTP 200 (this repo's actual publish success code, not the
  fixture's own literal `201`) plus both of the fixture's stated
  post-publish invariants (anchors served byte-identical; recomputed
  `content_hash` matches). `anc-002` asserts 400 `schema_violation` and its
  doc-comment states plainly that this exercises the *upstream*
  `acdp_validation::validate_anchors` shape check inherited from the `acdp`
  0.8.2 bump, not this repo's own Phase 3 version gate. `anc-003` asserts
  400 `schema_violation` on both a sub-`0.5.0` and a `0.5.0`-advertising
  registry, and additionally pins the ordering Phase 3 already established:
  on the sub-`0.5.0` registry this repo's own §10 version gate fires first
  (message names §10, not the SDK's "MUST be omitted entirely" wording); on
  the `0.5.0` registry the gate passes and the SDK's own empty-array rule
  fires instead. `anc`'s classification is unchanged by this phase — it was
  never `EXCUSED` and still isn't (`KNOWN_FAMILIES`'s doc-comment now
  records the added direct coverage) — and the skip manifest in
  `replays_spec_fixtures_when_present` still correctly shows
  `anc: 5 (non-HTTP fixture ...)`, since the replayer itself still doesn't
  replay any `anc-*` fixture; the three new tests run beside it, not in
  place of it. `MIN_REPLAYED_EXCHANGES` stays at exactly 4.

  `anc-004` and `anc-005` are deliberately OUT OF SCOPE: `anc-004` is a pure
  hash-computation golden vector (no endpoint, no request) over
  `acdp-crypto`'s JCS/hash pipeline, which this repo delegates to via the
  `acdp` dependency and does not own — Phase 5's
  `anchors_round_trip_byte_exact_sqlite` / `pg_anchors_round_trip_byte_exact`
  already prove that pipeline handles anchors correctly *through this
  repo's own storage*, which is what this repo is accountable for.
  `anc-005` is consumer-side behavioral (a scheme-unaware verifier
  tolerating an unknown scheme) — a registry has no verifier role, and the
  pinned spec places all five `anc-*` fixtures in `acdp-consumer`'s
  `required_fixtures`, never in any `acdp-registry-*` profile's.

  Confirmed green: `ACDP_REQUIRE_CONFORMANCE=1 ACDP_SPEC_DIR=<pinned
  417211f checkout> cargo test -p acdp-registry-server --features
  storage-sqlite,playground --test conformance --test conformance_gate`
  exits 0, with `replayed 4 exchange(s); failures=0` and zero
  `ACDP_SPEC_DIR unset` lines.

- **Behavioral and structural proof that `anchors[].uri` is never
  dereferenced** (`REG-3` Phase 6). Proves RFC-ACDP-0016 §6's NORMATIVE
  rule — stricter than the DataRef SSRF posture — that "there is no code
  path in core verification that ever reads `anchors[].uri`". Two tests,
  because neither alone is sufficient:
  `anchors_uri_never_dereferenced_publish_and_retrieve`
  (`crates/acdp-registry-server/tests/http_integration.rs`) binds a
  loopback `TcpListener`, publishes a context whose `anchors[0].uri`
  targets it, retrieves the context back, and asserts (after a bounded
  drain window, not an immediate check) that the listener observed **zero**
  connections at every point — while webhook delivery (the one subsystem
  near the publish path that *does* make a real outbound call) is
  deliberately wired live against a *second*, independent listener, so
  "zero" is a discriminating claim rather than an artifact of a harness
  that makes no outbound calls at all. The SSRF guard is configured with
  `SsrfPolicy::allow_test_loopback()` throughout so the guard is provably
  not what keeps the anchor listener silent — the claim under test is
  "nothing attempts the connection," not "a guard blocked it."
  `crates/acdp-registry-server/tests/anchors_uri_never_dereferenced.rs`
  adds the structural half: it enumerates every outbound-HTTP call site in
  the whole `crates/` tree (scoped to the zero-argument HTTP-client dispatch
  idiom, which cannot collide with channel `.send(msg)` calls that always
  take an argument) and asserts the set is *exactly* the three audited,
  legitimate ones (`acdp-registry-webhook/src/lib.rs`,
  `acdp-registry-auth/src/revocation_poller.rs`,
  `acdp-registry-core/src/witness.rs`) — failing loudly if a fourth ever
  appears — and that none of those three files mentions "anchor" in any
  form. Both live mutation checks were performed and confirmed: temporarily
  adding a throwaway fetch of `anchors[0].uri` to the publish path turned
  the behavioral test red (`left: 1, right: 0` on the zero-connections
  assertion); temporarily corrupting the structural test's expected-file
  set turned both structural assertions red with a clear drift diff. Both
  mutations were reverted before landing.

- **Byte-exact `anchors` round-trip proof, both storage backends** (`REG-3`
  Phase 5). Proves RFC-ACDP-0016 §5's normative requirement and anc-001's
  stated post-publish invariant: `anchors` survives publish → store →
  retrieve byte-exactly, such that `acdp::crypto::compute_content_hash`
  over the retrieved body reproduces the published `content_hash`. No test
  in this repo recomputed `content_hash` from a retrieved body at all
  before this (`grep -rn compute_content_hash crates/` was zero hits) —
  this is a first for the repo, not just for anchors.
  `anchors_round_trip_byte_exact_sqlite` /
  `anchors_two_entries_preserve_order_sqlite`
  (`crates/acdp-registry-server/tests/http_integration.rs`) and
  `pg_anchors_round_trip_byte_exact` / `pg_anchors_two_entries_preserve_order`
  (`crates/acdp-registry-server/tests/pg_integration.rs`) publish a
  **freshly-signed, self-consistent** request through the real router
  (`RequestBuilder::build()` computes its own `content_hash` — anc-001's
  own placeholder `content_hash`/`signature` are never replayed; anc-001 is
  used only as the shape reference for the first anchor's
  `scheme`/`content_hash`), fetch both `GET /contexts/{ctx_id}` and
  `GET /contexts/{ctx_id}/body`, and assert against both: the served
  `anchors` array is order-sensitive deep-equal (raw `serde_json::Value`,
  since `AnchorEntry` has no `Eq`/`Hash`) to what was sent, AND the
  recomputed hash matches. The two-anchor test body carries a `uri`, a
  flattened extension key holding a plain integer
  (`AnchorEntry.extensions`, `#[serde(flatten)]`) and a second flattened
  key holding `1e-7` — a value Postgres's `jsonb` type is known to
  re-render differently (in text form) from `serde_json`'s own output,
  unlike the plain integer, which round-trips through JSONB unchanged
  either way — on the first entry, and a structurally different second
  entry whose `scheme` sorts alphabetically *before* the first entry's (so
  a "helpful" ascending sort would visibly reorder the pair rather than
  being a no-op on the fixture). Array ORDER is therefore genuinely
  exercised (reordering changes the JCS preimage, and an accidental sort
  would now be caught), and Postgres's JSONB storage
  (`serde_json::to_value`, a normalizing representation — number
  re-rendering, key dedup/reorder) has real surface to diverge from
  SQLite's `TEXT` storage (`serde_json::to_string`) if it were going to. It
  doesn't: both backends reproduce the published `content_hash`
  byte-exactly — including across the `1e-7` re-rendering — run against a
  real `postgres:16-alpine` container — **no cross-backend JSONB
  normalization divergence found**. The PRIMARY proof of byte-exactness is
  the hash-recomputation assertion itself: because JCS canonicalization is
  sensitive to field drop, field mutation, and array reorder alike, a
  passing recompute on its own already rules out all three. Each
  round-trip test additionally runs a narrower, supplementary regression
  guard (`assert_ne!`) that simulates `anchors` being dropped from the
  served value and confirms the hash-recompute assertion would go red in
  that specific case — this guard only exercises the drop case, not
  reorder or mutation, so it does not by itself establish byte-exactness;
  it exists to catch a regression where the recompute assertion above
  stops actually depending on `anchors` (e.g. a future refactor that reads
  `content_hash` from a cached field instead of recomputing it).
- **RFC-ACDP-0016 §10/§14 version gate** (`REG-3` Phase 3). RFC-ACDP-0016
  (typed external `anchors`) is still **Draft**, not Final — this repo
  implements the two MUST-reject rules the spec defines for that field
  while the rest of the RFC remains a plain-library-type pass-through (see
  the Phase 2 `acdp` 0.8.1 → 0.8.2 bump below). A publish request carrying
  `anchors` is now rejected with `schema_violation` / HTTP 400 unless
  **both**: (§10) the registry's own **advertised** `acdp_version` — the
  exact string served at `GET /.well-known/acdp.json` — is `>= 0.5.0`, and
  (§14) the request's own **declared** `body.acdp_version` is `>= 0.5.0`
  (absent ⇒ `0.1.0` per `VERSIONING.md`'s layers table, so an omitted
  field is rejected exactly like an explicit `"0.1.0"`). The check runs in
  `publish_inner` (`crates/acdp-registry-core/src/handlers/context.rs`)
  immediately after the request body deserializes and before the per-agent
  rate limiter, so a version-rejected publish never consumes a producer's
  publish budget, and it sits above the `did:key` / playground-pinned /
  test-only / default `did:web` branch, covering all four publish paths
  with one gate. No new error variant or wire code was minted — both
  predicates reuse the existing `RegistryError::Acdp(AcdpError::SchemaViolation(..))`
  → `schema_violation` / 400 idiom, with the rejection message naming which
  of the two predicates failed. A private `version_at_least(v, major, minor)`
  helper (with its own unit tests, including the numeric-vs-lexical
  `"0.10.0" >= 0.5.0` case) is reimplemented in `context.rs` rather than
  reusing `acdp-validation`'s own version of the same name, which is
  private and not re-exported by the `acdp` facade crate; it fails closed
  on any version string that isn't plain `MAJOR.MINOR.PATCH`. `anchors: []`
  on a sub-0.5.0 registry is caught by this gate before the SDK's own
  empty-vec rejection ever runs (both produce the same wire outcome, but
  this gate fires first); `anchors: null` continues to be rejected at
  deserialize time, unrelated to this gate. The read path
  (`GET /contexts/{ctx_id}`, `/body`) is untouched — §10 gates publish
  only, and a body stored while the registry advertised `0.5.0` is served
  byte-exactly even if the registry's advertised version later changes.
  This phase does **not** make `acdp_version: "0.5.0"` reachable from any
  shipped configuration — the gate is exercised only via
  `crates/acdp-registry-server/tests/http_integration.rs`'s explicit
  `CapabilitiesDocument` override harness (`caps_050()`); making 0.5.0
  actually reachable in production config is a separate, later, one-way-door
  change.

- **JWT revocation** (`SEC-01`, `FEAT-02`): new `RevocationStore` trait with
  in-memory, SQLite, and Postgres backends; `issued_tokens` migrations
  (Sqlite 006, Postgres 005); `AuthService::issue_token` records every
  minted `jti` so `POST /auth/token/revoke` can authorize ownership;
  `JwtSigner::with_revocations` rejects revoked tokens at validate time.
- **Cross-registry resolution** (`FEAT-01`): `retrieve` forwards `ctx_id`s
  whose authority differs from the local registry through
  `acdp::client::CrossRegistryResolver`. Gated by
  `registry.cross_registry_resolution = true` (default).
- **Visibility search filter** (`FEAT-07`):
  `GET /contexts/search?visibility=public|restricted|private`.
- **Webhook event correlation** (`FEAT-04`, `FEAT-05`):
  `ContextPublished` carries `X-Run-Id` and the publish request's
  `derived_from` list.
- **Configurable CORS** (`SEC-02`): `[registry.cors] allowed_origins`.
  Empty (default) sends no CORS headers — replaces the prior
  `CorsLayer::permissive()`.
- **Body-size limit layer** (`SEC-06`): `tower_http`
  `RequestBodyLimitLayer` applies `limits.max_payload_bytes` to every
  route, not just publish.
- **SSRF guard on webhook URL** (`SEC-03`) and **non-empty webhook
  secret** (`SEC-04`): both enforced at startup by
  `WebhookEmitter::try_spawn` and `main::validate_config`.
- **DID-method fast-fail** (`SEC-05`):
  `AuthService::issue_challenge` rejects `agent_id`s that don't begin
  with `did:web:` before writing to the challenge store.
- **Pre-bind config validation** (`FEAT-09`): `main::validate_config`
  decodes `jwt_secret`, validates the webhook URL via the SSRF policy,
  checks TLS materials exist, and refuses the literal `changeme`
  placeholder.
- **Conformance harness** (`BUG-07`): `tests/conformance.rs` replays
  `pub-*` and `ret-*` fixtures from `ACDP_SPEC_DIR` when present;
  status + `json_contains` assertions with a null-as-wildcard sentinel.
- **Playground matrix test** (`DESIGN-03`): asserts `/admin/contexts` is
  mounted when the `playground` feature is compiled in but the runtime
  flag is off.
- **`POST /auth/token/revoke` endpoint** (`FEAT-02`).
- **Graceful shutdown** (`OPS-03`): `axum_server::Handle` with a 30s
  drain on `SIGTERM` / `Ctrl-C`.
- **Pretty-log toggle** (`OPS-04`): `ACDP_LOG_FORMAT=pretty` switches
  `tracing-subscriber` away from JSON for local development.
- Initial 8-crate workspace scaffold.
- `acdp-registry-types`: configuration (TOML + env), `RegistryError` with HTTP
  projection, webhook event envelopes, JWT bearer claims.
- `acdp-registry-store`: `ExtendedRegistryStore` trait extending
  `acdp::registry::RegistryStore` with `list_contexts`, `health`, `migrate`.
- `acdp-registry-sqlite`: SQLite backend with FTS5 virtual table, migrations,
  atomic `commit_publish`, idempotency cache, and visibility-filtered search.
- `acdp-registry-pg`: Postgres backend with `TIMESTAMPTZ` / `TEXT[]` / `JSONB`,
  `tsvector` FTS, `FOR UPDATE` row locking on the supersession check.
- `acdp-registry-auth`: DID challenge-response via `acdp::did::WebResolver` +
  `verify_ed25519`, HS256 JWT issuance/validation, pluggable
  `ChallengeStore` (in-memory + SQLite + Postgres).
- `acdp-registry-webhook`: HMAC-SHA256-signed POSTs with retry/backoff.
- `acdp-registry-core`: axum router + handlers generic over the storage trait.
- `acdp-registry-server`: binary wiring via Cargo features
  (`storage-sqlite` default, `storage-pg`, `storage-memory`, `playground`).
- Docker image (multi-stage with `cargo-chef`) + docker-compose with Postgres.
- GitHub Actions: `ci.yml` (fmt + clippy across feature matrix + test +
  cargo-deny), `release-plz.yml`, `docker.yml`.

### Changed

<!-- REG-11 #156 (Lane B) -->

- **BREAKING** (`#156`): the memory-backend tenancy refusal now covers
  `auth.require_tenant = true` as well as a non-empty
  `[[auth.tenant_agents]]`. Either signal alone, combined with
  `storage.backend = "memory"`, is refused at startup.

  This **narrows** the acceptance criterion the original refusal shipped
  under, which said every other backend/tenancy combination still starts.
  That is deliberate: `require_tenant = true` with an empty `tenant_agents`
  is a real configuration. With no agent bindings, no registry-issued token
  ever carries a `tenant` claim, so on the read path a caller asserts its
  tenant with the `X-Tenant-Id` header — which is what the registry's own
  default-deny message instructs. (Publishes differ: strict mode
  deliberately ignores that spoofable header when the producer has no
  binding, so a publish is denied outright.) On the memory backend those
  reads then fail identically to the case already refused.
  Strict mode denies every request resolving to no tenant, and any tenant a
  caller does assert cannot match the reserved `default` that every row
  reports, so each tenant-scoped read returns zero rows while the registry
  starts cleanly. Keying the refusal on `[[auth.tenant_agents]]` alone left
  that arm silently under-serving.

  An untenanted memory registry — neither signal set — still starts, which
  is the ephemeral demo case the backend exists for.

  Nothing in the repo relied on the newly-refused combination. A sweep for
  the memory backend combined with either tenancy signal found no test,
  fixture, example config, compose file, CI job, or doc snippet that hits
  it: `config/registry.example.toml` ships `sqlite` with
  `require_tenant = false`, `docker/config.docker.toml` ships `postgres`,
  and every `StorageBackend::Memory` site in the tree is in
  `validate_config` or its own tests. (The three integration tests that set
  `require_tenant = true` also set `tenant_agents`, so they were already
  inside the Phase 8 guard; they run on SQLite and never call
  `validate_config` regardless.)

<!-- end REG-11 #156 -->

<!-- REG-11 Phase 8 (Lane B) -->

- **BREAKING** (`REG-11` Phase 8, `#137`): `storage.backend = "memory"`
  combined with a non-empty `[[auth.tenant_agents]]` is now refused at
  startup. `validate_config` runs before migrations and before the socket
  is bound, so the process exits with a message naming both the backend and
  tenancy instead of starting a registry that serves nothing. A deployment
  that set both previously started cleanly and answered every tenant-scoped
  read with zero rows; it must now move to the `sqlite` or `postgres`
  backend, which are tenancy-aware.

  A warning would have nothing working to preserve on the read path.
  `MemoryStore` (`crates/acdp-registry-server/src/memory_ext.rs`) overrides
  none of the three tenancy methods on `ExtendedRegistryStore`, so it
  inherits their untenanted defaults: `set_tenant_of_ctx` is a no-op, and
  `tenant_of_ctx` / `tenants_of_ctxs` report `default` for every row.
  `default` is `RESERVED_TENANT`, which `reject_reserved_tenant`
  (`crates/acdp-registry-core/src/handlers/context.rs`) refuses from both
  `X-Tenant-Id` and the token claim — so the one tenant every row reports is
  the one tenant no caller may assert, and the filter matches nothing.

  The new check sits immediately after the existing `#17` guard that
  refuses `tenant_agents` with `require_tenant = false`, keeping the two
  tenancy refusals together; because that guard forces strict mode whenever
  `tenant_agents` is set, the rejected configuration is always the strict
  one. No other backend/tenancy combination was affected by Phase 8
  itself (see the `#156` entry above, which later narrowed this).
  Documented in `docs/MULTI-TENANCY.md` (new "Backend support" section)
  and `docs/CONFIGURATION.md`.

  *(This entry originally noted that `require_tenant = true` with an empty
  `tenant_agents` on the memory backend fails the same way and was not
  refused, tracking it as `#156`. That gap is closed by the `#156` entry
  above, in the same release, so the caveat has been removed rather than
  left to read as a standing limitation.)*

<!-- end REG-11 Phase 8 -->

<!-- REG-11 Phase 6 (Lane A) -->

- **The `EXCUSED`/`DEFERRED` ratchet now actually ratchets, in every CI job**
  (`REG-11` Phase 6, `#115`, `#130`): previously nothing in
  `crates/acdp-registry-server/tests/conformance.rs` forced a spec-required
  family *out* of `DEFERRED` and away from `EXCUSED` — zero coverage plus a
  written reason plus an open issue number was permanently green. A new
  `CORE_INEXCUSABLE_FAMILIES: &[&str]` const mirrors, by family, the pinned
  spec's `acdp-registry-core` `required_fixtures` ∪ `conditional_fixtures`
  (18 families: the 5 already `COVERED` — `can`, `idem`, `pub`, `ret`,
  `vis` — plus the 13 still `DEFERRED` — `body`, `caps`, `data-ref`,
  `did-ssrf`, `dk`, `err`, `lin`, `meta`, `rate`, `rev`, `schema`, `sig`,
  `status`). Two assertions give it teeth: **`core_inexcusable_families_
  are_never_excused_or_unclassified`** is unconditional (no `ACDP_SPEC_DIR`
  needed, so it runs in the required `tests` job) and fails if any mirror
  family is ever moved into `EXCUSED` or drops out of `COVERED ∪ DEFERRED`;
  the existing spec-gated `no_excused_family_is_required_by_our_profile`
  (required `conformance (spec fixtures)` job) now also `assert_eq!`s the
  mirror against the same set recomputed live from the pinned spec, so the
  literal cannot silently rot against a future spec-pin bump. Moving a
  family `DEFERRED` → `COVERED` requires **zero** edits to either assertion
  or the const, by design — the mirror is keyed to the spec's family-level
  obligations, not to which bucket currently covers them. The unconditional
  half is deliberate belt-and-suspenders: `conformance (spec fixtures)` sets
  `ACDP_REQUIRE_CONFORMANCE=1` and is a required status check today, but
  that required-check set is maintained by a sibling repo's hand-written
  mirror (independently confirmed stale as of 2026-09-05), so the
  unconditional `tests`-job half is what keeps the guarantee even if that
  context is ever dropped from branch protection. Measured, not derived:
  `ACDP_SPEC_DIR=<pinned-spec-checkout> ACDP_REQUIRE_CONFORMANCE=1 cargo
  test -p acdp-registry-server --features storage-sqlite,playground --test
  conformance --test conformance_gate -- --nocapture` → 44 passed + 1
  passed, 0 failed, `replayed 30 exchange(s); failures=0` (`pub: 3`, `ret: 1`,
  `vis: 26` — `MIN_REPLAYED_EXCHANGES` unchanged); `cargo test --workspace`
  and `cargo clippy --workspace --all-targets -- -D warnings` both clean.
- **Corrected seven `DEFERRED` reasons that misdescribed this repo's own
  implementation** (`REG-11` Phase 6, `#130`): four were factually false —
  `rate` claimed a missing "clock/limiter seam", but
  `limits.publish_rate_per_minute` (`config.rs:560-561`) is already enforced
  by the in-process `AgentRateLimiter` (`rate_limit.rs`, wired at
  `state.rs:86-89`), proven end-to-end by the sibling challenge-limiter test
  (`http_integration.rs:843-873`); `data-ref` called the family
  "consumer-leaning", but the 7 `data-ref-*` fixtures in
  `acdp-registry-core`'s `required_fixtures` (`data-ref-001..007`) are
  registry-side publish-path rejections (RFC-ACDP-0002 §6) — the 8th,
  `data-ref-008-external-data-ref-hash-mismatch`, is a consumer fetch-time
  check and is not required of this profile; `status` called it "lifecycle
  status transitions", but the fixtures test the `status` *string's*
  grammar (RFC-ACDP-0004 §4.1), not lifecycle state; `rev` called it a
  "verification-side family", but RFC-ACDP-0014 §4/§5 assigns this to the
  registry, which already implements `ContextType::KeyRevocation`. Three
  more overstated the gap as "needing a new seam" when the seam already
  exists: `log`'s `/log/checkpoint`, `/log/proof`, and `/log/entries`
  routes are always mounted (`crates/acdp-registry-core/src/lib.rs:86-88`).
  `log`, `rcpt`, and `lhr` each have two real causes, not one: one fixture
  per family (`log-001`/`log-003`, `rcpt-001`, `lhr-001`) carries no
  `applies_to_profiles` and is a non-HTTP golden vector needing a
  direct-vector pass; the rest (`log-002`/`log-004`, `rcpt-002..004`,
  `lhr-002..004`) are restricted to a profile this harness doesn't
  advertise (`HARNESS_PROFILES`, `conformance.rs:425`) — advertising it
  would not make the non-HTTP vectors run.
  No family moved bucket in this phase — this is a record correction plus
  the new ratchet, not new coverage.

- **`did-ssrf`'s deferral reason corrected (same review pass).** It claimed the family
  "needs a controlled resolver seam this harness doesn't have yet". That named the wrong
  cause and was falsifiable from this suite's own output: all five `did-ssrf-*` fixtures
  are reported under `non-HTTP fixture (vectors / schema / informative)` in the skip
  tally, so they never reach a resolver. The seam also already exists —
  `acdp_did::WebResolver` applies `SsrfPolicy::default()` unconditionally, and exposes
  `with_ssrf_policy` and `with_test_endpoint` under the `test-transport` feature already
  enabled on `acdp` in this crate's dev-dependencies. The real gap is a direct-vector
  pass like `can`'s.

<!-- end REG-11 Phase 6 -->

- **BREAKING** (`REG-11` Phase 3, `#133`): `GET /admin/contexts` is now
  gated behind `require_admin_bearer`, like every other `/admin/*` route.
  A registry with an empty `auth.admin_tokens` (the shipped default in both
  `config/registry.example.toml` and `docker/config.docker.toml`) now
  answers 403 `admin-only` where it previously served rows to anyone —
  operators who rely on this route MUST configure at least one entry in
  `auth.admin_tokens` and send it as `Authorization: Bearer <token>`.
  `caller_from_headers` was deliberately removed from this handler: the
  admin gate has already resolved "who is calling", and re-parsing the same
  header a second time under `caller_from_headers`'s rules would hand the
  admin token to `validate_bearer`, which fails on a non-JWT and returns 403
  whenever `auth.enabled = true` — precisely the registries that configure
  admin tokens. `tenant_for_request` is still called; it is a separate
  resolution step, deliberately tolerant of a non-JWT bearer. The frozen
  disclosure rule: an admin bearer counts as an **authenticated but
  unnamed** caller for the RFC-ACDP-0008 §4.5 public arm. Restricted and
  private bodies are never disclosed to the admin listing — the SQL
  predicate's restricted/private arms both require a non-NULL requester DID
  (`LIST_VISIBILITY_SQLITE`, `crates/acdp-registry-sqlite/src/store.rs:423-436`,
  and its Postgres twin, `crates/acdp-registry-pg/src/store.rs:171-175`),
  which a `None` requester can never reach. Both shipped configs gained a
  commented `# admin_tokens = ["<generate out of band>"]` under `[auth]` so
  the now-mandatory setting is discoverable.
- **Restored the RFC-ACDP-0008 §4.5 `anonymous_public_reads` disjunct to
  `list_contexts`** (`REG-11` Phase 2, `#133`): the pg/sqlite list-visibility
  predicate was a bit-for-bit copy of `search`'s disclosure predicate MINUS
  the `anonymous_public_reads ||` term on the `public` arm — `retrieve` and
  `search` both already honor the flag; `list_contexts` was the sole
  outlier. `ExtendedRegistryStore::list_contexts` gains a fifth parameter,
  `anonymous_public_reads: bool` (`crates/acdp-registry-store/src/lib.rs`),
  mirroring `RegistryStore::search`'s parameter of the same name; both SQL
  backends' visibility predicate now reads
  `Public => anonymous_public_reads || requester.is_some()`, arm-for-arm
  with `search` (`acdp-registry-pg/src/store.rs:171-175`,
  `acdp-registry-sqlite/src/store.rs:423-436`; the SQLite `LIST_VISIBILITY_SQLITE`
  const grows from three `?` placeholders, all bound to the requester, to
  five: `?req`, `?anon`, `?req`×3).
  **Observable behavior is unchanged in this release**: the sole production
  call site, `admin_list` behind `GET /admin/contexts`
  (`acdp-registry-core/src/handlers/admin.rs`), passes a literal `true`
  rather than `auth.anonymous_public_reads`, so today's "public rows always
  listed" outcome is reproduced byte-for-byte. Wiring the real config value
  there, together with gating the route behind the admin bearer, is a
  later, deliberately atomic change — not this one. Both backends'
  `sql_disclosure_matches_rfc_4_5_across_the_matrix` oracle test now
  exercises `list_contexts` under both `anonymous_public_reads` values
  inside the same `for anon_reads in [true, false]` loop that already
  covered `search`, closing the one place this repo's own §4.5 restatement
  didn't reach.
- **Twelve dependency majors** (`REG-11` Phase 1, `#136`): `rand` 0.8→0.10
  (`rand::thread_rng()` → `rand::rng()`, `RngCore` no longer at the crate
  root — `crates/acdp-registry-auth/src/service.rs`,
  `crates/acdp-registry-server/src/main.rs`), `hmac` 0.12→0.13 (`KeyInit`
  now imported separately from `Mac` —
  `crates/acdp-registry-webhook/src/lib.rs:250`), `jsonwebtoken` 9→11
  (switches the JWT crypto provider to the `rust_crypto` feature — no
  other provider was enabled by default before), `thiserror` 1→2,
  `ed25519-dalek` 2→3, `toml` 0.8→1.1, plus `tower-http`, `sha2`, `base64`,
  `config`, `metrics-exporter-prometheus`, and `serial_test`. `serial_test`
  is held at `3.x` rather than the dependabot-proposed `4.x`, which
  requires rustc 1.93.1 and would break the `msrv (1.88)` CI job. Added a
  `deny.toml` `advisories.ignore` entry for `RUSTSEC-2023-0071` ("Marvin",
  an RSA private-key timing side channel): `rsa` enters the dependency
  graph only because jsonwebtoken 11's `rust_crypto` feature enables it
  unconditionally, every JWT verification pins a single non-RSA algorithm
  before any crypto verifier is constructed, and this registry holds no
  RSA private key material to time. **This is the repository's second
  advisories-ignore entry, not its first** — `RUSTSEC-2025-0134` was
  ignored and then removed by PR #97 once `axum-server` 0.8 dropped
  `rustls-pemfile` from the graph entirely; this one is expected to
  outlive that pattern, since no upstream `rsa` patch exists for Marvin.
- **Extracted a shared `tests/common/` harness for `conformance.rs` and
  `http_integration.rs`** (`REG-10` Phase 6). Rust integration tests
  compile to separate binaries, so `conformance.rs` couldn't reach
  `http_integration.rs`'s router-building code and had grown three
  near-identical ad-hoc routers plus its own copies of
  `pct_encode_path_segment`, `body_to_json`, and `producer`. All of that
  now lives in `crates/acdp-registry-server/tests/common/mod.rs`
  (`mod common;` in both files), parameterized over store backend
  (`StoreMode::Memory` | `StoreMode::File` — `conformance.rs` used an
  in-memory `SqliteStore`, `http_integration.rs` a `NamedTempFile`; both
  are preserved) and capabilities document, so `conformance.rs`'s three
  routers and `http_integration.rs`'s harness ladder now both build on
  `common::build_harness_with_webhook`. `body_to_json` is deliberately kept
  as two functions rather than one: the two files' copies differed, with
  `http_integration.rs`'s panicking on an empty or non-JSON body and
  `conformance.rs`'s degrading to `Value::Null`. The strict form is the
  shared default at all 53 call sites, and `body_to_json_lenient` is used
  at exactly one — the fixture replayer, which drains arbitrary spec
  fixtures where an empty response is legitimate. Collapsing them onto the
  lenient form would have silently removed a guard from ~50 assertions.
  Pure refactor: the only line changed inside a `#[test]` body is that one
  replayer call, which is behavior-preserving, and the full suite passes
  with the exact same test count as before (175, across all seven binaries
  under `--features storage-sqlite,playground`).

- **Reworded the wit-001/wit-004 quorum assertion's message and its
  preceding comment** (`REG-10` Phase 5, GitHub issue #113) in
  `wit004_key_mismatch_cosignature_is_rejected_and_wit001_golden_is_accepted`.
  The old message claimed the assertion proved `report_both.witnesses`
  names *wit-001's* witness and not wit-004's — impossible by
  construction, since the test pins both fixtures to the same witness
  assertionMethod key and only ever registers one witness DID. The
  assertion is unchanged; it actually proves the one verifying
  cosignature is attributed exactly once in `witnesses`, consistent with
  `witnessed_count`. No executable change.

- **`storage-memory` gets its first required CI coverage** (`REG-10`,
  issue #109). `.github/workflows/ci.yml`'s `clippy` job gains a fourth
  step, `clippy (memory)`, running
  `cargo clippy -p acdp-registry-server --no-default-features --features
  storage-memory --all-targets -- -D warnings`; the `test` job gains a
  matching `cargo test (memory)` step running `cargo test -p
  acdp-registry-server --no-default-features --features storage-memory`.
  Both are appended as steps to the existing jobs, matching how the
  pg/sqlite/playground legs are already structured — no new job, no
  matrix, and `--no-default-features` is load-bearing: `storage-sqlite`
  is the crate's `default` feature, and a bare `--features storage-memory`
  would trip the `storage-sqlite`+`storage-memory` mutual-exclusion
  `compile_error!` in `crates/acdp-registry-server/src/main.rs`. Both legs
  land in the *required* `clippy`/`test` jobs, not the advisory `msrv`
  job, so a future break in `memory_ext.rs` now blocks merge instead of
  going uncaught entirely — before this change no CI job built
  `storage-memory` at all. Deliberately scoped as compile + lint coverage,
  not behavioral coverage: `--all-targets` compiles the bin and test
  targets under this feature set (closing a compile gap `memory_ext.rs`
  had never been checked against before), and `cargo test`'s memory leg
  runs the binary's own unit tests plus three tests from the two
  always-compiled integration binaries, but `tests/conformance.rs`,
  `tests/http_integration.rs`, and `tests/metrics_integration.rs` are all
  `#![cfg(feature = "storage-sqlite")]` and compile to zero tests under
  `storage-memory` — this leg proves the memory cfg gates and the memory
  `run()` arm typecheck and pass lint, not that the memory-backed store
  behaves correctly against the HTTP surface. Verified locally: both
  commands pass as-is (clippy clean; 40 tests pass — 37 unit plus 3 from
  the two always-compiled integration test binaries, with `conformance.rs`
  / `http_integration.rs` / `metrics_integration.rs` / `pg_integration.rs`
  each reporting `0 tests` under this feature set); a deliberate type
  error introduced into `memory_ext.rs`'s `put` impl made the clippy leg
  fail with `E0061`, confirming the leg is non-vacuous, then was reverted.
  `CONTRIBUTING.md`'s feature-flag variant block gains the matching
  `storage-memory` invocations alongside the existing pg/sqlite ones.
- **`acdp_version` capability advertisement now reaches `"0.5.0"`** (`REG-3`
  Phase 4 — **one-way-door**). Phase 3's RFC-ACDP-0016 §10/§14 version gate
  shipped with no reachable configuration of the shipped binary that could
  ever clear it — the ladder topped out at `"0.4.0"`, so every anchored
  publish was rejected forever. `crates/acdp-registry-server/src/main.rs`'s
  `build_capabilities` is refactored from the four-rung ordered if/else
  ladder into an order-independent `max()` over independent per-feature
  version claims (`ladder_claims` / `acdp_version_claim`): witnesses
  configured still contributes `"0.4.0"`, lifecycle/log/head-receipts still
  contributes `"0.3.0"`, a configured receipt key still contributes
  `"0.2.0"`, the base floor is still `"0.1.0"` — and a fifth,
  **unconditional** claim of `"0.5.0"` is added for `anchors` support,
  since RFC-ACDP-0016 §10 is explicit that anchors is "a body field, not a
  registry surface" with no new profile or admin-config gate to check (the
  accept/reject/store/serve handling runs on every publish regardless of
  config). Because that claim is both unconditional and the largest value
  in the `max()`, it wins for every configuration: **every reachable
  deployment of the shipped binary now advertises `acdp_version >=
  "0.5.0"`**, including a completely bare one with no receipt key, log, or
  witnesses configured. This is a deliberate, acknowledged trade-off, not
  an oversight — the previous four rungs no longer distinguish themselves
  in what `build_capabilities` actually serves (a consumer can no longer
  infer "does this registry aggregate witness signatures" from
  `acdp_version` alone), which is exactly the cost the plan names for this
  option. `RegistryServer::try_new`'s `validate_capabilities` startup check
  still passes for every existing config permutation (its only
  version-conditioned guard is `>= 0.3.0` requiring
  `supports_idempotency_key: true`, which is unconditionally `true` here
  regardless of version). This phase **executes the follow-up OQ2's own
  `DECISIONS.md` entry (2026-08-29) already recorded** — "if a 5th
  `acdp_version` rung is ever added, consider replacing the ordered if/else
  ladder with an order-independent `max()` over per-feature version
  claims" — rather than superseding OQ2's decision; OQ2's conditional
  0.4.0-ahead-of-0.3.0 ordering is unchanged, just re-expressed as one
  candidate among several. Logged `UNCONFIRMED` in `ASSUMPTIONS.md` pending
  `/reconcile` sign-off, per this repo's standing practice for one-way-door
  decisions.
- **Bumped `acdp` 0.8.1 → 0.8.2** (`REG-3` Phase 2), pulling all twelve
  `acdp-*` workspace crates in lockstep. This inherits `AnchorEntry`,
  `PublishRequest::anchors`, `Body::anchors`, `validate_anchors`, and
  anchors-in-preimage hashing (RFC-ACDP-0016) as plain library types — this
  repo adds no local struct or validation code for them in this commit. The
  crypto dependency graph moved with it, not just `acdp` itself: major
  version bumps across `base16ct` (0.2→1.0), `crypto-bigint` (0.5→0.7),
  `ecdsa` (0.16→0.17), `elliptic-curve` (0.13→0.14), `ff`, `group`, `p256`,
  `primeorder`, `rfc6979`, `sec1`, plus new dependencies
  `curve25519-dalek` 5.0, `ed25519-dalek` 3.0, `der`, `digest` 0.11,
  `sha2` 0.11, and `signature` 3.0 (`hashbrown` 0.16 dropped). This repo's
  own direct `ed25519-dalek = "2.2"` dev/runtime dependency
  (`acdp-registry-auth`, `acdp-registry-server`) now coexists with `acdp`'s
  transitive `ed25519-dalek` 3.0 as two separate major-version instances in
  the graph; it previously relied on feature unification with `acdp`
  0.8.1's own (then-matching) `ed25519-dalek 2.x` dependency to enable the
  `rand_core` feature (`SigningKey::generate`), which the 0.8.2 bump broke
  by moving `acdp`'s own dependency to `ed25519-dalek` 3.0. Fixed by
  splitting `acdp-registry-auth`'s `ed25519-dalek = "2.2"` dependency: kept
  featureless under `[dependencies]` (its actual production use, `jwt.rs`'s
  PEM decoding, never calls `generate`) and added a new
  `[dev-dependencies] ed25519-dalek = { version = "2.2", features =
  ["rand_core"] }` for tests that do call `generate` — rather than widening
  the production feature set for a test-only need. `acdp-registry-server`'s
  own `[dev-dependencies]` `ed25519-dalek` entry gains the same explicit
  `rand_core` feature for the same reason (it did not carry the feature
  before this commit; feature unification with `acdp`'s own then-2.x
  dependency supplied it implicitly). Neither fix bumps this repo's own
  dependency to 3.0 or pins `acdp` back — both are manifest-only, no
  production source changed. `cargo deny check` stays green (advisories,
  licenses, bans, sources all `ok`) with `deny.toml`'s `ignore = []`
  unchanged; the expanded graph's ~30 new/duplicated transitive crates
  (`base64`, `block-buffer`, `cmov`, `const-oid`, `cpubits`, `crypto-common`,
  `ctutils`, `curve25519-dalek`, `der`, `digest`, `ed25519`, `ed25519-dalek`,
  `fiat-crypto`, `hmac`, `hybrid-array`, `pkcs8`, `primefield`, `serdect`,
  `sha2`, `signature`, `spki`, `wnaf`, plus a `lru` 0.16→0.18 bump not
  previously called out) all license-clear under the existing allow-list and
  raise no new advisory; `[bans] multiple-versions = "warn"` accepts the
  resulting duplicate-major-version crates (including the `ed25519-dalek`
  2.x/3.x split) as warnings, not failures. **This commit alone would let a
  publish carry `anchors` with no version gate whatsoever** — it ships only
  combined with the RFC-ACDP-0016 §10/§14 version gate (`REG-3` Phase 3) in
  the same PR, and must not reach `main` on its own.
- **Pinned conformance spec SHA bumped to `417211f6a13aeceef4db00eb67f98ed0ed13761b`**
  (`REG-3`) in `.github/workflows/ci.yml`. The only substantive delta since the
  prior pin is RFC-ACDP-0016's draft and its conformance pack (the new `anc-*`
  fixture family, SPEC-9); the third commit in the range is an unrelated
  SPEC-7 rev-002 change with no anchors content. This repo does **not** yet
  implement RFC-ACDP-0016 — `anc` is classified in
  `crates/acdp-registry-server/tests/conformance.rs`'s `KNOWN_FAMILIES` (not
  `EXCUSED`) and picked up by the replay harness's non-HTTP fallthrough, same
  as `wit`; real coverage is a separate, later change.
- **Pinned conformance spec SHA** (`REG-2`) adopted in
  `.github/workflows/ci.yml`: now `31cf8743b62debe2c7c8572ce3a3a0b7ca5ad099`.
  Annotation-only at this pin: RFC-ACDP-0015 promoted Draft → **Final**
  (0.4.0), the `invalid_witness_cosignature` error code promoted
  Proposed → **Stable**, and the `acdp-log-witness` profile promoted
  Draft → **Final**. No fixture family, fixture shape, `id`, `request`,
  or `expected` field changed; the conformance harness runs unchanged
  against the new pin (`16 passed; 0 failed`, 4 exchanges replayed).
- **SHA-pinned credential-bearing workflow actions** (`REG-8`): every
  third-party action in `docker.yml` and `release-plz.yml` (plus
  `peter-evans/repository-dispatch` in `notify-website.yml`) now
  resolves at an immutable 40-hex commit SHA with a `# vX.Y.Z` (or
  `# stable` for `dtolnay/rust-toolchain`, a selector rather than a
  version) comment, matching `acdp-rs`'s two-tier pinning posture:
  `docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f
  # v3.12.0`, `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9
  # v3.7.0`, `docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051
  # v5.10.0`, `docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  # v6.19.2` (both call sites), `dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30
  # stable` (matches `acdp-rs`'s own current pin verbatim),
  `MarcoIeni/release-plz-action@2eb1d8bcb770b4c48ccfaad919734b38b51958c9
  # v0.5.131`, and `peter-evans/repository-dispatch@28959ce8df70de7be546dd1250a005dd32156697
  # v4.0.1`. First-party `actions/checkout@v4` stays tag-pinned
  (deliberate, matching the sibling's first-party tier), and the
  `acdp-ci/.github/workflows/*@v1` reusable-workflow refs are
  untouched (pinning those would break family propagation).
  `docker/login-action`, the pushing `docker/build-push-action` call,
  `MarcoIeni/release-plz-action`, and `dtolnay/rust-toolchain` are not
  exercised by this PR's own CI (gated off `pull_request` events or
  behind `on: push: branches: [main]`). `docker/login-action`,
  `docker/build-push-action`, and `MarcoIeni/release-plz-action` were
  each independently re-verified against their tag via `gh api`.
  `dtolnay/rust-toolchain` is the one deliberate exception: it is
  pinned to match `acdp-rs`'s own current SHA verbatim rather than to
  whatever `@stable` resolves to today (the two diverge — see the
  Approach section of `plans/reg2-reg5-reg6-reg8-reg9-wave4.md`
  Phase 9), so verifying it against `@stable` would show a mismatch
  by design; parity with the sibling's pin is the actual check.
- **Retired stale supply-chain narration** (`REG-9`): the
  `Cargo.toml` comment above the `acdp` dependency wrongly described a
  0.5.3-era, per-sub-crate version mix; it now states that `acdp`
  0.8.1 is a facade crate over eleven sub-crates published to
  crates.io and kept in lockstep at the same version, without naming
  individual sub-crate versions. `deny.toml`'s dead `allow-git` entry
  for the `acdp-rs` repo (a leftover from when `acdp` was git-sourced)
  is removed, which silences a persistent `cargo deny`
  `unmatched-source` warning. The one behavioral consequence: any
  future git dependency on `acdp-rs` is now a `cargo deny` finding
  instead of a silent allowance.
- **Wire-code mapping for `invalid_witness_cosignature`** (`REG-2`):
  `AcdpError::InvalidWitnessCosignature` now maps to wire code
  `invalid_witness_cosignature` / HTTP 502 in
  `acdp-registry-types::error::{acdp_wire_code, http_status_for_acdp}`,
  instead of falling through to the `internal_error`/500 catch-all.
  Deliberately kept distinct from `invalid_log_proof` even though both
  are 502, so a client can tell which upstream artifact failed
  verification. No handler emits this error yet (`grep -rn
  InvalidWitnessCosignature crates/acdp-registry-core/src/handlers/`
  returns zero hits) — this only closes the wire-mapping gap ahead of
  emission, which is a separate later change.
- **`acdp_version` claims 0.4.0 when witnesses are configured** (`REG-2`):
  `main::build_capabilities`'s version ladder gains a new rung, checked
  first, `!cfg.witnesses.is_empty() => "0.4.0"`. RFC-ACDP-0015 §6.1 witness
  cosignature aggregation — already implemented in full by
  `acdp-registry-core::witness` — is the sole registry-side 0.4.0
  obligation, so a deployment that aggregates witnesses was serving a
  0.4.0 wire member (`witness_signatures`) under a 0.3.0 `acdp_version`
  banner; this closes that under-claim and makes the prior `REG-2`
  wire-code entry's below-0.4.0 gate satisfiable rather than vacuously
  true (no deployment could ever have claimed 0.4.0 before this). Gated
  on `!cfg.witnesses.is_empty()` rather than `cfg.log.enabled`, since
  `validate_config` already refuses startup with witnesses configured and
  `log.enabled = false` — the new rung stays monotone with the existing
  0.3.0 rung on the real startup path without over-claiming 0.4.0 for
  every transparency-log registry that aggregates nothing. Does **not**
  advertise the `acdp-log-witness` profile — the spec forbids that for a
  registry (a witness is not a registry); only the version string
  changes.
- **Fixture-driven `wit-004`/`wit-001` coverage** (`REG-2`):
  `acdp-registry-server/tests/conformance.rs` gains
  `wit004_key_mismatch_cosignature_is_rejected_and_wit001_golden_is_accepted`,
  the first genuine coverage of the `wit-*` family against real pinned
  fixture data. Drives `acdp::client::verify_witness_cosignature_value`
  and `evaluate_witness_quorum` directly (not HTTP — RFC-ACDP-0015 §8
  witness-cosignature verification is a pure library check): the pinned
  wrong-key `wit-004` cosignature is rejected with
  `InvalidWitnessCosignature` naming the actual signature-verification
  failure, the paired `wit-001` golden verifies under the same witness
  key as a positive control, and the rejected cosignature does not count
  toward the N-witnessed quorum while the golden one does. `wit-*`
  remains classified "non-HTTP fixture" by the HTTP replay harness — this
  adds coverage beside it, not a reclassification.
- **Strengthened registry-side fork-refusal tests** (`REG-2`):
  `acdp-registry-core::witness`'s existing
  `cosignature_over_wrong_root_is_rejected` and
  `cosignature_beyond_current_head_is_rejected` previously asserted
  only `matches!(err, AcdpError::InvalidWitnessCosignature(_))` — a
  variant shared by the log-id mismatch, the beyond-head case, and every
  §8 verification failure, so `cosignature_over_wrong_root_is_rejected`
  could not tell a real root-mismatch rejection from an accidental
  beyond-head one. Both tests now additionally assert on their own
  distinct error MESSAGE wording (root_hash/checkpoint-mismatch vs.
  "beyond this registry's current head"), and both now assert the store
  holds zero cosignatures for the checkpoint tuple after the rejection —
  the property that actually matters operationally, since a rejected
  forged cosignature must never be stored or the aggregator could later
  serve a bogus one. `cosignature_over_wrong_root_is_rejected`'s forged
  root is now hardcoded to wit-002's own pinned root-rewrite vector
  (`sha256:deadbeef00000000000000000000000000000000000000000000000000000000`
  from `wit-002-consistency-refusal.json`) instead of an arbitrary byte
  pattern. **Scope note:** `wit-002` describes a WITNESS's obligation (a
  witness refuses to cosign a root-rewrite BEFORE signing and persists
  evidence of the refusal). This repo is a REGISTRY, not a witness — it
  never cosigns anything and structurally cannot exhibit that half of
  wit-002's behavior. This change covers only the mirror-image defense
  the registry DOES own: refusing to STORE/AGGREGATE a cosignature that
  doesn't match its own recomputed root, pinned to wit-002's forged root
  value. It is **not** a claim of wit-002 coverage.
- **BREAKING: `registry.profiles` allowlist** (`REG-5`):
  `main::validate_config` now refuses to boot if `registry.profiles`
  contains anything other than the seven *registry* profiles the pinned
  ACDP spec defines (`REGISTRY_ADVERTISABLE_PROFILES`, new in
  `acdp-registry-types::config`: `acdp-registry-core`,
  `acdp-registry-discovery`, `acdp-registry-federated`,
  `acdp-registry-receipts`, `acdp-registry-head-receipts`,
  `acdp-registry-transparency-log`, `acdp-registry-lifecycle`) — derived
  by rule (every `profiles[].id` in the spec's `registries/profiles.json`
  prefixed `acdp-registry-`), not hand-maintained, and checked by a new
  conformance test against the pinned spec so a future spec change turns
  CI red rather than drifting silently. The allowlist check runs BEFORE
  the existing per-profile backing-config guards (receipts key,
  head-receipts, lifecycle, transparency-log), so a typo is reported
  before an unrelated missing-config complaint. `acdp-log-witness`
  specifically is rejected with a dedicated message: a witness is not a
  registry (RFC-ACDP-0015 §6.1) — a registry MAY aggregate cosignatures
  under `acdp-registry-transparency-log` without ever advertising
  `acdp-log-witness` itself. This is a breaking change for any deployment
  that had an unknown or `acdp-log-witness` string in `registry.profiles`
  — this repo's own shipped examples and tests (`config/
  registry.example.toml`, `docker/config.docker.toml`, and every
  in-repo test config) were audited and only ever set allowlisted
  values, so none of them are affected.
- **BREAKING** (`SEC-07`): `auth.anonymous_public_reads` now defaults
  to `false`, matching `CLAUDE.md`. Operators upgrading who rely on
  world-readable public contexts MUST set the field explicitly:
  `[auth] anonymous_public_reads = true`.
- **Pagination, search** (`BUG-01`, `BUG-02`, `BUG-03`): cursor-based
  pagination is now driven by the SQL `LIMIT limit+1` sentinel — no
  more phantom next pages when the in-Rust visibility filter drops
  rows. Postgres `list_contexts` binds `LIMIT` via `$N` instead of
  string concatenation; search applies the cursor predicate and limit
  in SQL on both backends.
- **Health endpoint** (`BUG-05`): `GET /healthz` returns HTTP 503
  (with `status: "degraded"`) when storage health fails, so load
  balancers and Kubernetes readiness probes take the pod out of
  rotation. The body shape is unchanged.
- **DB-backed challenge store** (`BUG-06`, `DESIGN-02`): SQLite and
  Postgres binaries now wire `SqliteChallengeStore` /
  `PgChallengeStore` instead of the in-memory store. Multi-replica
  Postgres deployments no longer break the handshake when an agent
  hits a different replica for the token step.
- **Challenge duplicate-nonce error mapping** (`BUG-04`): SQLite and
  Postgres `ChallengeStore::put` map unique-constraint violations to
  `AuthError::ChallengeReplay`, matching `InMemoryChallengeStore`.
- **Cross-registry resolution failures** map to HTTP 502 (bad
  gateway), matching `KeyResolutionUnreachable`.
- **`total_estimate` in search responses** (`DESIGN-05`) is now `None`
  rather than the page-local match count (which was misleading; it was
  always ≤ `limit`).
- **`ContextType` storage** (`DESIGN-04`): typed accessor replaces the
  `serde_json::to_value(...).as_str()` round-trip in both backends and
  the publish event, so future multi-field variants don't silently
  serialize to the empty string.
- **Webhook emitter constructor** is now `WebhookEmitter::try_spawn`
  (URL + secret validation); `spawn` is kept for tests but no longer
  invoked by the server binary.
- **Default tracing format** stays JSON; opt into pretty via
  `ACDP_LOG_FORMAT=pretty`.
- **Docker Compose**: secrets sourced from `${VAR:-default}` env
  substitution; `auth.jwt_secret = "changeme"` aborts startup.
- **`axum` bumped 0.7 → 0.8, `tower` 0.4 → 0.5, `tower-http` 0.5 → 0.6**
  (`REG-6`): completes the HTTP-stack line-up the prior `axum-server`
  bump left half-done, collapsing the duplicate `tower` (0.4.13/0.5.3)
  and `tower-http` (0.5.2/0.6.11) trees the lockfile carried from the
  mismatched pairing — `Cargo.lock` now resolves a single `tower` 0.5.x
  and `tower-http` 0.6.x. All nine route path params in
  `acdp-registry-core::build_router` move from axum 0.7's `:ctx_id` /
  `:lineage_id` syntax to 0.8's `{ctx_id}` / `{lineage_id}` syntax (no
  behavior change — `matchit`'s static-over-dynamic route priority,
  e.g. `/contexts/search` over `/contexts/{ctx_id}`, is preserved).
  `TimeoutLayer::new` is deprecated in tower-http 0.6; the 30s response
  timeout now uses
  `TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30))`,
  same behavior. **Operator-visible change:** the Prometheus `route=`
  label on every parameterized endpoint (e.g. `GET /contexts/{ctx_id}`)
  changes from the old `/contexts/:ctx_id` form to the new
  `/contexts/{ctx_id}` form, since the label is sourced from axum's
  `MatchedPath`. Dashboards or alerts keyed on the old label form will
  go silently blank until updated to match. A new assertion in
  `tests/metrics_integration.rs` pins the new label form on a
  parameterized request so this doesn't regress unnoticed again.
- **SHA-pinned `ci.yml`'s third-party actions, and corrected an unreachable pin**
  (`REG-10`, #111): the fifteen `dtolnay/rust-toolchain`, `Swatinem/rust-cache`,
  `taiki-e/install-action`, and `EmbarkStudios/cargo-deny-action` refs across `ci.yml`'s
  eight jobs now resolve at an immutable 40-hex commit SHA with a trailing
  `# <version-or-branch>` comment, extending `REG-8`'s pinning posture from
  `docker.yml`/`release-plz.yml` to the last unpinned workflow. First-party `actions/*`
  refs stay tag-pinned, unchanged.
  All seven `dtolnay/rust-toolchain` call sites now pin
  `6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772 # master` and pass an explicit `toolchain:`
  (`stable` at six sites, `"1.88"` in `msrv`). dtolnay requires a pinned SHA to sit within
  `master`'s history — anything else is eventually garbage-collected — and the
  previously-used `4be7066…`, inherited from `release-plz.yml`, is today reachable from no
  ref at all. That pin is corrected in `release-plz.yml` as part of this change rather than
  copied into six more jobs.
  `Swatinem/rust-cache@6323deb… # v2.9.2` (six sites) and
  `EmbarkStudios/cargo-deny-action@3c63498… # v2.1.1` are ordinary tag-to-SHA pins.
  `taiki-e/install-action@1ed6d7be… # v2.87.2` pins a release SHA on `main` and passes
  `tool: cargo-llvm-cov` explicitly. The `@cargo-llvm-cov` tool tag defaults that input, but
  upstream strongly discourages pinning tool tags by hash: those commits are regenerated per
  release and are never in `main`'s history, so a hash pin starts referencing a commit that
  is not present on the repository.
  Because `# master` is a ref selector rather than a semver tag, Dependabot's
  `github-actions` ecosystem (`.github/dependabot.yml`, monthly) has nothing to track for the
  `dtolnay/rust-toolchain` pins; the `# v2.9.2`, `# v2.1.1`, and `# v2.87.2` pins will be
  kept current.

### Fixed

- **The playground publish branch now honors `supports_idempotency_key`**
  (`REG-11` Phase 5, `#128`): `crates/acdp-registry-core/src/handlers/
  context.rs`'s playground unpinned publish branch — the manual
  idempotency lookup/record dance it runs around `publish_unverified_for_tests`
  — reaches the SDK's `RegistryServer::commit_via_store` just like the other
  three publish paths (verified did:web, did:key, pinned-verified), but only
  via an unconditional `commit_via_store(req, None, None, None)` tail call
  (`server.rs:557`) that hardcodes the idempotency key to `None`, so
  `commit_via_store`'s own `supports_idempotency_key` gate (`server.rs:666`)
  is a no-op for this path and the branch cannot delegate this decision to
  it — previously honored ANY `Idempotency-Key` header unconditionally, with
  no check of
  `state.server.capabilities().supports_idempotency_key` anywhere in that
  branch. Fixed with one shared `idem_key` binding, computed once before the
  lookup and reused at both the lookup and record call sites, rather than two
  independent `&&` conditions: gating only the lookup would still write a
  record that a later `supports_idempotency_key = true` flip would start
  replaying — resurrecting replays from records that should never have
  existed — and gating only the record would still replay today. A single
  binding makes that divergence unrepresentable. Also corrected the
  handler's doc comment, which claimed `Idempotency-Key` "is honored when
  the registry advertises support" — true of the other three branches, false
  of this one before the fix — to instead name the actual mechanism and why
  this branch cannot delegate this decision.
  Two new direct tests in `crates/acdp-registry-server/tests/conformance.rs`,
  placed immediately after `idem005_no_support_ignores_idempotency_key_header`:
  `idem_playground_branch_honors_supports_idempotency_key_gate` (two
  publishes of the same body with the same key now get different `ctx_id`s
  when the capability is `false`) and
  `idem_playground_branch_writes_no_idempotency_record_when_gated_off`
  (asserts `GET /admin/status`'s `idempotency.records == 0`, which a
  lookup-only fix would not catch). Both use a **did:web** producer, not
  did:key — `context.rs`'s did:key branch is checked, and returns, before
  the playground branch is ever reached, so a did:key producer would
  silently re-exercise the already-gated SDK path and prove nothing about
  the branch under test. `idem005_no_support_ignores_idempotency_key_header`'s
  own doc comment is amended (not its assertions) to reflect that the gap it
  recorded is now fixed and covered from both sides.
  `#128`'s second bullet (`docs/CONFIGURATION.md:242`) was already
  discharged by PR #132 (`REG-11` context finding 5); no further doc change
  was needed for it here.
  No test result is asserted as measured in this entry: `cargo test` cannot
  run in this environment (EACCES writing `.d` files even with
  `CARGO_TARGET_DIR` on a fresh scratch dir), so verification is via CI on
  the PR.

- **Documentation sweep for the `#133` fix** (`REG-11` Phase 4): removed every
  doc statement and source comment describing `GET /admin/contexts` as
  ungated or as "the one exception" among `/admin/*` routes — `docs/HTTP-API.md`
  (the "Most `/admin/*` routes" paragraph, the "one exception" paragraph,
  and the route's own "Not admin-bearer gated" paragraph — the route-table
  footnote had already been removed in an earlier phase), `docs/OPERATIONS.md`
  (two "is an exception" / "is not" gated statements),
  `docs/CONFIGURATION.md` (the `admin_tokens` row's "does not
  disable `GET /admin/contexts`" clause), `crates/acdp-registry-core/src/lib.rs`'s
  route comment ("but NOT every `/admin/*` route"), and
  `crates/acdp-registry-types/src/config.rs`'s `admin_tokens` doc (which named
  only `POST /admin/pinned-keys/reload`, stale even before this plan — the
  field already gated five routes before Phase 3, and now gates all six).
  Added the disclosure rule to `ExtendedRegistryStore::list_contexts`'s trait
  doc (`crates/acdp-registry-store/src/lib.rs`), the one file this correction
  belongs in that no phase's file list had named.
  **This explicitly supersedes the "Documentation-accuracy pass (`REG-10`
  docs follow-up)" entry under the Documentation section below** (the one
  claiming `HTTP-API.md`'s "requires the admin bearer... it does not" and
  describing the gap as "a pre-existing gap... not a behavior change") —
  that entry was correct when written (PR
  #132, before Phases 2-3 shipped the fix) and is now the opposite of current
  behavior. Read it as history, not as the current contract.
  This is the sentence [SECURITY.md](SECURITY.md)'s "Keep
  `auth.anonymous_public_reads = false` unless the registry is meant to serve
  world-readable public contexts" was really about: it needed no edit here,
  but it only became fully true with this fix — before Phase 3,
  `GET /admin/contexts` disclosed public contexts to anonymous callers
  regardless of that setting.
  Docs-only; no behavior change. Not compiled locally — `rustdoc` (`docs`
  CI job) is the verification signal for this phase.

### Security

<!-- REG-11 #161 (Lane B) -->

- **Startup now refuses a blank or whitespace-padded entry in
  `auth.admin_tokens`** (`#161`).

  The failure this closes is not an operator blanking their admin allowlist —
  it is a deployment with **several working admin tokens where one templated
  from an unset variable**. The allowlist compare folds over every entry
  without early return (deliberately, for constant time), so
  `["tok-a", "tok-b", ""]` admits the empty token *alongside* the real ones.
  Every genuine token keeps working, the list is non-empty, and nothing looks
  anomalous — the deployment reads as correctly configured while
  `/admin/*` is open, including the live pinned-keys reload and the
  registry-attested retract/republish routes.

  The mechanism: `require_admin_bearer` strips `"Bearer "` and does not trim,
  so `Authorization: Bearer ` yields `""`, which matches an empty entry.
  **This is reachable over HTTP/2**, which preserves trailing whitespace in
  header values. Over HTTP/1.1 `httparse` strips trailing SP/HTAB/CR/LF before
  the value reaches the handler, so the same request arrives as `"Bearer"` and
  is refused. The registry serves both protocols.

  Padded entries such as `"tok "` are refused for the same reason from the
  other direction: HTTP/1.1 trims the request header but not the configured
  value, so such a token authenticates over HTTP/2 and 403s over HTTP/1.1.
  That fails closed rather than open, but it is the same templating accident
  and it is indistinguishable from a typo.

  **This is a hardening gap, not a live vulnerability.** It requires operator
  misconfiguration, and no shipped configuration is affected — both
  `config/registry.example.toml` and `docker/config.docker.toml` leave
  `admin_tokens` commented out, i.e. an empty *list*, which correctly means
  "admin routes disabled" and remains valid. What makes it worth closing is
  the direction of the failure: templating from an unset environment variable
  **fails open rather than closed**, which is the wrong direction for a
  security gate.

  The guard is in `validate_config`, beside the existing `auth.jwt_secret`
  checks — the same class of shared secret, already guarded three ways (empty,
  the `changeme` placeholder, and a decoded-length floor) while `admin_tokens`
  entries were not inspected at all. Failing at startup rather than per request
  keeps a misconfiguration from presenting as a client-side 403.

  The constant-time comparison itself (`ct_eq`, `#23`) is correct and
  unchanged; the gap was strictly upstream of it, in what reached the
  allowlist.

<!-- end REG-11 #161 -->

- **`chacha20` bumped 0.10.1 → 0.10.2** (`REG-11` Phase 2 ride-along;
  lockfile-only version bump, not a `deny.toml` ignore): `0.10.1` is
  yanked from crates.io. It sits behind `rand::rng()` on the
  auth-challenge-nonce path (`crates/acdp-registry-auth/src/service.rs`),
  so this closes the CSPRNG core to a yanked dependency without any code
  change; `cargo update -p chacha20` only re-resolves the lockfile.
- `SEC-01` through `SEC-07` — full sweep landed; see Added/Changed
  above for individual items. Notable: empty-string webhook secrets
  no longer silently produce valid HMACs (`SEC-04`), and the
  `RequestBodyLimitLayer` (`SEC-06`) protects every route from
  arbitrarily-large request bodies.
- **`h2` bumped 0.4.15 → 0.4.19** (lockfile-only version bump, not a
  `deny.toml` ignore): resolves `RUSTSEC-2026-0258`, in which `h2`
  queued empty `DATA` frames without limit, risking unbounded memory
  growth or a length-overflow panic. Reached transitively via
  `hyper` ← `axum` / `axum-server` / `hyper-rustls` / `reqwest`.
- **`[graph] all-features = true`** (`REG-7`) in `deny.toml`: the
  cargo-deny advisory/license/bans gate now resolves every
  feature-gated subgraph, including the `storage-pg` path the Docker
  image ships (`STORAGE_FEATURE=storage-pg` by default in
  `docker/Dockerfile`), instead of only the default-features graph.
  `cargo deny --workspace check` remains green with no new findings.
- **`axum-server` bumped 0.7 → 0.8** (`REG-6`): removes `rustls-pemfile`
  from the dependency graph entirely (0.8.0 replaced it with
  `rustls-pki-types`'s `PemObject` trait), so the `RUSTSEC-2025-0134`
  ignore entry is deleted from `deny.toml` rather than merely
  satisfied. `axum_server::Handle` is now generic over the bind
  address (`Handle<A: Address>`); `main.rs` annotates its one
  `Handle::<SocketAddr>::new()` construction site (shared by both the
  non-TLS and TLS-capable serve paths) and the `spawn_shutdown_watcher`
  signature accordingly. No router or crypto-provider changes —
  `tls-rustls` still resolves to `rustls/aws-lc-rs`.

### Documentation

<!-- REG-11 #152 (Lane B) -->

- **Bearer-parsing behaviour is now documented** (`#152`), in a new
  "Presenting a bearer" section of `docs/AUTHENTICATION.md`, with
  cross-references from `README.md` and `SECURITY.md`.

  Two facts were true but written down nowhere. First, an `Authorization`
  header the registry does not recognise as a bearer — a non-`Bearer` scheme, a
  misspelled header, a non-UTF-8 value — is treated as **anonymous** on the
  ordinary read/publish routes rather than refused: a typo'd scheme never reaches
  token validation at all. Only a well-formed bearer that then fails validation
  is rejected, and that rejection is `403 not_authorized` — this registry emits
  no `401` on the auth path. What the caller sees after the anonymous
  classification depends on the route and on `auth.anonymous_public_reads`
  (default `false`), so it may be a refusal or a filtered result set.
  `/admin/*` refuses all the same inputs with `403`.

  Second, the two parsers disagree. `extract_bearer` accepts `Bearer ` or
  `bearer ` and trims the token; `require_admin_bearer` accepts `Bearer ` only
  and does not trim. So `bearer <jwt>` authenticates on `/contexts/*` and 403s
  on `/admin/*`. Both admin behaviours are pinned by tests
  (`bearer_scheme_is_case_sensitive`, `rejects_token_with_extra_whitespace`), so
  the strictness is deliberate rather than accidental.

  The section corrects a claim in the issue that prompted it: `#152` argued the
  lax parser is the RFC 7235-conformant one. It is not — both parsers hard-code
  their prefixes, so `BEARER` and `BeArEr` are rejected by **both**. Neither is
  case-insensitive; one simply accepts an extra spelling.

  Trailing whitespace is documented as protocol-dependent, which is the one
  behaviour here that cannot be stated flatly: `httparse` strips trailing
  whitespace from HTTP/1.1 header values before any handler sees them, while
  HTTP/2 preserves it. `Bearer <jwt> ` is therefore accepted everywhere over
  HTTP/1.1 and refused by `/admin/*` over HTTP/2.

<!-- end REG-11 #152 -->

- Reference guides under `docs/`: an index (`README.md`) plus
  `HTTP-API.md` (every endpoint, media types, and the RFC-ACDP-0007
  error envelope), `AUTHENTICATION.md` (DID challenge-response, JWT
  claims, HS256 vs EdDSA/JWKS, token revocation, cross-issuer
  revocation federation), `CONFIGURATION.md` (the full config tree and
  startup validation), `MULTI-TENANCY.md` (tenant resolution and strict
  mode), and `WEBHOOKS.md` (event payloads and the signature scheme).
- `ARCHITECTURE.md` and `OPERATIONS.md` refreshed to match the current
  code (crates.io `acdp` dependency, EdDSA/JWKS, revocation federation,
  multi-tenancy, admin endpoints, rate limiting). Protocol-level material
  links to the `acdp` library docs rather than being restated.
- `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` corrected to reflect
  that `acdp` is consumed from crates.io (no sibling path dependency) and
  the current auth/hardening surface.
- **Documentation-accuracy pass (`REG-10` docs follow-up) — two inaccuracies
  corrected, both in the permissive direction (docs described the code as
  safer/more restricted than it actually is). Two source comments carrying
  the same false permissive framing were also corrected
  (`crates/acdp-registry-core/src/lib.rs`, `crates/acdp-registry-core/src/handlers/admin.rs`)
  — comments only, no logic or signature changes, no behavior change.**
  - `CONFIGURATION.md`'s `[playground]` section and `README.md`'s feature
    list said the DID-signature bypass itself was "compiled in only with
    the `playground` Cargo feature." It is not: only the two `/admin/*`
    routes (`admin_router` in `crates/acdp-registry-core/src/lib.rs`) are
    `#[cfg(feature = "playground")]`-gated. The publish handler's
    DID-verification skip
    (`crates/acdp-registry-core/src/handlers/context.rs`, the
    `playground_snapshot.enabled` branch) is a plain runtime `if` present in
    every build, including a stock release binary — verified directly: that
    file's only `cfg` attributes are three `#[cfg(test)]` blocks. Corrected
    to say so; the existing "never enable
    in production" warning is retained and strengthened — it now leads the
    section (previously buried behind a paragraph of compile-gating detail)
    and reads as the stronger, accurate claim (the risk exists regardless of
    how the binary was built, and is scoped to non-`did:key` publishes),
    not weakened. `OPERATIONS.md` and `HTTP-API.md` already scoped
    the feature-gate claim correctly, to the admin routes only.
  - `HTTP-API.md`'s endpoint table and Admin section said `GET
    /admin/contexts` requires the admin bearer (`auth.admin_tokens`), like
    the other `/admin/*` routes. It does not: `admin_list`
    (`crates/acdp-registry-core/src/handlers/admin.rs`) calls only
    `caller_from_headers`/`tenant_for_request` — the same resolution the
    regular tenant-scoped read routes use — and never
    `require_admin_bearer`, unlike `reload_pinned_keys`, `admin_status`,
    `lineage_audit`, and the lifecycle-transition handlers, which do.
    With `auth.enabled = false` the route is fully anonymous — and even with
    `auth.enabled = true`, no bearer is required at all when the
    `Authorization` header is simply absent (`caller_from_headers` returns
    `Ok(None)`), so an unauthenticated request still enumerates public
    contexts. This is a pre-existing gap between the route's `/admin/` path
    and its actual authorization, not a behavior change — `OPERATIONS.md`
    and `README.md`'s endpoint table corrected to match.
