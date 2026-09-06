# Decisions log

Durable record of `/reconcile` outcomes. Each entry: the original assumption, the
recommending agent's verdict, the human decision, and the resulting status. `/ship` and
future `/reconcile` passes read this file instead of replaying the conversation.

## 2026-08-29 — `reg3-anchors` Phase 4 (RFC-ACDP-0016 version-gated anchors, PR B in flight)

Reconciled pre-ship, per `/drive`'s own sequencing (run once every phase is `DONE`,
before the closing `/ship` pass). One `UNCONFIRMED` entry, a genuine one-way door
(public wire-contract change to the capabilities advertisement).

### 1. Make `acdp_version: "0.5.0"` reachable in the capability ladder
- **Assumption:** without this phase, RFC-ACDP-0016 §10's version gate is dead on
  arrival — the pre-existing ladder in `build_capabilities`
  (`crates/acdp-registry-server/src/main.rs`) topped out at `"0.4.0"`, so no
  configuration of the shipped binary could ever advertise `>= 0.5.0`, and every
  anchored publish would be rejected forever in production.
- **Chosen implementation:** the `max()`-over-per-feature-version-claims refactor
  (`main.rs:866-957`) — `ladder_claims`/`ladder_rung_claim`/`acdp_version_claim` — with
  an unconditional `ANCHORS_VERSION_CLAIM: (5, "0.5.0")` folded in, so every reachable
  deployment now advertises `acdp_version >= "0.5.0"`, no config gate to opt out. This
  executes the prior wave's OQ2 follow-up (`DECISIONS.md`, `reg2-reg5-reg6-reg8-reg9-wave4`
  entry) rather than superseding it.
- **Recommending agent:** fresh Fable pass (one-way-door tier, per `/reconcile`'s own
  tiering rule), independent of the Fable pass already run during `/implement`'s Phase 4
  verification gate (that one checked implementation correctness; this one checked
  whether the choice is still the strongest long-term call now that the code exists).
- **Fable's recommendation:** **CONFIRM as-is.** Re-verified the "dead on arrival" claim
  directly against `crates/acdp-registry-core/src/handlers/context.rs:338-347` (the
  accept gate keys on `state.server.capabilities().acdp_version`). Found the
  implementation-time framing of alternative (b) — a config opt-in flag gating only the
  *advertisement* — was inaccurate: because the accept gate keys on the advertised
  version, a default-false flag would de facto gate anchors *acceptance itself*,
  shipping the feature broken-by-default for any operator who never finds the flag, and
  would reintroduce the exact version-regression hazard (advertised version dropping
  back down when a flag is toggled off) that the one-way-door analysis most wanted to
  avoid. The unconditional constant is the only shape where the advertised version can
  never regress. Residual risk (an operator with no interest in anchors has no opt-out)
  is unchanged from before this phase either way, since anchor handling is unconditional
  code regardless of the advertisement mechanism.
- **Human decision:** **Confirm as-is**, per Fable's recommendation.
- **Status:** CONFIRMED (2026-08-29).

---

## Summary (`reg3-anchors` Phase 4)

1 entry, confirmed as recommended — no code changes needed. PR B (Phases 2-7) is now
clear to proceed to the closing `/ship` pass; this was the only `UNCONFIRMED` entry
blocking it.

---

## 2026-08-29 — `reg1-reg7-conformance-deny` (REG-1 PR #94, REG-7 PR #93, both merged)

Reconciled post-ship, per `/drive`'s own procedure (both PRs already merged; this pass
closes out `ASSUMPTIONS.md`'s 8 `UNCONFIRMED` entries logged during implementation).

### 1. `checkout-spec@v1` vs inline checkout
- **Assumption:** shipped an inline `actions/checkout@v4` for the spec pin in
  `.github/workflows/ci.yml`'s `conformance` job, diverging from
  `acdp-ci/DELIVERY-STANDARD.md:64-71`'s stated "MUST use `checkout-spec@v1`."
- **Recommendation (Opus):** confirm as-is. Decisive finding: the `v1` tag in `acdp-ci`
  (`8e99405`) is six commits behind `main` and does not contain the `checkout-spec`
  action at all (added later in `22dd548`) — a workflow referencing
  `acdp-ci/actions/checkout-spec@v1` today would fail to resolve. Zero repos in the
  family use the shared action; `acdp-rs` itself still does inline checkout, confirming
  DELIVERY-STANDARD.md's claim about `acdp-rs` is stale. The document describes an
  intent, not a current state.
- **Decision:** Confirm as-is. File a GitHub issue in `acdp-ci` flagging: (a) `v1` needs
  re-tagging to include `checkout-spec`, (b) DELIVERY-STANDARD.md:64-71's status line
  needs correcting for both `acdp-rs` and this repo.
- **Status:** CONFIRMED (2026-08-29). **Follow-up owed:** file the `acdp-ci` issue
  (tracked below, not yet filed as of this entry — see Follow-ups).
- **Correction (2026-09-01):** the `acdp-ci` issue was filed and resolved —
  `acdp-ci#9` ("Move the v1 tag — CI-1/CI-6/CI-7 hardening is merged to main
  but unreachable at v1"), now CLOSED. `acdp-ci`'s `v1` tag has been re-tagged
  to the current `main` HEAD (`015910153b61c32abbe018afe85d44868897bf3b`,
  verified via `git rev-parse v1^{commit}`/`git rev-parse main` in a local `acdp-ci`
  checkout) and now contains `actions/checkout-spec` (`git ls-tree -r v1`
  lists `actions/checkout-spec/action.yml`). The premise that motivated
  "confirm as-is" (an unusable `v1`) no longer holds; this repo still does
  inline checkout rather than adopting `checkout-spec@v1`, which is fine —
  nothing requires the change — but the DELIVERY-STANDARD.md staleness this
  entry flagged for `acdp-ci` is only PARTIALLY fixed: `acdp-ci#9` (closed) was
  scoped solely to re-tagging `v1` and never mentions the status-line text, and
  a byte-for-byte diff of `DELIVERY-STANDARD.md`'s status paragraph between
  `22dd548` and current `acdp-ci` HEAD (`0159101`) shows no change — it still
  reads "As of 2026-08-28: `acdp-rs` pins via this action; `acdp-verifier-py`
  (PY-2) and `acdp-registry-rs` (REG-1) are scheduled to adopt it — until they
  do, their CI does not enforce this rule." That line is now factually wrong
  about this repo: `acdp-registry-rs` already pins the spec at a 40-hex SHA
  inline (`.github/workflows/ci.yml:161`), just not via `checkout-spec@v1`.
  Part (b) of the original follow-up (correcting the status line) was never
  filed and remains outstanding.
- **Superseded (2026-09-06, `#155`):** this repo now uses the shared action.
  `.github/workflows/ci.yml`'s `conformance` job calls
  `agentcontextdistributionprotocol/acdp-ci/actions/checkout-spec@015910153b61c32abbe018afe85d44868897bf3b # v1`,
  so the inline `actions/checkout` spec step this entry describes — and the
  `.github/workflows/ci.yml:161` line the 2026-09-01 correction cites — no
  longer exist. The original "confirm as-is" is left standing above on purpose:
  it was correct on 2026-08-29, when `v1` genuinely did not contain the action.
  Only its premise changed, and the 2026-09-01 correction had already recorded
  that change. The pinned spec ref is untouched
  (`d1f06d0d49b73d411a3983d3877321ccaccd38e7`); the action itself is pinned at
  the commit `v1` dereferences to — `v1` is an annotated tag, so `refs/tags/v1`
  → tag object `82b2a25…` → commit `0159101…`, which is why `@v1` would not
  have been a pin at all. That matches `acdp-verifier-py`'s call site verbatim
  and `REG-8`/`REG-10`'s rule that non-`actions/*` refs resolve at an immutable
  SHA. Part (b) above is unchanged by this and is now *worse* than stale:
  `DELIVERY-STANDARD.md`'s status line says this repo is "scheduled to adopt"
  the action and that "until they do, their CI does not enforce this rule" —
  flatly false once `#155` lands. Still not filed; still owed.

### 2. `bump-spec.yml` scope
- **Assumption:** no `bump-spec.yml` in this repo; the pinned spec SHA will never
  auto-refresh via the family's `repository_dispatch: spec-released` mechanism.
- **Recommendation (Opus):** change — add it now. This repo's inline checkout shape is
  compatible with the shared `bump-spec-ref.yml@v1` caller (its matcher handles both the
  inline `repository:`/`ref:` shape and the `checkout-spec@` shape), so no
  `checkout-spec@v1` adoption is required first. But found a deeper gap: the spec repo's
  own `notify-spec-consumers.yml` dispatch matrix is hardcoded to `[acdp-rs,
  acdp-verifier-py]` — adding `bump-spec.yml` here alone doesn't close the loop; this
  repo also needs adding to that matrix, a cross-repo edit in the spec repo.
- **Decision:** Add `bump-spec.yml` here as a near-term follow-up (inert until
  dispatched, zero CI-time risk). File the spec-repo dispatch-matrix addition as a
  separate, paired cross-repo item.
- **Status:** NEEDS-FOLLOWUP (2026-08-29). Not a one-way door, not blocking anything
  already shipped. **Follow-up owed:** (a) add `bump-spec.yml` to this repo, (b) file an
  issue/PR against the spec repo's `notify-spec-consumers.yml` matrix + update
  DELIVERY-STANDARD.md's status line for this repo.
- **Correction (2026-09-01):** part (a) shipped — `.github/workflows/bump-spec.yml`
  exists (commit `87e4127`, "ci: add bump-spec.yml for spec-pin bumps (#110) (#119)").
  Part (b) is still outstanding: the spec repo's
  `.github/workflows/notify-spec-consumers.yml` dispatch matrix (line 25) is still
  hardcoded `repo: [acdp-rs, acdp-verifier-py]` — `acdp-registry-rs` has not been added,
  verified directly against that file. **Status:** part (a) DONE, part (b) still
  NEEDS-FOLLOWUP.
- **Note (2026-09-06, `#155`):** the compatibility argument in the recommendation
  above still holds, but this repo now exercises the *other* branch of that
  matcher. `bump-spec-ref.yml@v1` anchors on either a `repository: <spec>` line
  or an `acdp-ci/actions/checkout-spec@` line; since `#155` this repo matches on
  the latter. Verified by running that workflow's own anchor-count `awk`, its
  `perl` rewriter and its post-rewrite assertion against the new `ci.yml`: one
  anchor, and a simulated bump rewrote exactly one line, the spec `ref:`. Note
  for future editors: adding an explicit `repository:` to the `checkout-spec`
  step would create a second anchor and make `bump-spec.yml` fail every run.

### 4. REG-1 acceptance criterion — the "as applicable" reading
- **Assumption:** REG-1's acceptance criterion named six families (`pub-, vis-, idem-,
  caps-, lc-, fed-`) as ones that should execute "as applicable." Shipped reading: only
  `pub`/`ret` genuinely replay; the other five are accounted-for skips.
- **Recommendation (Opus):** the shipped disclosure is honest, but the "as applicable"
  reading doesn't hold uniformly across all five skipped families. `lc`/`fed` (disjoint
  advertised profile) and `caps` (non-HTTP, document-schema fixture) are legitimately
  "not applicable." `vis` and `idem` are different: both are core-*required* by the
  spec's own `acdp-registry-core` profile (confirmed via `required_fixtures`/
  `conditional_fixtures`), and the ratchet's own excuse rule would mechanically reject
  excusing them if asked — so calling them "not applicable" is inconsistent with the
  ratchet's own logic. Closing the gap needs a "stateful replay" capability (pre-seed a
  golden `sig-001` context, advertise more profiles, substitute `{ctx_id}` templates) —
  real new work, not a quick fix; priced in the plan as "roughly a phase of its own,"
  reaching ~19 fixtures (`vis`/`idem`/`lc` together).
- **Decision:** REG-1 as shipped stands (already merged, honestly disclosed in the PR
  body) — no rework of merged code. Schedule the stateful-replay phase as a concrete
  near-term follow-up item (not indefinite backlog), specifically to close `vis`/`idem`
  coverage.
- **Status:** NEEDS-FOLLOWUP (2026-08-29). Shipped code is sound; a scheduling gap, not
  a code defect. **Follow-up owed:** schedule "stateful replay" as a new REG-item
  (numbering TBD by whoever next touches `plans/00-overview.md`'s status board).
- **Correction (2026-09-01):** the "`lc`/`fed` and `caps` are legitimately not
  applicable" claim above does not match the shipped `EXCUSED`/`DEFERRED` split.
  Verified directly against `crates/acdp-registry-server/tests/conformance.rs`: `EXCUSED`
  (~6585-6618) is exactly `fp`, `data-ref-ssrf`, `fed`, `rot` — only `fed` of the three
  named here actually got the "not applicable" treatment. `caps` is `DEFERRED`
  (~6714-6719) with the reason "required-but-uncovered: ... mechanically inexcusable" —
  the opposite of not-applicable. `lc` is `DEFERRED` (~6730-6735), reason: "plausibly
  excusable, but that has never been declared, so it stays DEFERRED rather than silently
  assumed EXCUSED" — i.e. this entry's own "not applicable" framing is precisely the
  unearned assumption that DEFERRED status was created to refuse. The stateful-replay
  follow-up this entry scheduled did ship (REG-10 Phases 5-11): `vis` and `idem` are now
  both `COVERED` in the same file (Replayed + Direct for `vis`; Direct for `idem`),
  closing the gap this entry flagged for those two families. `caps` and `lc` remain
  open, tracked as `DEFERRED` under issue #115, not closed by this correction.

### 3. `can`/`lin` deliberately not excused from the coverage ratchet
- **Assumption:** `can` (12 fixtures) and `lin` (1 fixture) stay in `KNOWN_FAMILIES`
  with zero coverage rather than being added to `EXCUSED`, despite looking like pure
  library golden-vectors — because both are in `acdp-registry-core.required_fixtures`.
- **Recommendation (Opus):** confirm the policy — it's mechanically self-enforcing
  (`no_excused_family_is_required_by_our_profile` would reject excusing either by
  construction) and independently spec-verified twice this session. Separately: `can`
  and `lin` appear in zero Rust source (no `acdp-jcs` golden-vector re-assertion exists
  in this workspace either) — the recommender suggests `can` specifically might be
  cheaply closeable via a direct content-hash-path test, independent of and much cheaper
  than the expensive `vis`/`idem`/`lc` stateful-replay work.
- **Decision:** Confirm the policy as-is (no change to `EXCUSED`). Confirmed as
  recommended in the batch check — `can`'s cheap-closure finding is noted for whoever
  schedules the coverage-gap follow-up work (see #4 above), not separately scheduled by
  this pass.
- **Status:** CONFIRMED (2026-08-29).

### 5. `h2` CVE fix bundled into the REG-7 PR
- **Assumption:** `RUSTSEC-2026-0258` (h2, unrelated to REG-7's actual ask) was found
  already blocking `cargo-deny` on `main`, independent of the `all-features` flip, and
  fixed as its own commit/phase within REG-7's PR (#93, merged) rather than filed
  separately.
- **Recommendation (Opus):** confirm as-is. No policy in `DELIVERY-STANDARD.md` or
  `CONTRIBUTING.md` against bundling; REG-7's acceptance was literally unreachable
  without the fix; it was reported not silenced (version bump, no `ignore` entry, per
  REG-7's own instruction); kept as a separate commit so the flip's green run stays
  attributable to the flip. Already merged — reverting would undo a safe security fix
  for no benefit.
- **Decision:** Confirm as-is.
- **Status:** CONFIRMED (2026-08-29).

### 8. Plan-text overclaim ("yields exactly four")
- **Assumption:** the plan's Phase 4 prose claims its two-part excuse rule "yields
  exactly four" excused families — not mechanically true (ten families satisfy the
  stated two-part rule; a third, unstated criterion — "server doesn't implement it" —
  is what narrows ten to four). Zero shipped-code impact; the code's own doc-comment
  states the rule correctly.
- **Recommendation (Opus):** confirm, no edit needed — the plan file already carries a
  self-correction block (added during this session) stating the exact finding, sitting
  *before* the overclaimed line in reading order, so a future reader hits the caveat
  first. Editing the original line would just add a third copy of the same disclosure.
- **Decision:** Confirm as-is, no further plan edit.
- **Status:** CONFIRMED (2026-08-29).

### 6. Stale `deny.toml` entries (REG-9 scope)
- **Assumption:** an unused `allow-git` entry for `acdp-rs` and a stale "consumed from
  git" comment in `deny.toml`, left untouched (REG-9's separately scheduled item).
- **Recommendation (Opus):** confirm as deferred. Verified dead (workspace pulls `acdp`
  from crates.io, confirmed via `Cargo.toml`); benign `unmatched-source` warning is the
  only cost; folding into REG-7's PR would have been scope creep for zero risk
  reduction.
- **Decision:** Confirm, deferred to REG-9.
- **Status:** CONFIRMED (2026-08-29).

### 7. `storage-memory` uncovered by CI
- **Assumption:** a third storage-backend feature (`storage-memory`) is exercised by
  zero CI jobs today; noticed in passing, not added to any REG-1/REG-7 phase.
- **Recommendation (Opus):** confirm as flagged, but treat as a real gap rather than
  purely informational — unlike the deny.toml entries, this gates actual compiled code
  (`crates/acdp-registry-server/src/memory_ext.rs`, `#[cfg]` branches in `main.rs`) and
  a documented user-facing config option (`docs/CONFIGURATION.md:112`), so zero CI
  coverage means a silent compile break is possible for anyone selecting it. Cheap fix
  (one clippy matrix entry) argues for scheduling, not doing it unscheduled here.
- **Decision:** Confirm as recommended — file as a trackable backlog item (not just a
  passive note), owner TBD ("whoever owns CI-matrix completeness").
- **Status:** NEEDS-FOLLOWUP (2026-08-29). **Follow-up owed:** file a backlog item (new
  REG-item or a note on `plans/00-overview.md`'s status board) for
  `storage-memory` CI coverage.
- **Correction (2026-09-01):** shipped — commit `57d74e9` ("ci: build and lint
  storage-memory in required checks (REG-10, #109) (#118)"). `.github/workflows/ci.yml`
  now runs a `clippy (memory)` step (`--no-default-features --features storage-memory`,
  lines 56-60) and a `cargo test (memory)` step (lines 135-138) inside the `test` job
  (`test:` at line 97, display name `tests`) — not the `msrv` job (lines 64-80), which
  only runs `cargo check (sqlite default)` (line 74) and `cargo check (postgres)`
  (line 76) and never touches `storage-memory`. **Status:** DONE.

---

## Summary

7 entries confirmed, 3 of those confirmed-with-a-scheduled-follow-up (#2 bump-spec.yml,
#4 stateful-replay phase, #7 storage-memory CI coverage), 1 additional follow-up
(#1's `acdp-ci` issue). Zero entries changed the already-shipped code — both PR #93 and
PR #94 stand as merged. Zero one-way doors were in play. **Follow-ups still owed, not
yet done as of this reconcile pass:**
1. File a GitHub issue in `acdp-ci` re: `v1` tag missing `checkout-spec`, and
   DELIVERY-STANDARD.md's stale status lines (entry #1).
2. Add `bump-spec.yml` to this repo (entry #2, part a).
3. File/pair a cross-repo item for the spec repo's dispatch-matrix + DELIVERY-STANDARD
   status line (entry #2, part b).
4. Schedule a "stateful replay" REG-item to close `vis`/`idem` coverage (entry #4).
5. File a backlog item for `storage-memory` CI coverage (entry #7).

None of these are blocking anything already merged. They are new, separately-scoped
work items for a future session.

**Correction (2026-09-01) — status of the five follow-ups above, re-verified against
current `main`:**
1. PARTIAL — `acdp-ci#9` filed and closed; `acdp-ci`'s `v1` tag now points at `main` and
   contains `checkout-spec`. But `acdp-ci#9`'s scope was the `v1` tag only — it never
   mentions DELIVERY-STANDARD.md's status lines, which remain byte-identical to
   `22dd548` and are now factually wrong about this repo (see entry #1's correction
   above). The stale-status-line half of this follow-up was never filed and is still
   owed.
2. DONE — `.github/workflows/bump-spec.yml` shipped (commit `87e4127`, #119).
3. STILL OWED — the spec repo's `notify-spec-consumers.yml` dispatch matrix (line 25) is
   still `[acdp-rs, acdp-verifier-py]`; `acdp-registry-rs` has not been added.
4. DONE — `vis`/`idem` are both `COVERED` in
   `crates/acdp-registry-server/tests/conformance.rs` as of REG-10 Phases 5-11 (see entry
   #4's correction above). Note `caps`/`lc` were never claimed closeable by this
   follow-up and remain `DEFERRED` (#115).
5. DONE — `storage-memory` runs in `.github/workflows/ci.yml`'s required checks (commit
   `57d74e9`, #118; see entry #7's correction above).

Item 3 is fully open; item 1's status-line half is also still open (see above).

---

## 2026-08-29 — `reg2-reg5-reg6-reg8-reg9-wave4` (REG-2, REG-5, REG-6, REG-8, REG-9 — PRs #95, #96, #97, #99, #101, all merged)

Reconciled post-ship, per `/drive`'s own procedure. 5 `UNCONFIRMED` entries logged during
`/implement` (the plan's own Open Questions section already proposed a defensible default
for each, so `/implement` proceeded without stopping — this pass converts those into
confirmed decisions). Ranked by blast radius: OQ2 (public wire contract) first, OQ1
(design-honesty of a test-coverage substitution) second, OQ3–OQ5 (low/near-zero blast
radius, already realized as merged code) batched per reconcile's own norm for trivial
items.

### OQ2 — advertise `acdp_version: "0.4.0"` when aggregating witness cosignatures
- **Assumption:** a registry with `[[witnesses]]` configured should stop under-claiming
  `acdp_version: "0.3.0"`, since it already serves the 0.4.0 `witness_signatures` wire
  member (`main::build_capabilities`, gated on `!cfg.witnesses.is_empty()`, ordered
  before the 0.3.0 rung).
- **Recommendation:** confirm. This item already received a dedicated **Fable**
  one-way-door pass during `/implement`'s own phase-verification gate (not the default
  Opus) — Fable independently confirmed `validate_config` genuinely runs before
  `build_capabilities` on every real startup path with no hot-reload escape hatch, the
  §6.1 witness-aggregation implementation fulfills its obligation in full, and no
  consumer can be made worse off (spec min-version gates have no upper bound). This
  reconcile pass added: (1) the version bump is the *only* wire-visible signal available
  — `acdp-log-witness` is still Draft and explicitly not for registries, so there's no
  profile-based alternative; (2) checked all 4 downstream family repos
  (`acdp-control-plane`, `acdp-playground`, `acdp-ui-console`, `acdp-rs`/
  `acdp-verifier-py`) for consumers that could be surprised — none exist,
  `acdp-playground` already accepts `"0.4.0"` (added weeks before this wave, unrelated
  commit); (3) confirmed the inverse also holds — claiming 0.4.0 imposes no new
  obligation, since the only 0.4.0-version-conditional spec rule is a *permission* gate
  (`invalid_witness_cosignature` MUST NOT be emitted below 0.4.0), not a MUST the
  registry would need to newly satisfy. One nuance recorded, not a defect: the gate is on
  config (`witnesses` non-empty) while the wire member is on data (verified cosignatures
  present) — a freshly-started registry can advertise 0.4.0 before its first cosignature
  arrives. This is correct (config-gating is the right axis; `build_capabilities` runs
  once at startup and can't track live data without a redesign).
- **Decision:** Confirm as-is.
- **Status:** CONFIRMED (2026-08-29). Optional, non-blocking follow-up noted for a future
  wave: if a 5th `acdp_version` rung is ever added, consider replacing the ordered
  if/else ladder with an order-independent `max()` over per-feature version claims —
  value is low at 4 rungs, not worth doing now.

### OQ1 — accept the wit-002/wit-004 vacuous-pass substitution
- **Assumption:** REG-2's literal acceptance text ("wit-002 and wit-004 pass in this
  repo's harness") was already true, vacuously, before any of this work — both fixtures
  skip as non-HTTP vectors, and a skip counts as "pass, no failures."
- **Recommendation:** confirm. Independently re-verified against the merged code on
  `main`: the new `wit004_key_mismatch_...` test genuinely exercises real Ed25519
  verification (the asserted failure message `"signature verification failed"` is
  produced by exactly one call site in `acdp-crypto`, traced to confirm it can't be
  produced by any other failure mode in the function under test); the positive control
  (`wit-001`'s golden) isolates exactly one variable (the signature bytes) via a
  same-key/same-body cross-check; the test genuinely runs in CI under require-mode, not
  skipped. The strengthened registry-side fork-refusal tests
  (`cosignature_over_wrong_root_is_rejected`, `cosignature_beyond_current_head_is_rejected`)
  discriminate on non-overlapping message substrings, confirmed against the actual
  upstream `acdp-types` source producing those strings. The cost (≈200 lines across two
  files, one sitting, zero production-code risk) was proportionate: the alternative (a
  bare skip-line claim) would have been actively misleading for a security-adjacent
  claim (witness cosignature / fork detection), in the exact way this repo's own REG-1
  `KNOWN_FAMILIES`/`EXCUSED` ratchet already exists to prevent.
- **Decision:** Confirm as-is. Log two optional follow-ups as backlog (neither blocking,
  neither in this wave's scope):
  1. Split `verify_and_store` at the DID-resolution boundary (`crates/acdp-registry-core/src/witness.rs:133`)
     so the post-resolution half is directly testable, converting the current
     non-persistence assertions from a forward guard (they test a function with no write
     calls) into proof against the actual reject-then-no-write path. ~15 lines of
     production refactor, no behavior change.
  2. Reword the comment at `crates/acdp-registry-server/tests/conformance.rs`'s quorum
     assertion (near the `report_both.witnesses == vec![witness_id]` check) — it implies
     the assertion discriminates wit-001's witness from wit-004's, but the test already
     proves those are the same DID; the actually-discriminating assertions are the
     `witnessed_count` checks just above it.
- **Status:** CONFIRMED (2026-08-29). **Follow-ups owed:** the two items above, both low
  priority, not scheduled.
- **Correction (2026-09-01):** both follow-ups shipped in commit `0d26107` ("refactor
  (core): split verify_and_store for testability; state what the quorum assertion proves
  (#112, #113) (#121)"). (1) `verify_and_store` is now split at the DID-resolution
  boundary into a private `verify_and_store_resolved` in
  `crates/acdp-registry-core/src/witness.rs`, with two new tests exercising the
  post-resolution store path directly against a real `SqliteStore`. (2) The quorum
  assertion's message and surrounding comment at
  `crates/acdp-registry-server/tests/conformance.rs:4893` now states the honest
  limitation — it proves consistency with `witnessed_count` but cannot discriminate
  which of the two cosignatures verified. **Status:** DONE.

### OQ3 — file a spec-repo issue for the assumed `rev-001` profiles.md/profiles.json divergence
- **Assumption:** at spec pin `31cf874`, `profiles.md`'s `acdp-registry-core` row lists
  `rev-001` among its fixtures, but `profiles.json`'s `required_fixtures` (72 entries)
  doesn't contain it — assumed to be a spec-side documentation inconsistency worth an
  upstream issue.
- **Recommendation:** the assumption's premise doesn't hold — checked directly against
  `profiles.json` and found `rev-001-revocation-context-golden` **is** present, in
  `conditional_fixtures` (`required_when: "acdp_version >= 0.3.0"`), which the ratchet
  correctly reads. This is the exact same required-vs-conditional distinction this
  repo's own REG-1 coverage ratchet was built to handle (`no_excused_family_is_required_by_our_profile`
  checks both lists for the same reason). No spec bug exists; filing an issue would
  misreport a non-bug to the spec maintainer.
- **Decision:** No issue filed. Confirmed the premise was wrong, not the original
  "file an issue" plan.
- **Status:** CONFIRMED (2026-08-29) — closed, not deferred; nothing further owed.

### OQ4 — REG-8's reach: also SHA-pin `peter-evans/repository-dispatch`
- **Assumption:** `notify-website.yml` carries a credential-adjacent third-party action
  the wave's literal scope (`docker.yml`, `release-plz.yml`) didn't name, but `acdp-rs`
  already pins it.
- **Recommendation:** confirm. Independently re-verified on `main`: the pin is byte-exact
  parity with `acdp-rs`'s own pin (same 40-hex SHA, same version comment). Swept every
  workflow for any other credential-bearing action that might have been missed — none
  found; all three secret-consuming workflows (`docker.yml`, `release-plz.yml`,
  `notify-website.yml`) have every third-party action SHA-pinned, with only the
  deliberate first-party carve-outs (`actions/checkout`, `actions/create-github-app-token`)
  left on tags.
- **Decision:** Confirm as-is.
- **Status:** CONFIRMED (2026-08-29). Two follow-ups noted, both out of this wave's
  scope, not scheduled: (a) `acdp-registry-rs`'s `ci.yml` still floats several
  non-credential third-party actions that `acdp-rs` SHA-pins repo-wide — a policy gap
  between the two repos, not a defect in this decision; (b) `ci.yml:63`'s
  `dtolnay/rust-toolchain@master` is a mutable branch ref, the loosest pin in the repo —
  cheapest single hardening pickup if a future pass wants one.
- **Correction (2026-09-01):** both follow-ups shipped, commit `9313267` ("ci(security):
  SHA-pin third-party actions and replace two unreachable pins (#116)"). (a) Every
  third-party `uses:` line in `.github/workflows/ci.yml` is now SHA-pinned — 15 of 15
  (`grep -c 'uses:.*@[0-9a-f]\{40\}' .github/workflows/ci.yml` → 15); only the deliberate
  first-party `actions/checkout@v4` / `actions/upload-artifact@v4` carve-outs remain on
  tags, matching the posture this entry already treated as acceptable. (b)
  `dtolnay/rust-toolchain` is now pinned to
  `6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772 # master` (a real commit SHA, not a floating
  branch ref); `ci.yml:63` no longer refers to that line at all — the file has grown, and
  line 63 is now a comment ("instead of aspirational. Checks both shipped storage
  backends."). **Status:** DONE.

### OQ5 — PR count: kept PR C (axum-server 0.8) and PR D (axum 0.8 migration) separate
- **Assumption:** isolating the axum-server security fix from the larger HTTP-stack
  migration means a router regression in the latter can't block the former.
- **Recommendation:** confirm, and record a standing policy. Verified the split paid off
  in practice, not just in theory: PR #97 (the advisory fix) merged and closed
  `RUSTSEC-2025-0134` a full 31 minutes before PR #99 (the full migration) was even
  opened — the security fix was never gated behind code that didn't exist yet. The split
  was also near-free: the two PRs' source-file diffs are disjoint, overlapping only in
  the manifest spine (`Cargo.toml`/`Cargo.lock`/`CHANGELOG.md`), trivial to sequence.
- **Decision:** Confirm as-is. Adopt as a standing policy for this repo: a change that
  closes a security advisory ships in its own PR and is never bundled into an adjacent
  larger migration, even when both touch the same crate family and even under time
  pressure — conditioned on the split being cheap (confined to manifest-file overlap); if
  a future advisory fix genuinely cannot compile without the larger migration, the split
  stops being free and this policy should yield.
- **Status:** CONFIRMED (2026-08-29).

---

## Summary

5 entries, all confirmed as recommended — no changes to shipped code, no genuine
one-way-door ambiguity found on the one item (OQ2) that warranted a dedicated look.
**Follow-ups owed, not yet started, none blocking:**
1. `verify_and_store` resolver-boundary refactor + real persist-skip test (OQ1).
2. Comment reword at `conformance.rs`'s quorum assertion (OQ1).
3. `acdp-playground/playground/conformance.py`'s stale docstring (OQ2, cross-repo,
   cosmetic — surfaced by the OQ2 recommender while checking downstream consumers).
4. `ci.yml`'s non-credential third-party actions left unpinned, unlike `acdp-rs`'s
   repo-wide posture (OQ4).
5. `ci.yml:63`'s `dtolnay/rust-toolchain@master` — the loosest pin in the repo, a mutable
   branch ref (OQ4).

All five are new, separately-scoped, low-priority items for a future session — none
require action before anything already merged is considered done.

**Correction (2026-09-01) — status of the five follow-ups above, re-verified against
current `main`:**
1. DONE — shipped in `0d26107` (#112). See OQ1's correction above.
2. DONE — shipped in `0d26107` (#113). See OQ1's correction above.
3. Not re-verified by this pass — `acdp-playground` is a sibling repo outside this
   correction's scope; status unchanged.
4. DONE — `ci.yml`'s third-party actions are now all SHA-pinned (`9313267`, #116). See
   OQ4's correction above.
5. DONE — `dtolnay/rust-toolchain` is SHA-pinned, not a floating `@master` ref (`9313267`,
   #116). See OQ4's correction above.

---

# RECONCILED (2026-09-01) — `reg10-conformance-and-ci-hygiene`

Four `UNCONFIRMED` entries from the REG-10 plan, walked in blast-radius order. Each was
given to a fresh **Opus** recommender (Opus substituted for Fable per standing
instruction); every recommendation was input only. All four verdicts are the human's.

## 1. First-party reusable workflows trusted by mutable `@v1` (Phase 3)

- **Assumption:** #111's SHA-pinning mandate scopes to third-party actions;
  `agentcontextdistributionprotocol/*` reusable workflows are trusted by major tag.
  `bump-spec.yml:18` uses `bump-spec-ref.yml@v1` with `secrets: inherit`. Ranked first:
  the only entry touching a trust boundary, and the only one that can change without a
  commit in this repo. **This assumption had never been logged** — it surfaced from
  review of the phase, not from `ASSUMPTIONS.md`; it is now recorded there retroactively.
- **Recommendation (Opus):** CONFIRM as-is. It is an existing convention, not a new risk —
  all three first-party refs in this repo use `@v1`, and the convention is stated upstream
  at `acdp-ci/.github/workflows/auto-merge.yml:10-11`. SHA-pinning the outer hop would be
  partly illusory, since the callee itself consumes `actions/checkout@v7` and
  `create-github-app-token@v3`. Its own strongest counter: the ruleset's admin bypass makes
  it a speed bump, and "we already do it elsewhere" is precedent, not justification.
- **Correction to that recommendation (found on the ship gate, after the decision):** the
  upstream citation does not carry the weight it was given. `auto-merge.yml:10-11` says
  first-party `actions/*` — GitHub's own namespace — are trusted by major tag; it says
  nothing about `agentcontextdistributionprotocol/*` reusable workflows, and the same file
  SHA-pins the third-party `dependabot/fetch-metadata`. So the "existing convention"
  support reduces to the three in-repo `@v1` refs, which the recommendation itself already
  labelled precedent rather than justification. The verdict is unchanged — it was confirmed
  on the reachability and trigger analysis, not on this citation — but the citation is
  narrower than the recommendation implied and should not be leaned on again.
- **Two of its claims were independently re-verified before the decision, because both
  changed the answer:**
  - An earlier check in this session found `acdp-ci` had **no** rulesets. That is now
    stale. Ruleset `21899019` `protect-v-tags` exists, `enforcement: active`, created
    `2026-08-30T21:36:03-07:00`, covering `refs/tags/v*` with
    `creation`/`update`/`deletion`/`non_fast_forward`, `bypass_actors` = `RepositoryRole 5`
    (admin) only. The force-move vector the assumption was written about closed between
    the two checks.
  - **The recommender was corrected on one point.** It treated `bump-spec.yml` and
    `auto-merge.yml` as comparably exposed and concluded auto-merge should be fixed first.
    They differ in kind: `bump-spec.yml` has `secrets: inherit` (org bot App key +
    `CARGO_REGISTRY_TOKEN`) but only `repository_dispatch`/`workflow_dispatch` triggers, so
    it is not fork-reachable; `auto-merge.yml` runs `on: pull_request` but has **no**
    `secrets: inherit`, receiving only `contents: write`/`pull-requests: write`, which
    GitHub downgrades to read-only for fork PRs. High-privilege/low-reach vs.
    lower-privilege/high-reach — its "fix auto-merge first" conclusion does not follow.
- **Decision:** **Confirm as-is.** No code change. The `auto-merge.yml` observation was
  reviewed and deliberately left as-is — no issue filed, recorded here instead so it is not
  rediscovered as novel.
- **Status:** CONFIRMED (2026-09-01).

## 2. Memory `test` leg ships without an anti-vacuity guard (Phase 2)

- **Assumption:** the load-bearing half of #109's fix is `clippy (memory)`'s `--all-targets`
  compile, which cannot go vacuous; the `cargo test (memory)` leg therefore ships with no
  assertion on its own test count.
- **Recommendation (Opus):** CONFIRM the entry as written — and file the *real* gap
  separately rather than amending this one. The feared regression is near-unreachable:
  `tests/anchors_uri_never_dereferenced.rs` is a source-grep test that never constructs a
  store, so gating it on `storage-sqlite` would defeat its own purpose; even if someone did,
  the leg drops to 38, not 0 (`conformance_gate.rs` is ungated and survives; the "37" in the
  recommendation and in `ASSUMPTIONS.md` was off by one, corrected in both).
  The count is read off the sources, not off a run — see the evidence caveat below. It cannot go vacuous, only thinner. The
  `ACDP_REQUIRE_CONFORMANCE` precedent does not transfer — that guards a suite compiling to
  literally zero, and there is no such cliff here. Its own strongest counter: under memory
  the harness exercises `MemoryStore` zero times, so the run half is substantively
  decorative either way.
- **The larger gap it identified:** `MemoryStore` overrides only `migrate`/`health`/
  `list_contexts` (`crates/acdp-registry-server/src/memory_ext.rs:98-119`), so tenancy runs
  on trait defaults. Traced through, tenancy **fails closed** on memory — a non-default
  tenant sees nothing — which is a broken demo, not a data leak, on a backend documented as
  ephemeral. Its proportionate fix is not a behavioral suite but one startup refusal
  mirroring the existing guard at `crates/acdp-registry-server/src/main.rs:317-323`.
- **Evidence limits, stated rather than papered over:** the recommender could not run
  `cargo test` (sandbox denied `target/` writes). Neither could this pass — cargo fails to
  write `.d` files in *any* directory in this environment, including a freshly created one,
  though it succeeded earlier in the session. **Entry 2 therefore rests on static
  verification of the cfg gates, not on a measured test count.** Gates confirmed from
  source: `conformance.rs:383`, `http_integration.rs:26`, `metrics_integration.rs:8` are
  `#![cfg(feature = "storage-sqlite")]`; `pg_integration.rs:20` is `storage-pg`;
  `anchors_uri_never_dereferenced.rs` and `conformance_gate.rs` carry no crate-level cfg.
- **Decision:** **Confirm, and file the real gap as its own issue.** The count guard stays
  unbuilt — it is a tripwire for a door nobody uses, priced in false positives on every new
  test. The startup-refusal fix is tracked separately, not folded into a CI-plumbing phase.
- **Status:** CONFIRMED (2026-09-01). Follow-up filed as #137; not blocking.

## 3. Pin durability generalized to `taiki-e/install-action` (Phase 1)

- **Assumption:** the human's ruling on `dtolnay/rust-toolchain` — prefer a default-branch-
  reachable SHA plus an explicit input over a convenient-but-unreachable ref-selector SHA —
  is a principle that generalizes, not a one-off.
- **Recommendation (Opus):** CONFIRM. Verified: the pin `1ed6d7be` is a true ancestor of
  `main` (`compare` → `behind 14`); the `cargo-llvm-cov` tool tag is off `main`'s history
  entirely (`ahead 1, behind 0`), and the tag has since moved off the entry's earlier
  `ea647c55` to `2af88edc` — which is the point, these commits are regenerated per release.
  Stated precisely, because an earlier draft of this line overstated it: `ea647c55` still
  resolves (HTTP 200, `ahead 1, behind 14`); it is dangling — referenced by no tag or
  branch — not deleted. Upstream's own framing of the hazard is a commit *not present on
  the repository*, which is a stronger condition than this one and is not what happened
  here. Upstream's own security section
  *discourages* hash-pinning tool tags and routes pinners to a version tag, so the chosen
  shape follows vendor guidance rather than deviating from it. The "version bumps now need a
  deliberate commit" objection is answered in-repo by `.github/dependabot.yml:13-19`.
- **Decision:** **Confirm as-is.** No code change.
- **Status:** CONFIRMED (2026-09-01).

## 4. Amended acceptance criterion 4 (Phase 1)

- **Assumption:** AC4's wording ("the coverage job's install-action pin still defaults
  `tool: cargo-llvm-cov`") encoded a *means*, not the *end*, and was amended to "the coverage
  job installs `cargo-llvm-cov`, via an explicitly passed `tool:` input on a `main`-reachable
  pin."
- **Recommendation (Opus):** CONFIRM. AC4's letter was unsatisfiable — `tool` is required
  with no default on `v2`/`main`; a `default:` exists only in the generated tool-tag commit,
  i.e. only on the ref the phase existed to stop using. AC4 thus encoded "keep the orphan
  pin" as a hidden premise. What makes the amendment legitimate rather than
  criterion-shopping: the *end* was preserved verbatim, only the *means* clause moved, and it
  was logged rather than quietly applied. Its own strongest counter: amendment-by-implementer
  erodes if unpoliced.
- **Decision:** **Confirm as-is.** Adopted as the standing rule for future phases: **amend a
  criterion only when the new wording is strictly narrower than or equal to the original on
  the outcome; escalate when it would weaken what is being verified. Always log the
  amendment.**
- **Status:** CONFIRMED (2026-09-01).

## Standing rule adopted this pass — extending a prior human ruling

Entry 3 raised a question larger than itself: a ruling given on one action was extended to a
second without re-asking. Put to the human directly, since it sets precedent. **Ruling: a
prior decision may be extended to a new instance without re-asking only when all three
hold —**

1. the **reason given** applies unchanged, not merely the outcome;
2. the second instance sits inside the **same unit of work** already under review;
3. the blast radius is **bounded and fails loudly**.

Anything failing one of the three gets asked. Logging to `ASSUMPTIONS.md` as `UNCONFIRMED`
remains mandatory either way — that log, not the good outcome, is what made this entry
reviewable at all.

## Summary

4 entries: **4 confirmed, 0 changed, 0 deferred.** No code follow-up blocks the next
`/ship`. One non-blocking issue filed (#137 — entry 2's `MemoryStore` startup refusal). One
previously-unlogged Phase 3 assumption recorded retroactively in `ASSUMPTIONS.md`. Two
standing rules adopted: the criterion-amendment rule (entry 4) and the ruling-extension bar
(above).
