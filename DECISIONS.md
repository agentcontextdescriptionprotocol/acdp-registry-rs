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
