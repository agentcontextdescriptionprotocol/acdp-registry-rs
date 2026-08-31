# Assumptions log — `reg1-reg7-conformance-deny`

Decisions made against `plans/reg1-reg7-conformance-deny.md`'s Open Questions during
`/drive`. All 8 entries below were reconciled on 2026-08-29 — see `DECISIONS.md` for the
full recommendation + human decision on each. This file is kept as the original record;
`DECISIONS.md` is the durable, current source of truth.

## RECONCILED (2026-08-29) — see DECISIONS.md for full detail

1. **Inline `actions/checkout@v4` vs `checkout-spec@v1`.** CONFIRMED as-is — the `v1`
   tag doesn't even contain the shared action yet. Follow-up: file an `acdp-ci` issue.

2. **`bump-spec.yml` out of scope.** Changed to NEEDS-FOLLOWUP — add it as a near-term
   follow-up (inert until dispatched), paired with a cross-repo spec-matrix item.

3. **`can`/`lin` not excused.** CONFIRMED — policy correct and self-enforcing. `can`'s
   possible cheap-closure path (direct content-hash test) noted for the stateful-replay
   follow-up, not separately scheduled.

8. **Plan-text "yields exactly four" overclaim.** CONFIRMED, no edit needed — the plan
   already self-corrects before the overclaimed line in reading order.

4. **REG-1 acceptance criterion "as applicable" reading.** Narrowed on reconcile: `lc`/
   `fed`/`caps` are legitimately not-applicable; `vis`/`idem` are core-required and the
   gap should be scheduled, not left indefinite. Shipped code stands; NEEDS-FOLLOWUP for
   a stateful-replay phase.

5. **`h2` advisory fix bundled into REG-7's PR.** CONFIRMED — no bundling policy
   violated, fix was a prerequisite for REG-7's own acceptance criterion, already merged.

6. **Stale `deny.toml` entries left untouched.** CONFIRMED, deferred to REG-9.

7. **`storage-memory` uncovered by CI.** CONFIRMED as flagged, but elevated from a
   passive note to NEEDS-FOLLOWUP — file a trackable backlog item.

---

**Outstanding follow-ups from this reconcile pass** (see `DECISIONS.md`'s Summary for
full detail — none block anything already shipped):
1. File an `acdp-ci` issue re: `v1` tag + DELIVERY-STANDARD.md staleness.
2. Add `bump-spec.yml` to this repo.
3. File a cross-repo item for the spec repo's dispatch matrix + DELIVERY-STANDARD status.
4. Schedule a "stateful replay" REG-item for `vis`/`idem` coverage.
5. File a backlog item for `storage-memory` CI coverage.

---

## `reg2-reg5-reg6-reg8-reg9-wave4` — logged during `/drive` 2026-08-29

Plan: `plans/reg2-reg5-reg6-reg8-reg9-wave4.md`. The plan's own Open Questions section
(lines 1252-1300) already proposed a clearly-best, cheap-to-reverse default for each of
its five open questions; per `/implement`'s stop-condition tiers none is a fork with no
defensible default, so the pipeline proceeded on each proposed default rather than
pausing. Logged here for `/reconcile`.

**RECONCILED (2026-08-29) — all 5 confirmed as recommended, see `DECISIONS.md` for full
detail.** OQ2 additionally received a dedicated Fable one-way-door pass during
`/implement` itself. OQ3's assumed premise (a spec-side `rev-001` documentation gap)
turned out false on direct verification — the fixture is correctly covered via
`conditional_fixtures`, so no issue was filed. Five low-priority, non-blocking follow-ups
logged in `DECISIONS.md`'s Summary; none scheduled.

### OQ1 — accept the wit-002/wit-004 vacuous-pass substitution
- **Plan:** plans/reg2-reg5-reg6-reg8-reg9-wave4.md
- **Assumed:** REG-2's literal acceptance text ("wit-002 and wit-004 pass in this repo's
  harness") is already true today, vacuously, via the non-HTTP skip path — not via any
  behavioral coverage.
- **Chose:** refuse the vacuous reading. Phase 4 executes wit-004's real cryptographic
  vector against the registry's own cosignature+quorum verification path; Phase 5
  strengthens the registry's existing (but non-discriminating) fork-refusal unit tests to
  pin wit-002's forged root and assert failure *reasons*, not just the error variant.
- **Alternatives:** take the vacuous pass, bump the pin, and write one sentence
  documenting that the fixtures skip as non-HTTP. Cheaper, but would let a wire-level
  "conformance" claim stand on a skip line — inconsistent with this repo's established
  posture (REG-1's own coverage ratchet exists to prevent exactly this).
- **Blast radius if wrong:** low — Phases 4-5 are additive test coverage plus two small
  wire-mapping arms (Phase 2/3, separately assumption-logged below); nothing they add is
  load-bearing for anything else in the plan. Reverting means deleting two test functions
  and two match arms.
- **Status:** CONFIRMED (2026-08-29)

### OQ2 — advertise `acdp_version: "0.4.0"` when aggregating witness cosignatures
- **Plan:** plans/reg2-reg5-reg6-reg8-reg9-wave4.md
- **Assumed:** a registry with `[[witnesses]]` configured (and therefore aggregating
  RFC-ACDP-0015 §6.1 `witness_signatures`) should stop under-claiming `acdp_version:
  "0.3.0"` in its served capabilities document.
- **Chose:** add a `0.4.0` rung to `build_capabilities`'s version ladder, gated on
  `!cfg.witnesses.is_empty()`, ordered before the existing `0.3.0` rung. This is the
  wave's only wire-contract change, so Phase 3 was routed to a fresh **Fable** verifier
  rather than the default Opus, per `/implement`'s one-way-door stop-condition rule for
  public API contracts — see Phase 3's `PROGRESS.md` entry for Fable's verdict.
- **Alternatives:** (a) leave it at 0.3.0 — rejected, this is the actual drift (serving a
  0.4.0 wire member under a 0.3.0 banner); (b) a new opt-in config flag — rejected, the
  spec is explicit there is no new capability flag for this, and a flag would let the
  advertisement drift from actual behavior; (c) gate on `cfg.log.enabled` instead of
  `!cfg.witnesses.is_empty()` — rejected, over-claims for any transparency-log registry
  that aggregates nothing.
- **Blast radius if wrong:** low-medium — config-derived, one `if` branch, no persisted
  state, reverts with a single-commit revert. But it is a public, wire-visible
  advertisement read by consumers (and downstream family members touching witness
  surfaces this wave and next — UI-2, CP-2), so it's the one item in this wave worth a
  deliberate second look rather than a rubber stamp.
- **Status:** CONFIRMED (2026-08-29)

### OQ3 — file a spec-repo issue for the `rev-001` profiles.md/profiles.json divergence
- **Plan:** plans/reg2-reg5-reg6-reg8-reg9-wave4.md
- **Assumed:** at spec pin `31cf874`, `registries/profiles.md`'s `acdp-registry-core` row
  lists `rev-001` among its conformance fixtures, but `registries/profiles.json`'s
  `acdp-registry-core.required_fixtures` (72 entries) does not contain it — a documented
  spec-side inconsistency, not a bug in this repo (the coverage ratchet reads the JSON,
  so nothing here breaks).
- **Chose:** file an issue in the spec repo describing the divergence — issue-filing is
  unrestricted cross-repo per `/plan`'s Cross-repo work section (never a write to the spec
  repo itself). Not yet filed as of this log entry.
- **Alternatives:** ignore it (it's not blocking); silently work around it in this repo's
  own harness (would hide a spec authoring bug rather than surface it upstream).
- **Blast radius if wrong:** near zero — worst case is a spurious issue that the spec
  maintainer closes as expected behavior.
- **Status:** CONFIRMED (2026-08-29) — premise was wrong (rev-001 IS covered, via conditional_fixtures); no issue filed.

### OQ4 — REG-8's reach: also SHA-pin `peter-evans/repository-dispatch`
- **Plan:** plans/reg2-reg5-reg6-reg8-reg9-wave4.md
- **Assumed:** the wave named only `docker.yml` and `release-plz.yml` for REG-8, but
  `notify-website.yml` also carries a credential-adjacent third-party action
  (`peter-evans/repository-dispatch@v4`, consuming a bot token minted by
  `actions/create-github-app-token@v2`) that `acdp-rs` already SHA-pins.
- **Chose:** pin `peter-evans/repository-dispatch` too, in the same PR (Phase 9), at the
  same SHA `acdp-rs` uses (`28959ce8df70de7be546dd1250a005dd32156697` — exact parity
  verified). Left `actions/create-github-app-token@v2` on its major tag (first-party
  tier, matching the sibling) and left every `acdp-ci/.github/workflows/*@v1`
  reusable-workflow ref untouched (pinning those would break family propagation).
- **Alternatives:** pin only what the wave named literally (`docker.yml`,
  `release-plz.yml`) and leave `notify-website.yml` for a future pass — rejected as
  needlessly narrow given the one-line cost and the direct sibling precedent.
- **Blast radius if wrong:** near zero — one more immutable SHA pin, reverts with the
  same single-commit revert as any other Phase 9 pin.
- **Status:** CONFIRMED (2026-08-29)

### OQ5 — PR count: keep PR C (axum-server 0.8) and PR D (axum 0.8) as two separate PRs
- **Plan:** plans/reg2-reg5-reg6-reg8-reg9-wave4.md
- **Assumed:** the plan's default is 5 PRs, with the axum-server advisory fix (Phase 7)
  isolated from the full axum/tower/tower-http migration (Phase 8) so a router regression
  in the latter cannot block the security fix in the former.
- **Chose:** kept 5 PRs as planned rather than collapsing C+D into one PR with two
  commits (the plan's offered alternative for "too many PRs for a solo maintainer").
- **Alternatives:** collapse C+D — the plan states this is a defensible alternative that
  preserves the revert boundary at the commit level while halving review overhead; not
  taken because the plan's own stated default already has the stronger reasoning (a
  reviewer can merge/revert C independently of whether D is ready) and nothing in this
  run's context indicated the maintainer finds 5 PRs burdensome.
- **Blast radius if wrong:** trivial — purely a review-ergonomics preference, no code
  difference either way; reversing the decision later just means opening D against C's
  merged `main` state instead of C's branch, or squashing two already-merged PRs'
  history, neither of which is costly.
- **Status:** CONFIRMED (2026-08-29)

---

## `reg3-anchors` Phase 4 — make `acdp_version: "0.5.0"` reachable — logged during
`/implement` 2026-08-29

Plan: `plans/reg3-anchors.md`, Phase 4 (`"Make acdp_version: 0.5.0 reachable in the
capability ladder"`) — the plan's single flagged **one-way-door** item, routed to a
dedicated Fable verification pass per `/implement`'s stop-condition rule for
public-API-contract changes, mirroring how the prior wave routed OQ2 (the witness
0.4.0 rung).

- **Plan:** plans/reg3-anchors.md
- **Assumed:** without this phase, Phase 3's RFC-ACDP-0016 §10/§14 version gate is dead
  on arrival in production — the pre-existing ladder in `build_capabilities`
  (`crates/acdp-registry-server/src/main.rs`) topped out at `"0.4.0"`, so no
  configuration of the shipped binary could ever advertise `>= 0.5.0`, and every
  anchored publish would be rejected forever.
- **Chose:** option (a), implemented as the `max()`-over-per-feature-version-claims
  refactor the plan explicitly prefers over a literal unconditional `"0.5.0".into()`.
  `build_capabilities`'s four-rung ordered if/else ladder is replaced by
  `ladder_claims`/`ladder_rung_claim`/`acdp_version_claim`: each pre-existing rung keeps
  its own independent predicate and claim (witnesses configured → `"0.4.0"`;
  lifecycle/log/head-receipts configured → `"0.3.0"`; a configured receipt key alone →
  `"0.2.0"`; base floor → `"0.1.0"`), and a fifth, **unconditional** claim of `"0.5.0"`
  is added for `anchors` support (RFC-ACDP-0016 §10: "no new profile ... anchors is a
  body field, not a registry surface" — the accept/reject/store/serve handling runs on
  every publish regardless of config, so there is no admin-config gate to check and
  therefore no "claimed but unexercised" state to overclaim). Because the anchors claim
  is both unconditional and the largest value among all claims, it wins `max()` for
  every configuration: every reachable deployment of the shipped binary now advertises
  `acdp_version >= "0.5.0"`, including a completely bare one. This executes OQ2's own
  recorded follow-up (`DECISIONS.md`, 2026-08-29 entry for
  `plans/reg2-reg5-reg6-reg8-reg9-wave4.md`'s OQ2 — *"if a 5th acdp_version rung is
  ever added, consider replacing the ordered if/else ladder with an order-independent
  max() over per-feature version claims"*) rather than superseding OQ2's decision:
  OQ2's conditional 0.4.0-ahead-of-0.3.0 ordering is unchanged, just re-expressed as one
  candidate claim among several, still independently falsifiable (verified directly:
  `capabilities_acdp_version_ladder`'s four original assertions now target
  `ladder_rung_claim`, the pre-anchors max, so they stay green even though
  `build_capabilities` itself now always returns `"0.5.0"`; a fifth assertion proves
  the anchors claim is reachable through the full path; deleting the anchors claim from
  `acdp_version_claim`'s `max()` set was confirmed, by temporarily editing the code and
  re-running the suite, to turn only that fifth assertion red while the other four stay
  green).
- **Alternatives:**
  - (b) An explicit `[registry]` config opt-in (default `false`) that lifts the
    ceiling to 0.5.0. Preserves the pre-Phase-4 ladder's per-deployment signaling value
    and operator control over a publicly-observable wire claim, at the cost of one new
    config field, one `validate_config` line, and a "why does this knob exist" question
    in review. The plan calls this "the strongest alternative" — stronger than its own
    first draft credited — but it was not chosen because it is not what the plan's
    approach section ultimately prefers, and because RFC-ACDP-0016 §10 gives no
    principled admin-facing axis to gate the knob on (anchors handling is unconditional
    code; a config flag would just be ceremony wrapping a value that's true either way).
  - (c) Leave the ladder alone. Fully spec-conformant (§10 requires rejection below
    0.5.0, not that anyone advertise 0.5.0) and zero-risk, but anchors then never work
    on any real deployment, making Phases 2-3 and 5-7 of this plan inert in production.
    Rejected, but named so the cost of doing nothing is explicit.
- **Blast radius if wrong:** cheap to reverse in code — the whole change is one
  config-derived expression with no persisted state; deleting `ANCHORS_VERSION_CLAIM`'s
  use in `acdp_version_claim` is a one-commit revert back to the pre-Phase-4 ladder
  shape. It is **not** cheap to reverse in the world: `acdp_version` is a public,
  wire-visible advertisement that consumers read and change behavior on, and every
  reachable deployment's advertised version jumps to `"0.5.0"` the moment this ships —
  an advertised version that goes up and then back down is a worse signal to consumers
  than one that never moved. This is the concrete reason the phase is flagged
  one-way-door and routed to Fable rather than the default Opus verification pass.
- **Status:** CONFIRMED (2026-08-29) — see `DECISIONS.md` for the full Fable
  recommendation and human decision.

---

## `reg10-conformance-and-ci-hygiene` — logged during `/implement` 2026-08-31

### Pin durability over upstream's default ergonomics (Phase 1)
- **Plan:** plans/reg10-conformance-and-ci-hygiene.md
- **Assumed:** the human's decision on the `dtolnay/rust-toolchain` orphaned pin — prefer a
  SHA reachable from the default branch plus an explicit input, over a convenient-but-
  unreachable ref-selector SHA — is a *principle* that generalizes, not a one-off ruling on
  that single action.
- **Chose:** applied the same resolution to `taiki-e/install-action` without stopping to ask
  again. Pinned `1ed6d7be…  # v2.87.2` (`compare main...` → `identical`) and passed
  `tool: cargo-llvm-cov` explicitly, replacing `ea647c55… # cargo-llvm-cov` (`ahead 1,
  behind 0` — not in `main`'s history; upstream's README calls hash-pinning tool tags
  "strongly discouraged" for exactly this reason).
- **Alternatives:** (a) stop and ask a second time — rejected, it is the identical tradeoff
  in the same phase, and re-asking spends the human's attention on a settled question;
  (b) keep the tool-tag pin and accept ~daily orphaning — rejected outright, it reproduces
  the defect this phase exists to remove; (c) revert install-action to `@cargo-llvm-cov`
  unpinned — rejected, abandons the phase's goal for one action.
- **Blast radius if wrong:** near zero. One workflow line plus a `with:` block; revert is a
  one-line change. If the explicit `tool:` were wrong the coverage job fails loudly at
  `cargo llvm-cov`, in CI, before merge.
- **Status:** UNCONFIRMED

### Amended acceptance criterion 4 (Phase 1)
- **Plan:** plans/reg10-conformance-and-ci-hygiene.md
- **Assumed:** AC4 as written ("the coverage job's install-action pin still defaults
  `tool: cargo-llvm-cov`") encoded a *means*, not the *end*. Its intent is that the coverage
  job installs cargo-llvm-cov.
- **Chose:** amended AC4 to "the coverage job installs `cargo-llvm-cov`, via an explicitly
  passed `tool:` input on a `main`-reachable pin." The original letter is unsatisfiable on a
  durable pin, since the `default:` exists only in the generated tool-tag commit.
- **Alternatives:** hold AC4 literally and keep the orphan-prone pin — rejected; that would
  let a criterion written before the facts were known dictate a worse outcome.
- **Blast radius if wrong:** none beyond the item above; this is bookkeeping on the same
  change.
- **Status:** UNCONFIRMED

### Memory `test` leg ships without an anti-vacuity guard (Phase 2)
- **Plan:** plans/reg10-conformance-and-ci-hygiene.md
- **Assumed:** the `cargo test (memory)` leg's value is that it links and runs the binary's
  harness under the memory cfg; the load-bearing half of #109's fix is the `clippy (memory)`
  leg's `--all-targets` compile, which cannot go vacuous.
- **Chose:** shipped the leg with no assertion on its own test count. Today it runs 40 tests
  (37 unit + 2 from `tests/anchors_uri_never_dereferenced.rs` + 1 from
  `tests/conformance_gate.rs`). `conformance.rs`, `http_integration.rs` and
  `metrics_integration.rs` each run 0, all being `#![cfg(feature = "storage-sqlite")]`;
  `pg_integration.rs` also runs 0, but because it is `#![cfg(feature = "storage-pg")]`
  (`tests/pg_integration.rs:20`). If someone later adds a `storage-sqlite` cfg gate to
  `anchors_uri_never_dereferenced.rs`, the leg silently drops to 37 with no signal.
- **Alternatives:** (a) reuse `tests/conformance_gate.rs` by setting
  `ACDP_REQUIRE_CONFORMANCE` on the new memory step — rejected because it does not work:
  that guard asserts `cfg!(feature = "storage-sqlite")` is *on*
  (`tests/conformance_gate.rs:15`), so pointing it at the memory leg would make the leg
  fail, not guard it. A correct guard needs a new always-compiled test file asserting its
  own presence — a source change outside this phase's scope, which is CI plumbing only;
  (b) assert a hardcoded test count — rejected, it turns every legitimate new test into a
  CI failure.
- **Blast radius if wrong:** low and slow. The compile/lint coverage survives regardless; only
  the run-the-harness half could erode, and only via a future edit that adds a sqlite cfg gate
  to a currently-ungated test file.
- **Status:** UNCONFIRMED
