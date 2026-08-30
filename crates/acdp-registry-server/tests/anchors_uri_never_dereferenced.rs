//! REG-3 Phase 6 — structural ratchet complementing the behavioral test in
//! `http_integration.rs` (`anchors_uri_never_dereferenced_publish_and_retrieve`).
//!
//! RFC-ACDP-0016 §6 is NORMATIVE and stricter than the DataRef SSRF posture:
//! "`uri` MUST NOT be dereferenced by registries or consumers as part of
//! ACDP-level verification ... there is no code path in core verification
//! that ever reads `anchors[].uri`." The behavioral test proves that claim
//! for the one path it exercises (publish + retrieve); it says nothing
//! about some other, untested path. This test instead enumerates every
//! `.send()`-idiom outbound-HTTP call site in the workspace (the pattern
//! this repo's real reqwest-based clients actually use — not every
//! conceivable HTTP-dispatch spelling; a hand-rolled `reqwest::get(..)` or
//! `.execute(req)` call would not match this grep) and pins the set to
//! exactly the three audited, legitimate ones, so a *fourth* `.send()`-idiom
//! client wired into a code path the behavioral test doesn't traverse still
//! fails CI — and asserts that none of the three even mentions "anchor".
//!
//! See `plans/reg3-anchors.md`, Phase 6, for the full spec this test
//! implements.

use std::path::{Path, PathBuf};

/// The exact, exhaustive, audited set of files containing an outbound-HTTP
/// call site, relative to the workspace root, as of REG-3 Phase 6. Update
/// this deliberately — never widen it silently — if a new legitimate
/// outbound-HTTP call site is added; doing so should force a human to also
/// re-audit that the new site never threads `anchors[].uri` into a request.
const EXPECTED_SEND_SITES: &[&str] = &[
    "crates/acdp-registry-webhook/src/lib.rs",
    "crates/acdp-registry-auth/src/revocation_poller.rs",
    "crates/acdp-registry-core/src/witness.rs",
];

/// This file's own path relative to the workspace root. The `.send()`
/// literal is deliberately never spelled out verbatim in this file's own
/// source (it's assembled by concatenation) so this exclusion is
/// belt-and-braces, not load-bearing — kept in case a future edit to this
/// file's own doc comments or assertions ever writes the literal out.
const SELF_PATH: &str = "crates/acdp-registry-server/tests/anchors_uri_never_dereferenced.rs";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this test target is
    // `<workspace_root>/crates/acdp-registry-server`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // .../crates
        .and_then(Path::parent) // workspace root
        .expect("acdp-registry-server lives two levels under the workspace root")
        .to_path_buf()
}

/// Recursively collect every `.rs` file under `dir` into `out`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("file type");
        if file_type.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// True iff `src` contains a zero-argument dispatch call — the
/// reqwest/http-client idiom used by all three legitimate sites (e.g.
/// `client.get(..).header(..).<call>().await`). This is scoped
/// specifically to the *zero-argument* form: Rust's channel senders
/// (`mpsc::Sender`, `oneshot::Sender`, `broadcast::Sender`, ...) always
/// take the message as an argument (`tx.send(msg)`), so they structurally
/// cannot match a zero-argument call and this grep does not need to (and
/// does not) special-case them. `WebhookEmitter::emit_with_tenant`'s own
/// `self.tx.try_send(delivery)` is exactly such a case — one argument, a
/// different method name, no match here.
fn contains_outbound_http_dispatch_call(src: &str) -> bool {
    let mut pattern = String::from(".");
    pattern.push_str("send");
    pattern.push_str("()");
    src.contains(pattern.as_str())
}

#[test]
fn outbound_http_send_sites_are_exactly_the_three_legitimate_ones() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut rs_files = Vec::new();
    collect_rs_files(&crates_dir, &mut rs_files);
    assert!(
        !rs_files.is_empty(),
        "sanity: expected to find .rs files under {crates_dir:?}"
    );

    let mut found: Vec<String> = rs_files
        .iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/"); // normalize on the off chance this ever runs on Windows
            if rel == SELF_PATH {
                return None;
            }
            let src = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
            contains_outbound_http_dispatch_call(&src).then_some(rel)
        })
        .collect();
    found.sort();

    let mut expected: Vec<String> = EXPECTED_SEND_SITES.iter().map(|s| s.to_string()).collect();
    expected.sort();

    assert_eq!(
        found, expected,
        "the set of outbound-HTTP call sites has drifted from the audited set \
         (RFC-ACDP-0016 §6 / plans/reg3-anchors.md Phase 6). If this is a deliberate new \
         outbound-HTTP call site, update EXPECTED_SEND_SITES in this file *and* re-audit that \
         the new site does not read `anchors[].uri` before widening this list — do not widen \
         it silently."
    );
}

/// RFC-ACDP-0016 §6 NORMATIVE: "there is no code path in core verification
/// that ever reads `anchors[].uri`". None of the three legitimate
/// outbound-HTTP call sites — the *only* places in the workspace that make
/// an outbound HTTP call at all, per the test above — may even mention
/// "anchor" in any form. This is the criterion-5 check, asserted here in
/// code rather than only confirmed by hand.
#[test]
fn none_of_the_three_send_sites_mentions_anchor() {
    let root = workspace_root();
    for rel in EXPECTED_SEND_SITES {
        let path = root.join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        assert!(
            !src.to_lowercase().contains("anchor"),
            "{rel} (an outbound-HTTP call site) must not mention \"anchor\" in any form — \
             RFC-ACDP-0016 §6 forbids `anchors[].uri` from ever being dereferenced, and this \
             is one of only three places in the whole workspace that make an outbound HTTP call"
        );
    }
}
