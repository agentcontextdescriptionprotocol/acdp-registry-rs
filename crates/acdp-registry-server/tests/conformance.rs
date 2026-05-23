//! ACDP spec conformance scaffold.
//!
//! When `ACDP_SPEC_DIR` is set to a checkout of the spec repo, this test
//! walks `${ACDP_SPEC_DIR}/fixtures/{pub,vis,fed}-*` and replays each
//! fixture through the registry. When unset (the common CI case), the
//! test logs a skip and returns success — running the spec suite is
//! opt-in to keep the repo independently testable.
//!
//! The exact fixture format is the spec repo's contract; this file
//! intentionally only walks paths and prints what it finds. Add real
//! request/response assertions once the spec repo lands its fixture
//! contract.

#![cfg(feature = "storage-sqlite")]

use std::path::PathBuf;

#[test]
fn replays_spec_fixtures_when_present() {
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

    let entries = std::fs::read_dir(&fixtures)
        .unwrap_or_else(|e| panic!("read {fixtures:?}: {e}"))
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with("pub-") || n.starts_with("vis-") || n.starts_with("fed-"))
                .unwrap_or(false)
        })
        .count();

    eprintln!(
        "conformance: discovered {entries} pub/vis/fed fixtures under {} \
         (replay assertions not yet wired — TODO once spec repo lands the fixture contract)",
        fixtures.display()
    );
}
