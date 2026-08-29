//! Guards the conformance suite against a vacuous pass: `tests/conformance.rs` is
//! `#![cfg(feature = "storage-sqlite")]`, so a job that forgets that feature would
//! compile the entire suite away and still report green.
// `cfg!(feature = "storage-sqlite")` is a compile-time constant for any
// single build (clippy checks this crate with its default features, which
// include `storage-sqlite`), but it varies across the different
// `--features`/`--no-default-features` invocations this test is meant to
// guard — that's the whole point of the assertion, so silence the
// constant-value lint rather than drop it.
#[allow(clippy::assertions_on_constants)]
#[test]
fn require_mode_implies_the_conformance_suite_is_compiled_in() {
    if std::env::var("ACDP_REQUIRE_CONFORMANCE").is_ok() {
        assert!(
            cfg!(feature = "storage-sqlite"),
            "ACDP_REQUIRE_CONFORMANCE is set but `storage-sqlite` is off, so \
             tests/conformance.rs compiled to nothing — this run proves nothing. \
             Run the conformance job with --features storage-sqlite,playground."
        );
    }
}
