# Contributing

Thanks for your interest in `acdp-registry-rs`.

## Setup

1. Install Rust 1.88 or newer (`rustup install stable`).
2. (Optional) Install `cargo-deny` if you plan to touch dependencies.

The protocol library [`acdp`](https://crates.io/crates/acdp) is consumed from
crates.io — no sibling checkout is required.

## Pre-PR check set

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the feature-flag variants if you touched the server binary or its callers:

```bash
cargo clippy -p acdp-registry-server --no-default-features --features storage-pg --all-targets -- -D warnings
cargo clippy -p acdp-registry-server --features storage-sqlite,playground   --all-targets -- -D warnings
cargo test   -p acdp-registry-server --features storage-sqlite,playground
```

CI additionally gates PRs on checks you can reproduce locally:

```bash
# Postgres-backed tests (skipped silently when the env var is unset).
# Point ACDP_REGISTRY_TEST_PG_URL at a disposable database.
ACDP_REGISTRY_TEST_PG_URL=postgres://acdp:acdp@localhost:5432/acdp_registry \
    cargo test -p acdp-registry-pg
ACDP_REGISTRY_TEST_PG_URL=postgres://acdp:acdp@localhost:5432/acdp_registry \
    cargo test -p acdp-registry-server --no-default-features --features storage-pg --test pg_integration

# MSRV — the workspace must compile on Rust 1.88.
cargo +1.88 check --workspace --all-targets

# rustdoc must build warning-free.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Dependency audit (runs unconditionally in CI, not optional).
cargo deny check
```

CI also measures coverage with `cargo llvm-cov` (summary on the run page, lcov
artifact attached) and smoke-tests the Docker image on every PR — it builds the
`storage-pg` image, boots it against Postgres, and curls `/healthz`.

## Commit messages

Conventional Commits are required. The release pipeline derives the changelog
and version bumps from these prefixes:

- `feat:` — new user-visible capability
- `fix:` — bug fix
- `docs:` — documentation only
- `refactor:` — internal refactor with no behavior change
- `test:` — tests only
- `chore:` — tooling / metadata
- `BREAKING CHANGE:` (or `!` suffix) — semver-breaking change

## Adding a new endpoint

See `CLAUDE.md` → "Adding a new endpoint" for the four-step recipe.

## Documentation

Reference docs live in [`docs/`](docs/README.md) (HTTP API, authentication,
configuration, multi-tenancy, webhooks, operations). When a change alters the
HTTP surface, config, auth, or operational behavior, update the relevant page in
the same PR. Document protocol-level concepts by linking to the
[`acdp` library docs](https://github.com/agentcontextdistributionprotocol/acdp-rs/tree/main/docs)
rather than restating them.

## Migrations

- Number new migrations sequentially within `crates/acdp-registry-<backend>/migrations/`.
- Never edit an applied migration; add a new one.
- Each migration must be idempotent (`CREATE TABLE IF NOT EXISTS`, `ON CONFLICT
  DO NOTHING`, etc.).

## Security disclosures

See [SECURITY.md](SECURITY.md).
