# Contributing

Thanks for your interest in `acdp-registry-rs`.

## Setup

1. Clone the sibling [`acdp-rs`](https://github.com/agentcontextdescriptionprotocol/acdp-rs)
   into the parent directory. The workspace consumes it as a path dependency.
2. Install Rust 1.86 or newer (`rustup install stable`).
3. (Optional) Install `cargo-deny` if you plan to touch dependencies.

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
```

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

## Migrations

- Number new migrations sequentially within `crates/acdp-registry-<backend>/migrations/`.
- Never edit an applied migration; add a new one.
- Each migration must be idempotent (`CREATE TABLE IF NOT EXISTS`, `ON CONFLICT
  DO NOTHING`, etc.).

## Security disclosures

See [SECURITY.md](SECURITY.md).
