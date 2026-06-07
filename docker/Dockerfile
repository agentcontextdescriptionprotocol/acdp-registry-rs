# syntax=docker/dockerfile:1
#
# Two-stage build: Rust toolchain + cargo-chef for cached dependency
# builds, then a slim runtime image carrying the static binary.

FROM rust:1.88-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /workspace

FROM chef AS planner
# Bring in the protocol library (sibling repo) AND this repo so the path
# dependency in Cargo.toml resolves inside the container.
COPY ./acdp-rs            /workspace/acdp-rs
COPY ./acdp-registry-rs   /workspace/acdp-registry-rs
WORKDIR /workspace/acdp-registry-rs
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG STORAGE_FEATURE=storage-pg
# The full workspace (incl. the sibling acdp-rs path dependency) must be present
# for `cargo chef cook` to lay out and compile the dependency graph.
COPY --from=planner /workspace/acdp-rs           /workspace/acdp-rs
COPY --from=planner /workspace/acdp-registry-rs  /workspace/acdp-registry-rs
WORKDIR /workspace/acdp-registry-rs
# Cook compiles (and caches) only the dependencies — it overwrites the crate
# sources with dummy `fn main() {}` / empty-lib skeletons to do so.
RUN cargo chef cook --release --recipe-path recipe.json \
        --no-default-features --features "${STORAGE_FEATURE}" \
        -p acdp-registry-server
# Restore the REAL sources over the skeleton stubs cook left behind, THEN build
# the actual binary. Without this re-copy, `cargo build` re-links the stub
# `fn main() {}` and ships a ~300 KB no-op that exits 0 and never binds.
COPY ./acdp-rs            /workspace/acdp-rs
COPY ./acdp-registry-rs   /workspace/acdp-registry-rs
RUN cargo build --release \
        --no-default-features --features "${STORAGE_FEATURE}" \
        -p acdp-registry-server
RUN strip /workspace/acdp-registry-rs/target/release/acdp-registry

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 1001 --home /app acdp
COPY --from=builder /workspace/acdp-registry-rs/target/release/acdp-registry /usr/local/bin/acdp-registry
USER acdp
WORKDIR /app
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/acdp-registry"]
