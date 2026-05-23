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
COPY --from=planner /workspace/acdp-rs           /workspace/acdp-rs
COPY --from=planner /workspace/acdp-registry-rs  /workspace/acdp-registry-rs
WORKDIR /workspace/acdp-registry-rs
RUN cargo chef cook --release --recipe-path recipe.json \
        --no-default-features --features "${STORAGE_FEATURE}" \
        -p acdp-registry-server
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
