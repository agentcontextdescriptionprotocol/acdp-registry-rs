# syntax=docker/dockerfile:1
#
# Two-stage build: Rust toolchain + cargo-chef for cached dependency
# builds, then a slim runtime image carrying the binary.
#
# `acdp` is consumed from crates.io, so the build context is just this repo.

FROM rust:1.88-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG STORAGE_FEATURE=storage-pg
# Only recipe.json is needed to compile (and cache) the dependency graph.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json \
        --no-default-features --features "${STORAGE_FEATURE}" \
        -p acdp-registry-server
# The build SHA is declared AFTER `cargo chef cook` on purpose: its value
# changes every commit, so declaring it earlier would bust the dependency
# cache the two-stage build exists for. The final layer below rebuilds on
# every commit anyway, so it costs nothing here.
#
# It arrives as a build ARG rather than from `git describe` in a build.rs:
# `.dockerignore` excludes `.git/`, so no git metadata exists in the build
# context. Unset (a plain `docker build`) leaves `option_env!` as `None` and
# the served version falls back to the bare package version.
ARG ACDP_BUILD_SHA
ENV ACDP_BUILD_SHA=${ACDP_BUILD_SHA}
# Bring in the real sources and build the actual binary.
COPY . .
RUN cargo build --release \
        --no-default-features --features "${STORAGE_FEATURE}" \
        -p acdp-registry-server
RUN strip /app/target/release/acdp-registry

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 1001 --home /app acdp
COPY --from=builder /app/target/release/acdp-registry /usr/local/bin/acdp-registry
USER acdp
WORKDIR /app
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/acdp-registry"]
