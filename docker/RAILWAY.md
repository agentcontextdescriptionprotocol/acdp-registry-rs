# Deploying the registry to Railway

The CI pipeline (`.github/workflows/docker.yml`) builds a multi-arch image and
pushes it to the GitHub Container Registry (GHCR) on every push to `main` and on
every `v*` tag:

```
ghcr.io/agentcontextdistributionprotocol/acdp-registry:latest   # default branch
ghcr.io/agentcontextdistributionprotocol/acdp-registry:v0.1.0   # release tags
ghcr.io/agentcontextdistributionprotocol/acdp-registry:sha-<sha>
```

## Deploy the prebuilt GHCR image (recommended)

`acdp` is consumed from crates.io, so Railway *could* build this repo from source
directly. We still recommend deploying the **prebuilt GHCR image**: it's the
exact multi-arch artifact CI already built and tested, so deploys are fast and
reproducible instead of recompiling the Rust workspace on every push.

## One-time GHCR setup

Railway needs to pull from GHCR. Either:

- **Make the package public** — GitHub → repo → *Packages* → `acdp-registry` →
  *Package settings* → change visibility to **Public**. Then Railway pulls with
  no credentials. (Simplest.)
- **Or keep it private** and give Railway a registry credential: a GitHub PAT
  with `read:packages` scope, configured on the Railway service.

## Creating the Railway service (later)

1. New Project → **Deploy from a Docker image**.
2. Image: `ghcr.io/agentcontextdistributionprotocol/acdp-registry:latest`
   (pin a `vX.Y.Z` tag for production stability).
3. Add a **PostgreSQL** plugin (the image is built with `STORAGE_FEATURE=storage-pg`).
4. Set the env vars below.
5. Networking → expose the service; set the target port (see `$PORT` note).

### Required env vars

| Variable | Value |
|----------|-------|
| `ACDP_REGISTRY_STORAGE__BACKEND` | `postgres` — the GHCR image is compiled Postgres-only and mounts no config file on Railway, so the backend must be selected here (the default is `sqlite`, which the image refuses to run) |
| `ACDP_REGISTRY_STORAGE__POSTGRES_URL` | `${{ Postgres.DATABASE_URL }}` (Railway reference) |
| `ACDP_REGISTRY_AUTH__JWT_SECRET` | a real secret — `openssl rand -base64 32` (the binary refuses to start on the literal `changeme`) |
| `ACDP_REGISTRY_REGISTRY__BIND` | `0.0.0.0` |
| `ACDP_REGISTRY_REGISTRY__ALLOW_PUBLIC_BIND` | `true` (non-loopback bind opt-in) |
| `ACDP_REGISTRY_REGISTRY__PORT` | `${{ PORT }}` — Railway injects `$PORT`; the registry config key is `registry.port`, so map it explicitly |
| `ACDP_REGISTRY_REGISTRY__AUTHORITY` | your public hostname (e.g. `acdp-registry.up.railway.app`) |
| `RUST_LOG` | `info,acdp=info,acdp_registry=info` |

> **TLS:** terminate TLS at Railway's edge and run the container with
> `registry.tls.enabled = false` (as in `config.docker.toml`). The
> `ALLOW_PUBLIC_BIND` opt-in exists so a non-loopback bind without in-process
> TLS is a deliberate choice.

### Healthcheck

Point Railway's healthcheck at **`/healthz`**.

## Local parity

`docker/docker-compose.yml` runs the same image against a local Postgres — use it
to validate config before promoting to Railway.
