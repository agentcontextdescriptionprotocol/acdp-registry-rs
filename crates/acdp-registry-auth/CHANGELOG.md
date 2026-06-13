

## [0.1.0](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/releases/tag/acdp-registry-auth-v0.1.0) - 2026-06-13

### Added

- *(auth,store)* admin pinned-key reload, tenant-bound tokens, durable revocation cursors, tenant-scoped pagination ([#21](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/21))
- *(auth)* cross-issuer revocation poller (consumer of CP feed) ([#20](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/20))
- *(auth)* JWT tenant claim is authoritative; X-Tenant-Id is fallback ([#19](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/19))
- *(auth)* accept ecdsa-p256 on /auth/token (closes plan §10 gap) ([#16](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/16))
- *(auth)* EdDSA signing + JWKS endpoint (registry mirror of CP §2 follow-up) ([#15](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/15))
- *(registry)* harden auth, pagination, lineage, and operational surface
- initial acdp-registry workspace with hardened auth handshake

### Fixed

- P0/P1 security and RFC-conformance remediation ([#24](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/24))

### Other

- expand unit and integration coverage across all crates ([#38](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/pull/38))
- unbreak Docker build and cargo-deny on PR pipeline
