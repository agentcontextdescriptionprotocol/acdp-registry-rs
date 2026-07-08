//! Context CRUD + search + lineage endpoints.

use std::sync::Arc;

use acdp::types::primitives::{AgentDid, CtxId, LineageId, Visibility};
use acdp::types::publish::{PublishRequest, PublishResponse};
use acdp::types::search::{SearchParams, SearchResponse};
use acdp_registry_auth::extract_bearer;
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::{event::WebhookEvent, RegistryError};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

use crate::state::AppState;

/// Query-string DTO mirroring `acdp::types::search::SearchParams`.
/// We deserialize this from `?q=foo&type=bar&…` and convert at the
/// handler boundary, since the protocol's `SearchParams` is
/// Serialize-only.
#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    #[serde(rename = "type")]
    pub context_type: Option<String>,
    pub domain: Option<String>,
    pub tags: Option<String>,
    pub agent_id: Option<String>,
    pub schema_uri: Option<String>,
    pub derived_from: Option<String>,
    pub created_after: Option<String>,
    pub created_before: Option<String>,
    pub data_period_start_after: Option<String>,
    pub data_period_end_before: Option<String>,
    pub expires_after: Option<String>,
    pub expires_before: Option<String>,
    pub status: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    /// FEAT-07: restrict results to a single visibility level. Owned by
    /// `acdp-registry-core` (not `acdp::types::search::SearchParams`)
    /// because the upstream struct doesn't carry the field — the filter
    /// is applied in the handler, after the store search runs.
    pub visibility: Option<String>,
}

impl SearchQuery {
    fn into_params(self) -> (SearchParams, Option<Visibility>) {
        let visibility = self.visibility.as_deref().and_then(parse_visibility);
        (
            SearchParams {
                q: self.q,
                context_type: self.context_type,
                domain: self.domain,
                tags: self.tags,
                agent_id: self.agent_id,
                schema_uri: self.schema_uri,
                derived_from: self.derived_from,
                created_after: self.created_after,
                created_before: self.created_before,
                data_period_start_after: self.data_period_start_after,
                data_period_end_before: self.data_period_end_before,
                expires_after: self.expires_after,
                expires_before: self.expires_before,
                status: self.status,
                limit: self.limit,
                cursor: self.cursor,
            },
            visibility,
        )
    }
}

fn parse_visibility(s: &str) -> Option<Visibility> {
    match s {
        "public" => Some(Visibility::Public),
        "restricted" => Some(Visibility::Restricted),
        "private" => Some(Visibility::Private),
        _ => None,
    }
}

/// Caller-asserted tenant id from the `X-Tenant-Id` request header.
///
/// Prefer [`tenant_for_request`] in handlers that have access to the
/// AppState — it consults the JWT `tenant` claim first and falls back
/// to this header. This raw header extractor is retained for early-
/// publish call sites where the bearer hasn't been validated yet AND
/// for tests; it should not be the primary tenant source on
/// authenticated reads.
///
/// Returns `None` when the header is absent or empty.
pub(crate) fn tenant_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Resolve the operative tenant for a request. Precedence:
///
///   1. JWT `tenant` claim — authoritative because the issuer signs
///      it. A bearer can't assert a tenant they weren't actually
///      bound to.
///   2. `X-Tenant-Id` header — legacy / trust-on-input fallback.
///   3. `None` — no tenant filter (V0 backward-compat).
///
/// When both 1 and 2 are present and disagree, returns
/// `Err(AuthChallenge("tenant assertion mismatch"))` — the header is
/// claiming a tenant the JWT didn't bind, which is either misconfig
/// or hostile. Same shape as a failed-auth error so it surfaces as
/// a clean 401/403 at the response layer.
pub(crate) fn tenant_for_request<S: ExtendedRegistryStore + 'static>(
    state: &AppState<S>,
    headers: &HeaderMap,
) -> Result<Option<String>, RegistryError> {
    let header_tenant = tenant_from_headers(headers);
    reject_reserved_tenant(header_tenant.as_deref())?;
    if !state.config.auth.enabled {
        // Auth disabled — header is the only signal.
        return Ok(header_tenant);
    }
    // Strict mode: a multi-tenant deployment that mandates every request be
    // scoped to a tenant, with the JWT claim as the sole authority for an
    // authenticated caller.
    let strict = state.config.auth.require_tenant;

    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer);

    let resolved = match bearer {
        // A valid bearer is present: the JWT claim is authoritative.
        Some(token) => match state.auth.validate_bearer_claims(token) {
            Ok(claims) => match claims.tenant {
                // Bound token — claim wins; a disagreeing header is rejected.
                Some(c) => reconcile_tenant_sources(Some(c), header_tenant)?,
                // Unbound token. In strict mode the spoofable header must NOT
                // be allowed to assert a tenant the issuer never bound, so we
                // ignore it (and fall to the default-deny check below). In
                // lax mode we preserve V0 behavior and honor the header.
                None => {
                    if strict {
                        None
                    } else {
                        header_tenant
                    }
                }
            },
            Err(_) => {
                // Token didn't validate. We do NOT short-circuit on a bad
                // bearer here — `caller_from_headers` is the right place for
                // that decision (it surfaces the 401). Treat tenant
                // resolution as header-only when claims can't be read.
                header_tenant
            }
        },
        // No bearer (e.g. a producer-signed publish): header is the only
        // signal available.
        None => header_tenant,
    };

    if strict && resolved.is_none() {
        // Default-deny: an enforced multi-tenant registry will not serve a
        // request that resolves to no tenant — that would run with the tenant
        // filter disabled and surface cross-tenant rows.
        return Err(RegistryError::AuthChallenge(
            "this registry requires a tenant scope: send X-Tenant-Id or use a tenant-bound token"
                .into(),
        ));
    }
    // A `default` claim (issuer-signed) is also rejected — the reserved
    // sentinel is never a valid asserted tenant from any source.
    reject_reserved_tenant(resolved.as_deref())?;
    Ok(resolved)
}

/// Reject `RESERVED_TENANT` ("default") as an explicitly-asserted tenant from
/// any source (header or token claim). It is the column default for untenanted
/// rows, so allowing a caller to assert it would alias the entire untenanted
/// bucket — a cross-boundary read/write (#4). Untenanted rows remain reachable
/// only via the *absence* of any tenant assertion (`None`).
pub(crate) fn reject_reserved_tenant(tenant: Option<&str>) -> Result<(), RegistryError> {
    if tenant == Some(acdp_registry_types::config::RESERVED_TENANT) {
        return Err(RegistryError::Acdp(
            acdp::error::AcdpError::SchemaViolation(
                "'default' is a reserved tenant sentinel and cannot be asserted via X-Tenant-Id \
             or a token claim"
                    .into(),
            ),
        ));
    }
    Ok(())
}

/// Resolve the tenant a **publish** writes into.
///
/// Publish is producer-authenticated (the signature over `content_hash` proves
/// `agent_id`), so — unlike a read — the authoritative tenant is the producer's
/// `[[auth.tenant_agents]]` binding, NOT a spoofable `X-Tenant-Id` header.
/// Letting a raw header decide the write tenant allowed any producer to inject
/// a context into an arbitrary tenant's namespace (#2). Precedence:
///   * auth disabled → header only (V0), reserved sentinel rejected;
///   * bound agent → its configured tenant is authoritative; a disagreeing
///     header is rejected;
///   * unbound agent → strict mode rejects (no header-asserted tenant on a
///     write); lax mode preserves V0 header behavior.
pub(crate) fn tenant_for_publish<S: ExtendedRegistryStore + 'static>(
    state: &AppState<S>,
    headers: &HeaderMap,
    agent_id: &str,
) -> Result<Option<String>, RegistryError> {
    let header_tenant = tenant_from_headers(headers);
    reject_reserved_tenant(header_tenant.as_deref())?;
    if !state.config.auth.enabled {
        return Ok(header_tenant);
    }
    let strict = state.config.auth.require_tenant;

    // When the producer's `agent_id` is not authoritatively bound to a tenant
    // by a token claim, fall back to the `[[auth.tenant_agents]]` config
    // binding for that agent — NOT a raw header. A producer-signed publish that
    // carries no tenant-bound token must not be able to assert an arbitrary
    // tenant via the spoofable `X-Tenant-Id` header (#2).
    let binding_fallback = |header: Option<String>| -> Result<Option<String>, RegistryError> {
        match state.config.auth.tenant_for_agent(agent_id) {
            Some(t) => reconcile_tenant_sources(Some(t), header),
            None => Ok(if strict { None } else { header }),
        }
    };

    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer);

    let resolved = match bearer {
        // A valid bearer with a `tenant` claim is issuer-signed and
        // authoritative (same as the read path); a disagreeing header is
        // rejected. An unbound token (or one that doesn't validate) falls back
        // to the producer's config binding.
        Some(token) => match state.auth.validate_bearer_claims(token) {
            Ok(claims) => match claims.tenant {
                Some(c) => reconcile_tenant_sources(Some(c), header_tenant)?,
                None => binding_fallback(header_tenant)?,
            },
            Err(_) => binding_fallback(header_tenant)?,
        },
        None => binding_fallback(header_tenant)?,
    };

    if strict && resolved.is_none() {
        return Err(RegistryError::AuthChallenge(
            "this registry requires a tenant scope: publish with a tenant-bound agent or token"
                .into(),
        ));
    }
    reject_reserved_tenant(resolved.as_deref())?;
    Ok(resolved)
}

/// Pure precedence: JWT claim > X-Tenant-Id header > None. Mismatch
/// between the two surfaces as an auth-challenge error.
pub(crate) fn reconcile_tenant_sources(
    claim: Option<String>,
    header: Option<String>,
) -> Result<Option<String>, RegistryError> {
    match (claim, header) {
        (Some(c), Some(h)) if c != h => {
            tracing::warn!(claim = %c, header = %h, "tenant assertion mismatch");
            Err(RegistryError::AuthChallenge(
                "X-Tenant-Id does not match the tenant the token was issued under".into(),
            ))
        }
        (Some(c), _) => Ok(Some(c)),
        (None, h) => Ok(h),
    }
}

/// `POST /contexts`.
///
/// The publish pipeline already carries the producer's signature over
/// `content_hash`, so this endpoint does NOT require a bearer token.
/// `Idempotency-Key` is honored when the registry advertises support.
pub async fn publish<S: ExtendedRegistryStore + 'static>(
    state: State<Arc<AppState<S>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PublishResponse>, RegistryError> {
    // FEAT-10: record the failure outcome centrally so every `?` early return
    // is captured by its wire code. Success outcomes (`inserted` /
    // `idempotent_replay`) plus the receipt / log-leaf counters are recorded
    // inline on the accept path inside `publish_inner`.
    let result = publish_inner(state, headers, body).await;
    if let Err(e) = &result {
        crate::metrics::record_publish(e.wire_code());
    }
    result
}

async fn publish_inner<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PublishResponse>, RegistryError> {
    // SEC-06: the body length cap is now enforced by
    // `tower_http::limit::RequestBodyLimitLayer` so the same bound applies
    // uniformly to `/auth/*` and any future endpoint, not just publish.
    let req: PublishRequest = serde_json::from_slice(&body)
        .map_err(|e| RegistryError::Acdp(acdp::error::AcdpError::SchemaViolation(e.to_string())))?;
    // RFC-ACDP-0003 §6.1/§6.2.1: the Idempotency-Key value is 1–256 ASCII
    // printable characters. An empty, over-long, or non-printable value is
    // treated as ABSENT (the publish proceeds without idempotency) — NOT
    // rejected with an error. The previous code rejected valid 256-char keys
    // (off-by-one) and 400'd on out-of-range values (#20).
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            (1..=256).contains(&s.len()) && s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
        })
        .map(str::to_string);
    // FEAT-04: forward the orchestrator's correlation id to the event so
    // downstream consumers (Seam Runtime, control plane) can link the
    // publish to a run record.
    let run_id = headers
        .get("x-run-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(str::to_string);

    // REG-P1-3: per-agent publish rate limit (RFC-ACDP-0008 §4.3). Checked
    // here — after the body parses so we know the signing agent, before the
    // expensive verify/persist pipeline. The limiter is keyed by the signing
    // `agent_id`, so one noisy producer can't starve others.
    if let Some(limiter) = &state.rate_limiter {
        if let Err(retry_after_seconds) = limiter.check(req.agent_id.as_str()) {
            crate::metrics::record_rate_limit_rejection("publish_per_agent");
            return Err(RegistryError::RateLimited {
                retry_after_seconds,
            });
        }
    }

    // Resolve the tenant this publish writes into. Publish is
    // producer-authenticated (the signature over content_hash proves
    // `agent_id`), so the authoritative tenant is the producer's
    // `[[auth.tenant_agents]]` binding — NOT a spoofable `X-Tenant-Id` header.
    // The earlier code stamped the row from the raw header, which let any
    // producer inject a context into an arbitrary tenant's namespace (#2).
    // Resolved here, before the expensive verify/persist pipeline.
    let publish_tenant = tenant_for_publish(&state, &headers, req.agent_id.as_str())?;

    let server = state.server.clone();
    let resolver = state.auth.resolver.clone();
    // Snapshot the playground config once per request. The cell is
    // mutable (plan §2: `POST /admin/pinned-keys/reload` swaps it
    // live) so a clone here is the cheapest way to keep an internally
    // consistent view for the duration of this request without holding
    // the read lock across `.await` boundaries below.
    let playground_snapshot = state
        .playground
        .read()
        .expect("playground RwLock poisoned")
        .clone();
    let response: PublishResponse = if playground_snapshot.enabled {
        // Playground: skip DID verification — stop after schema + size + hash.
        // `publish_unverified_for_tests` doesn't accept an idempotency key,
        // so we run idempotency lookup/record around it via the store to
        // preserve replay semantics for tests and demos.
        //
        // Pinned-key enforcement (FEAT-Phase5): when operators configure
        // playground.pinned_keys, the registry refuses to accept publishes
        // claiming a pinned DID unless the signature verifies against the
        // pinned public key. In strict mode (`pinned_only = true`), every
        // publishing agent must be listed.
        let pin_outcome = crate::playground::enforce_pinned_signature(&req, &playground_snapshot)?;
        tracing::debug!(
            agent_did = req.agent_id.as_str(),
            pin_outcome = ?pin_outcome,
            "playground pinned-key check"
        );

        if let Some(key) = idempotency_key.as_deref() {
            let server2 = server.clone();
            let agent2 = req.agent_id.clone();
            let key2 = key.to_string();
            let prior = tokio::task::spawn_blocking(move || {
                server2.store().idempotency_lookup(&agent2, &key2)
            })
            .await
            .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
            if let Some(rec) = prior {
                if rec.expires_at > Utc::now() {
                    if rec.content_hash.0 == req.content_hash.0 {
                        crate::metrics::record_publish("idempotent_replay");
                        return Ok(Json(rec.response));
                    } else {
                        return Err(RegistryError::Acdp(
                            acdp::error::AcdpError::DuplicatePublish(format!(
                                "Idempotency-Key '{key}' was previously used by '{}' \
                                 with a different content_hash",
                                req.agent_id
                            )),
                        ));
                    }
                }
            }
        }
        let server2 = server.clone();
        let req_clone = req.clone();
        let resp =
            tokio::task::spawn_blocking(move || server2.publish_unverified_for_tests(&req_clone))
                .await
                .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
        if let Some(key) = idempotency_key.as_deref() {
            let server2 = server.clone();
            let agent2 = req.agent_id.clone();
            let key2 = key.to_string();
            let hash = req.content_hash.clone();
            let resp_clone = resp.clone();
            // #25: honor the configured TTL instead of a hardcoded 24h, matching
            // the production commit path (acdp::registry::server::commit_via_store).
            let expires = Utc::now()
                + chrono::Duration::seconds(state.config.limits.idempotency_key_ttl_seconds as i64);
            tokio::task::spawn_blocking(move || {
                server2
                    .store()
                    .idempotency_record(&agent2, &key2, &hash, &resp_clone, expires)
            })
            .await
            .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
        }
        resp
    } else if req.agent_id.as_str().starts_with("did:key:") {
        // did:key producers (ACDP 0.2.0 workstream C): steps 7–8 run
        // through acdp's pure offline verifier — the DID *is* the key, so
        // no DID document fetch and no SSRF surface. The capabilities gate
        // inside the validator rejects with `key_resolution_failed` when
        // `did:key` is not advertised in `supported_did_methods` (the
        // anchor-plan / dk-003 pinned behavior). The pipeline is sync, so
        // it runs on the blocking pool like the store calls.
        let server2 = server.clone();
        let req_clone = req.clone();
        let idem = idempotency_key.clone();
        let tenant = publish_tenant.clone();
        tokio::task::spawn_blocking(move || {
            server2.publish_verified_did_key_in_tenant(
                &req_clone,
                idem.as_deref(),
                tenant.as_deref(),
            )
        })
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??
    } else {
        // Production path: full RFC-ACDP-0003 §2.1 pipeline. The resolved
        // tenant is threaded into the atomic commit so `tenant_id` is written
        // in the same INSERT as the context row (P0 #3) — no separate stamping
        // UPDATE that a crash could leave stranded in the default bucket.
        server
            .publish_verified_in_tenant(
                &req,
                idempotency_key.as_deref(),
                &resolver,
                publish_tenant.as_deref(),
            )
            .await?
    };

    // Playground path only: `publish_unverified_for_tests` does not carry
    // tenancy, so stamp it post-publish here. The production path above already
    // wrote `tenant_id` atomically with the row. A `None` from
    // `tenant_for_request` means "no tenant asserted" → the column default
    // ('default') is kept.
    if playground_snapshot.enabled {
        if let Some(tenant_id) = &publish_tenant {
            state
                .server
                .store()
                .set_tenant_of_ctx(response.ctx_id.as_str(), tenant_id)
                .await?;
        }
    }

    if let Some(emitter) = &state.webhook {
        // REG-P2-4: forward the publishing agent's tenant as `X-Tenant-Id`
        // so a multi-tenant control plane attributes the event correctly.
        emitter.emit_with_tenant(
            WebhookEvent::ContextPublished {
                registry_authority: state.config.registry.authority.clone(),
                registry_base_url: state.config.registry.effective_base_url(),
                ctx_id: response.ctx_id.as_str().to_string(),
                lineage_id: response.lineage_id.as_str().to_string(),
                agent_id: req.agent_id.as_str().to_string(),
                context_type: context_type_str(&req.context_type),
                visibility: match req.visibility {
                    acdp::types::Visibility::Public => "public",
                    acdp::types::Visibility::Restricted => "restricted",
                    acdp::types::Visibility::Private => "private",
                }
                .into(),
                version: response.version,
                created_at: response.created_at,
                // FEAT-05: lineage graphs need `derived_from`; without it the
                // control plane can only reconstruct intra-lineage history.
                derived_from: req
                    .derived_from
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect(),
                run_id,
                // ACDP 0.2.0 workstream B touchpoint: surface the producer
                // key fingerprint and the minted receipt so the control
                // plane can correlate without re-fetching the context.
                // Both come straight off the publish response — absent on
                // a receipt-less (0.1.0-mode) registry.
                key_fingerprint: response
                    .registry_receipt
                    .as_ref()
                    .and_then(|r| r.get("key_fingerprint"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                registry_receipt: response.registry_receipt.clone().map(Box::new),
            },
            publish_tenant.clone(),
        );
    }

    // FEAT-10: accepted publish. `record_publish("inserted")` labels the
    // outcome; a minted receipt (RFC-ACDP-0010) and an appended transparency
    // -log leaf (RFC-ACDP-0012, one per accepted publish when the log is
    // enabled) get their own counters. Note: a production-path idempotent
    // replay also lands here and is counted as `inserted` — the store dedupes
    // internally and does not surface the replay flag to the handler; only the
    // playground path (above) distinguishes replays.
    crate::metrics::record_publish("inserted");
    if response.registry_receipt.is_some() {
        crate::metrics::record_receipt_minted();
    }
    if state.log.is_some() {
        crate::metrics::record_log_leaf();
    }

    Ok(Json(response))
}

/// DESIGN-04: same typed accessor as in the storage backends.
fn context_type_str(t: &acdp::types::primitives::ContextType) -> String {
    use acdp::types::primitives::ContextType;
    match t {
        ContextType::DataSnapshot => "data_snapshot".into(),
        ContextType::Analysis => "analysis".into(),
        ContextType::Prediction => "prediction".into(),
        ContextType::Alert => "alert".into(),
        ContextType::KeyRevocation => "key-revocation".into(),
        ContextType::Custom(s) => s.clone(),
    }
}

/// `GET /contexts/{ctx_id}`.
///
/// FEAT-01: when the `ctx_id`'s authority differs from this registry's
/// `config.registry.authority`, the request is delegated to
/// `CrossRegistryResolver` (RFC-ACDP-0006 §4.1). The resolver verifies the
/// foreign capabilities document, retrieves the body, recomputes the
/// content hash, and verifies the producer's signature via the local
/// `WebResolver`. Foreign retrieval is gated by
/// `registry.cross_registry_resolution`.
///
/// REG-P2-5 — federation auth mode is **public-only by design.** The resolver
/// fetches the foreign body anonymously: it forwards NO caller credentials to
/// the upstream registry. A remote `restricted`/`private` context therefore
/// returns 404 from the foreign registry (its visibility gate hides it from an
/// anonymous requester), so this registry can only ever surface remote *public*
/// contexts — it never proxies privileged remote data on a caller's behalf.
/// Authenticated federation (minting scoped credentials per trusted authority)
/// is intentionally out of scope for v0.1; revisit if cross-tenant private
/// federation is required. SSRF on this path is gated by the resolver's
/// `SsrfPolicy` (REG-P2-3): private/internal authorities fail with 502
/// `cross_registry_resolution_failed`, never an internal fetch.
pub async fn retrieve<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
) -> Result<Json<acdp::types::body::FullContext>, RegistryError> {
    let requester = caller_from_headers(&state, &headers)?;

    let parsed = CtxId::parse(ctx_id.clone()).map_err(RegistryError::Acdp)?;
    if parsed.authority() != state.config.registry.authority {
        let Some(resolver) = &state.cross_registry else {
            return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
                "context not found (cross-registry resolution disabled)".into(),
            )));
        };
        let verified = resolver
            .resolve(&parsed)
            .await
            .map_err(RegistryError::Acdp)?;
        let ctx = acdp::types::body::FullContext {
            body: verified.body().clone(),
            registry_state: acdp::types::body::RegistryState {
                status: acdp::types::primitives::Status::Active,
                lifecycle_events: None,
                extensions: Default::default(),
            },
            // Pass the upstream registry's receipt through verbatim (the
            // resolver has already verified it — and *required* it when the
            // upstream advertises `acdp-registry-receipts`, fed-009). The
            // receipt's `registry_did` binds to the ORIGIN authority, which
            // matches the ctx_id authority the caller asked for, so
            // consumers re-verify it against the origin, not this proxy.
            registry_receipt: verified.receipt().cloned(),
            lineage_head_receipt: None,
            log_inclusion: None,
            extensions: Default::default(),
        };
        if let Some(emitter) = &state.webhook {
            emitter.emit(WebhookEvent::ContextRetrieved {
                registry_authority: state.config.registry.authority.clone(),
                ctx_id: ctx.body.ctx_id.as_str().to_string(),
                requester_did: requester.as_ref().map(|d| d.as_str().to_string()),
                at: Utc::now(),
            });
        }
        return Ok(Json(ctx));
    }

    // Resolve the tenant scope up front (before the DB read) so a strict-mode
    // default-deny fails fast and doesn't create a 404-vs-401 existence oracle
    // between a missing row and an unscoped request.
    let requested_tenant = tenant_for_request(&state, &headers)?;

    let server = state.server.clone();
    let ctx_id_typed = CtxId(ctx_id.clone());
    let req_owned = requester.clone();
    let ctx =
        tokio::task::spawn_blocking(move || server.retrieve(&ctx_id_typed, req_owned.as_ref()))
            .await
            .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
    let Some(ctx) = ctx else {
        return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
            "context not found".into(),
        )));
    };
    // Tenant gate. JWT `tenant` claim is preferred over X-Tenant-Id;
    // mismatch between the two → tenant_for_request returns Err
    // (surfaces as 401/403, not a silent not-found). When neither is
    // present → V0 behavior, no filter.
    if let Some(requested_tenant) = requested_tenant {
        let stored = state
            .server
            .store()
            .tenant_of_ctx(&ctx_id)
            .await?
            .unwrap_or_else(|| "default".into());
        if stored != requested_tenant {
            return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
                "context not found".into(),
            )));
        }
    }
    if let Some(emitter) = &state.webhook {
        emitter.emit(WebhookEvent::ContextRetrieved {
            registry_authority: state.config.registry.authority.clone(),
            ctx_id: ctx.body.ctx_id.as_str().to_string(),
            requester_did: requester.as_ref().map(|d| d.as_str().to_string()),
            at: Utc::now(),
        });
    }
    Ok(Json(ctx))
}

/// `GET /contexts/{ctx_id}/body`.
pub async fn retrieve_body<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
) -> Result<Json<acdp::types::body::Body>, RegistryError> {
    let requested_tenant = tenant_for_request(&state, &headers)?;
    let requester = caller_from_headers(&state, &headers)?;
    // Tenant gate before fetching the body — saves work when the
    // caller can't see this row anyway.
    if let Some(ref tenant) = requested_tenant {
        let stored = state
            .server
            .store()
            .tenant_of_ctx(&ctx_id)
            .await?
            .unwrap_or_else(|| "default".into());
        if &stored != tenant {
            return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
                "context not found".into(),
            )));
        }
    }
    let server = state.server.clone();
    let ctx_id_typed = CtxId(ctx_id);
    let body = tokio::task::spawn_blocking(move || {
        server.retrieve_body(&ctx_id_typed, requester.as_ref())
    })
    .await
    .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
    body.map(Json)
        .ok_or(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
            "context not found".into(),
        )))
}

/// Maximum inner pages the §7 refill loop walks before returning what
/// it has. Caps the cost of a tenant whose results are sparse-or-absent
/// inside the upstream's ordered scan — without the cap, a tenant with
/// zero matches against a busy registry would walk the whole table.
///
/// Short-page contract (#15): hitting this cap can return FEWER than the
/// requested `limit` rows while still emitting a non-`None` `next_cursor`.
/// A short page is therefore NOT an end-of-results signal — clients MUST
/// keep paging until `next_cursor` is `None`. `search_paginates_past_fully_hidden_pages`
/// asserts a sparse result set drains completely across pages.
const SEARCH_REFILL_MAX_PAGES: usize = 6;

/// `GET /contexts/search`.
///
/// When the caller asserts a tenant (JWT claim or `X-Tenant-Id` header)
/// and the registry serves multiple tenants, the upstream
/// `RegistryStore::search` returns a single page of up-to-N rows that
/// the handler must then narrow to the caller's tenant. Pre-§7 the
/// narrowing happened *after* pagination, so a `?limit=20` request
/// against a busy mixed-tenant registry could return 2 rows even though
/// many more exist for that tenant just beyond the page.
///
/// §7 fix: bounded refill. The handler asks the store for successive
/// pages along the cursor and accumulates only rows that match the
/// caller's tenant until `target` is reached. The loop is capped at
/// `SEARCH_REFILL_MAX_PAGES` so a tenant with zero matches doesn't
/// turn one HTTP request into an unbounded backend scan.
///
/// DESIGN-01: the RFC-ACDP-0008 §4.5 *visibility* disclosure predicate now
/// runs in the store's search SQL (so restricted/private bodies are never
/// read or decoded, pages fill to `limit` w.r.t. disclosure, and
/// `resp.total_estimate` carries an honest §4.5-scoped pre-page count). The
/// *tenant* narrowing below is the last remaining post-query filter — the
/// upstream `RegistryStore::search` contract carries no tenant, so the
/// bounded refill loop still compensates for it (SECURITY follow-up #14).
pub async fn search<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, RegistryError> {
    let requester = caller_from_headers(&state, &headers)?;
    let query_text = q.q.clone();
    let (params, visibility_filter) = q.into_params();
    let requested_tenant = tenant_for_request(&state, &headers)?;

    let resp = run_search_with_refill(
        &state,
        requester.clone(),
        params,
        visibility_filter,
        requested_tenant,
    )
    .await?;

    if let Some(emitter) = &state.webhook {
        emitter.emit(WebhookEvent::SearchExecuted {
            registry_authority: state.config.registry.authority.clone(),
            query: query_text,
            result_count: resp.matches.len(),
            requester_did: requester.as_ref().map(|d| d.as_str().to_string()),
            at: Utc::now(),
        });
    }
    Ok(Json(resp))
}

/// Drive `server.search` with handler-side post-filters (visibility +
/// tenant). When either post-filter is active, walks the cursor across up
/// to [`SEARCH_REFILL_MAX_PAGES`] inner pages so a busy registry can still
/// return a non-trivial page worth of matches even when the leading raw
/// pages are mostly hidden by the filter.
///
/// `matches.len()` may end up slightly above `target` on the final
/// inner page (we don't truncate to avoid skipping the surplus on the
/// next user request — the cursor encodes positions at the page level,
/// not the row level). Callers treat `limit` as a hint, not a strict
/// cap. The `next_cursor` returned is the *last inner page's*
/// `next_cursor`, so resuming pagination is correct.
async fn run_search_with_refill<S: ExtendedRegistryStore + 'static>(
    state: &Arc<AppState<S>>,
    requester: Option<acdp::types::primitives::AgentDid>,
    mut params: SearchParams,
    visibility_filter: Option<Visibility>,
    requested_tenant: Option<String>,
) -> Result<SearchResponse, RegistryError> {
    let target = params.limit.unwrap_or(20).max(1) as usize;
    // Inner pages always ask for `target` rows so a healthy tenant gets
    // close to the right page in a single hop. Set once; only `cursor`
    // changes per iteration. The fan-out is capped by
    // SEARCH_REFILL_MAX_PAGES regardless.
    params.limit = Some(target as u32);

    let mut accumulated: Vec<acdp::types::search::SearchResult> = Vec::with_capacity(target);
    let mut cursor = params.cursor.clone();
    let mut total_estimate: Option<u64> = None;
    let mut iterations = 0usize;

    loop {
        iterations += 1;
        params.cursor = cursor.clone();

        let server = state.server.clone();
        let req_owned = requester.clone();
        // `server.search` is synchronous, so it runs on the blocking pool.
        // We move `params` in and hand it back out with the result, which
        // lets the loop reuse it next iteration without requiring
        // `SearchParams: Clone` — keeps this crate decoupled from an
        // upstream derive.
        let (result, returned_params) = tokio::task::spawn_blocking(move || {
            let r = server.search(&params, req_owned.as_ref());
            (r, params)
        })
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))?;
        params = returned_params;
        let resp = result?;

        // First page sets the estimate; we don't try to aggregate across
        // pages because the upstream estimate is already a hint.
        if total_estimate.is_none() {
            total_estimate = resp.total_estimate;
        }

        let mut matches = resp.matches;
        if let Some(want) = &visibility_filter {
            matches.retain(|m| m.visibility.as_ref() == Some(want));
        }
        if let Some(tenant) = &requested_tenant {
            if !matches.is_empty() {
                let ids: Vec<&str> = matches.iter().map(|m| m.ctx_id.as_str()).collect();
                let owners = state.server.store().tenants_of_ctxs(&ids).await?;
                matches.retain(|m| {
                    owners
                        .get(m.ctx_id.as_str())
                        .map(|t| t == tenant)
                        .unwrap_or(false)
                });
            }
        }
        // SECURITY follow-up (#14, overlaps DESIGN-01 in plans/defered): the
        // tenant filter runs HERE, post-query, because the upstream
        // `RegistryServer::search` / `RegistryStore::search` contract carries no
        // tenant. The store's `next_cursor` is therefore anchored on the last
        // RAW scanned row, which may belong to another tenant — so a returned
        // cursor can disclose a foreign row's `(created_at, ctx_id)` (a
        // low-grade ordering/existence oracle; the row itself is removed by the
        // retain above, so no context DATA leaks). Closing this fully requires
        // pushing the tenant predicate into the store's search SQL (a
        // tenant-aware `ExtendedRegistryStore::search`), so the scan — and thus
        // the cursor — only ever sees the caller's own rows.
        accumulated.extend(matches);

        // Refill whenever a handler-side post-filter could have dropped rows
        // below `target` — i.e. a tenant is asserted OR a `?visibility=` narrow
        // is active (REG-P2-8). When neither filter is set the store already
        // returned a full page, so the original single-page behavior is
        // preserved bit-for-bit for non-multitenant, unfiltered deployments.
        let post_filtered = requested_tenant.is_some() || visibility_filter.is_some();
        let should_refill = post_filtered
            && accumulated.len() < target
            && resp.next_cursor.is_some()
            && iterations < SEARCH_REFILL_MAX_PAGES;

        cursor = resp.next_cursor;
        if !should_refill {
            break;
        }
    }

    Ok(SearchResponse {
        matches: accumulated,
        total_estimate,
        next_cursor: cursor,
    })
}

/// `GET /lineages/{lineage_id}`.
pub async fn lineage<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(lineage_id): Path<String>,
) -> Result<Json<Vec<acdp::types::body::FullContext>>, RegistryError> {
    let requested_tenant = tenant_for_request(&state, &headers)?;
    let requester = caller_from_headers(&state, &headers)?;
    let server = state.server.clone();
    let id = LineageId(lineage_id);
    let mut items = tokio::task::spawn_blocking(move || server.lineage(&id, requester.as_ref()))
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
    if let Some(tenant) = requested_tenant {
        if !items.is_empty() {
            let ids: Vec<&str> = items.iter().map(|c| c.body.ctx_id.as_str()).collect();
            let owners = state.server.store().tenants_of_ctxs(&ids).await?;
            items.retain(|c| {
                owners
                    .get(c.body.ctx_id.as_str())
                    .map(|t| t == &tenant)
                    .unwrap_or(false)
            });
        }
    }
    Ok(Json(items))
}

/// `GET /lineages/{lineage_id}/current`.
pub async fn current<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(lineage_id): Path<String>,
) -> Result<Json<acdp::types::body::FullContext>, RegistryError> {
    let requested_tenant = tenant_for_request(&state, &headers)?;
    let requester = caller_from_headers(&state, &headers)?;
    let server = state.server.clone();
    let id = LineageId(lineage_id);
    let ctx = tokio::task::spawn_blocking(move || server.current(&id, requester.as_ref()))
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
    let Some(ctx) = ctx else {
        return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
            "no current version".into(),
        )));
    };
    if let Some(tenant) = requested_tenant {
        let stored = state
            .server
            .store()
            .tenant_of_ctx(ctx.body.ctx_id.as_str())
            .await?
            .unwrap_or_else(|| "default".into());
        if stored != tenant {
            return Err(RegistryError::Acdp(acdp::error::AcdpError::NotFound(
                "no current version".into(),
            )));
        }
    }
    Ok(Json(ctx))
}

/// `POST /contexts/{ctx_id}/retract` (RFC-ACDP-0013 §6).
pub async fn retract<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
    body: Bytes,
) -> Result<Json<acdp::types::body::FullContext>, RegistryError> {
    let r = lifecycle_transition(
        state,
        headers,
        ctx_id,
        body,
        acdp::types::lifecycle::LifecycleEventType::Retracted,
    )
    .await;
    crate::metrics::record_lifecycle_event(
        "retract",
        if r.is_ok() {
            "accepted"
        } else {
            r.as_ref().err().map(lifecycle_outcome).unwrap_or("error")
        },
    );
    r
}

/// Outcome label for a lifecycle event metric — the wire code so a rejected
/// transition (e.g. `invalid_lifecycle_transition`) is distinguishable.
fn lifecycle_outcome(e: &RegistryError) -> &'static str {
    e.wire_code()
}

/// `POST /contexts/{ctx_id}/republish` (RFC-ACDP-0013 §6).
pub async fn republish<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Path(ctx_id): Path<String>,
    body: Bytes,
) -> Result<Json<acdp::types::body::FullContext>, RegistryError> {
    let r = lifecycle_transition(
        state,
        headers,
        ctx_id,
        body,
        acdp::types::lifecycle::LifecycleEventType::Republished,
    )
    .await;
    crate::metrics::record_lifecycle_event(
        "republish",
        if r.is_ok() {
            "accepted"
        } else {
            r.as_ref().err().map(lifecycle_outcome).unwrap_or("error")
        },
    );
    r
}

/// Shared RFC-ACDP-0013 §6 pipeline behind both lifecycle endpoints.
///
/// Ordering follows §6 (and §14: visibility before any other check, so
/// the endpoints never leak existence):
///
/// 1. Profile gate — a registry not advertising `acdp-registry-lifecycle`
///    returns `not_implemented` (HTTP 501) before touching the request.
/// 2. Envelope + event shape (`acdp::registry::parse_lifecycle_request`):
///    a body-content member is the `immutable_field` category error
///    (fixture lc-002); the event parses through the closed §4 schema.
/// 3. Path binding: `event.ctx_id` must equal the path `{ctx_id}`.
/// 4. Per-agent rate limiting (RFC-ACDP-0008 §4.3 — lifecycle endpoints
///    are writes), keyed by the event actor like publish is keyed by the
///    signing agent.
/// 5. Tenant gate (mirrors `retrieve`): a cross-tenant ctx_id 404s.
/// 6. The SDK server pipeline: visibility-first resolution, event
///    validation + endpoint binding, actor authentication
///    (`actor == body.agent_id`), signature verification through the full
///    RFC-ACDP-0001 §5.11 resolver pipeline (`did:web`) or the pure
///    offline path (`did:key`), strict-alternation transition validation,
///    and the atomic append — returning the post-transition
///    full-retrieval envelope (or the current state on a byte-identical
///    `event_id` retry).
///
/// The producer's authentication is the event signature itself (like a
/// publish); a bearer token is only consulted for read visibility.
async fn lifecycle_transition<S: ExtendedRegistryStore + 'static>(
    state: Arc<AppState<S>>,
    headers: HeaderMap,
    ctx_id: String,
    body: Bytes,
    event_type: acdp::types::lifecycle::LifecycleEventType,
) -> Result<Json<acdp::types::body::FullContext>, RegistryError> {
    use acdp::error::AcdpError;
    use acdp::types::lifecycle::LifecycleEventType;

    // 1. Profile gate (§6: non-advertising registries MUST 501).
    if !state.config.lifecycle.enabled {
        return Err(RegistryError::Acdp(AcdpError::NotImplemented(
            "this registry does not advertise acdp-registry-lifecycle \
             (RFC-ACDP-0013 §6: lifecycle endpoints are not implemented)"
                .into(),
        )));
    }

    // 2. Closed envelope + closed event schema. `immutable_field` for
    //    body-content members wins over the generic closed-shape error.
    let raw: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| RegistryError::Acdp(AcdpError::SchemaViolation(e.to_string())))?;
    let (event, _raw_event) =
        acdp::registry::parse_lifecycle_request(&raw).map_err(RegistryError::Acdp)?;

    // 3. §6 step 2: the event binds to exactly one context — the path's.
    let path_ctx = CtxId::parse(ctx_id).map_err(RegistryError::Acdp)?;
    if event.ctx_id != path_ctx {
        return Err(RegistryError::Acdp(AcdpError::SchemaViolation(format!(
            "event.ctx_id '{}' does not match the request path ctx_id '{path_ctx}' \
             (RFC-ACDP-0013 §6 step 2)",
            event.ctx_id
        ))));
    }

    // 4. Per-agent write rate limit, keyed by the event actor.
    if let Some(limiter) = &state.rate_limiter {
        if let Err(retry_after_seconds) = limiter.check(event.actor.as_str()) {
            crate::metrics::record_rate_limit_rejection("lifecycle_per_agent");
            return Err(RegistryError::RateLimited {
                retry_after_seconds,
            });
        }
    }

    // 5. Tenant gate — same shape as `retrieve`: a ctx_id outside the
    //    caller's tenant is indistinguishable from a missing one.
    let requested_tenant = tenant_for_request(&state, &headers)?;
    let stored_tenant = state
        .server
        .store()
        .tenant_of_ctx(path_ctx.as_str())
        .await?;
    if let Some(tenant) = &requested_tenant {
        if stored_tenant.as_deref().unwrap_or("default") != tenant {
            return Err(RegistryError::Acdp(AcdpError::NotFound(
                "context not found".into(),
            )));
        }
    }

    // 6. Full §6 pipeline in the SDK server. Visibility is evaluated for
    //    the bearer-authenticated requester (anonymous otherwise) BEFORE
    //    actor/signature checks — error ordering never lets an
    //    unauthorized caller learn a context exists (§14).
    let requester = caller_from_headers(&state, &headers)?;
    let server = state.server.clone();
    let ctx = if event.actor.as_str().starts_with("did:key:") {
        // did:key verification is pure/offline — run on the blocking pool
        // like the other synchronous store pipelines.
        let event2 = event.clone();
        let requester2 = requester.clone();
        tokio::task::spawn_blocking(move || match event_type {
            LifecycleEventType::Retracted => {
                server.retract_verified_did_key(&event2, requester2.as_ref())
            }
            _ => server.republish_verified_did_key(&event2, requester2.as_ref()),
        })
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??
    } else {
        // did:web (and any future resolvable method): the full
        // RFC-ACDP-0001 §5.11 resolver pipeline, as at publish.
        let resolver = state.auth.resolver.clone();
        match event_type {
            LifecycleEventType::Retracted => {
                server
                    .retract_verified(&event, requester.as_ref(), &resolver)
                    .await?
            }
            _ => {
                server
                    .republish_verified(&event, requester.as_ref(), &resolver)
                    .await?
            }
        }
    };

    if let Some(emitter) = &state.webhook {
        let webhook_tenant = stored_tenant.filter(|t| t != "default");
        let common = (
            state.config.registry.authority.clone(),
            ctx.body.ctx_id.as_str().to_string(),
            ctx.body.lineage_id.as_str().to_string(),
        );
        let evt = match event.event_type {
            acdp::types::lifecycle::LifecycleEventType::Retracted => {
                WebhookEvent::ContextRetracted {
                    registry_authority: common.0,
                    ctx_id: common.1,
                    lineage_id: common.2,
                    actor: event.actor.as_str().to_string(),
                    event_id: event.event_id.clone(),
                    reason: event.reason.clone(),
                    at: Utc::now(),
                }
            }
            _ => WebhookEvent::ContextRepublished {
                registry_authority: common.0,
                ctx_id: common.1,
                lineage_id: common.2,
                actor: event.actor.as_str().to_string(),
                event_id: event.event_id.clone(),
                reason: event.reason.clone(),
                at: Utc::now(),
            },
        };
        emitter.emit_with_tenant(evt, webhook_tenant);
    }

    Ok(Json(ctx))
}

/// Pull an authenticated caller DID out of the `Authorization` header.
///
/// Returns `Ok(None)` for unauthenticated requests (no header, non-Bearer
/// scheme, or `auth.enabled = false`); downstream code then applies the
/// public-only filter. Returns `Err(401)` for a bearer header that *is*
/// present but invalid — we don't silently degrade to anonymous because
/// a client whose token just expired should see that explicitly.
pub(crate) fn caller_from_headers<S: ExtendedRegistryStore + 'static>(
    state: &AppState<S>,
    headers: &HeaderMap,
) -> Result<Option<AgentDid>, RegistryError> {
    if !state.config.auth.enabled {
        // Auth disabled — every caller is anonymous regardless of what
        // headers they send. Lets operators flip auth off without minting
        // a fresh JWT secret for every test client.
        return Ok(None);
    }
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(token) = extract_bearer(value) else {
        return Ok(None);
    };
    Ok(Some(state.auth.validate_bearer(token)?))
}

#[cfg(test)]
mod tenant_precedence_tests {
    use super::reconcile_tenant_sources;
    use acdp_registry_types::RegistryError;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn claim_wins_when_both_present_and_agree() {
        let out = reconcile_tenant_sources(s("a"), s("a")).unwrap();
        assert_eq!(out, s("a"));
    }

    #[test]
    fn claim_wins_when_header_absent() {
        let out = reconcile_tenant_sources(s("a"), None).unwrap();
        assert_eq!(out, s("a"));
    }

    #[test]
    fn header_used_when_claim_absent_backward_compat() {
        let out = reconcile_tenant_sources(None, s("legacy")).unwrap();
        assert_eq!(out, s("legacy"));
    }

    #[test]
    fn both_absent_returns_none() {
        assert_eq!(reconcile_tenant_sources(None, None).unwrap(), None);
    }

    #[test]
    fn mismatch_errors_out() {
        let err = reconcile_tenant_sources(s("a"), s("b")).unwrap_err();
        assert!(matches!(err, RegistryError::AuthChallenge(_)));
    }
}

#[cfg(test)]
mod tenant_helper_tests {
    use super::{reject_reserved_tenant, tenant_from_headers};
    use acdp::error::AcdpError;
    use acdp_registry_types::RegistryError;
    use axum::http::HeaderMap;

    #[test]
    fn reject_reserved_tenant_blocks_the_default_sentinel() {
        // #4: "default" is the column default for untenanted rows; asserting it
        // from any source would alias the whole untenanted bucket.
        let err = reject_reserved_tenant(Some("default")).unwrap_err();
        assert!(matches!(
            err,
            RegistryError::Acdp(AcdpError::SchemaViolation(_))
        ));
    }

    #[test]
    fn reject_reserved_tenant_allows_none_and_real_tenants() {
        assert!(reject_reserved_tenant(None).is_ok());
        assert!(reject_reserved_tenant(Some("tenant-a")).is_ok());
        // Only the exact sentinel is reserved — a lookalike is fine.
        assert!(reject_reserved_tenant(Some("default-2")).is_ok());
    }

    #[test]
    fn tenant_from_headers_extracts_trims_and_drops_empty() {
        let mut h = HeaderMap::new();
        assert_eq!(tenant_from_headers(&h), None, "absent header → None");

        h.insert("x-tenant-id", "  tenant-a  ".parse().unwrap());
        assert_eq!(
            tenant_from_headers(&h),
            Some("tenant-a".to_string()),
            "surrounding whitespace is trimmed"
        );

        h.insert("x-tenant-id", "   ".parse().unwrap());
        assert_eq!(
            tenant_from_headers(&h),
            None,
            "a whitespace-only header is treated as absent"
        );
    }
}
