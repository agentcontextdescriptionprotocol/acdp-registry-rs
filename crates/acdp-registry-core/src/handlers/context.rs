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
    if !state.config.auth.enabled {
        // Auth disabled — header is the only signal.
        return Ok(header_tenant);
    }
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Ok(header_tenant);
    };
    let Some(token) = extract_bearer(value) else {
        return Ok(header_tenant);
    };
    let claim_tenant = match state.auth.validate_bearer_claims(token) {
        Ok(claims) => claims.tenant,
        Err(_) => {
            // Token didn't validate. We do NOT short-circuit on a bad
            // bearer here — `caller_from_headers` is the right place
            // for that decision (it surfaces the 401). Treat the
            // tenant resolution as header-only when claims can't be
            // read.
            return Ok(header_tenant);
        }
    };
    reconcile_tenant_sources(claim_tenant, header_tenant)
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
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PublishResponse>, RegistryError> {
    // SEC-06: the body length cap is now enforced by
    // `tower_http::limit::RequestBodyLimitLayer` so the same bound applies
    // uniformly to `/auth/*` and any future endpoint, not just publish.
    let req: PublishRequest = serde_json::from_slice(&body)
        .map_err(|e| RegistryError::Acdp(acdp::error::AcdpError::SchemaViolation(e.to_string())))?;
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // FEAT-04: forward the orchestrator's correlation id to the event so
    // downstream consumers (Seam Runtime, control plane) can link the
    // publish to a run record.
    let run_id = headers
        .get("x-run-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(str::to_string);
    if let Some(k) = &idempotency_key {
        if k.is_empty() || k.len() > 255 {
            return Err(RegistryError::Acdp(
                acdp::error::AcdpError::SchemaViolation(
                    "Idempotency-Key length must be between 1 and 255 bytes".into(),
                ),
            ));
        }
    }

    let server = state.server.clone();
    let resolver = state.auth.resolver.clone();
    let response: PublishResponse = if state.config.playground.enabled {
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
        let pin_outcome =
            crate::playground::enforce_pinned_signature(&req, &state.config.playground)?;
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
            let expires = Utc::now() + chrono::Duration::hours(24);
            tokio::task::spawn_blocking(move || {
                server2
                    .store()
                    .idempotency_record(&agent2, &key2, &hash, &resp_clone, expires)
            })
            .await
            .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;
        }
        resp
    } else {
        // Production path: full RFC-ACDP-0003 §2.1 pipeline.
        server
            .publish_verified(&req, idempotency_key.as_deref(), &resolver)
            .await?
    };

    // Stamp tenant_id post-publish. The protocol-level upsert path
    // doesn't carry tenancy (acdp::registry::RegistryStore is shared
    // across implementations); we apply it here via the extended
    // trait. A `None` from tenant_from_headers means "no tenant
    // header was sent" → the column's default ('default') is kept.
    if let Some(tenant_id) = tenant_from_headers(&headers) {
        state
            .server
            .store()
            .set_tenant_of_ctx(response.ctx_id.as_str(), &tenant_id)
            .await?;
    }

    if let Some(emitter) = &state.webhook {
        emitter.emit(WebhookEvent::ContextPublished {
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
        });
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
                extensions: Default::default(),
            },
            registry_receipt: None,
            extensions: Default::default(),
        };
        if let Some(emitter) = &state.webhook {
            emitter.emit(WebhookEvent::ContextRetrieved {
                ctx_id: ctx.body.ctx_id.as_str().to_string(),
                requester_did: requester.as_ref().map(|d| d.as_str().to_string()),
                at: Utc::now(),
            });
        }
        return Ok(Json(ctx));
    }

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
    if let Some(requested_tenant) = tenant_for_request(&state, &headers)? {
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

/// `GET /contexts/search`.
pub async fn search<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, RegistryError> {
    let requester = caller_from_headers(&state, &headers)?;
    let query_text = q.q.clone();
    let (params, visibility_filter) = q.into_params();
    let server = state.server.clone();
    let req_owned = requester.clone();
    let mut resp = tokio::task::spawn_blocking(move || server.search(&params, req_owned.as_ref()))
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??;

    // FEAT-07: client-supplied visibility filter applied at the handler
    // boundary because the upstream `SearchParams` shape has no such field.
    // The visibility-gate in the store still runs first (RFC-ACDP-0008
    // §4.5 disclosure rules), so this only narrows results the caller is
    // already permitted to see.
    if let Some(want) = visibility_filter {
        resp.matches
            .retain(|m| m.visibility.as_ref() == Some(&want));
    }

    // Tenant filter — same opt-in semantics as retrieve. Absent
    // X-Tenant-Id → no filter (V0 backward-compat). Present → drop
    // any match whose row is tagged to a different tenant. Uses the
    // batch lookup so it's one extra query, not N.
    if let Some(requested_tenant) = tenant_for_request(&state, &headers)? {
        if !resp.matches.is_empty() {
            let ids: Vec<&str> = resp.matches.iter().map(|m| m.ctx_id.as_str()).collect();
            let owners = state.server.store().tenants_of_ctxs(&ids).await?;
            resp.matches.retain(|m| {
                owners
                    .get(m.ctx_id.as_str())
                    .map(|t| t == &requested_tenant)
                    .unwrap_or(false)
            });
        }
    }

    if let Some(emitter) = &state.webhook {
        emitter.emit(WebhookEvent::SearchExecuted {
            query: query_text,
            result_count: resp.matches.len(),
            requester_did: requester.as_ref().map(|d| d.as_str().to_string()),
            at: Utc::now(),
        });
    }
    Ok(Json(resp))
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
