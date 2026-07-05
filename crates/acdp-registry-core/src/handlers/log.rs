//! Transparency-log endpoints (RFC-ACDP-0012 §8, ACDP 0.3.0).
//!
//! Three GET endpoints at the RFC-ACDP-0009 §2.11 reserved paths. All
//! are always mounted; a registry without `log.enabled` answers
//! `not_implemented` (HTTP 501) from the handler — the same posture as
//! the RFC-ACDP-0013 lifecycle endpoints. There is deliberately **no
//! `log_unavailable`** error anywhere (§7.1): an enabled log serves, a
//! disabled one is `not_implemented`, and nothing in between exists.
//!
//! Error semantics (§8.2/§8.3, §11):
//! - malformed / mixed / omitted parameters and out-of-range sizes →
//!   `schema_violation` (400);
//! - a `ctx_id` not in the log **or not visible to the requester** →
//!   `not_found` (404), indistinguishable from absence (the §8.2
//!   retrieval-visibility rule, RFC-ACDP-0008 §4.5);
//! - `leaf_index`-addressed and consistency queries are hash-only and
//!   apply **no visibility gate** (positions, hashes, and tree size are
//!   public by design, §15) — but the convenience `leaf` echo is served
//!   only to retrieval-authorized requesters (§8.2/§8.3);
//! - the registry never emits `invalid_log_proof` from these handlers:
//!   that code indicts a *verified* proof and is emitted by consumers /
//!   federated resolvers validating an upstream (§11).
//!
//! Tree computation is O(n) per request over the stored leaf hashes
//! (see `acdp_registry_store::log` for the design note); the current
//! head root is cached in [`LogState`].

use std::sync::Arc;

use acdp::crypto::merkle;
use acdp::error::AcdpError;
use acdp::types::log::{encode_sha256_hex, LogCheckpoint, LogConsistencyProof, LogInclusion};
use acdp::types::primitives::{AgentDid, CtxId};
use acdp_registry_store::{ExtendedRegistryStore, LogEntryRecord};
use acdp_registry_types::RegistryError;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use super::context::{caller_from_headers, tenant_for_request};
use crate::log::LogState;
use crate::state::AppState;

/// Page-size cap for `GET /log/entries` (§8.3: the registry MAY cap by
/// returning fewer entries than requested; RECOMMENDED cap ≥ 256).
/// Callers continue from `start + len(entries)`.
pub const LOG_ENTRIES_PAGE_CAP: u64 = 256;

/// §11 profile gate shared by all three handlers.
fn log_state<S: ExtendedRegistryStore + 'static>(
    state: &AppState<S>,
) -> Result<&Arc<LogState>, RegistryError> {
    state.log.as_ref().ok_or_else(|| {
        RegistryError::Acdp(AcdpError::NotImplemented(
            "this registry does not advertise acdp-registry-transparency-log \
             (RFC-ACDP-0012 §11: the /log/* endpoints are not implemented)"
                .into(),
        ))
    })
}

fn schema_violation(msg: String) -> RegistryError {
    RegistryError::Acdp(AcdpError::SchemaViolation(msg))
}

fn not_found() -> RegistryError {
    // Identical shape for "not logged" and "not visible" — no existence
    // oracle (§8.2 / RFC-ACDP-0008 §4.5).
    RegistryError::Acdp(AcdpError::NotFound("context not found in the log".into()))
}

fn parse_u64(name: &str, raw: &str) -> Result<u64, RegistryError> {
    raw.parse::<u64>().map_err(|_| {
        schema_violation(format!(
            "query parameter '{name}' must be a non-negative integer (got '{raw}')"
        ))
    })
}

fn to_usize(n: u64) -> Result<usize, RegistryError> {
    usize::try_from(n)
        .map_err(|_| schema_violation(format!("tree position {n} exceeds the platform bound")))
}

/// Whether the requester is authorized to retrieve `ctx_id` — the exact
/// `GET /contexts/{ctx_id}` rule (visibility per RFC-ACDP-0008 §4.5 plus
/// this registry's tenant gate). Gates the §8.2 `ctx_id` proof surface
/// and every `leaf` echo.
async fn requester_can_retrieve<S: ExtendedRegistryStore + 'static>(
    state: &Arc<AppState<S>>,
    requester: Option<&AgentDid>,
    requested_tenant: Option<&str>,
    ctx_id: &str,
) -> Result<bool, RegistryError> {
    let Ok(parsed) = CtxId::parse(ctx_id.to_string()) else {
        return Ok(false);
    };
    let server = state.server.clone();
    let req_owned = requester.cloned();
    let visible = tokio::task::spawn_blocking(move || server.retrieve(&parsed, req_owned.as_ref()))
        .await
        .map_err(|e| RegistryError::Internal(format!("join: {e}")))??
        .is_some();
    if !visible {
        return Ok(false);
    }
    if let Some(tenant) = requested_tenant {
        let stored = state
            .server
            .store()
            .tenant_of_ctx(ctx_id)
            .await?
            .unwrap_or_else(|| "default".into());
        if stored != tenant {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `MTH(D[tree_size])` over the stored hashes, wire form — caching the
/// current head (append-only makes any (size → root) pair immutable).
fn root_for(log: &LogState, tree_size: u64, hashes: &[[u8; 32]], current: u64) -> String {
    if let Some(cached) = log.cached_root(tree_size) {
        return cached;
    }
    let root = encode_sha256_hex(&merkle::merkle_tree_hash(hashes));
    if tree_size == current {
        log.cache_root(tree_size, &root);
    }
    root
}

/// Mint the §6 checkpoint at `tree_size`/`root` with a fresh timestamp.
fn mint_checkpoint(
    log: &LogState,
    tree_size: u64,
    root: &str,
) -> Result<LogCheckpoint, RegistryError> {
    log.signer
        .mint_log_checkpoint(&log.log_id, tree_size, root, Utc::now())
        .map_err(RegistryError::Acdp)
}

/// `GET /log/checkpoint` (§8.1) — the current signed tree head, bare.
/// Publicly readable wherever capabilities are: it reveals only tree
/// size, root, and time.
pub async fn log_checkpoint<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let log = log_state(&state)?;
    let tree_size = state.server.store().log_tree_size().await?;
    let root = match log.cached_root(tree_size) {
        Some(root) => root,
        None => {
            let hashes = state.server.store().log_leaf_hashes(tree_size).await?;
            root_for(log, tree_size, &hashes, tree_size)
        }
    };
    let checkpoint = mint_checkpoint(log, tree_size, &root)?;
    Ok(Json(serde_json::to_value(checkpoint)?))
}

/// Query surface of `GET /log/proof` (§8.2): two mutually exclusive
/// parameter sets. Values arrive as strings so malformed numbers are a
/// clean `schema_violation`, not a framework 400.
#[derive(Debug, Default, Deserialize)]
pub struct LogProofQuery {
    pub ctx_id: Option<String>,
    pub leaf_index: Option<String>,
    pub tree_size: Option<String>,
    pub first: Option<String>,
    pub second: Option<String>,
}

/// `GET /log/proof` (§8.2) — inclusion mode (`?ctx_id=` | `?leaf_index=`
/// [`&tree_size=`]) or consistency mode (`?first=&second=`).
pub async fn log_proof<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Query(q): Query<LogProofQuery>,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let log = log_state(&state)?.clone();

    let inclusion_mode = q.ctx_id.is_some() || q.leaf_index.is_some() || q.tree_size.is_some();
    let consistency_mode = q.first.is_some() || q.second.is_some();
    if inclusion_mode && consistency_mode {
        return Err(schema_violation(
            "mixing the inclusion parameters (ctx_id / leaf_index / tree_size) with the \
             consistency parameters (first / second) is not allowed (RFC-ACDP-0012 §8.2)"
                .into(),
        ));
    }
    if consistency_mode {
        return consistency_proof_response(&state, &log, &q).await;
    }
    if !inclusion_mode {
        return Err(schema_violation(
            "GET /log/proof requires either ?ctx_id= or ?leaf_index= (inclusion mode) or \
             ?first=&second= (consistency mode) (RFC-ACDP-0012 §8.2)"
                .into(),
        ));
    }
    inclusion_proof_response(&state, &log, &headers, &q).await
}

/// §8.2 inclusion mode.
async fn inclusion_proof_response<S: ExtendedRegistryStore + 'static>(
    state: &Arc<AppState<S>>,
    log: &Arc<LogState>,
    headers: &HeaderMap,
    q: &LogProofQuery,
) -> Result<Json<serde_json::Value>, RegistryError> {
    // Resolve the caller once; a bad bearer or tenant mismatch errors
    // out before any log state is consulted.
    let requester = caller_from_headers(state, headers)?;
    let requested_tenant = tenant_for_request(state, headers)?;
    let current = state.server.store().log_tree_size().await?;

    // (record, whether the requester may see the leaf echo)
    let (record, echo_leaf): (LogEntryRecord, bool) = match (&q.ctx_id, &q.leaf_index) {
        (Some(_), Some(_)) => {
            return Err(schema_violation(
                "supply exactly one of ?ctx_id= or ?leaf_index=, not both (RFC-ACDP-0012 §8.2)"
                    .into(),
            ));
        }
        // The consumer surface: retrieval visibility applies exactly as
        // for GET /contexts/{ctx_id} — an unauthorized (or unlogged)
        // ctx_id is `not_found`, indistinguishable from absence (§4.5).
        (Some(ctx_id), None) => {
            if !requester_can_retrieve(
                state,
                requester.as_ref(),
                requested_tenant.as_deref(),
                ctx_id,
            )
            .await?
            {
                return Err(not_found());
            }
            let record = state
                .server
                .store()
                .log_leaf_by_ctx(ctx_id)
                .await?
                .ok_or_else(not_found)?;
            (record, true)
        }
        // The auditor surface: positions are public (hash-only data
        // leaks nothing, §15) — no visibility gate on the proof itself;
        // only the leaf echo is authorization-gated below.
        (None, Some(raw)) => {
            let leaf_index = parse_u64("leaf_index", raw)?;
            let record = state
                .server
                .store()
                .log_leaf_by_index(leaf_index)
                .await?
                .ok_or_else(|| {
                    schema_violation(format!(
                        "leaf_index {leaf_index} is not < the current tree size {current} \
                         (RFC-ACDP-0012 §8.2)"
                    ))
                })?;
            let echo = requester_can_retrieve(
                state,
                requester.as_ref(),
                requested_tenant.as_deref(),
                &record.ctx_id,
            )
            .await?;
            (record, echo)
        }
        (None, None) => {
            return Err(schema_violation(
                "inclusion mode requires exactly one of ?ctx_id= or ?leaf_index= \
                 (RFC-ACDP-0012 §8.2)"
                    .into(),
            ));
        }
    };

    // §8.2: optional historical tree size — leaf_index < tree_size ≤ current.
    let tree_size = match &q.tree_size {
        Some(raw) => {
            let n = parse_u64("tree_size", raw)?;
            if !(record.leaf_index < n && n <= current) {
                return Err(schema_violation(format!(
                    "tree_size must satisfy leaf_index ({}) < tree_size ≤ current size \
                     ({current}), got {n} (RFC-ACDP-0012 §8.2)",
                    record.leaf_index
                )));
            }
            n
        }
        None => current,
    };

    let hashes = state.server.store().log_leaf_hashes(tree_size).await?;
    let path = merkle::inclusion_path(to_usize(record.leaf_index)?, &hashes).ok_or_else(|| {
        RegistryError::Internal(format!(
            "no inclusion path for leaf {} at size {tree_size}",
            record.leaf_index
        ))
    })?;
    let root = root_for(log, tree_size, &hashes, current);
    let checkpoint = mint_checkpoint(log, tree_size, &root)?;

    let mut inclusion = LogInclusion {
        log_id: log.log_id.clone(),
        leaf_index: record.leaf_index,
        tree_size,
        inclusion_path: path.iter().map(encode_sha256_hex).collect(),
        log_checkpoint: checkpoint,
        leaf: None,
    };
    if echo_leaf {
        // Convenience echo for retrieval-authorized requesters only —
        // absent (never null) otherwise. Verifiers MUST NOT trust it
        // (§9.1 step 1 reconstructs the leaf from verified material).
        inclusion.leaf = Some(record.leaf().map_err(RegistryError::Acdp)?);
    }
    Ok(Json(serde_json::to_value(inclusion)?))
}

/// §8.2 consistency mode — REQUIRED: detecting root rewrites is why the
/// log exists. Hash-only; no visibility gate.
async fn consistency_proof_response<S: ExtendedRegistryStore + 'static>(
    state: &Arc<AppState<S>>,
    log: &Arc<LogState>,
    q: &LogProofQuery,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let (Some(first_raw), Some(second_raw)) = (&q.first, &q.second) else {
        return Err(schema_violation(
            "consistency mode requires both ?first= and ?second= (RFC-ACDP-0012 §8.2)".into(),
        ));
    };
    let first = parse_u64("first", first_raw)?;
    let second = parse_u64("second", second_raw)?;
    let current = state.server.store().log_tree_size().await?;
    if first == 0 || first > second || second > current {
        return Err(schema_violation(format!(
            "consistency mode requires 0 < first ≤ second ≤ current tree size ({current}); \
             got first={first}, second={second} (RFC-ACDP-0012 §8.2)"
        )));
    }

    let hashes = state.server.store().log_leaf_hashes(second).await?;
    // Empty exactly when first == second (RFC 6962 §2.1.2).
    let path = merkle::consistency_proof(to_usize(first)?, &hashes).ok_or_else(|| {
        RegistryError::Internal(format!("no consistency proof for {first} → {second}"))
    })?;
    let root = root_for(log, second, &hashes, current);
    let checkpoint = mint_checkpoint(log, second, &root)?;

    let proof = LogConsistencyProof {
        log_id: log.log_id.clone(),
        first_tree_size: first,
        second_tree_size: second,
        consistency_path: path.iter().map(encode_sha256_hex).collect(),
        log_checkpoint: checkpoint,
    };
    Ok(Json(serde_json::to_value(proof)?))
}

/// Query surface of `GET /log/entries` (§8.3).
#[derive(Debug, Default, Deserialize)]
pub struct LogEntriesQuery {
    pub start: Option<String>,
    pub end: Option<String>,
}

/// `GET /log/entries?start=<i>&end=<j>` (§8.3) — `leaf_hash` for every
/// entry unconditionally (ordered leaf hashes alone let any third party
/// recompute every root); `leaf` only for entries whose context the
/// requester is authorized to retrieve. The page is capped at
/// [`LOG_ENTRIES_PAGE_CAP`]; callers continue from `start + len(entries)`.
pub async fn log_entries<S: ExtendedRegistryStore + 'static>(
    State(state): State<Arc<AppState<S>>>,
    headers: HeaderMap,
    Query(q): Query<LogEntriesQuery>,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let log = log_state(&state)?.clone();
    let (Some(start_raw), Some(end_raw)) = (&q.start, &q.end) else {
        return Err(schema_violation(
            "GET /log/entries requires both ?start= and ?end= (0-based, start inclusive, \
             end exclusive) (RFC-ACDP-0012 §8.3)"
                .into(),
        ));
    };
    let start = parse_u64("start", start_raw)?;
    let end = parse_u64("end", end_raw)?;
    let current = state.server.store().log_tree_size().await?;
    if !(start < end && end <= current) {
        return Err(schema_violation(format!(
            "entries range must satisfy start < end ≤ current tree size ({current}); \
             got start={start}, end={end} (RFC-ACDP-0012 §8.3)"
        )));
    }
    let capped_end = end.min(start.saturating_add(LOG_ENTRIES_PAGE_CAP));

    let requester = caller_from_headers(&state, &headers)?;
    let requested_tenant = tenant_for_request(&state, &headers)?;

    let records = state.server.store().log_entries(start, capped_end).await?;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let mut entry = json!({
            "leaf_index": record.leaf_index,
            "leaf_hash": record.leaf_hash,
        });
        // §8.3: `leaf` present ONLY where the requester could retrieve
        // the context (public: always); absent — never null — otherwise.
        // An unauthorized auditor learns that *a* publish occupies this
        // position, nothing else.
        if requester_can_retrieve(
            &state,
            requester.as_ref(),
            requested_tenant.as_deref(),
            &record.ctx_id,
        )
        .await?
        {
            entry["leaf"] = record.leaf_value().map_err(RegistryError::Acdp)?;
        }
        entries.push(entry);
    }
    Ok(Json(json!({
        "log_id": log.log_id,
        "start": start,
        "entries": entries,
    })))
}
