//! Webhook event envelope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Events the registry can emit. Each variant becomes the JSON `type` field
/// thanks to `serde(tag = "type")`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookEvent {
    /// A new context body was persisted.
    ContextPublished {
        /// Authority (bare DNS hostname) of the registry that emitted this
        /// event. The control plane attributes every event to a registry by
        /// this field; without it `ContextRetrieved` / `SearchExecuted` (which
        /// carry no `ctx_id` to parse an authority out of) are unattributable.
        registry_authority: String,
        /// Public base URL of the emitting registry, e.g.
        /// `https://registry.example.com`. The control plane bootstraps its
        /// `registries.base_url` from this so it can route federation proxy
        /// calls (`GET /contexts/:ctxId`).
        registry_base_url: String,
        ctx_id: String,
        lineage_id: String,
        agent_id: String,
        context_type: String,
        visibility: String,
        version: u32,
        created_at: DateTime<Utc>,
        /// `derived_from` ctx_ids carried on the publish request. The
        /// control plane builds lineage graphs from the event stream;
        /// without this it can only reconstruct lineage via `lineage_id`
        /// and loses cross-lineage provenance.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        derived_from: Vec<String>,
        /// Optional `X-Run-Id` correlation id from the publish request,
        /// used to link the event back to an orchestrator run record.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        /// RFC-ACDP-0010 §6 fingerprint of the producer key the registry
        /// actually resolved at publish time (`sha256:<hex>`). Present
        /// only on receipts-advertising registries (ACDP 0.2.0); additive
        /// — consumers tolerate the field's absence.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_fingerprint: Option<String>,
        /// The registry receipt minted for this publish (the full signed
        /// object, RFC-ACDP-0010 §4) so the control plane can correlate
        /// and re-verify without re-fetching the context. Present only on
        /// receipts-advertising registries; additive. Boxed to keep the
        /// enum's variants size-balanced (clippy::large_enum_variant);
        /// serde serializes a `Box<T>` exactly like `T`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registry_receipt: Option<Box<serde_json::Value>>,
    },
    /// A context was retrieved by an authenticated caller (visibility-filtered).
    ContextRetrieved {
        /// Authority of the emitting registry — see `ContextPublished`.
        registry_authority: String,
        ctx_id: String,
        requester_did: Option<String>,
        at: DateTime<Utc>,
    },
    /// A search query was executed.
    SearchExecuted {
        /// Authority of the emitting registry — see `ContextPublished`.
        registry_authority: String,
        query: Option<String>,
        result_count: usize,
        requester_did: Option<String>,
        at: DateTime<Utc>,
    },
}

impl WebhookEvent {
    /// Stable string name used for logging/tracing.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ContextPublished { .. } => "context.published",
            Self::ContextRetrieved { .. } => "context.retrieved",
            Self::SearchExecuted { .. } => "search.executed",
        }
    }
}
