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
    },
    /// A context was retrieved by an authenticated caller (visibility-filtered).
    ContextRetrieved {
        ctx_id: String,
        requester_did: Option<String>,
        at: DateTime<Utc>,
    },
    /// A search query was executed.
    SearchExecuted {
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
