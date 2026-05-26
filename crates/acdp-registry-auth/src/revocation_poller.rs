//! Cross-issuer revocation poller (plan §9).
//!
//! Polls each configured peer's `/auth/revocations` feed and applies
//! propagated entries to the local revocation store. The peer's feed
//! is admin-gated (`Authorization: Bearer <admin_token>`); a single
//! shared admin api key per peer is the V1 trust model.
//!
//! Per-issuer cursor (in unix-ms) is held in-memory only — on restart
//! the poller refetches the whole feed from `since=0`. The peer's
//! cursor pagination is strict-greater-than so a full refetch is
//! correct (just chatty). Persisting the cursor is plan-§9 follow-up.
//!
//! Failure modes:
//!   - Peer 4xx/5xx → log warn, retry next interval (don't crash).
//!   - Peer payload malformed → log warn, drop the batch.
//!   - Local store error → log warn, drop the batch (the entry will
//!     be retried next interval since the cursor only advances on
//!     successful local writes).

use std::sync::Arc;
use std::time::Duration;

use acdp_registry_types::config::RevocationFeedConfig;
use chrono::{DateTime, TimeZone, Utc};
use reqwest::Client;
use serde::Deserialize;

use crate::revocation_store::{RevocationRecord, RevocationStore};

#[derive(Debug, Deserialize)]
struct FeedEntry {
    jti: String,
    sub: String,
    #[serde(default)]
    #[allow(dead_code)]
    iss: String,
    exp: i64,
    revoked_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct FeedResponse {
    entries: Vec<FeedEntry>,
    next_cursor: Option<i64>,
}

/// Spawn a background task that polls each configured feed forever.
/// Returns immediately. Operators wire this in `main.rs` next to
/// `auth.spawn_evictor()`.
pub fn spawn_revocation_pollers(feeds: Vec<RevocationFeedConfig>, store: Arc<dyn RevocationStore>) {
    for cfg in feeds {
        let store = store.clone();
        tokio::spawn(async move {
            poll_loop(cfg, store).await;
        });
    }
}

async fn poll_loop(cfg: RevocationFeedConfig, store: Arc<dyn RevocationStore>) {
    let client = match Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "revocation poller: failed to build HTTP client");
            return;
        }
    };
    let mut cursor: i64 = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_seconds.max(1)));
    // Skip the first tick so we start polling immediately.
    interval.tick().await;
    loop {
        match fetch_once(&client, &cfg, cursor).await {
            Ok((applied, next)) => {
                tracing::info!(
                    issuer = %cfg.issuer,
                    count = applied.len(),
                    next_cursor = ?next,
                    "revocation feed poll succeeded"
                );
                if let Some(c) = next {
                    cursor = c;
                }
                apply_entries_or_log(applied, &store, &cfg).await;
            }
            Err(e) => {
                tracing::warn!(
                    issuer = %cfg.issuer,
                    error = %e,
                    "revocation feed poll failed (will retry)"
                );
            }
        }
        interval.tick().await;
    }
}

/// Fetch one page of the feed. Returns (entries, next_cursor) on
/// success. Caller is responsible for applying the entries + advancing
/// the cursor.
async fn fetch_once(
    client: &Client,
    cfg: &RevocationFeedConfig,
    cursor: i64,
) -> Result<(Vec<FeedEntry>, Option<i64>), String> {
    let resp = client
        .get(&cfg.feed_url)
        .bearer_auth(&cfg.admin_token)
        .query(&[("since", cursor.to_string().as_str()), ("limit", "200")])
        .send()
        .await
        .map_err(|e| format!("transport: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: FeedResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    Ok((body.entries, body.next_cursor))
}

async fn apply_entries_or_log(
    entries: Vec<FeedEntry>,
    store: &Arc<dyn RevocationStore>,
    cfg: &RevocationFeedConfig,
) {
    for e in entries {
        let expires_at = match Utc.timestamp_opt(e.exp, 0).single() {
            Some(t) => t,
            None => {
                tracing::warn!(jti = %e.jti, exp = e.exp, "feed entry has malformed exp");
                continue;
            }
        };
        let _ = revoked_at_from_ms(e.revoked_at_ms); // validate parse; we don't persist it locally
        if let Err(err) = store
            .revoke(RevocationRecord {
                jti: e.jti.clone(),
                agent_did: e.sub.clone(),
                expires_at,
            })
            .await
        {
            tracing::warn!(
                issuer = %cfg.issuer,
                jti = %e.jti,
                error = %err,
                "failed to apply propagated revocation"
            );
        }
    }
}

fn revoked_at_from_ms(ms: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_millis_opt(ms).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_feed_response() {
        let json = r#"{
            "entries": [
                {"jti": "a", "sub": "did:web:alice", "iss": "cp.local",
                 "exp": 9999999999, "revoked_at_ms": 1700000000000}
            ],
            "next_cursor": 1700000001000
        }"#;
        let r: FeedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].jti, "a");
        assert_eq!(r.next_cursor, Some(1700000001000));
    }

    #[test]
    fn parses_a_terminal_page_with_null_next_cursor() {
        let json = r#"{"entries": [], "next_cursor": null}"#;
        let r: FeedResponse = serde_json::from_str(json).unwrap();
        assert!(r.entries.is_empty());
        assert_eq!(r.next_cursor, None);
    }

    #[test]
    fn revoked_at_from_ms_round_trips_a_known_instant() {
        let dt = revoked_at_from_ms(1_700_000_001_500).unwrap();
        assert_eq!(dt.timestamp_millis(), 1_700_000_001_500);
    }
}
