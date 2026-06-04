//! Cross-issuer revocation poller (plan §9).
//!
//! Polls each configured peer's `/auth/revocations` feed and applies
//! propagated entries to the local revocation store. The peer's feed
//! is admin-gated (`Authorization: Bearer <admin_token>`); a single
//! shared admin api key per peer is the V1 trust model.
//!
//! Per-issuer cursor (in unix-ms) is persisted via
//! [`RevocationStore::get_revocation_cursor`] /
//! [`set_revocation_cursor`] (plan §5). On startup the poller reads
//! the persisted cursor; on a successfully-applied batch it writes
//! the new cursor. A restart picks up exactly where the prior
//! instance left off — no re-fetching the whole feed from `since=0`.
//!
//! Failure modes:
//!   - Peer 4xx/5xx → log warn, retry next interval (don't crash).
//!   - Peer payload malformed → log warn, drop the batch.
//!   - Local revoke() error on any entry in a batch → log warn, drop
//!     the batch AND leave the cursor unchanged so the failed entry
//!     retries next interval. This is the cost of correctness: a
//!     single failing entry replays the whole page once a tick.
//!   - Cursor persistence error → log warn, advance the in-memory
//!     cursor anyway (so the next poll within this process doesn't
//!     refetch). A restart would re-fetch the page, but `revoke()`
//!     is idempotent so the apply is harmless.

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
    /// The issuer that minted this token. Used to confine a peer's feed to the
    /// issuer it is authoritative for (#7): an entry attributed to a different
    /// issuer is anomalous (peer bug, or an attempt to revoke another issuer's
    /// tokens) and is dropped.
    #[serde(default)]
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
    // Restart-survival (plan §5): start from the persisted cursor.
    // A None / error here is non-fatal — falling back to 0 just
    // re-fetches the full feed once, which is correct (idempotent
    // revoke + strict-greater-than pagination upstream).
    let mut cursor: i64 = match store.get_revocation_cursor(&cfg.issuer).await {
        Ok(Some(c)) => {
            tracing::info!(
                issuer = %cfg.issuer,
                cursor = c,
                "revocation poller resumed from persisted cursor"
            );
            c
        }
        Ok(None) => 0,
        Err(e) => {
            tracing::warn!(
                issuer = %cfg.issuer,
                error = %e,
                "failed to load persisted revocation cursor, starting at 0"
            );
            0
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_seconds.max(1)));
    // Skip the first tick so we start polling immediately.
    interval.tick().await;
    loop {
        match fetch_once(&client, &cfg, cursor).await {
            Ok((entries, next)) => {
                let count = entries.len();
                let all_succeeded = apply_entries(&entries, &store, &cfg).await;
                tracing::info!(
                    issuer = %cfg.issuer,
                    count,
                    next_cursor = ?next,
                    all_succeeded,
                    "revocation feed poll succeeded"
                );
                // Plan §5: advance the cursor ONLY when every entry
                // in the batch applied locally. A partial failure
                // keeps the cursor where it is so the next tick
                // refetches the failed entries.
                if all_succeeded {
                    if let Some(c) = next {
                        cursor = c;
                        if let Err(e) = store.set_revocation_cursor(&cfg.issuer, c).await {
                            tracing::warn!(
                                issuer = %cfg.issuer,
                                cursor = c,
                                error = %e,
                                "failed to persist revocation cursor (will replay on restart)"
                            );
                        }
                    }
                }
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

/// Apply each entry to the local store. Returns `true` only if every
/// entry succeeded (the plan-§5 contract — partial failure keeps the
/// cursor where it is so the failed entry retries next tick).
///
/// Entries with a malformed `exp` are *skipped* but still count as
/// "applied": they're irrecoverable upstream errors (a broken peer
/// payload), so refetching won't fix them. A future audit can grep
/// for the warn log if these become frequent.
async fn apply_entries(
    entries: &[FeedEntry],
    store: &Arc<dyn RevocationStore>,
    cfg: &RevocationFeedConfig,
) -> bool {
    let mut all_succeeded = true;
    for e in entries {
        // #7: only honor revocations the polled peer is authoritative for. A
        // feed entry attributed to a different issuer is anomalous — drop it so
        // one peer cannot inject revocations labelled as another issuer. Empty
        // `iss` is tolerated for backward compatibility with feeds that omit it
        // (the configured peer is the implicit authority). NOTE: this does not
        // by itself prevent a fully-compromised configured peer from revoking
        // an arbitrary `jti`; per-issuer scoping of the revocation store
        // (keying is_revoked on the token's signed `iss`) is the deeper fix and
        // requires a schema migration — tracked as a follow-up.
        if !e.iss.is_empty() && e.iss != cfg.issuer {
            tracing::warn!(
                issuer = %cfg.issuer,
                entry_iss = %e.iss,
                jti = %e.jti,
                "revocation feed entry from a foreign issuer; dropping (cross-issuer injection guard)"
            );
            continue;
        }
        let expires_at = match Utc.timestamp_opt(e.exp, 0).single() {
            Some(t) => t,
            None => {
                // #26: dead-letter explicitly. A malformed `exp` is permanent,
                // so we log loudly and skip rather than holding the cursor —
                // holding it would stall the entire feed on one bad entry.
                tracing::error!(
                    issuer = %cfg.issuer,
                    jti = %e.jti,
                    exp = e.exp,
                    "revocation feed entry has malformed exp; dropping (cannot apply)"
                );
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
                "failed to apply propagated revocation; cursor will not advance this tick"
            );
            all_succeeded = false;
        }
    }
    all_succeeded
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
