//! Per-agent publish rate limiting (RFC-ACDP-0008 §4.3 REQUIRED).
//!
//! A fixed-window counter keyed by the signing `agent_id`. In-memory and
//! per-process: a horizontally-scaled deployment should additionally bound
//! publishes at a shared layer (gateway / Redis). We deliberately avoid a
//! new dependency (`dashmap`) — a `Mutex<HashMap>` is ample for the single
//! lock-per-publish access pattern, matching the workspace's dep-graph
//! minimization principle.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
/// Opportunistic prune threshold — keeps the agent map from growing without
/// bound when many distinct agents publish once and never return.
const PRUNE_AT: usize = 4096;

struct Bucket {
    window_start: Instant,
    count: u32,
}

/// Fixed-window limiter: at most `limit` publishes per 60s per agent.
pub struct AgentRateLimiter {
    limit: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl AgentRateLimiter {
    /// Construct a limiter allowing `limit_per_minute` publishes per agent.
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit: limit_per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Record one publish attempt by `agent_id`. Returns `Err(retry_after_secs)`
    /// when the agent is over budget for the current window, otherwise `Ok`.
    pub fn check(&self, agent_id: &str) -> Result<(), u64> {
        self.check_at(agent_id, Instant::now())
    }

    fn check_at(&self, agent_id: &str, now: Instant) -> Result<(), u64> {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= PRUNE_AT {
            map.retain(|_, b| now.duration_since(b.window_start) < WINDOW);
        }
        let bucket = map.entry(agent_id.to_string()).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        if now.duration_since(bucket.window_start) >= WINDOW {
            bucket.window_start = now;
            bucket.count = 0;
        }
        if bucket.count >= self.limit {
            let elapsed = now.duration_since(bucket.window_start);
            // At least 1s so a client never sees `Retry-After: 0`.
            let retry = WINDOW.saturating_sub(elapsed).as_secs().max(1);
            return Err(retry);
        }
        bucket.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let rl = AgentRateLimiter::new(3);
        let t0 = Instant::now();
        assert!(rl.check_at("agent-a", t0).is_ok());
        assert!(rl.check_at("agent-a", t0).is_ok());
        assert!(rl.check_at("agent-a", t0).is_ok());
        let retry = rl
            .check_at("agent-a", t0)
            .expect_err("4th should be limited");
        assert!(
            (1..=60).contains(&retry),
            "retry-after out of range: {retry}"
        );
    }

    #[test]
    fn separate_agents_have_separate_budgets() {
        let rl = AgentRateLimiter::new(1);
        let t0 = Instant::now();
        assert!(rl.check_at("agent-a", t0).is_ok());
        assert!(rl.check_at("agent-a", t0).is_err());
        // A different agent is unaffected by agent-a's exhausted budget.
        assert!(rl.check_at("agent-b", t0).is_ok());
    }

    #[test]
    fn window_resets_after_60s() {
        let rl = AgentRateLimiter::new(1);
        let t0 = Instant::now();
        assert!(rl.check_at("agent-a", t0).is_ok());
        assert!(rl.check_at("agent-a", t0).is_err());
        let later = t0 + Duration::from_secs(61);
        assert!(
            rl.check_at("agent-a", later).is_ok(),
            "budget should refresh in the next window"
        );
    }
}
