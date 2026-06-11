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

/// Fixed-window limiter: at most `limit` publishes per 60s per agent, plus an
/// optional process-global ceiling across ALL keys per 60s.
pub struct AgentRateLimiter {
    limit: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Process-wide ceiling per window. `u32::MAX` ⇒ effectively disabled.
    /// Defends the unauthenticated `/auth/challenge` endpoint (#24): the
    /// per-agent key is attacker-controlled, so varying `agent_id` bypasses
    /// the per-key bound — the global counter caps total flooding regardless.
    global_limit: u32,
    global: Mutex<Bucket>,
}

impl AgentRateLimiter {
    /// Construct a limiter allowing `limit_per_minute` per agent, with no
    /// global ceiling (used by the publish limiter, keyed by the verified
    /// producer `agent_id`).
    pub fn new(limit_per_minute: u32) -> Self {
        Self::with_global_ceiling(limit_per_minute, u32::MAX)
    }

    /// Like [`new`](Self::new) but also enforces a process-global ceiling of
    /// `global_limit_per_minute` across all keys.
    pub fn with_global_ceiling(limit_per_minute: u32, global_limit_per_minute: u32) -> Self {
        Self {
            limit: limit_per_minute,
            buckets: Mutex::new(HashMap::new()),
            global_limit: global_limit_per_minute,
            global: Mutex::new(Bucket {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    /// Check the process-global ceiling (#24). Call this in addition to
    /// [`check`](Self::check) on unauthenticated endpoints where the per-key
    /// identity is attacker-controlled.
    pub fn check_global(&self) -> Result<(), u64> {
        self.check_global_at(Instant::now())
    }

    fn check_global_at(&self, now: Instant) -> Result<(), u64> {
        if self.global_limit == u32::MAX {
            return Ok(());
        }
        let mut b = self.global.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(b.window_start) >= WINDOW {
            b.window_start = now;
            b.count = 0;
        }
        if b.count >= self.global_limit {
            let elapsed = now.duration_since(b.window_start);
            return Err(WINDOW.saturating_sub(elapsed).as_secs().max(1));
        }
        b.count += 1;
        Ok(())
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
    fn global_ceiling_caps_total_across_distinct_keys() {
        // #24: per-agent budget is generous, but the global ceiling caps total
        // flooding even when the attacker rotates agent_id every request.
        let rl = AgentRateLimiter::with_global_ceiling(1_000, 2);
        let t0 = Instant::now();
        assert!(rl.check_global_at(t0).is_ok());
        assert!(rl.check_global_at(t0).is_ok());
        assert!(
            rl.check_global_at(t0).is_err(),
            "global ceiling must reject once exhausted regardless of key"
        );
        // Refreshes next window.
        let later = t0 + Duration::from_secs(61);
        assert!(rl.check_global_at(later).is_ok());
    }

    #[test]
    fn no_global_ceiling_by_default() {
        let rl = AgentRateLimiter::new(1);
        let t0 = Instant::now();
        for _ in 0..10_000 {
            assert!(
                rl.check_global_at(t0).is_ok(),
                "new() must not impose a global ceiling"
            );
        }
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

    #[test]
    fn window_boundary_is_inclusive_at_exactly_60s() {
        // The reset is `>= WINDOW`, so the budget refreshes at exactly 60.0s
        // but NOT a tick earlier (59.999s is still the same window).
        let rl = AgentRateLimiter::new(1);
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0).is_ok());
        assert!(rl.check_at("a", t0).is_err());
        // 59.999s in — still throttled.
        assert!(rl
            .check_at("a", t0 + Duration::from_millis(59_999))
            .is_err());
        // Exactly 60s — new window.
        assert!(rl.check_at("a", t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn retry_after_never_reports_zero() {
        // Near the very end of a window the remaining seconds floor to 0;
        // the limiter clamps to 1 so a client never sees `Retry-After: 0`.
        let rl = AgentRateLimiter::new(1);
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0).is_ok());
        let retry = rl
            .check_at("a", t0 + Duration::from_millis(59_500))
            .expect_err("still throttled");
        assert_eq!(retry, 1, "sub-second remainder must clamp to 1s");
    }

    #[test]
    fn prune_evicts_only_stale_buckets() {
        let rl = AgentRateLimiter::new(10);
        let t0 = Instant::now();
        // Fill the map to the prune threshold with buckets in the current window.
        for i in 0..PRUNE_AT {
            assert!(rl.check_at(&format!("agent-{i}"), t0).is_ok());
        }
        // A new key one full window later trips the opportunistic prune; every
        // existing bucket is now stale and must be evicted, leaving just the
        // freshly-inserted key.
        let later = t0 + Duration::from_secs(61);
        assert!(rl.check_at("newcomer", later).is_ok());
        let len = rl.buckets.lock().unwrap().len();
        assert_eq!(len, 1, "stale buckets must be pruned, got {len} entries");
    }

    #[test]
    fn global_and_per_agent_counters_are_independent() {
        // Exhausting the per-agent budget must not consume the global counter,
        // and vice-versa — the publish path checks them separately.
        let rl = AgentRateLimiter::with_global_ceiling(1, 1);
        let t0 = Instant::now();
        // Use up the per-agent budget for "a".
        assert!(rl.check_at("a", t0).is_ok());
        assert!(rl.check_at("a", t0).is_err());
        // The global counter is untouched — its first call still succeeds.
        assert!(rl.check_global_at(t0).is_ok());
        assert!(rl.check_global_at(t0).is_err());
        // And a different agent's per-agent budget is likewise untouched.
        assert!(rl.check_at("b", t0).is_ok());
    }
}
