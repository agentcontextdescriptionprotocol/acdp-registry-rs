//! Per-agent publish rate limiting (RFC-ACDP-0008 §4.3 REQUIRED).
//!
//! A fixed-window counter keyed by the signing `agent_id`. In-memory and
//! per-process: a horizontally-scaled deployment should additionally bound
//! publishes at a shared layer (gateway / Redis). We deliberately avoid a
//! new dependency (`dashmap`) — a `Mutex<HashMap>` is ample for the single
//! lock-per-publish access pattern, matching the workspace's dep-graph
//! minimization principle.

use std::collections::HashMap;
use std::net::IpAddr;
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

/// A single CIDR block, used to recognise trusted reverse proxies (FEAT-06).
///
/// Stored as the network base address plus a prefix length so matching is a
/// masked bitwise compare — no allocation, no external `ipnet` dependency
/// (matching the workspace's dep-minimization principle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    base: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse `"10.0.0.0/8"` / `"fc00::/7"`. A bare IP (`"1.2.3.4"`) is treated
    /// as a `/32` (v4) or `/128` (v6) host route.
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let base: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("invalid IP in CIDR '{s}'"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix in CIDR '{s}'"))?,
            None => max,
        };
        if prefix_len > max {
            return Err(format!("prefix /{prefix_len} out of range for CIDR '{s}'"));
        }
        Ok(Self { base, prefix_len })
    }

    /// Does `ip` fall within this block? IPv4-mapped IPv6 peers are compared
    /// after canonicalisation (done by the caller), so a v4 CIDR matches a
    /// `::ffff:a.b.c.d` peer.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(o)) => masked_eq(&b.octets(), &o.octets(), self.prefix_len),
            (IpAddr::V6(b), IpAddr::V6(o)) => masked_eq(&b.octets(), &o.octets(), self.prefix_len),
            _ => false,
        }
    }
}

/// Compare the top `prefix_len` bits of two equal-length octet arrays.
fn masked_eq(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
    let mut bits = prefix_len as usize;
    for (x, y) in a.iter().zip(b.iter()) {
        if bits == 0 {
            break;
        }
        let take = bits.min(8);
        let mask = if take == 8 {
            0xFFu8
        } else {
            // top `take` bits set
            !(0xFFu8 >> take)
        };
        if (x & mask) != (y & mask) {
            return false;
        }
        bits -= take;
    }
    true
}

/// Operator-configured set of reverse-proxy CIDRs whose `X-Forwarded-For`
/// header this registry is willing to trust (FEAT-06). Empty = trust none.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    cidrs: Vec<Cidr>,
}

impl TrustedProxies {
    /// Parse a list of CIDR strings, collecting every parse error so the
    /// caller (startup validation) can reject a misconfiguration up front.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut cidrs = Vec::with_capacity(entries.len());
        for e in entries {
            cidrs.push(Cidr::parse(e)?);
        }
        Ok(Self { cidrs })
    }

    /// Parse, silently dropping (and logging) invalid entries. Used on the
    /// hot construction path where startup validation has already run.
    pub fn parse_lossy(entries: &[String]) -> Self {
        let cidrs = entries
            .iter()
            .filter_map(|e| match Cidr::parse(e) {
                Ok(c) => Some(c),
                Err(err) => {
                    tracing::warn!(entry = %e, error = %err, "ignoring invalid trusted_proxy CIDR");
                    None
                }
            })
            .collect();
        Self { cidrs }
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

/// Resolve the effective client IP for rate-limiting (FEAT-06).
///
/// `peer` is the TCP socket peer address (already IPv4-canonicalised by the
/// caller). `xff` is the raw `X-Forwarded-For` header value, if present.
///
/// SECURITY: `X-Forwarded-For` is caller-controlled and is honoured ONLY when
/// `peer` is itself a trusted proxy. In that case the real client is the
/// rightmost XFF entry that is not itself a trusted proxy — i.e. we walk the
/// forwarded chain from the right (nearest hop first), skipping trusted
/// proxies, and take the first address a trusted proxy actually received the
/// request from. If every XFF entry is a trusted proxy (or XFF is
/// absent/garbage), we fall back to `peer`. When `trusted` is empty, XFF is
/// never consulted.
pub fn client_ip(peer: IpAddr, xff: Option<&str>, trusted: &TrustedProxies) -> IpAddr {
    if trusted.is_empty() || !trusted.contains(peer) {
        return peer;
    }
    let Some(xff) = xff else {
        return peer;
    };
    // Right-to-left: the last entry is the address the trusted peer saw.
    for hop in xff.rsplit(',') {
        let hop = hop.trim();
        // XFF entries may carry a port (rare) — strip anything after the IP.
        let candidate = hop.parse::<IpAddr>().ok().map(canonical_ip).or_else(|| {
            hop.parse::<std::net::SocketAddr>()
                .ok()
                .map(|s| canonical_ip(s.ip()))
        });
        match candidate {
            Some(ip) if trusted.contains(ip) => continue, // another trusted hop
            Some(ip) => return ip,                        // first untrusted → the client
            None => return peer,                          // garbage → don't trust the chain
        }
    }
    peer
}

/// Canonicalise an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4
/// form so CIDR matching and bucket keys are stable regardless of the
/// listener's dual-stack representation.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
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

    // ── CIDR + client-IP resolution (FEAT-06) ───────────────────────

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matches_v4_and_v6_ranges() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(c.contains(ip("10.255.255.255")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("192.168.1.1")));

        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(ip("192.168.1.42")));
        assert!(!c.contains(ip("192.168.2.42")));

        let c = Cidr::parse("fc00::/7").unwrap();
        assert!(c.contains(ip("fd00::1")));
        assert!(!c.contains(ip("fe80::1")));

        // bare host route
        let c = Cidr::parse("203.0.113.7").unwrap();
        assert!(c.contains(ip("203.0.113.7")));
        assert!(!c.contains(ip("203.0.113.8")));
    }

    #[test]
    fn cidr_rejects_garbage_and_out_of_range() {
        assert!(Cidr::parse("not-an-ip/8").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("::/129").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
    }

    #[test]
    fn client_ip_ignores_xff_when_no_trusted_proxies() {
        // Empty trust set: XFF is never consulted, socket peer wins.
        let trusted = TrustedProxies::default();
        let got = client_ip(ip("203.0.113.9"), Some("1.1.1.1"), &trusted);
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted_peer() {
        // Peer is NOT a trusted proxy, so its XFF is a spoof attempt — ignore.
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        let got = client_ip(ip("203.0.113.9"), Some("1.1.1.1"), &trusted);
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn client_ip_honors_xff_from_trusted_peer() {
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        // Trusted proxy at 10.0.0.5 forwarded a request from the real client.
        let got = client_ip(ip("10.0.0.5"), Some("198.51.100.7"), &trusted);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn client_ip_walks_chain_of_trusted_proxies() {
        // client → proxy(10.0.0.9) → proxy(10.0.0.5=peer). XFF lists the
        // client then the first proxy; we skip the trusted hop and return
        // the client.
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        let got = client_ip(ip("10.0.0.5"), Some("198.51.100.7, 10.0.0.9"), &trusted);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn client_ip_falls_back_when_all_hops_trusted() {
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        let got = client_ip(ip("10.0.0.5"), Some("10.0.0.9, 10.0.0.8"), &trusted);
        assert_eq!(got, ip("10.0.0.5"));
    }

    #[test]
    fn client_ip_falls_back_on_garbage_xff() {
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        let got = client_ip(ip("10.0.0.5"), Some("garbage"), &trusted);
        assert_eq!(got, ip("10.0.0.5"));
    }

    #[test]
    fn client_ip_canonicalises_v4_mapped_peer_against_v4_cidr() {
        // A dual-stack listener may report the peer as ::ffff:10.0.0.5; the
        // caller canonicalises before calling, so simulate that here.
        let trusted = TrustedProxies::parse(&["10.0.0.0/8".into()]).unwrap();
        let peer = canonical_ip(ip("::ffff:10.0.0.5"));
        assert_eq!(peer, ip("10.0.0.5"));
        let got = client_ip(peer, Some("198.51.100.7"), &trusted);
        assert_eq!(got, ip("198.51.100.7"));
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
