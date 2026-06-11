//! HMAC-signed webhook emitter.
//!
//! `WebhookEmitter::spawn` starts a background worker that drains an mpsc
//! channel and POSTs each event to the configured URL. Failed deliveries
//! are retried with exponential backoff up to `max_retries`. Signing
//! follows GitHub's convention: `X-ACDP-Signature: sha256=<hex>` over the
//! raw JSON body.

use std::time::Duration;

use acdp::safe_http::SsrfPolicy;
use acdp_registry_types::{WebhookConfig, WebhookEvent};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Wire schema version of the webhook envelope. Bump on any
/// backwards-incompatible change to the serialized event shape so the control
/// plane can branch on it.
pub const WEBHOOK_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("send channel closed")]
    Closed,
    #[error("encode: {0}")]
    Encode(String),
    #[error("config: {0}")]
    Config(String),
}

type HmacSha256 = Hmac<Sha256>;

/// An event plus out-of-band routing metadata carried to the worker. The
/// `tenant_id` travels as the `X-Tenant-Id` request header — NOT in the
/// signed JSON body — so the GitHub-compatible signature scheme and the
/// stable event schema are both preserved while still letting a
/// multi-tenant control plane attribute the delivery.
///
/// `event_id` is minted once at emit time (REG-P2-6) and reused across every
/// delivery retry, so the control plane can dedupe re-deliveries.
#[derive(Debug, Clone)]
struct Delivery {
    event_id: String,
    event: WebhookEvent,
    tenant_id: Option<String>,
}

/// What actually goes on the wire: the event flattened under a small envelope
/// carrying `event_id` + `schema_version`. Flattening keeps the historical
/// shape (top-level `type` + variant fields) so existing consumers keep
/// working while gaining the two dedupe/versioning fields.
#[derive(Debug, Serialize)]
struct WireEnvelope<'a> {
    event_id: &'a str,
    schema_version: &'a str,
    #[serde(flatten)]
    event: &'a WebhookEvent,
}

/// Handle held by the HTTP layer. `emit` is non-blocking; the worker
/// drains events asynchronously.
#[derive(Clone)]
pub struct WebhookEmitter {
    tx: mpsc::Sender<Delivery>,
}

impl WebhookEmitter {
    /// Validate the webhook configuration and spawn the worker.
    ///
    /// SEC-03: the URL is checked against the same SSRF policy
    /// (`acdp::safe_http::SsrfPolicy::default()`) that the DID resolver
    /// uses — HTTPS-only, no IP literals, hostnames only. Without this
    /// gate a misconfigured or maliciously set webhook URL turns the
    /// registry into an SSRF proxy against internal services like the
    /// AWS / GCP metadata endpoint.
    ///
    /// SEC-04: when the webhook is enabled and has a non-empty URL, the
    /// shared HMAC secret must be non-empty. The HMAC primitive will
    /// happily compute over a zero-length key, which means a receiver
    /// that checks `X-ACDP-Signature` will accept every event as
    /// authentic — defeating the integrity guarantee.
    pub fn try_spawn(config: WebhookConfig) -> Result<Self, WebhookError> {
        if config.enabled && !config.url.is_empty() {
            acdp::safe_http::SsrfPolicy::default()
                .check_url(&config.url)
                .map_err(|e| {
                    WebhookError::Config(format!(
                        "webhook.url '{}' rejected by SSRF policy: {e}",
                        config.url
                    ))
                })?;
            if config.secret.trim().is_empty() {
                return Err(WebhookError::Config(
                    "webhook.secret must be non-empty when webhook.enabled and webhook.url \
                     are set; HMAC over an empty key accepts every signature"
                        .into(),
                ));
            }
        }
        Ok(Self::spawn(config))
    }

    /// Spawn without configuration validation. Prefer `try_spawn` —
    /// retained for tests and for cases where the caller has already
    /// validated the config. Uses the strict default SSRF policy.
    pub fn spawn(config: WebhookConfig) -> Self {
        Self::spawn_with_policy(config, acdp::safe_http::SsrfPolicy::default())
    }

    /// Like [`spawn`](Self::spawn) but with an explicit SSRF policy for the
    /// delivery client. Production uses the strict default (via `spawn` /
    /// `try_spawn`); tests that POST to a local listener pass
    /// `SsrfPolicy::allow_test_loopback()`.
    pub fn spawn_with_policy(config: WebhookConfig, policy: acdp::safe_http::SsrfPolicy) -> Self {
        let capacity = config.queue_capacity.max(1);
        let (tx, rx) = mpsc::channel::<Delivery>(capacity);
        tokio::spawn(worker(config, rx, policy));
        Self { tx }
    }

    /// Snapshot of the delivery queue for the admin status endpoint:
    /// `(in_flight, capacity)`. `in_flight` is how many events are buffered
    /// and not yet delivered; nearing `capacity` means the worker is falling
    /// behind and events are at risk of being dropped.
    pub fn queue_status(&self) -> (usize, usize) {
        let capacity = self.tx.max_capacity();
        let in_flight = capacity.saturating_sub(self.tx.capacity());
        (in_flight, capacity)
    }

    /// Fire and forget. The channel is bounded; if the worker can't keep
    /// up, the event is dropped with a warn log rather than blocking the
    /// HTTP handler.
    pub fn emit(&self, event: WebhookEvent) {
        self.emit_with_tenant(event, None);
    }

    /// Like [`emit`](Self::emit) but tags the delivery with a tenant id,
    /// forwarded as the `X-Tenant-Id` header so a multi-tenant control
    /// plane can attribute the event. The id never enters the signed body.
    pub fn emit_with_tenant(&self, event: WebhookEvent, tenant_id: Option<String>) {
        let delivery = Delivery {
            event_id: Uuid::new_v4().to_string(),
            event,
            tenant_id,
        };
        match self.tx.try_send(delivery) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("webhook queue full; event dropped");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("webhook channel closed; event dropped");
            }
        }
    }
}

async fn worker(config: WebhookConfig, mut rx: mpsc::Receiver<Delivery>, policy: SsrfPolicy) {
    // SEC (#6): the delivery client filters every resolved IP through the SSRF
    // policy at DNS time and refuses redirects, so a webhook URL whose DNS
    // answers (or 3xx redirects to) a private/IMDS address cannot turn the
    // registry into an SSRF proxy. The earlier plain client did neither.
    let client =
        match acdp::safe_http::safe_client(&policy, Duration::from_secs(config.timeout_seconds)) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "webhook: cannot build HTTP client; disabling");
                return;
            }
        };
    while let Some(delivery) = rx.recv().await {
        if !config.enabled || config.url.is_empty() {
            continue;
        }
        if let Err(e) = deliver(&client, &config, &delivery).await {
            tracing::warn!(error = %e, event = delivery.event.name(), "webhook delivery failed");
        }
    }
}

async fn deliver(
    client: &reqwest::Client,
    config: &WebhookConfig,
    delivery: &Delivery,
) -> Result<(), WebhookError> {
    let event = &delivery.event;
    let envelope = WireEnvelope {
        event_id: &delivery.event_id,
        schema_version: WEBHOOK_SCHEMA_VERSION,
        event,
    };
    let body = serde_json::to_vec(&envelope).map_err(|e| WebhookError::Encode(e.to_string()))?;
    let sig = sign(&config.secret, &body);

    let mut backoff = Duration::from_millis(250);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let mut builder = client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .header("X-ACDP-Signature", &sig)
            .header("X-ACDP-Event", event.name())
            .header("X-ACDP-Event-Id", &delivery.event_id);
        if let Some(tenant) = &delivery.tenant_id {
            builder = builder.header("X-Tenant-Id", tenant);
        }
        let resp = builder.body(body.clone()).send().await;
        match resp {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let status = r.status();
                if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
                    // 4xx (non-429) won't change on retry — treat as permanent
                    // failure so operators can grep for `webhook_4xx`.
                    tracing::warn!(
                        event = "webhook_4xx",
                        status = %status,
                        url = %config.url,
                        attempt,
                        "webhook 4xx; giving up"
                    );
                    return Ok(());
                }
                tracing::warn!(
                    status = %status,
                    attempt,
                    "webhook non-2xx response"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, attempt, "webhook transport error");
            }
        }
        if attempt >= config.max_retries {
            return Ok(());
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(15));
    }
}

/// `"sha256=" + hex(HMAC-SHA256(secret, body))` — same shape as GitHub.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key len");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Accept exactly one HTTP/1.1 request, return its raw bytes, and
    /// reply `200 OK`. Enough to assert on the delivered headers + body
    /// without pulling in an HTTP server dependency.
    async fn capture_one_request(listener: TcpListener) -> String {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        // Read until we've seen the header terminator and the full body.
        loop {
            let n = socket.read(&mut chunk).await.expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            if let Some(header_end) = text.find("\r\n\r\n") {
                let content_len = text
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length: ")
                            .or_else(|| l.strip_prefix("Content-Length: "))
                    })
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= header_end + 4 + content_len {
                    break;
                }
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("write response");
        socket.flush().await.ok();
        String::from_utf8_lossy(&buf).to_string()
    }

    fn published_event() -> WebhookEvent {
        WebhookEvent::ContextPublished {
            registry_authority: "registry.example.com".into(),
            registry_base_url: "https://registry.example.com".into(),
            ctx_id: "acdp://registry.example.com/abc".into(),
            lineage_id: "lin-1".into(),
            agent_id: "did:web:agent.example.com".into(),
            context_type: "analysis".into(),
            visibility: "public".into(),
            version: 1,
            created_at: Utc::now(),
            derived_from: Vec::new(),
            run_id: None,
        }
    }

    #[tokio::test]
    async fn forwards_tenant_header_and_authority_in_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let capture = tokio::spawn(capture_one_request(listener));

        let config = WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/hook"),
            secret: "shhh".into(),
            timeout_seconds: 5,
            max_retries: 1,
            queue_capacity: 8,
        };
        let emitter = WebhookEmitter::spawn_with_policy(config, SsrfPolicy::allow_test_loopback());
        emitter.emit_with_tenant(published_event(), Some("tenant-x".into()));

        let raw = capture.await.expect("join");
        // Routing metadata travels as a header, not in the signed body.
        assert!(
            raw.contains("x-tenant-id: tenant-x") || raw.contains("X-Tenant-Id: tenant-x"),
            "expected X-Tenant-Id header, got:\n{raw}"
        );
        assert!(
            raw.contains("x-acdp-event: context.published")
                || raw.contains("X-ACDP-Event: context.published"),
            "expected X-ACDP-Event header, got:\n{raw}"
        );
        // Attribution fields land in the JSON body.
        assert!(
            raw.contains("\"registry_authority\":\"registry.example.com\""),
            "expected registry_authority in body, got:\n{raw}"
        );
        assert!(
            raw.contains("\"registry_base_url\":\"https://registry.example.com\""),
            "expected registry_base_url in body, got:\n{raw}"
        );
        // Tenant id must NOT pollute the signed body.
        assert!(
            !raw.contains("tenant-x\""),
            "tenant id leaked into JSON body:\n{raw}"
        );
        // REG-P2-6: envelope carries event_id + schema_version, and event_id
        // is echoed in a header for cheap dedup.
        assert!(
            raw.contains("\"schema_version\":\"1.0\""),
            "expected schema_version in body, got:\n{raw}"
        );
        assert!(
            raw.contains("\"event_id\":\""),
            "expected event_id in body, got:\n{raw}"
        );
        assert!(
            raw.to_ascii_lowercase().contains("x-acdp-event-id:"),
            "expected X-ACDP-Event-Id header, got:\n{raw}"
        );
    }

    #[tokio::test]
    async fn distinct_emits_get_distinct_event_ids() {
        fn event_id_of(raw: &str) -> String {
            let needle = "\"event_id\":\"";
            let start = raw.find(needle).expect("event_id present") + needle.len();
            let rest = &raw[start..];
            let end = rest.find('"').expect("event_id terminated");
            rest[..end].to_string()
        }
        async fn capture_once(emitter: &WebhookEmitter, addr: std::net::SocketAddr) -> String {
            let listener = TcpListener::bind(addr).await.expect("rebind");
            let cap = tokio::spawn(capture_one_request(listener));
            emitter.emit(published_event());
            cap.await.expect("join")
        }

        // First listener to learn a free port, then reuse it sequentially.
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = probe.local_addr().expect("addr");
        drop(probe);
        let config = WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/hook"),
            secret: "shhh".into(),
            timeout_seconds: 5,
            max_retries: 1,
            queue_capacity: 8,
        };
        let emitter = WebhookEmitter::spawn_with_policy(config, SsrfPolicy::allow_test_loopback());
        let a = event_id_of(&capture_once(&emitter, addr).await);
        let b = event_id_of(&capture_once(&emitter, addr).await);
        assert_ne!(a, b, "each emit must mint a fresh event_id");
    }

    // ── signature correctness ────────────────────────────────────────

    #[test]
    fn sign_produces_github_shaped_hmac() {
        let sig = sign("topsecret", b"hello world");
        // Shape: "sha256=" + 64 lowercase hex chars.
        let hex = sig.strip_prefix("sha256=").expect("sha256= prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Recompute independently — the digest must match an HMAC-SHA256 over
        // the same (key, body), proving sign() isn't doing anything bespoke.
        let mut mac = HmacSha256::new_from_slice(b"topsecret").unwrap();
        mac.update(b"hello world");
        let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert_eq!(sig, expected);
    }

    #[test]
    fn sign_is_sensitive_to_body_and_secret() {
        let base = sign("k", b"body");
        assert_ne!(
            base,
            sign("k", b"body!"),
            "a changed body must change the sig"
        );
        assert_ne!(
            base,
            sign("k2", b"body"),
            "a changed secret must change the sig"
        );
    }

    #[tokio::test]
    async fn delivered_signature_authenticates_the_raw_body() {
        // The whole point of X-ACDP-Signature: a receiver recomputing
        // sign(secret, raw_body) gets exactly the header value. This is the
        // contract GitHub-compatible consumers rely on.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let capture = tokio::spawn(capture_one_request(listener));

        let config = WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/hook"),
            secret: "shhh".into(),
            timeout_seconds: 5,
            max_retries: 1,
            queue_capacity: 8,
        };
        let emitter = WebhookEmitter::spawn_with_policy(config, SsrfPolicy::allow_test_loopback());
        emitter.emit(published_event());

        let raw = capture.await.expect("join");
        let (head, body) = raw.split_once("\r\n\r\n").expect("header/body split");
        let sig_header = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("x-acdp-signature:"))
            .and_then(|l| l.split_once(':').map(|(_, v)| v))
            .map(str::trim)
            .expect("X-ACDP-Signature header present");
        let recomputed = sign("shhh", body.as_bytes());
        assert_eq!(
            sig_header, recomputed,
            "receiver-side recomputation must match the transmitted signature"
        );
        // A receiver using the wrong secret must NOT validate.
        assert_ne!(sig_header, sign("wrong", body.as_bytes()));
    }

    // ── config validation (SEC-03 / SEC-04) ──────────────────────────

    fn cfg(url: &str, secret: &str, enabled: bool) -> WebhookConfig {
        WebhookConfig {
            enabled,
            url: url.into(),
            secret: secret.into(),
            timeout_seconds: 5,
            max_retries: 1,
            queue_capacity: 8,
        }
    }

    #[tokio::test]
    async fn try_spawn_rejects_empty_secret_when_enabled() {
        // SEC-04: HMAC over an empty key accepts every signature.
        let err = WebhookEmitter::try_spawn(cfg("https://hooks.example.com/acdp", "  ", true))
            .err()
            .expect("empty secret must be rejected");
        assert!(matches!(err, WebhookError::Config(_)), "got {err:?}");
        assert!(err.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn try_spawn_rejects_ssrf_url() {
        // SEC-03: a URL resolving to an internal/IMDS address (or non-HTTPS)
        // is refused before the worker ever starts.
        let err = WebhookEmitter::try_spawn(cfg("http://169.254.169.254/latest", "secret", true))
            .err()
            .expect("SSRF-violating URL must be rejected");
        assert!(matches!(err, WebhookError::Config(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn try_spawn_skips_validation_when_disabled() {
        // A disabled webhook need not carry a secret or a vetted URL.
        assert!(WebhookEmitter::try_spawn(cfg("", "", false)).is_ok());
    }

    #[tokio::test]
    async fn omits_tenant_header_when_absent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let capture = tokio::spawn(capture_one_request(listener));

        let config = WebhookConfig {
            enabled: true,
            url: format!("http://{addr}/hook"),
            secret: "shhh".into(),
            timeout_seconds: 5,
            max_retries: 1,
            queue_capacity: 8,
        };
        let emitter = WebhookEmitter::spawn_with_policy(config, SsrfPolicy::allow_test_loopback());
        emitter.emit(published_event());

        let raw = capture.await.expect("join");
        assert!(
            !raw.to_ascii_lowercase().contains("x-tenant-id"),
            "did not expect X-Tenant-Id header, got:\n{raw}"
        );
    }
}
