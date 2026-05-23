//! HMAC-signed webhook emitter.
//!
//! `WebhookEmitter::spawn` starts a background worker that drains an mpsc
//! channel and POSTs each event to the configured URL. Failed deliveries
//! are retried with exponential backoff up to `max_retries`. Signing
//! follows GitHub's convention: `X-ACDP-Signature: sha256=<hex>` over the
//! raw JSON body.

use std::time::Duration;

use acdp_registry_types::{WebhookConfig, WebhookEvent};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::mpsc;

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

/// Handle held by the HTTP layer. `emit` is non-blocking; the worker
/// drains events asynchronously.
#[derive(Clone)]
pub struct WebhookEmitter {
    tx: mpsc::Sender<WebhookEvent>,
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
    /// validated the config.
    pub fn spawn(config: WebhookConfig) -> Self {
        let capacity = config.queue_capacity.max(1);
        let (tx, rx) = mpsc::channel::<WebhookEvent>(capacity);
        tokio::spawn(worker(config, rx));
        Self { tx }
    }

    /// Fire and forget. The channel is bounded; if the worker can't keep
    /// up, the event is dropped with a warn log rather than blocking the
    /// HTTP handler.
    pub fn emit(&self, event: WebhookEvent) {
        match self.tx.try_send(event) {
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

async fn worker(config: WebhookConfig, mut rx: mpsc::Receiver<WebhookEvent>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "webhook: cannot build HTTP client; disabling");
            return;
        }
    };
    while let Some(event) = rx.recv().await {
        if !config.enabled || config.url.is_empty() {
            continue;
        }
        if let Err(e) = deliver(&client, &config, &event).await {
            tracing::warn!(error = %e, event = event.name(), "webhook delivery failed");
        }
    }
}

async fn deliver(
    client: &reqwest::Client,
    config: &WebhookConfig,
    event: &WebhookEvent,
) -> Result<(), WebhookError> {
    let body = serde_json::to_vec(event).map_err(|e| WebhookError::Encode(e.to_string()))?;
    let sig = sign(&config.secret, &body);

    let mut backoff = Duration::from_millis(250);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let resp = client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .header("X-ACDP-Signature", &sig)
            .header("X-ACDP-Event", event.name())
            .body(body.clone())
            .send()
            .await;
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
