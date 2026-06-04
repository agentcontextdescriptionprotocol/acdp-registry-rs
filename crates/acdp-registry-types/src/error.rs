//! Registry-layer errors plus their HTTP projection.
//!
//! Wraps [`acdp::error::AcdpError`] so HTTP-binding code can also surface
//! storage failures, config problems, and auth-layer faults uniformly.

use acdp::error::{AcdpError, SupersessionReason};
use serde::Serialize;
use thiserror::Error;

/// Top-level error returned by registry handlers, storage backends, and
/// the auth service. Maps to an RFC-ACDP-0007 §5 wire envelope when
/// surfaced through axum.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Wrapped protocol-layer error (carries its own RFC-ACDP-0007 code).
    #[error(transparent)]
    Acdp(#[from] AcdpError),

    /// Storage backend failure (db connectivity, migration, etc.).
    #[error("storage error: {0}")]
    Storage(String),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Auth challenge unknown, expired, or mismatched.
    #[error("auth challenge: {0}")]
    AuthChallenge(String),

    /// Bearer token invalid, expired, revoked.
    #[error("auth token: {0}")]
    AuthToken(String),

    /// JWT signing / parsing failure.
    #[error("jwt error: {0}")]
    Jwt(String),

    /// Per-agent publish rate limit exceeded (RFC-ACDP-0008 §4.3). Carries
    /// the bounded retry window surfaced as a `Retry-After` header.
    #[error("rate limited; retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },

    /// Webhook delivery failure (for the worker; not surfaced to API callers).
    #[error("webhook delivery error: {0}")]
    WebhookDelivery(String),

    /// Anything else.
    #[error("internal error: {0}")]
    Internal(String),
}

impl RegistryError {
    /// Wire error code per RFC-ACDP-0007 §5.
    pub fn wire_code(&self) -> &'static str {
        match self {
            Self::Acdp(e) => acdp_wire_code(e),
            Self::Storage(_) => "internal_error",
            Self::Config(_) => "internal_error",
            Self::AuthChallenge(_) | Self::AuthToken(_) | Self::Jwt(_) => "not_authorized",
            Self::RateLimited { .. } => "rate_limited",
            Self::WebhookDelivery(_) | Self::Internal(_) => "internal_error",
        }
    }

    /// HTTP status code for the wire envelope.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Acdp(e) => http_status_for_acdp(e),
            // RFC-ACDP-0007 §5: `not_authorized` is HTTP 403. The v0.1.0 code
            // registry has no 401-bearing code, and `http_status_for_acdp`
            // already pairs `not_authorized` with 403 — keep the auth-layer
            // rejections consistent with that pairing.
            Self::AuthChallenge(_) | Self::AuthToken(_) | Self::Jwt(_) => 403,
            Self::RateLimited { .. } => 429,
            Self::Storage(_) | Self::WebhookDelivery(_) | Self::Internal(_) | Self::Config(_) => {
                500
            }
        }
    }
}

/// RFC-ACDP-0007 §5 error envelope.
#[derive(Debug, Serialize)]
pub struct WireError {
    pub error: WireErrorBody,
}

#[derive(Debug, Serialize)]
pub struct WireErrorBody {
    pub code: String,
    pub message: String,
    /// Optional structured detail (RFC-ACDP-0007 §5). Currently carries
    /// `{ "reason": "<snake_case>" }` for `superseded_target`. Absent (not
    /// `null`) when there is nothing to add.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl From<&RegistryError> for WireError {
    fn from(err: &RegistryError) -> Self {
        let (message, details) = err.wire_message_and_details();
        Self {
            error: WireErrorBody {
                code: err.wire_code().into(),
                message,
                details,
            },
        }
    }
}

impl RegistryError {
    /// The client-facing message and optional structured details for the
    /// wire envelope.
    ///
    /// Two rules from RFC-ACDP-0007 §5 are enforced here:
    /// - `internal_error` responses MUST NOT leak stack traces or sensitive
    ///   context, so any error projecting to `internal_error` (storage/driver
    ///   failures, config, webhook, catch-all) gets a static message and the
    ///   real detail is logged server-side only.
    /// - `superseded_target` carries `details.reason` so a client can
    ///   distinguish the four failure conditions without parsing `message`.
    fn wire_message_and_details(&self) -> (String, Option<serde_json::Value>) {
        if self.wire_code() == "internal_error" {
            return ("internal error".to_string(), None);
        }
        if let Self::Acdp(AcdpError::SupersededTarget { reason, message }) = self {
            let details = serde_json::to_value(reason)
                .ok()
                .map(|r| serde_json::json!({ "reason": r }));
            return (message.clone(), details);
        }
        (self.to_string(), None)
    }
}

fn acdp_wire_code(err: &AcdpError) -> &'static str {
    match err {
        AcdpError::SchemaViolation(_) | AcdpError::InvalidBody(_) | AcdpError::MissingField(_) => {
            "schema_violation"
        }
        AcdpError::PayloadTooLarge(_) => "payload_too_large",
        AcdpError::EmbeddedTooLarge(_) => "embedded_too_large",
        // `canonicalization_failed` is NOT in the RFC-ACDP-0007 §5 registry.
        // A failure to canonicalize the body means its `content_hash` cannot
        // be reproduced — surface it as the registered body-hash failure.
        AcdpError::Canonicalization(_) => "hash_mismatch",
        AcdpError::HashMismatch { .. } | AcdpError::RemoteHashMismatch(_) => "hash_mismatch",
        // RFC-ACDP-0007 §5: a DataRef divergence MUST stay distinct from a
        // body-level hash failure (the body + signature remain valid).
        AcdpError::DataRefHashMismatch(_) => "data_ref_hash_mismatch",
        AcdpError::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        // Permanent (400) vs transient (502) must stay distinct so clients
        // key retry behavior off the code (RFC-ACDP-0007 §5).
        AcdpError::KeyResolution(_) => "key_resolution_failed",
        AcdpError::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        AcdpError::InvalidSignature(_) => "invalid_signature",
        AcdpError::NotImplemented(_) => "not_implemented",
        AcdpError::DuplicatePublish(_) => "duplicate_publish",
        AcdpError::SupersededTarget { .. } => "superseded_target",
        AcdpError::NotFound(_) => "not_found",
        AcdpError::NotAuthorized(_) => "not_authorized",
        AcdpError::InvalidCursor(_) => "invalid_cursor",
        AcdpError::CursorExpired => "cursor_expired",
        AcdpError::RateLimited(_) => "rate_limited",
        AcdpError::CrossRegistryResolutionFailed(_) => "cross_registry_resolution_failed",
        _ => "internal_error",
    }
}

fn http_status_for_acdp(err: &AcdpError) -> u16 {
    match err {
        AcdpError::SchemaViolation(_)
        | AcdpError::InvalidBody(_)
        | AcdpError::MissingField(_)
        | AcdpError::Canonicalization(_)
        | AcdpError::HashMismatch { .. }
        | AcdpError::RemoteHashMismatch(_)
        | AcdpError::DataRefHashMismatch(_)
        | AcdpError::UnsupportedAlgorithm(_)
        | AcdpError::KeyResolution(_)
        | AcdpError::InvalidSignature(_)
        | AcdpError::InvalidCursor(_)
        | AcdpError::CursorExpired => 400,
        AcdpError::PayloadTooLarge(_) | AcdpError::EmbeddedTooLarge(_) => 413,
        AcdpError::KeyNotAuthorized(_) | AcdpError::NotAuthorized(_) => 403,
        AcdpError::NotFound(_) => 404,
        AcdpError::DuplicatePublish(_) => 409,
        // RFC-ACDP-0007 §5 / RFC-ACDP-0003 §3.1: `superseded_target` is
        // 400 for static violations and 409 only for true race conditions.
        AcdpError::SupersededTarget { reason, .. } => match reason {
            SupersessionReason::VersionMismatch | SupersessionReason::AlreadySuperseded => 409,
            // NotFound, LineageMismatch, CrossRegistrySupersessionUnsupported,
            // LineageWalkFailed, Other → static client error.
            _ => 400,
        },
        AcdpError::RateLimited(_) => 429,
        // 502 is the right status for both "upstream is unreachable" and
        // "upstream returned garbage" — the registry itself is healthy,
        // the gateway hop failed. Matches `KeyResolutionUnreachable`.
        AcdpError::KeyResolutionUnreachable(_) | AcdpError::CrossRegistryResolutionFailed(_) => 502,
        AcdpError::NotImplemented(_) => 501,
        _ => 500,
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for RegistryError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::{
            header::{CONTENT_TYPE, RETRY_AFTER},
            HeaderValue, StatusCode,
        };
        let status =
            StatusCode::from_u16(self.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = WireError::from(&self);
        let mut resp = (status, axum::Json(body)).into_response();
        // RFC-ACDP-0007 §4: every ACDP failure response MUST carry the
        // `application/acdp+json` media type. Set it here so an error returned
        // from any route (not just the ACDP route group) is conformant.
        resp.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/acdp+json"),
        );
        // RFC-ACDP-0008 §4.3 SHOULD: bound 429s with a Retry-After header.
        if let Self::RateLimited {
            retry_after_seconds,
        } = &self
        {
            if let Ok(v) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                resp.headers_mut().insert(RETRY_AFTER, v);
            }
        }
        resp
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Acdp(AcdpError::SchemaViolation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acdp(e: AcdpError) -> RegistryError {
        RegistryError::Acdp(e)
    }

    /// #10/#11 — wire codes MUST be exactly the RFC-ACDP-0007 §5 registry
    /// strings. These previously diverged (`signature_invalid`,
    /// `algorithm_not_supported`, `key_resolution`, `canonicalization_failed`).
    #[test]
    fn wire_codes_match_rfc0007_s5() {
        assert_eq!(
            acdp(AcdpError::InvalidSignature("x".into())).wire_code(),
            "invalid_signature"
        );
        assert_eq!(
            acdp(AcdpError::UnsupportedAlgorithm("x".into())).wire_code(),
            "unsupported_algorithm"
        );
        assert_eq!(
            acdp(AcdpError::KeyResolution("x".into())).wire_code(),
            "key_resolution_failed"
        );
        assert_eq!(
            acdp(AcdpError::KeyResolutionUnreachable("x".into())).wire_code(),
            "key_resolution_unreachable"
        );
        assert_eq!(
            acdp(AcdpError::DataRefHashMismatch("x".into())).wire_code(),
            "data_ref_hash_mismatch"
        );
        // canonicalization failure has no registered code → body-hash failure.
        assert_eq!(
            acdp(AcdpError::Canonicalization("x".into())).wire_code(),
            "hash_mismatch"
        );
    }

    /// #11 — `data_ref_hash_mismatch` and `hash_mismatch` are distinct (both
    /// 400) so a consumer can tell a body failure from a data-layer failure.
    #[test]
    fn data_ref_hash_mismatch_is_distinct_and_400() {
        let e = acdp(AcdpError::DataRefHashMismatch("x".into()));
        assert_eq!(e.wire_code(), "data_ref_hash_mismatch");
        assert_eq!(e.http_status(), 400);
    }

    /// #12 — status branches on the supersession reason: static → 400,
    /// race → 409.
    #[test]
    fn superseded_target_status_branches_on_reason() {
        let mk = |r| {
            acdp(AcdpError::SupersededTarget {
                reason: r,
                message: "m".into(),
            })
        };
        assert_eq!(mk(SupersessionReason::NotFound).http_status(), 400);
        assert_eq!(mk(SupersessionReason::LineageMismatch).http_status(), 400);
        assert_eq!(mk(SupersessionReason::LineageWalkFailed).http_status(), 400);
        assert_eq!(
            mk(SupersessionReason::CrossRegistrySupersessionUnsupported).http_status(),
            400
        );
        assert_eq!(mk(SupersessionReason::VersionMismatch).http_status(), 409);
        assert_eq!(mk(SupersessionReason::AlreadySuperseded).http_status(), 409);
    }

    /// #12 — `details.reason` reaches the wire so clients don't parse `message`.
    #[test]
    fn superseded_target_wire_carries_reason_detail() {
        let e = acdp(AcdpError::SupersededTarget {
            reason: SupersessionReason::LineageMismatch,
            message: "declared lineage ≠ predecessor".into(),
        });
        let w = WireError::from(&e);
        assert_eq!(w.error.code, "superseded_target");
        assert_eq!(
            w.error.details.as_ref().unwrap()["reason"],
            serde_json::json!("lineage_mismatch")
        );
    }

    /// #19 — auth-layer rejections are 403 (RFC-ACDP-0007 §5 `not_authorized`),
    /// not 401, matching the code↔status pairing used elsewhere.
    #[test]
    fn auth_errors_are_403() {
        assert_eq!(RegistryError::AuthChallenge("x".into()).http_status(), 403);
        assert_eq!(RegistryError::AuthToken("x".into()).http_status(), 403);
        assert_eq!(RegistryError::Jwt("x".into()).http_status(), 403);
        assert_eq!(
            RegistryError::AuthChallenge("x".into()).wire_code(),
            "not_authorized"
        );
    }

    /// #18 — `internal_error` envelopes MUST NOT leak driver/SQL detail.
    #[test]
    fn internal_errors_do_not_leak_detail() {
        let cases = [
            RegistryError::Storage(
                "relation \"contexts\" does not exist (SQLSTATE 42P01) at line 42".into(),
            ),
            RegistryError::Config("missing [auth] section in /etc/secret.toml".into()),
            RegistryError::Internal("panic at src/store.rs:921".into()),
            RegistryError::Acdp(AcdpError::RegistryInternal(
                "connection pool exhausted".into(),
            )),
        ];
        for e in cases {
            let w = WireError::from(&e);
            assert_eq!(w.error.code, "internal_error", "{e:?}");
            assert_eq!(w.error.message, "internal error", "leaked: {:?}", w.error);
            assert!(w.error.details.is_none());
        }
    }
}
