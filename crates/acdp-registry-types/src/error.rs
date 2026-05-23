//! Registry-layer errors plus their HTTP projection.
//!
//! Wraps [`acdp::error::AcdpError`] so HTTP-binding code can also surface
//! storage failures, config problems, and auth-layer faults uniformly.

use acdp::error::AcdpError;
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
            Self::WebhookDelivery(_) | Self::Internal(_) => "internal_error",
        }
    }

    /// HTTP status code for the wire envelope.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Acdp(e) => http_status_for_acdp(e),
            Self::AuthChallenge(_) | Self::AuthToken(_) | Self::Jwt(_) => 401,
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
}

impl From<&RegistryError> for WireError {
    fn from(err: &RegistryError) -> Self {
        Self {
            error: WireErrorBody {
                code: err.wire_code().into(),
                message: err.to_string(),
            },
        }
    }
}

fn acdp_wire_code(err: &AcdpError) -> &'static str {
    match err {
        AcdpError::SchemaViolation(_) | AcdpError::InvalidBody(_) | AcdpError::MissingField(_) => {
            "schema_violation"
        }
        AcdpError::PayloadTooLarge(_) => "payload_too_large",
        AcdpError::EmbeddedTooLarge(_) => "embedded_too_large",
        AcdpError::Canonicalization(_) => "canonicalization_failed",
        AcdpError::HashMismatch { .. } => "hash_mismatch",
        AcdpError::RemoteHashMismatch(_) | AcdpError::DataRefHashMismatch(_) => "hash_mismatch",
        AcdpError::UnsupportedAlgorithm(_) => "algorithm_not_supported",
        AcdpError::KeyNotAuthorized(_) => "key_not_authorized",
        AcdpError::KeyResolution(_) | AcdpError::KeyResolutionUnreachable(_) => "key_resolution",
        AcdpError::InvalidSignature(_) => "signature_invalid",
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
        AcdpError::DuplicatePublish(_) | AcdpError::SupersededTarget { .. } => 409,
        AcdpError::RateLimited(_) => 429,
        AcdpError::KeyResolutionUnreachable(_) => 502,
        _ => 500,
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for RegistryError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status =
            StatusCode::from_u16(self.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = WireError::from(&self);
        (status, axum::Json(body)).into_response()
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Acdp(AcdpError::SchemaViolation(e.to_string()))
    }
}
