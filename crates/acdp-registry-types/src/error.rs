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
        // RFC-ACDP-0013 §10 — the lifecycle wire codes (ACDP 0.3.0).
        // `immutable_field` is the category error for body-content members
        // on a lifecycle request (activated from the v0.1.0 reservation);
        // `invalid_lifecycle_transition` is the state conflict (double
        // retract / spurious republish).
        AcdpError::ImmutableField(_) => "immutable_field",
        AcdpError::InvalidLifecycleTransition(_) => "invalid_lifecycle_transition",
        // RFC-ACDP-0012 §11 — a transparency-log proof / checkpoint failed
        // the §9 verification procedures. On the wire this is emitted by a
        // federated resolver (or any registry validating an UPSTREAM's
        // proofs on a caller's behalf) — hence 502, the upstream is at
        // fault. The registry's own /log/* handlers never emit it: their
        // failure modes are schema_violation (malformed queries),
        // not_found (unlogged / invisible ctx_id), and not_implemented
        // (profile not advertised). There is no log_unavailable (§7.1).
        AcdpError::InvalidLogProof(_) => "invalid_log_proof",
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
        | AcdpError::CursorExpired
        // RFC-ACDP-0013 §6 step 2 / §10: `immutable_field` is HTTP 400.
        | AcdpError::ImmutableField(_) => 400,
        AcdpError::PayloadTooLarge(_) | AcdpError::EmbeddedTooLarge(_) => 413,
        AcdpError::KeyNotAuthorized(_) | AcdpError::NotAuthorized(_) => 403,
        AcdpError::NotFound(_) => 404,
        // RFC-ACDP-0013 §6 step 4 / §10: a lifecycle-transition conflict is
        // HTTP 409 — a state conflict, like the 409 arm of superseded_target.
        AcdpError::DuplicatePublish(_) | AcdpError::InvalidLifecycleTransition(_) => 409,
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
        // RFC-ACDP-0012 §11: `invalid_log_proof` is HTTP 502 — the upstream
        // whose proof failed verification is at fault, not this registry.
        AcdpError::InvalidLogProof(_) => 502,
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

    /// RFC-ACDP-0013 §10 — the two lifecycle wire codes map to their
    /// registered code/status pairs: `immutable_field` is 400 (category
    /// error, fixture lc-002), `invalid_lifecycle_transition` is 409
    /// (state conflict, like the 409 arm of `superseded_target`).
    #[test]
    fn lifecycle_wire_codes_match_rfc0013_s10() {
        let imm = acdp(AcdpError::ImmutableField("body member on /retract".into()));
        assert_eq!(imm.wire_code(), "immutable_field");
        assert_eq!(imm.http_status(), 400);

        let conflict = acdp(AcdpError::InvalidLifecycleTransition(
            "already retracted".into(),
        ));
        assert_eq!(conflict.wire_code(), "invalid_lifecycle_transition");
        assert_eq!(conflict.http_status(), 409);
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

    /// RFC-ACDP-0007 §5: size-cap rejections are 413 (not 400) so a client
    /// can distinguish "too big" from "malformed".
    #[test]
    fn payload_and_embedded_too_large_are_413() {
        let payload = acdp(AcdpError::PayloadTooLarge("2 MiB".into()));
        assert_eq!(payload.wire_code(), "payload_too_large");
        assert_eq!(payload.http_status(), 413);

        let embedded = acdp(AcdpError::EmbeddedTooLarge("128 KiB".into()));
        assert_eq!(embedded.wire_code(), "embedded_too_large");
        assert_eq!(embedded.http_status(), 413);
    }

    /// RFC-ACDP-0012 §11 — `invalid_log_proof` is a registered 0.3.0 wire
    /// code, HTTP 502 (the upstream whose proof failed is at fault). The
    /// registry's own /log/* handlers never emit it; the mapping exists
    /// for federation paths that verify an upstream's proofs.
    #[test]
    fn invalid_log_proof_is_502_with_registered_code() {
        let e = acdp(AcdpError::InvalidLogProof("path does not fold".into()));
        assert_eq!(e.wire_code(), "invalid_log_proof");
        assert_eq!(e.http_status(), 502);
    }

    /// A failed gateway hop (federation / unreachable key resolution) is 502 —
    /// the registry itself is healthy, the upstream hop failed. Keeping these
    /// distinct from 400/404 lets clients key retry behavior off the status.
    #[test]
    fn gateway_hop_failures_are_502() {
        let xreg = acdp(AcdpError::CrossRegistryResolutionFailed("peer down".into()));
        assert_eq!(xreg.wire_code(), "cross_registry_resolution_failed");
        assert_eq!(xreg.http_status(), 502);

        let key = acdp(AcdpError::KeyResolutionUnreachable(
            "did:web timeout".into(),
        ));
        assert_eq!(key.wire_code(), "key_resolution_unreachable");
        assert_eq!(key.http_status(), 502);
    }

    /// Cursor faults are permanent client errors (400), and the two reasons
    /// stay distinct so a client can tell "you sent garbage" from "your page
    /// token aged out, restart pagination".
    #[test]
    fn cursor_faults_are_400_and_distinct() {
        let invalid = acdp(AcdpError::InvalidCursor("not base64".into()));
        assert_eq!(invalid.wire_code(), "invalid_cursor");
        assert_eq!(invalid.http_status(), 400);

        let expired = acdp(AcdpError::CursorExpired);
        assert_eq!(expired.wire_code(), "cursor_expired");
        assert_eq!(expired.http_status(), 400);
    }

    /// The common retrieval/publish outcomes land on their RFC-ACDP-0007 §5
    /// status codes. Guards against a refactor silently collapsing them.
    #[test]
    fn common_outcomes_map_to_expected_status() {
        assert_eq!(acdp(AcdpError::NotFound("ctx".into())).http_status(), 404);
        assert_eq!(
            acdp(AcdpError::NotFound("ctx".into())).wire_code(),
            "not_found"
        );
        assert_eq!(
            acdp(AcdpError::DuplicatePublish("k".into())).http_status(),
            409
        );
        assert_eq!(
            acdp(AcdpError::KeyNotAuthorized("vm".into())).http_status(),
            403
        );
        assert_eq!(
            acdp(AcdpError::KeyNotAuthorized("vm".into())).wire_code(),
            "key_not_authorized"
        );
        assert_eq!(
            acdp(AcdpError::NotAuthorized("x".into())).http_status(),
            403
        );
        assert_eq!(acdp(AcdpError::RateLimited("x".into())).http_status(), 429);
    }

    /// The registry-layer rate-limit variant projects to 429 + `rate_limited`,
    /// independent of the protocol-layer `AcdpError::RateLimited`.
    #[test]
    fn registry_rate_limited_is_429() {
        let e = RegistryError::RateLimited {
            retry_after_seconds: 30,
        };
        assert_eq!(e.http_status(), 429);
        assert_eq!(e.wire_code(), "rate_limited");
    }

    /// RFC-ACDP-0007 §5: `details` is absent (the key is omitted, not `null`)
    /// when there is nothing structured to add — so a generic client doesn't
    /// have to distinguish `null` from missing.
    #[test]
    fn wire_envelope_omits_details_when_absent() {
        let e = acdp(AcdpError::NotFound("ctx".into()));
        let json = serde_json::to_value(WireError::from(&e)).unwrap();
        assert!(
            json["error"].get("details").is_none(),
            "details should be omitted, got: {json}"
        );
        assert_eq!(json["error"]["code"], "not_found");
        assert!(json["error"]["message"].is_string());
    }

    /// RFC-ACDP-0007 §4 + RFC-ACDP-0008 §4.3: an error response carries the
    /// `application/acdp+json` media type, and a 429 additionally carries a
    /// `Retry-After` header echoing the bounded window.
    #[cfg(feature = "axum")]
    #[test]
    fn rate_limited_response_sets_retry_after_and_acdp_media_type() {
        use axum::response::IntoResponse;
        let resp = RegistryError::RateLimited {
            retry_after_seconds: 42,
        }
        .into_response();
        assert_eq!(resp.status().as_u16(), 429);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/acdp+json"
        );
        assert_eq!(resp.headers().get("retry-after").unwrap(), "42");
    }

    /// A non-429 error still carries the ACDP media type but MUST NOT carry a
    /// stray `Retry-After`.
    #[cfg(feature = "axum")]
    #[test]
    fn non_rate_limited_response_has_no_retry_after() {
        use axum::response::IntoResponse;
        let resp = acdp(AcdpError::NotFound("ctx".into())).into_response();
        assert_eq!(resp.status().as_u16(), 404);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/acdp+json"
        );
        assert!(resp.headers().get("retry-after").is_none());
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
