//! Playground-mode pinned-key enforcement.
//!
//! In playground mode the publish handler short-circuits the full
//! DID-web resolution pipeline (so demos don't need DID documents
//! served over HTTPS). That makes any agent_id+signature pair pass —
//! anyone can claim any DID. `PlaygroundConfig.pinned_keys` (see
//! `acdp-registry-types::config`) opts the operator back into
//! integrity: publishes from listed agents must verify against the
//! pinned public key.
//!
//! This module is the bridge between the pure-data
//! [`PlaygroundConfig`] in the types crate and the Ed25519 verifier
//! in `acdp::crypto::verify`. Splitting it out keeps the publish
//! handler thin and makes the policy testable in isolation.
//!
//! Strict vs lax modes are documented on [`PlaygroundConfig`]. The
//! decision tree this module implements:
//!
//! ```text
//!   pinned_keys empty?      ──► Ok(Skipped)             (no policy)
//!   agent in pinned list?   ──► verify_ed25519(...)     (Verified | Err)
//!   not in list, lax?       ──► Ok(Unpinned)            (allowed)
//!   not in list, strict?    ──► Err(NotAuthorized)      (rejected)
//! ```

use acdp::error::AcdpError;
use acdp::types::publish::PublishRequest;
use acdp_registry_types::{config::PlaygroundConfig, RegistryError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Outcome of [`enforce_pinned_signature`].
///
/// `Verified` and `Unpinned` are both "publish may proceed"; they're
/// kept distinct so the handler can log the path taken (useful when
/// triaging "why did this publish go through?" tickets).
#[derive(Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// `pinned_keys` was empty — no policy active.
    Skipped,
    /// Agent was pinned and the signature verified against the pinned key.
    Verified,
    /// Agent was not pinned and `pinned_only = false`.
    Unpinned,
}

/// Verify a publish request against the pinned-key list.
///
/// Returns `Ok(_)` when the publish should proceed; `Err(_)` when it
/// must be rejected. The returned [`PinOutcome`] tells the caller
/// which branch fired (mainly for logging).
///
/// Algorithm support is currently Ed25519 only; pinned entries that
/// declare any other algorithm are surfaced as an internal config
/// error so the operator sees the misconfiguration on first publish.
pub fn enforce_pinned_signature(
    req: &PublishRequest,
    config: &PlaygroundConfig,
) -> Result<PinOutcome, RegistryError> {
    if config.pinned_keys.is_empty() {
        return Ok(PinOutcome::Skipped);
    }

    let agent_did = req.agent_id.as_str();
    let Some(pinned) = config.pinned_for(agent_did) else {
        if config.pinned_only {
            return Err(RegistryError::Acdp(AcdpError::KeyNotAuthorized(format!(
                "agent_did '{agent_did}' is not in playground.pinned_keys \
                 and playground.pinned_only is true"
            ))));
        }
        return Ok(PinOutcome::Unpinned);
    };

    if pinned.algorithm != "ed25519" {
        return Err(RegistryError::Config(format!(
            "pinned algorithm '{}' for {agent_did} is not supported (only ed25519)",
            pinned.algorithm
        )));
    }

    let pub_bytes_vec = STANDARD.decode(&pinned.public_key_b64).map_err(|e| {
        RegistryError::Config(format!(
            "pinned public_key_b64 for {agent_did} is not valid base64: {e}"
        ))
    })?;
    let pub_bytes: [u8; 32] = pub_bytes_vec.as_slice().try_into().map_err(|_| {
        RegistryError::Config(format!(
            "pinned public_key_b64 for {agent_did} decoded to {} bytes (expected 32)",
            pub_bytes_vec.len()
        ))
    })?;

    acdp::crypto::verify::verify_ed25519(
        &pub_bytes,
        &req.signature.value,
        req.content_hash.as_str(),
    )
    .map_err(RegistryError::Acdp)?;

    Ok(PinOutcome::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::primitives::{AgentDid, ContextType, Visibility};
    use acdp_registry_types::config::PinnedAgentKey;

    /// Build a real, signed PublishRequest from a freshly generated
    /// SigningKey. Mirrors what the Python SDK builds — same canonical
    /// hash + Ed25519 signature path, so the verifier exercises the
    /// real wire format.
    fn build_signed_request(key: SigningKey, did: &str) -> (PublishRequest, String) {
        let agent_did = AgentDid::new(did);
        let key_id = format!("{did}#key-1");
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(key.verifying_key_bytes());
        let producer = Producer::new(key, agent_did, &key_id);
        let req = producer
            .publish_request()
            .title("test")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .summary("body")
            .build()
            .expect("build request");
        (req, pub_b64)
    }

    fn cfg(pinned: Vec<PinnedAgentKey>, strict: bool) -> PlaygroundConfig {
        PlaygroundConfig {
            enabled: true,
            pinned_keys: pinned,
            pinned_only: strict,
        }
    }

    #[test]
    fn empty_pinned_list_is_skipped() {
        let key = SigningKey::generate();
        let (req, _) = build_signed_request(key, "did:web:x:agents:alice");
        let outcome = enforce_pinned_signature(&req, &cfg(vec![], false)).unwrap();
        assert_eq!(outcome, PinOutcome::Skipped);
    }

    #[test]
    fn pinned_agent_with_matching_key_verifies() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_signed_request(key, did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let outcome = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap();
        assert_eq!(outcome, PinOutcome::Verified);
    }

    #[test]
    fn pinned_agent_with_wrong_key_is_rejected() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _real_pub) = build_signed_request(key, did);

        // Different key → mismatch → InvalidSignature
        let wrong = SigningKey::generate();
        let wrong_pub =
            base64::engine::general_purpose::STANDARD.encode(wrong.verifying_key_bytes());
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: wrong_pub,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InvalidSignature") || msg.contains("signature"),
            "expected signature failure, got {msg}"
        );
    }

    #[test]
    fn unpinned_agent_in_lax_mode_passes() {
        let key = SigningKey::generate();
        let (req, _) = build_signed_request(key, "did:web:x:agents:bob");
        let pinned_for_other = PinnedAgentKey {
            agent_did: "did:web:x:agents:alice".into(),
            public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let outcome = enforce_pinned_signature(&req, &cfg(vec![pinned_for_other], false)).unwrap();
        assert_eq!(outcome, PinOutcome::Unpinned);
    }

    #[test]
    fn unpinned_agent_in_strict_mode_is_rejected() {
        let key = SigningKey::generate();
        let (req, _) = build_signed_request(key, "did:web:x:agents:bob");
        let pinned_for_other = PinnedAgentKey {
            agent_did: "did:web:x:agents:alice".into(),
            public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned_for_other], true)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("not in playground.pinned_keys"), "got {msg}");
    }

    #[test]
    fn unsupported_algorithm_surfaces_config_error() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_signed_request(key, did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ecdsa-p256".into(),
            valid_from: None,
            valid_until: None,
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("ecdsa-p256"), "got {msg}");
    }

    #[test]
    fn invalid_base64_in_config_surfaces_config_error() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _) = build_signed_request(key, did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: "not-base64!!!".into(),
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("base64"), "got {msg}");
    }

    #[test]
    fn wrong_length_pinned_key_surfaces_config_error() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _) = build_signed_request(key, did);
        // 16 bytes encoded — wrong length
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: too_short,
            algorithm: "ed25519".into(),
            valid_from: None,
            valid_until: None,
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("32"), "got {msg}");
    }
}
