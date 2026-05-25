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
//! [`PlaygroundConfig`] in the types crate and the signature
//! verifiers in `acdp::crypto::verify`. Splitting it out keeps the
//! publish handler thin and makes the policy testable in isolation.
//!
//! Strict vs lax modes are documented on [`PlaygroundConfig`]. The
//! decision tree this module implements:
//!
//! ```text
//!   pinned_keys empty?         ──► Ok(Skipped)             (no policy)
//!   agent in pinned list?
//!     ├── alg mismatch?        ──► Err(downgrade defense)
//!     ├── ed25519              ──► verify_ed25519(...)
//!     └── ecdsa-p256           ──► verify_ecdsa_p256(...)
//!   not in list, lax?          ──► Ok(Unpinned)            (allowed)
//!   not in list, strict?       ──► Err(NotAuthorized)      (rejected)
//! ```
//!
//! ## Algorithm-downgrade defense
//!
//! The request's `signature.algorithm` MUST match the pinned entry's
//! `algorithm`. Without this check, an attacker who steals an Ed25519
//! key could claim `algorithm = "ecdsa-p256"` against an ECDSA-pinned
//! agent (or vice versa) and force-verify under the wrong code path.

use acdp::error::AcdpError;
use acdp::types::publish::PublishRequest;
use acdp_registry_types::{
    config::{PinnedAgentKey, PlaygroundConfig},
    RegistryError,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Supported algorithms for pinned-key entries.
///
/// Kept narrow on purpose: even though the ACDP signature-algorithms
/// registry lists more, only the ones a real agent in the wild
/// publishes today are accepted here. Add new variants by extending
/// this enum + the dispatch in [`enforce_pinned_signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedAlgorithm {
    Ed25519,
    EcdsaP256,
}

impl PinnedAlgorithm {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }
}

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
/// Algorithm dispatch covers `ed25519` (32-byte raw key) and
/// `ecdsa-p256` (65-byte SEC1-uncompressed key). The request's
/// declared `signature.algorithm` must match the pinned entry's
/// `algorithm` — see the downgrade-defense paragraph in this
/// module's docs.
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

    let alg = PinnedAlgorithm::parse(&pinned.algorithm).ok_or_else(|| {
        RegistryError::Config(format!(
            "pinned algorithm '{}' for {agent_did} is not supported (expected one of: ed25519, ecdsa-p256)",
            pinned.algorithm
        ))
    })?;

    // Downgrade defense: the request's signature algorithm MUST match
    // the pinned algorithm. Without this, a stolen key for one curve
    // could be claimed against the other curve's verifier.
    if req.signature.algorithm != alg.wire_name() {
        return Err(RegistryError::Acdp(AcdpError::KeyNotAuthorized(format!(
            "signature.algorithm '{}' does not match pinned algorithm '{}' for {agent_did}",
            req.signature.algorithm,
            alg.wire_name(),
        ))));
    }

    match alg {
        PinnedAlgorithm::Ed25519 => verify_ed25519_pinned(agent_did, pinned, req)?,
        PinnedAlgorithm::EcdsaP256 => verify_ecdsa_p256_pinned(agent_did, pinned, req)?,
    }

    Ok(PinOutcome::Verified)
}

fn verify_ed25519_pinned(
    agent_did: &str,
    pinned: &PinnedAgentKey,
    req: &PublishRequest,
) -> Result<(), RegistryError> {
    let pub_bytes_vec = STANDARD.decode(&pinned.public_key_b64).map_err(|e| {
        RegistryError::Config(format!(
            "pinned public_key_b64 for {agent_did} is not valid base64: {e}"
        ))
    })?;
    let pub_bytes: [u8; 32] = pub_bytes_vec.as_slice().try_into().map_err(|_| {
        RegistryError::Config(format!(
            "pinned ed25519 public_key_b64 for {agent_did} decoded to {} bytes (expected 32)",
            pub_bytes_vec.len()
        ))
    })?;

    acdp::crypto::verify::verify_ed25519(
        &pub_bytes,
        &req.signature.value,
        req.content_hash.as_str(),
    )
    .map_err(RegistryError::Acdp)
}

fn verify_ecdsa_p256_pinned(
    agent_did: &str,
    pinned: &PinnedAgentKey,
    req: &PublishRequest,
) -> Result<(), RegistryError> {
    let pub_bytes = STANDARD.decode(&pinned.public_key_b64).map_err(|e| {
        RegistryError::Config(format!(
            "pinned public_key_b64 for {agent_did} is not valid base64: {e}"
        ))
    })?;
    // SEC1 uncompressed P-256: 0x04 || X(32) || Y(32) = 65 bytes.
    if pub_bytes.len() != 65 {
        return Err(RegistryError::Config(format!(
            "pinned ecdsa-p256 public_key_b64 for {agent_did} decoded to {} bytes (expected 65 SEC1-uncompressed)",
            pub_bytes.len()
        )));
    }
    if pub_bytes[0] != 0x04 {
        return Err(RegistryError::Config(format!(
            "pinned ecdsa-p256 public_key_b64 for {agent_did} must start with 0x04 (SEC1 uncompressed); got 0x{:02x}",
            pub_bytes[0]
        )));
    }

    acdp::crypto::verify::verify_ecdsa_p256(
        &pub_bytes,
        &req.signature.value,
        req.content_hash.as_str(),
    )
    .map_err(RegistryError::Acdp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp::crypto::sign::P256SigningKey;
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::primitives::{AgentDid, ContextType, Visibility};
    use acdp_registry_types::config::PinnedAgentKey;

    /// Build a real, signed Ed25519 PublishRequest from a freshly
    /// generated SigningKey. Mirrors what the Python SDK builds.
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

    /// Build a P-256-signed publish request by hand. We don't have a
    /// `Producer::new_p256` helper, so we build the Ed25519 request
    /// first (to get the canonical content_hash + everything else) and
    /// then re-sign + relabel the `signature` field with P-256.
    fn build_p256_signed_request(did: &str) -> (PublishRequest, String) {
        // First build a request with a throwaway Ed25519 key — gives
        // us the right shape + a real content_hash to sign.
        let throwaway = SigningKey::generate();
        let (mut req, _) = build_signed_request(throwaway, did);

        // Now sign the canonical content_hash with a fresh P-256 key
        // and swap that into the signature object.
        let p256_key = P256SigningKey::generate();
        let sig_b64 = p256_key.sign_content_hash(&req.content_hash);
        req.signature.algorithm = "ecdsa-p256".into();
        req.signature.value = sig_b64;

        let pub_b64 = base64::engine::general_purpose::STANDARD
            .encode(p256_key.verifying_key_sec1());
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
    fn pinned_agent_with_matching_ed25519_key_verifies() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_signed_request(key, did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ed25519".into(),
        };
        let outcome = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap();
        assert_eq!(outcome, PinOutcome::Verified);
    }

    #[test]
    fn pinned_agent_with_wrong_ed25519_key_is_rejected() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _real_pub) = build_signed_request(key, did);

        let wrong = SigningKey::generate();
        let wrong_pub =
            base64::engine::general_purpose::STANDARD.encode(wrong.verifying_key_bytes());
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: wrong_pub,
            algorithm: "ed25519".into(),
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
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned_for_other], true)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("not in playground.pinned_keys"), "got {msg}");
    }

    // ── ECDSA-P256 cases ────────────────────────────────────────────

    #[test]
    fn pinned_agent_with_matching_p256_key_verifies() {
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_p256_signed_request(did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ecdsa-p256".into(),
        };
        let outcome = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap();
        assert_eq!(outcome, PinOutcome::Verified);
    }

    #[test]
    fn pinned_p256_with_wrong_key_is_rejected() {
        let did = "did:web:x:agents:alice";
        let (req, _real_pub) = build_p256_signed_request(did);
        let wrong = P256SigningKey::generate();
        let wrong_pub = base64::engine::general_purpose::STANDARD
            .encode(wrong.verifying_key_sec1());
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: wrong_pub,
            algorithm: "ecdsa-p256".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("InvalidSignature") || msg.contains("signature"),
            "expected signature failure, got {msg}"
        );
    }

    #[test]
    fn p256_pin_with_wrong_length_key_is_a_config_error() {
        let did = "did:web:x:agents:alice";
        let (req, _) = build_p256_signed_request(did);
        // Truncate to 32 bytes — wrong length for SEC1 uncompressed P-256.
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: too_short,
            algorithm: "ecdsa-p256".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("65"), "got {msg}");
    }

    #[test]
    fn p256_pin_with_wrong_sec1_tag_is_a_config_error() {
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_p256_signed_request(did);
        // Replace the first byte (0x04 SEC1 tag) with 0x02 (compressed
        // form) — verifier wouldn't accept this; we surface it as a
        // config error so the operator notices on first publish.
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(&pub_b64).unwrap();
        bytes[0] = 0x02;
        let bad_tag = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: bad_tag,
            algorithm: "ecdsa-p256".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("0x04") || msg.contains("SEC1"), "got {msg}");
    }

    // ── algorithm-downgrade defense ─────────────────────────────────

    #[test]
    fn ed25519_sig_against_p256_pin_is_rejected() {
        // Build an ed25519 publish request, then pin the agent with
        // a P-256 key. Request's signature.algorithm = "ed25519",
        // pinned.algorithm = "ecdsa-p256" → mismatch.
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _) = build_signed_request(key, did);
        let p256_key = P256SigningKey::generate();
        let pub_b64 = base64::engine::general_purpose::STANDARD
            .encode(p256_key.verifying_key_sec1());
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "ecdsa-p256".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("does not match pinned algorithm"),
            "expected downgrade-defense rejection, got {msg}"
        );
    }

    #[test]
    fn p256_sig_against_ed25519_pin_is_rejected() {
        let did = "did:web:x:agents:alice";
        let (req, _) = build_p256_signed_request(did);
        // Pin with an Ed25519 key — request's algorithm = "ecdsa-p256"
        // does not match → downgrade defense fires before any
        // verification path runs.
        let ed_key = SigningKey::generate();
        let ed_pub = base64::engine::general_purpose::STANDARD
            .encode(ed_key.verifying_key_bytes());
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: ed_pub,
            algorithm: "ed25519".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("does not match pinned algorithm"),
            "expected downgrade-defense rejection, got {msg}"
        );
    }

    // ── config errors ───────────────────────────────────────────────

    #[test]
    fn unsupported_algorithm_surfaces_config_error() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, pub_b64) = build_signed_request(key, did);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: pub_b64,
            algorithm: "rsa-sha256".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("rsa-sha256"), "got {msg}");
        assert!(msg.contains("ed25519, ecdsa-p256"), "got {msg}");
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
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("base64"), "got {msg}");
    }

    #[test]
    fn wrong_length_pinned_ed25519_key_surfaces_config_error() {
        let key = SigningKey::generate();
        let did = "did:web:x:agents:alice";
        let (req, _) = build_signed_request(key, did);
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let pinned = PinnedAgentKey {
            agent_did: did.into(),
            public_key_b64: too_short,
            algorithm: "ed25519".into(),
        };
        let err = enforce_pinned_signature(&req, &cfg(vec![pinned], false)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("32"), "got {msg}");
    }
}
