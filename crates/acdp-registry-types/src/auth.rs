//! Auth wire types for the DID challenge-response flow.
//!
//! Flow:
//! 1. Client `POST /auth/challenge` → server returns `AuthChallenge`.
//! 2. Client signs the canonical challenge input with their DID key.
//! 3. Client `POST /auth/token` with `TokenRequest` → server verifies
//!    via the resolved DID document and issues a `TokenResponse`.

use serde::{Deserialize, Serialize};

/// Server → client challenge envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub registry_authority: String,
    /// Unix-seconds expiry of this challenge.
    pub expires_at: i64,
    /// The exact canonical input the agent must sign (helpful for clients
    /// that don't want to reconstruct it locally).
    pub signing_input: String,
}

impl AuthChallenge {
    /// Construct the canonical signing input for a challenge.
    ///
    /// Format: `acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}`.
    /// Namespaced so a content_hash signature cannot be replayed here and
    /// vice versa.
    pub fn signing_input(nonce: &str, agent_id: &str, authority: &str, expires_at: i64) -> String {
        format!("acdp-registry-auth:v1:{nonce}:{agent_id}:{authority}:{expires_at}")
    }
}

/// Client → server token request: signed challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub agent_id: String,
    pub key_id: String,
    pub nonce: String,
    /// Unix-seconds expiry as echoed back by the client (must match server).
    pub expires_at: i64,
    /// Signature algorithm — currently `"ed25519"` only.
    pub algorithm: String,
    /// Base64-encoded signature over the challenge signing input.
    pub signature: String,
}

/// Server → client issued bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub token_type: String,
    /// Unix-seconds expiry.
    pub expires_at: i64,
}

/// Decoded JWT claims (issued + validated by `acdp-registry-auth`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerClaims {
    pub iss: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub acdp: AcdpClaims,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcdpClaims {
    #[serde(default)]
    pub registry: String,
    #[serde(default)]
    pub key_id: String,
}
