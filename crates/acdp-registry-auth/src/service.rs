//! `AuthService` — orchestrates challenge issuance, signature verification
//! via `acdp::did::WebResolver`, and JWT lifecycle.

use std::sync::Arc;

use acdp::did::WebResolver;
use acdp::types::primitives::AgentDid;
use acdp_registry_types::auth::AcdpClaims;
use acdp_registry_types::{AuthChallenge, AuthConfig, BearerClaims, TokenRequest, TokenResponse};
use chrono::{Duration, Utc};
use rand::RngCore;
use uuid::Uuid;

use crate::challenge_store::{ChallengeRecord, ChallengeStore};
use crate::jwt::JwtSigner;
use crate::AuthError;

/// Bundles configuration + challenge store + JWT signer + DID resolver.
pub struct AuthService {
    pub config: AuthConfig,
    pub challenges: Arc<dyn ChallengeStore>,
    pub signer: JwtSigner,
    pub resolver: Arc<WebResolver>,
    pub authority: String,
}

impl AuthService {
    pub fn new(
        config: AuthConfig,
        challenges: Arc<dyn ChallengeStore>,
        signer: JwtSigner,
        resolver: Arc<WebResolver>,
        authority: String,
    ) -> Self {
        Self {
            config,
            challenges,
            signer,
            resolver,
            authority,
        }
    }

    /// Issue a fresh challenge nonce and persist it.
    ///
    /// `agent_id` is stored alongside the nonce so the token-issue path can
    /// reject any peer that tries to redeem the nonce under a different DID.
    #[tracing::instrument(skip(self), fields(agent = %agent_id))]
    pub async fn issue_challenge(&self, agent_id: &str) -> Result<AuthChallenge, AuthError> {
        let mut bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut bytes);
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let nonce = URL_SAFE_NO_PAD.encode(bytes);
        let expires_at = Utc::now() + Duration::seconds(self.config.challenge_ttl_seconds as i64);
        let signing_input =
            AuthChallenge::signing_input(&nonce, agent_id, &self.authority, expires_at.timestamp());
        self.challenges
            .put(ChallengeRecord {
                nonce: nonce.clone(),
                agent_id: agent_id.to_string(),
                expires_at,
            })
            .await?;
        tracing::info!(nonce = %nonce, "challenge issued");
        Ok(AuthChallenge {
            nonce,
            registry_authority: self.authority.clone(),
            expires_at: expires_at.timestamp(),
            signing_input,
        })
    }

    /// Verify a signed challenge and issue a JWT.
    ///
    /// Steps:
    /// 1. Atomically take the nonce (rejects replay) and read its bindings.
    /// 2. Reject if the request's `agent_id` or `expires_at` doesn't match
    ///    what the registry committed at challenge issuance.
    /// 3. Reject if `expires_at` is past.
    /// 4. Reject algorithm ≠ ed25519.
    /// 5. Re-derive the canonical signing input and verify against the
    ///    DID document's `assertionMethod` key via
    ///    [`acdp::crypto::verify::verify_ed25519`].
    /// 6. Mint a JWT bound to the agent DID.
    #[tracing::instrument(skip(self, req), fields(agent = %req.agent_id, key_id = %req.key_id))]
    pub async fn issue_token(&self, req: TokenRequest) -> Result<TokenResponse, AuthError> {
        // 1.
        let rec = self
            .challenges
            .take(&req.nonce)
            .await?
            .ok_or_else(|| AuthError::ChallengeUnknown(req.nonce.clone()))?;

        // 2. Enforce the registry's own challenge bindings before any DID work.
        if rec.agent_id != req.agent_id {
            tracing::warn!(stored = %rec.agent_id, "token request agent_id mismatch");
            return Err(AuthError::ChallengeUnknown(
                "challenge agent_id mismatch".into(),
            ));
        }
        if rec.expires_at.timestamp() != req.expires_at {
            tracing::warn!(
                stored = rec.expires_at.timestamp(),
                requested = req.expires_at,
                "token request expires_at mismatch"
            );
            return Err(AuthError::ChallengeUnknown(
                "challenge expires_at mismatch".into(),
            ));
        }

        // 3.
        let now = Utc::now();
        if now.timestamp() > req.expires_at {
            return Err(AuthError::ChallengeExpired);
        }

        // 4.
        if req.algorithm != "ed25519" {
            return Err(AuthError::AlgorithmNotSupported(req.algorithm));
        }

        // 4. Resolve DID and verify signature using acdp primitives.
        let did_portion = req
            .key_id
            .split('#')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AuthError::KeyIdMalformed(req.key_id.clone()))?;
        if did_portion != req.agent_id {
            return Err(AuthError::KeyIdMismatch);
        }
        if !did_portion.starts_with("did:web:") {
            return Err(AuthError::UnsupportedDidMethod(did_portion.to_string()));
        }
        let fragment = req
            .key_id
            .split('#')
            .nth(1)
            .ok_or_else(|| AuthError::KeyIdMalformed(req.key_id.clone()))?;
        let doc = self
            .resolver
            .resolve(did_portion)
            .await
            .map_err(|e| AuthError::Resolution(e.to_string()))?;
        let vm = doc.find_by_fragment(fragment).ok_or_else(|| {
            AuthError::KeyIdMalformed(format!("fragment '{fragment}' not in DID doc"))
        })?;
        if !doc.is_assertion_method(&req.key_id) {
            return Err(AuthError::KeyNotAssertion);
        }
        // Algorithm-downgrade defense (RFC-ACDP-0008 §3.9): if the
        // verification method declares an algorithm (via `type` or
        // `publicKeyJwk` params), it MUST match `req.algorithm`.
        // Otherwise an attacker could submit `algorithm = ed25519`
        // pointing at a key authored under a different scheme.
        // `Verifier::verify_body` enforces the same check on the
        // publish path; do the same on the auth handshake.
        if let Some(declared) = vm.declared_algorithm() {
            if declared != req.algorithm {
                return Err(AuthError::AlgorithmNotSupported(format!(
                    "request algorithm '{}' does not match verification method type \
                     (declared '{}')",
                    req.algorithm, declared
                )));
            }
        }
        let pub_bytes = vm
            .ed25519_public_key_bytes()
            .map_err(|e| AuthError::Resolution(format!("key decode: {e}")))?;

        let signing_input = AuthChallenge::signing_input(
            &req.nonce,
            &req.agent_id,
            &self.authority,
            req.expires_at,
        );
        acdp::crypto::verify::verify_ed25519(&pub_bytes, &req.signature, &signing_input)
            .map_err(|e| AuthError::SignatureInvalid(e.to_string()))?;

        // 5.
        let exp = now + Duration::seconds(self.config.token_ttl_seconds as i64);
        let claims = BearerClaims {
            iss: self.signer.issuer.clone(),
            sub: req.agent_id.clone(),
            jti: Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            acdp: AcdpClaims {
                registry: self.authority.clone(),
                key_id: req.key_id.clone(),
            },
        };
        let token = self.signer.sign(&claims)?;
        tracing::info!(jti = %claims.jti, exp = exp.timestamp(), "token issued");
        Ok(TokenResponse {
            token,
            token_type: "Bearer".into(),
            expires_at: exp.timestamp(),
        })
    }

    /// Validate a bearer token and return the agent DID it represents.
    pub fn validate_bearer(&self, token: &str) -> Result<AgentDid, AuthError> {
        let claims = self.signer.validate(token)?;
        Ok(AgentDid::new(&claims.sub))
    }

    /// Spawn the background nonce-cleanup task.
    pub fn spawn_evictor(self: &Arc<Self>) {
        let challenges = self.challenges.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Err(e) = challenges.evict_expired(Utc::now()).await {
                    tracing::warn!(error = %e, "auth challenge eviction failed");
                }
            }
        });
    }
}

/// Extract a bearer token from an `Authorization` header value.
pub fn extract_bearer(value: &str) -> Option<&str> {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
}
