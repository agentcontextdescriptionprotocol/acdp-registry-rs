//! `AuthService` — orchestrates challenge issuance, signature verification
//! via `acdp::did::WebResolver`, and JWT lifecycle.

use std::sync::Arc;

use acdp::did::WebResolver;
use acdp::types::primitives::AgentDid;
use acdp_registry_types::auth::AcdpClaims;
use acdp_registry_types::{
    AuthChallenge, AuthConfig, BearerClaims, TenantAgentBinding, TokenRequest, TokenResponse,
};
use chrono::{Duration, Utc};
use rand::RngCore;
use uuid::Uuid;

use crate::challenge_store::{ChallengeRecord, ChallengeStore};
use crate::jwt::JwtSigner;
use crate::revocation_store::{RevocationRecord, RevocationStore};
use crate::AuthError;

/// Bundles configuration + challenge store + JWT signer + DID resolver.
pub struct AuthService {
    pub config: AuthConfig,
    pub challenges: Arc<dyn ChallengeStore>,
    pub signer: JwtSigner,
    pub resolver: Arc<WebResolver>,
    pub authority: String,
    pub revocations: Option<Arc<dyn RevocationStore>>,
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
            revocations: None,
        }
    }

    /// Attach the revocation store used by `revoke_token` and the signer.
    /// Callers SHOULD configure `signer` with the same store via
    /// `JwtSigner::with_revocations` so `validate` and `revoke` agree.
    pub fn with_revocations(mut self, store: Arc<dyn RevocationStore>) -> Self {
        self.revocations = Some(store);
        self
    }

    /// Issue a fresh challenge nonce and persist it.
    ///
    /// `agent_id` is stored alongside the nonce so the token-issue path can
    /// reject any peer that tries to redeem the nonce under a different DID.
    ///
    /// SEC-05: a lightweight `did:web:` prefix and length check runs before
    /// any storage work — full DID-web parsing still happens on
    /// `issue_token`. Without this the challenge table fills with garbage
    /// from clients that mistype the DID method.
    #[tracing::instrument(skip(self), fields(agent = %agent_id))]
    pub async fn issue_challenge(&self, agent_id: &str) -> Result<AuthChallenge, AuthError> {
        if !agent_id.starts_with("did:web:")
            || agent_id.len() < "did:web:".len() + 1
            || agent_id.len() > 2048
        {
            return Err(AuthError::UnsupportedDidMethod(agent_id.to_string()));
        }
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
    /// 4. Reject algorithm ∉ {ed25519, ecdsa-p256}.
    /// 5. Re-derive the canonical signing input and verify against the
    ///    DID document's `assertionMethod` key via the algorithm-specific
    ///    verifier ([`acdp::crypto::verify::verify_ed25519`] or
    ///    [`acdp::crypto::verify::verify_ecdsa_p256`]).
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
        if req.algorithm != "ed25519" && req.algorithm != "ecdsa-p256" {
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
        let signing_input = AuthChallenge::signing_input(
            &req.nonce,
            &req.agent_id,
            &self.authority,
            req.expires_at,
        );
        // Algorithm dispatch — Ed25519 stays the default; ECDSA-P256 is
        // accepted for agents that advertise an `EcdsaSecp256r1*` verification
        // method. Algorithm-downgrade defense already ran above (declared
        // algorithm on the VM must match req.algorithm).
        match req.algorithm.as_str() {
            "ed25519" => {
                let pub_bytes = vm
                    .ed25519_public_key_bytes()
                    .map_err(|e| AuthError::Resolution(format!("key decode: {e}")))?;
                acdp::crypto::verify::verify_ed25519(&pub_bytes, &req.signature, &signing_input)
                    .map_err(|e| AuthError::SignatureInvalid(e.to_string()))?;
            }
            "ecdsa-p256" => {
                let pub_bytes = vm
                    .ecdsa_p256_public_key_sec1()
                    .map_err(|e| AuthError::Resolution(format!("key decode: {e}")))?;
                acdp::crypto::verify::verify_ecdsa_p256(&pub_bytes, &req.signature, &signing_input)
                    .map_err(|e| AuthError::SignatureInvalid(e.to_string()))?;
            }
            // unreachable — guarded above, but stay defensive.
            other => return Err(AuthError::AlgorithmNotSupported(other.into())),
        }

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
            // Tenant binding (plan §4): when the agent is listed in
            // `auth.tenant_agents`, stamp the configured tenant id so
            // downstream `tenant_for_request` (and federated peers'
            // AuthGuards) see the same authoritative binding the CP
            // already emits. Agents not in the map carry `None`,
            // matching V0 behavior — backward compatible.
            tenant: tenant_for_agent(&self.config.tenant_agents, &req.agent_id),
        };
        let token = self.signer.sign(&claims)?;
        // SEC-01 (post-798cb34): record the issued jti so the revocation
        // endpoint can authorize "this is my token" lookups. Failing
        // here would issue an unrevocable token, which we treat as a
        // security failure — fail the request instead so the caller can
        // retry against a healthy backend.
        if let Some(rev) = &self.revocations {
            rev.record_issued(RevocationRecord {
                jti: claims.jti.clone(),
                agent_did: claims.sub.clone(),
                expires_at: exp,
            })
            .await?;
        }
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

    /// Validate a bearer token and return the full claim set. Callers
    /// that need the `tenant` claim (or future scope/aud claims) use
    /// this instead of `validate_bearer`. The two methods share the
    /// same validation path; one returns just the DID for legacy
    /// callers, the other returns everything.
    pub fn validate_bearer_claims(&self, token: &str) -> Result<BearerClaims, AuthError> {
        self.signer.validate(token)
    }

    /// Revoke a token by its `jti`. Returns `AuthError::TokenInvalid` when
    /// the caller's DID does not own the target token and
    /// `AuthError::Internal` if revocation is not configured. The caller
    /// SHOULD authenticate the bearer presenting the request and pass the
    /// resulting `caller_did` so an agent can only revoke their own tokens.
    pub async fn revoke_token(&self, jti: &str, caller_did: &str) -> Result<(), AuthError> {
        let Some(rev) = &self.revocations else {
            return Err(AuthError::Internal(
                "token revocation is not configured on this registry".into(),
            ));
        };
        match rev.owner_of(jti).await? {
            None => Err(AuthError::TokenInvalid(format!(
                "no record for jti '{jti}'"
            ))),
            Some(owner) if owner != caller_did => Err(AuthError::TokenInvalid(
                "may only revoke tokens issued to the calling DID".into(),
            )),
            Some(owner) => {
                rev.revoke(RevocationRecord {
                    jti: jti.into(),
                    agent_did: owner,
                    expires_at: Utc::now()
                        + Duration::seconds(self.config.token_ttl_seconds as i64),
                })
                .await
            }
        }
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
        if let Some(rev) = self.revocations.clone() {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    if let Err(e) = rev.evict_expired(Utc::now()).await {
                        tracing::warn!(error = %e, "revocation eviction failed");
                    }
                }
            });
        }
    }
}

/// Extract a bearer token from an `Authorization` header value.
pub fn extract_bearer(value: &str) -> Option<&str> {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
}

/// Resolve an `agent_did` against the configured agent→tenant bindings.
///
/// Returns the matching `tenant_id` (cloned) or `None` if the agent
/// isn't bound. Linear scan is fine — the binding list is bounded by
/// operator-managed config; we don't expect thousands of entries.
/// When multiple entries match the same DID, the first wins; this
/// mirrors how the CP's `parseTenantAgents` reports a duplicate as a
/// config error rather than silently merging.
pub(crate) fn tenant_for_agent(bindings: &[TenantAgentBinding], agent_did: &str) -> Option<String> {
    bindings
        .iter()
        .find(|b| b.agent_did == agent_did)
        .map(|b| b.tenant_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge_store::InMemoryChallengeStore;
    use crate::jwt::JwtSecret;
    use chrono::Duration;

    /// Build an AuthService just sufficient to drive `issue_token` up to
    /// the algorithm-check branch. The DID resolver still points at a
    /// real WebResolver — we don't reach it in the cases under test
    /// because the algorithm reject fires first.
    fn service_with_challenge(
        nonce: &str,
        agent_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> AuthService {
        let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::default());
        // Synchronous helper — InMemoryChallengeStore's put is async but the
        // mutex inside is sync, so block_on inside a test's tokio runtime works.
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::try_current();
            assert!(rt.is_ok(), "tests must run on a tokio runtime");
        });

        let signer = JwtSigner::new(
            JwtSecret::from_bytes(&[7u8; 32]),
            format!("did:web:{agent_id}-registry"),
            "registry.test".into(),
            30,
        );
        let resolver = Arc::new(WebResolver::new());
        let svc = AuthService::new(
            AuthConfig::default(),
            challenges.clone(),
            signer,
            resolver,
            "registry.test".into(),
        );
        // Seed the challenge synchronously via a futures::executor block.
        futures_block_on(async {
            challenges
                .put(ChallengeRecord {
                    nonce: nonce.into(),
                    agent_id: agent_id.into(),
                    expires_at,
                })
                .await
                .unwrap();
        });
        svc
    }

    fn futures_block_on<F: std::future::Future<Output = ()>>(f: F) {
        // We're already on a tokio runtime in the test — but the futures we
        // run here are tiny and synchronous-ish (HashMap operations under a
        // sync mutex), so a quick tokio block_on is fine.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(f);
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_unsupported_algorithm() {
        // Confirms the algorithm-accept set is exactly {ed25519, ecdsa-p256}
        // — RS256 / HS256 / ES512 all bounce off step 4 before any DID work.
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge("nonce-1", "did:web:agents.test:alice", expires_at);
        let req = TokenRequest {
            nonce: "nonce-1".into(),
            agent_id: "did:web:agents.test:alice".into(),
            expires_at: expires_at.timestamp(),
            algorithm: "rsa".into(),
            key_id: "did:web:agents.test:alice#key-1".into(),
            signature: "ignored".into(),
        };
        let err = svc.issue_token(req).await.unwrap_err();
        match err {
            AuthError::AlgorithmNotSupported(s) => assert_eq!(s, "rsa"),
            other => panic!("expected AlgorithmNotSupported, got {other:?}"),
        }
    }

    #[test]
    fn tenant_for_agent_returns_bound_tenant() {
        let bindings = vec![
            TenantAgentBinding {
                agent_did: "did:web:agents.example:alice".into(),
                tenant_id: "tenant-a".into(),
            },
            TenantAgentBinding {
                agent_did: "did:web:agents.example:bob".into(),
                tenant_id: "tenant-b".into(),
            },
        ];
        assert_eq!(
            tenant_for_agent(&bindings, "did:web:agents.example:alice"),
            Some("tenant-a".into())
        );
        assert_eq!(
            tenant_for_agent(&bindings, "did:web:agents.example:bob"),
            Some("tenant-b".into())
        );
    }

    #[test]
    fn tenant_for_agent_returns_none_for_unlisted_agent() {
        let bindings = vec![TenantAgentBinding {
            agent_did: "did:web:agents.example:alice".into(),
            tenant_id: "tenant-a".into(),
        }];
        assert_eq!(
            tenant_for_agent(&bindings, "did:web:agents.example:carol"),
            None
        );
    }

    #[test]
    fn tenant_for_agent_handles_empty_list() {
        assert_eq!(tenant_for_agent(&[], "did:web:agents.example:alice"), None);
    }

    #[test]
    fn tenant_for_agent_takes_first_when_duplicate() {
        // Duplicate-DID config is operator error, but the lookup must
        // remain deterministic; first wins.
        let bindings = vec![
            TenantAgentBinding {
                agent_did: "did:web:dup".into(),
                tenant_id: "first".into(),
            },
            TenantAgentBinding {
                agent_did: "did:web:dup".into(),
                tenant_id: "second".into(),
            },
        ];
        assert_eq!(
            tenant_for_agent(&bindings, "did:web:dup"),
            Some("first".into())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_accepts_ecdsa_p256_past_step_4() {
        // We can't end-to-end this without a live did.json. What we can
        // assert: `algorithm = "ecdsa-p256"` does NOT bounce off step 4 —
        // the failure surfaces from the DID-resolution step (5) instead.
        // That's exactly the boundary the §10 fix targets.
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge("nonce-2", "did:web:agents.test:bob", expires_at);
        let req = TokenRequest {
            nonce: "nonce-2".into(),
            agent_id: "did:web:agents.test:bob".into(),
            expires_at: expires_at.timestamp(),
            algorithm: "ecdsa-p256".into(),
            key_id: "did:web:agents.test:bob#key-1".into(),
            signature: "AAAA".into(),
        };
        let err = svc.issue_token(req).await.unwrap_err();
        // Whatever fails AFTER step 4 — resolver lookup, signature verify —
        // is not an AlgorithmNotSupported error. That's the contract here.
        assert!(
            !matches!(err, AuthError::AlgorithmNotSupported(_)),
            "ecdsa-p256 should not bounce off the algorithm check; got {err:?}"
        );
    }
}
