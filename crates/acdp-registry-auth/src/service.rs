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
    /// SEC-05: a lightweight `did:web:`/`did:key:` prefix and length check
    /// runs before any storage work — full DID parsing (and, for did:key,
    /// the `auth.did_methods` capability gate) still happens on
    /// `issue_token`. Without this the challenge table fills with garbage
    /// from clients that mistype the DID method. `did:web` and `did:key`
    /// share a prefix length (8 chars), so one length bound covers both.
    #[tracing::instrument(skip(self), fields(agent = %agent_id))]
    pub async fn issue_challenge(&self, agent_id: &str) -> Result<AuthChallenge, AuthError> {
        if !(agent_id.starts_with("did:web:") || agent_id.starts_with("did:key:"))
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
    /// 5. Resolve the signing key — `did:web` via the DID document's
    ///    `assertionMethod` (a live HTTP fetch), `did:key` via the pure
    ///    offline decoder (the DID *is* the key; gated on `did:key` being
    ///    in `auth.did_methods`, mirroring the publish-path capability
    ///    gate) — then verify against it via the algorithm-specific
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
        let fragment = req
            .key_id
            .split('#')
            .nth(1)
            .ok_or_else(|| AuthError::KeyIdMalformed(req.key_id.clone()))?;

        let pub_bytes: Vec<u8> = if did_portion.starts_with("did:web:") {
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
            match req.algorithm.as_str() {
                "ed25519" => vm
                    .ed25519_public_key_bytes()
                    .map(|b| b.to_vec())
                    .map_err(|e| AuthError::Resolution(format!("key decode: {e}")))?,
                "ecdsa-p256" => vm
                    .ecdsa_p256_public_key_sec1()
                    .map(|b| b.to_vec())
                    .map_err(|e| AuthError::Resolution(format!("key decode: {e}")))?,
                // unreachable — guarded by the algorithm check in step 4,
                // but stay defensive.
                other => return Err(AuthError::AlgorithmNotSupported(other.into())),
            }
        } else if did_portion.starts_with("did:key:") {
            // did:key: the DID *is* the key (acdp_did::key — a pure,
            // offline decoder), so there is no document to fetch and no
            // assertionMethod relationship to check; the key is authorized
            // by construction. Gated on `did:key` being in
            // `auth.did_methods`, mirroring the publish path's capability
            // gate (context.rs) — an operator who hasn't opted in to
            // did:key shouldn't have it silently accepted for auth either.
            if !self.config.did_methods.iter().any(|m| m == "did:key") {
                return Err(AuthError::UnsupportedDidMethod(did_portion.to_string()));
            }
            // Convention (acdp_did::key module doc): the key_id fragment
            // mirrors the DID's own method-specific id, i.e.
            // `did:key:z<mb>#z<mb>`. Require that match here as a defense
            // check — otherwise a mismatched fragment would silently
            // verify against the DID's own key regardless of what fragment
            // the caller claimed.
            let msi = did_portion.strip_prefix("did:key:").unwrap_or_default();
            if fragment != msi {
                return Err(AuthError::KeyIdMalformed(format!(
                    "did:key fragment '{fragment}' does not match method-specific id '{msi}'"
                )));
            }
            let material = acdp::did::resolve_did_key(did_portion)
                .map_err(|e| AuthError::Resolution(e.to_string()))?;
            // Algorithm-downgrade defense: the did:key multicodec prefix
            // fixes the algorithm — it MUST match the request's declared
            // algorithm, the same intent as the did:web `declared_algorithm`
            // check above.
            if material.algorithm() != req.algorithm {
                return Err(AuthError::AlgorithmNotSupported(format!(
                    "request algorithm '{}' does not match did:key algorithm '{}'",
                    req.algorithm,
                    material.algorithm()
                )));
            }
            match material {
                acdp::did::DidKeyMaterial::Ed25519(b) => b.to_vec(),
                acdp::did::DidKeyMaterial::EcdsaP256(b) => b.to_vec(),
            }
        } else {
            return Err(AuthError::UnsupportedDidMethod(did_portion.to_string()));
        };

        let signing_input = AuthChallenge::signing_input(
            &req.nonce,
            &req.agent_id,
            &self.authority,
            req.expires_at,
        );
        // Algorithm dispatch — Ed25519 stays the default; ECDSA-P256 is
        // accepted for agents that advertise an `EcdsaSecp256r1*` verification
        // method (did:web) or an ecdsa-p256 multicodec key (did:key).
        // Algorithm-downgrade defense already ran above in both branches.
        match req.algorithm.as_str() {
            "ed25519" => {
                let arr: [u8; 32] = pub_bytes.as_slice().try_into().map_err(|_| {
                    AuthError::Resolution(format!(
                        "ed25519 key must be 32 bytes, got {}",
                        pub_bytes.len()
                    ))
                })?;
                acdp::crypto::verify::verify_ed25519(&arr, &req.signature, &signing_input)
                    .map_err(|e| AuthError::SignatureInvalid(e.to_string()))?;
            }
            "ecdsa-p256" => {
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
            // #16: audience = this registry's authority, validated on every
            // bearer check so the token can't be replayed at another registry.
            aud: self.authority.clone(),
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
    use crate::revocation_store::InMemoryRevocationStore;
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

    fn bare_service() -> AuthService {
        let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::default());
        let signer = JwtSigner::new(
            JwtSecret::from_bytes(&[7u8; 32]),
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
        );
        AuthService::new(
            AuthConfig::default(),
            challenges,
            signer,
            Arc::new(WebResolver::new()),
            "registry.test".into(),
        )
    }

    #[tokio::test]
    async fn issue_challenge_rejects_malformed_did() {
        // SEC-05: cheap prefix/length screen before any storage work. Note
        // did:key is now a cheaply-accepted prefix too (full validation,
        // including the auth.did_methods gate, defers to issue_token —
        // see issue_challenge_accepts_valid_did_key below), so a
        // well-formed-looking did:key isn't in this rejected set anymore.
        let svc = bare_service();
        for bad in ["", "did:key:", "did:web:", "https://not-a-did"] {
            let err = svc.issue_challenge(bad).await.unwrap_err();
            assert!(
                matches!(err, AuthError::UnsupportedDidMethod(_)),
                "expected UnsupportedDidMethod for {bad:?}, got {err:?}"
            );
        }
        // Over the 2048-byte ceiling is also rejected.
        let huge = format!("did:web:{}", "a".repeat(2050));
        assert!(matches!(
            svc.issue_challenge(&huge).await.unwrap_err(),
            AuthError::UnsupportedDidMethod(_)
        ));
    }

    #[tokio::test]
    async fn issue_challenge_accepts_valid_did_key() {
        // The cheap prefix/length screen accepts did:key too; the
        // auth.did_methods opt-in gate is enforced later, in issue_token.
        let svc = bare_service();
        let ch = svc
            .issue_challenge("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .await
            .expect("valid did:key challenge issues");
        assert!(!ch.nonce.is_empty());
    }

    #[tokio::test]
    async fn issue_challenge_accepts_valid_did_and_binds_authority() {
        let svc = bare_service();
        let ch = svc
            .issue_challenge("did:web:agents.test:alice")
            .await
            .expect("valid did:web challenge issues");
        assert_eq!(ch.registry_authority, "registry.test");
        assert!(!ch.nonce.is_empty());
        // The signing input is registry-authority-namespaced (replay guard).
        assert!(ch.signing_input.contains("registry.test"));
        assert!(ch.signing_input.contains(&ch.nonce));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_agent_id_mismatch() {
        // Step 2: the nonce was bound to alice; bob cannot redeem it even with
        // a structurally valid request.
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge("nonce-mm", "did:web:agents.test:alice", expires_at);
        let req = TokenRequest {
            nonce: "nonce-mm".into(),
            agent_id: "did:web:agents.test:bob".into(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.test:bob#key-1".into(),
            signature: "ignored".into(),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::ChallengeUnknown(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_expires_at_mismatch() {
        // Step 2: a request that tampers with expires_at no longer matches the
        // value the registry committed at issuance.
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge("nonce-exp", "did:web:agents.test:alice", expires_at);
        let req = TokenRequest {
            nonce: "nonce-exp".into(),
            agent_id: "did:web:agents.test:alice".into(),
            expires_at: expires_at.timestamp() + 999, // tampered
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.test:alice#key-1".into(),
            signature: "ignored".into(),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::ChallengeUnknown(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_consumes_nonce_so_replay_fails() {
        // Step 1 atomicity at the service level: a second issue_token for the
        // same nonce sees it already consumed (ChallengeUnknown), even though
        // the first attempt failed downstream (no live DID to resolve).
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge("nonce-once", "did:web:agents.test:alice", expires_at);
        let mk = || TokenRequest {
            nonce: "nonce-once".into(),
            agent_id: "did:web:agents.test:alice".into(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            key_id: "did:web:agents.test:alice#key-1".into(),
            signature: "AAAA".into(),
        };
        let _ = svc.issue_token(mk()).await; // consumes the nonce
        assert!(matches!(
            svc.issue_token(mk()).await.unwrap_err(),
            AuthError::ChallengeUnknown(_)
        ));
    }

    // ── revoke_token ────────────────────────────────────────────────

    #[tokio::test]
    async fn revoke_token_errors_when_revocation_not_configured() {
        let svc = bare_service(); // no .with_revocations
        let err = svc.revoke_token("any", "did:web:caller").await.unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }

    #[tokio::test]
    async fn revoke_token_rejects_unknown_jti() {
        let store = Arc::new(InMemoryRevocationStore::new());
        let svc = bare_service().with_revocations(store);
        let err = svc
            .revoke_token("never-issued", "did:web:caller")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)));
    }

    #[tokio::test]
    async fn revoke_token_rejects_non_owner() {
        // Ownership enforcement: only the DID a token was issued to may revoke it.
        let store = Arc::new(InMemoryRevocationStore::new());
        store
            .record_issued(RevocationRecord {
                jti: "jti-owned".into(),
                agent_did: "did:web:agents.test:alice".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
            })
            .await
            .unwrap();
        let svc = bare_service().with_revocations(store.clone());
        let err = svc
            .revoke_token("jti-owned", "did:web:agents.test:mallory")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)));
        // The token stays live since the revoke was refused.
        assert!(!store.is_revoked("jti-owned").unwrap());
    }

    #[tokio::test]
    async fn revoke_token_succeeds_for_owner() {
        let store = Arc::new(InMemoryRevocationStore::new());
        store
            .record_issued(RevocationRecord {
                jti: "jti-owned".into(),
                agent_did: "did:web:agents.test:alice".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
            })
            .await
            .unwrap();
        let svc = bare_service().with_revocations(store.clone());
        svc.revoke_token("jti-owned", "did:web:agents.test:alice")
            .await
            .expect("owner may revoke");
        assert!(store.is_revoked("jti-owned").unwrap());
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

    // ── did:key auth (unlike did:web, this is fully offline — no live
    //    document to fetch — so these ARE genuine end-to-end tests, not
    //    just "doesn't bounce off an earlier check") ─────────────────────

    /// Build an AuthService with a given `AuthConfig` and a pre-seeded
    /// challenge, mirroring `service_with_challenge` but parameterized so
    /// did:key tests can opt in via `auth.did_methods`.
    fn service_with_challenge_and_config(
        config: AuthConfig,
        nonce: &str,
        agent_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> AuthService {
        let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::default());
        let signer = JwtSigner::new(
            JwtSecret::from_bytes(&[7u8; 32]),
            format!("did:web:{agent_id}-registry"),
            "registry.test".into(),
            30,
        );
        let resolver = Arc::new(WebResolver::new());
        let svc = AuthService::new(
            config,
            challenges.clone(),
            signer,
            resolver,
            "registry.test".into(),
        );
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

    fn did_key_config_enabled() -> AuthConfig {
        AuthConfig {
            did_methods: vec!["did:web".into(), "did:key".into()],
            ..AuthConfig::default()
        }
    }

    /// (did:key DID, key_id, signing key) for a deterministic Ed25519 seed.
    fn did_key_fixture(seed: u8) -> (String, String, ed25519_dalek::SigningKey) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = acdp::did::did_key_from_ed25519(sk.verifying_key().as_bytes());
        let msi = did.strip_prefix("did:key:").unwrap().to_string();
        let key_id = format!("{did}#{msi}");
        (did, key_id, sk)
    }

    fn sign_b64(sk: &ed25519_dalek::SigningKey, message: &str) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::Signer;
        STANDARD.encode(sk.sign(message.as_bytes()).to_bytes())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_did_key_when_not_in_did_methods() {
        // Default config is did:web-only — mirrors the publish path's
        // capability gate: did:key must be an explicit operator opt-in.
        let (did, key_id, sk) = did_key_fixture(41);
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge_and_config(
            AuthConfig::default(),
            "nonce-dk-1",
            &did,
            expires_at,
        );
        let signing_input = AuthChallenge::signing_input(
            "nonce-dk-1",
            &did,
            "registry.test",
            expires_at.timestamp(),
        );
        let req = TokenRequest {
            nonce: "nonce-dk-1".into(),
            agent_id: did.clone(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            key_id,
            signature: sign_b64(&sk, &signing_input),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::UnsupportedDidMethod(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_end_to_end_with_did_key() {
        // Genuine end-to-end: real keypair, real challenge signing_input,
        // real signature — verifies the full offline did:key path mints a
        // token, something we cannot do for did:web without a live did.json.
        let (did, key_id, sk) = did_key_fixture(42);
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge_and_config(
            did_key_config_enabled(),
            "nonce-dk-2",
            &did,
            expires_at,
        );
        let signing_input = AuthChallenge::signing_input(
            "nonce-dk-2",
            &did,
            "registry.test",
            expires_at.timestamp(),
        );
        let req = TokenRequest {
            nonce: "nonce-dk-2".into(),
            agent_id: did.clone(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            key_id,
            signature: sign_b64(&sk, &signing_input),
        };
        let resp = svc.issue_token(req).await.expect("did:key token issues");
        assert_eq!(resp.token_type, "Bearer");
        let claims = svc
            .validate_bearer_claims(&resp.token)
            .expect("token validates");
        assert_eq!(claims.sub, did);
        assert_eq!(claims.acdp.registry, "registry.test");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_did_key_tampered_signature() {
        let (did, key_id, _sk) = did_key_fixture(43);
        let (_other_did, _other_key_id, other_sk) = did_key_fixture(44);
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge_and_config(
            did_key_config_enabled(),
            "nonce-dk-3",
            &did,
            expires_at,
        );
        let signing_input = AuthChallenge::signing_input(
            "nonce-dk-3",
            &did,
            "registry.test",
            expires_at.timestamp(),
        );
        let req = TokenRequest {
            nonce: "nonce-dk-3".into(),
            agent_id: did.clone(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            key_id,
            // Signed by a DIFFERENT key than the one embedded in `did`.
            signature: sign_b64(&other_sk, &signing_input),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::SignatureInvalid(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_did_key_fragment_mismatch() {
        let (did, _key_id, sk) = did_key_fixture(45);
        let (other_did, _o, _os) = did_key_fixture(46);
        let other_msi = other_did.strip_prefix("did:key:").unwrap();
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge_and_config(
            did_key_config_enabled(),
            "nonce-dk-4",
            &did,
            expires_at,
        );
        let signing_input = AuthChallenge::signing_input(
            "nonce-dk-4",
            &did,
            "registry.test",
            expires_at.timestamp(),
        );
        let req = TokenRequest {
            nonce: "nonce-dk-4".into(),
            agent_id: did.clone(),
            expires_at: expires_at.timestamp(),
            algorithm: "ed25519".into(),
            // Fragment names a DIFFERENT did:key's method-specific id.
            key_id: format!("{did}#{other_msi}"),
            signature: sign_b64(&sk, &signing_input),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::KeyIdMalformed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn issue_token_rejects_did_key_algorithm_downgrade() {
        // The did:key is Ed25519 (its multicodec fixes the algorithm), but
        // the request claims ecdsa-p256 — must be rejected before any
        // signature verification, same intent as the did:web
        // declared_algorithm defense.
        let (did, key_id, sk) = did_key_fixture(47);
        let expires_at = Utc::now() + Duration::seconds(60);
        let svc = service_with_challenge_and_config(
            did_key_config_enabled(),
            "nonce-dk-5",
            &did,
            expires_at,
        );
        let signing_input = AuthChallenge::signing_input(
            "nonce-dk-5",
            &did,
            "registry.test",
            expires_at.timestamp(),
        );
        let req = TokenRequest {
            nonce: "nonce-dk-5".into(),
            agent_id: did.clone(),
            expires_at: expires_at.timestamp(),
            algorithm: "ecdsa-p256".into(),
            key_id,
            signature: sign_b64(&sk, &signing_input),
        };
        assert!(matches!(
            svc.issue_token(req).await.unwrap_err(),
            AuthError::AlgorithmNotSupported(_)
        ));
    }
}
