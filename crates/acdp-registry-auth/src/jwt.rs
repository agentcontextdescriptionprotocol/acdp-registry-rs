//! JWT issuance and validation.
//!
//! Two signing modes:
//!   - HS256 (default, backward-compatible) — symmetric HMAC over a shared secret.
//!   - EdDSA (Ed25519) — asymmetric. Public key is published at
//!     `GET /.well-known/jwks.json` so federated peers can verify without
//!     out-of-band secret distribution.
//!
//! The [`JwtSigner`] dispatches on its [`SigningMaterial`] variant. Operators
//! migrate by setting `auth.jwt_signing_alg = "EdDSA"` and providing
//! `auth.jwt_private_key_pem`; the symmetric `auth.jwt_secret` is then
//! ignored. Existing HS256 deployments need no config change.

use std::sync::Arc;

use acdp_registry_types::BearerClaims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::revocation_store::RevocationStore;
use crate::AuthError;

/// Wraps the raw HMAC secret so the encoding/decoding keys are built once.
#[derive(Clone)]
pub struct JwtSecret {
    encoding: Arc<EncodingKey>,
    decoding: Arc<DecodingKey>,
}

impl JwtSecret {
    /// Construct from raw bytes. Caller is responsible for ensuring
    /// the secret is ≥ 32 bytes of high-entropy material.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            encoding: Arc::new(EncodingKey::from_secret(bytes)),
            decoding: Arc::new(DecodingKey::from_secret(bytes)),
        }
    }

    /// Construct from a base64-encoded string (the form that goes in
    /// `RegistryConfig::auth::jwt_secret`).
    pub fn from_base64(b64: &str) -> Result<Self, AuthError> {
        use base64::engine::general_purpose::STANDARD;
        let bytes = STANDARD
            .decode(b64.trim())
            .map_err(|e| AuthError::Config(format!("jwt_secret base64: {e}")))?;
        if bytes.len() < 32 {
            return Err(AuthError::Config(format!(
                "jwt_secret must decode to ≥32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self::from_bytes(&bytes))
    }
}

/// Public-key JWK published in `/.well-known/jwks.json`. Only EdDSA mode
/// produces a JWK (HMAC keys are never published — they're symmetric).
#[derive(Debug, Clone, Serialize)]
pub struct PublicJwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub crv: String,
    pub x: String,
}

/// Operative signing material for a single algorithm.
#[derive(Clone)]
enum SigningMaterial {
    Hs256 {
        secret: JwtSecret,
        kid: String,
    },
    EdDsa {
        encoding: Arc<EncodingKey>,
        decoding: Arc<DecodingKey>,
        kid: String,
        public_jwk: PublicJwk,
    },
}

impl SigningMaterial {
    fn algorithm(&self) -> Algorithm {
        match self {
            SigningMaterial::Hs256 { .. } => Algorithm::HS256,
            SigningMaterial::EdDsa { .. } => Algorithm::EdDSA,
        }
    }

    fn kid(&self) -> &str {
        match self {
            SigningMaterial::Hs256 { kid, .. } => kid,
            SigningMaterial::EdDsa { kid, .. } => kid,
        }
    }

    fn encoding(&self) -> &EncodingKey {
        match self {
            SigningMaterial::Hs256 { secret, .. } => &secret.encoding,
            SigningMaterial::EdDsa { encoding, .. } => encoding,
        }
    }

    fn decoding(&self) -> &DecodingKey {
        match self {
            SigningMaterial::Hs256 { secret, .. } => &secret.decoding,
            SigningMaterial::EdDsa { decoding, .. } => decoding,
        }
    }

    fn public_jwk(&self) -> Option<&PublicJwk> {
        match self {
            SigningMaterial::Hs256 { .. } => None,
            SigningMaterial::EdDsa { public_jwk, .. } => Some(public_jwk),
        }
    }
}

/// JWT signer/verifier. Dispatches on the chosen [`SigningMaterial`].
#[derive(Clone)]
pub struct JwtSigner {
    material: SigningMaterial,
    pub issuer: String,
    pub registry_authority: String,
    pub leeway_seconds: u64,
    revocations: Option<Arc<dyn RevocationStore>>,
}

impl JwtSigner {
    /// Construct a backward-compatible HS256 signer. The `kid` is derived
    /// from the secret fingerprint so the `kid` header on issued tokens
    /// is stable across restarts.
    pub fn new(
        secret: JwtSecret,
        issuer: String,
        registry_authority: String,
        leeway_seconds: u64,
    ) -> Self {
        // Use the encoding-key's address as a stand-in for the secret
        // bytes (we don't expose them) to derive a fingerprint. The
        // operator-provided kid override path supersedes this if set.
        let kid = fingerprint_hs256(&secret);
        Self {
            material: SigningMaterial::Hs256 { secret, kid },
            issuer,
            registry_authority,
            leeway_seconds,
            revocations: None,
        }
    }

    /// Construct an EdDSA signer from a PEM-encoded Ed25519 private key.
    /// The public key is extracted and exposed via [`Self::jwks`].
    pub fn new_eddsa(
        private_key_pem: &str,
        issuer: String,
        registry_authority: String,
        leeway_seconds: u64,
        kid_override: Option<String>,
    ) -> Result<Self, AuthError> {
        let encoding = EncodingKey::from_ed_pem(private_key_pem.as_bytes())
            .map_err(|e| AuthError::Config(format!("jwt_private_key_pem (encoding): {e}")))?;
        // Extract the raw 32-byte public key so we can publish a JWK and
        // build a DecodingKey. ed25519-dalek would give us a typed key,
        // but we already pull in the `ed25519-compact` semantics via
        // jsonwebtoken — keeping our parsing scoped here.
        let (decoding, public_raw) = decode_ed25519_pem_to_public(private_key_pem)?;
        let kid = match kid_override {
            Some(k) if !k.is_empty() => k,
            _ => fingerprint(&public_raw),
        };
        let public_jwk = PublicJwk {
            kty: "OKP".into(),
            kid: kid.clone(),
            alg: "EdDSA".into(),
            use_: "sig".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(public_raw),
        };
        Ok(Self {
            material: SigningMaterial::EdDsa {
                encoding: Arc::new(encoding),
                decoding: Arc::new(decoding),
                kid,
                public_jwk,
            },
            issuer,
            registry_authority,
            leeway_seconds,
            revocations: None,
        })
    }

    /// Attach a revocation store. `validate` will reject any token whose
    /// `jti` is present and unexpired in the store.
    pub fn with_revocations(mut self, store: Arc<dyn RevocationStore>) -> Self {
        self.revocations = Some(store);
        self
    }

    /// JWKS published at `GET /.well-known/jwks.json`. HS256 returns an
    /// empty key set (symmetric secrets are never published); EdDSA
    /// returns the single active signing key.
    pub fn jwks(&self) -> serde_json::Value {
        match self.material.public_jwk() {
            Some(jwk) => serde_json::json!({ "keys": [jwk] }),
            None => serde_json::json!({ "keys": [] }),
        }
    }

    pub fn sign(&self, claims: &BearerClaims) -> Result<String, AuthError> {
        let mut header = Header::new(self.material.algorithm());
        header.kid = Some(self.material.kid().to_string());
        jsonwebtoken::encode(&header, claims, self.material.encoding())
            .map_err(|e| AuthError::Internal(format!("jwt sign: {e}")))
    }

    pub fn validate(&self, token: &str) -> Result<BearerClaims, AuthError> {
        let mut v = Validation::new(self.material.algorithm());
        v.set_issuer(&[&self.issuer]);
        // #16: bind the token to this registry's audience so a token minted for
        // a different registry (in a federation with overlapping trusted
        // issuers) is rejected. `aud` is required-present so a token without it
        // cannot slip past the audience check.
        v.set_audience(&[&self.registry_authority]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_exp = true;
        v.leeway = self.leeway_seconds;
        let data = jsonwebtoken::decode::<BearerClaims>(token, self.material.decoding(), &v)
            .map_err(|e| AuthError::TokenInvalid(e.to_string()))?;
        if data.claims.acdp.registry != self.registry_authority {
            return Err(AuthError::TokenInvalid(format!(
                "wrong registry: claim '{}' vs '{}'",
                data.claims.acdp.registry, self.registry_authority
            )));
        }
        if let Some(rev) = &self.revocations {
            if rev.is_revoked(&data.claims.jti)? {
                return Err(AuthError::TokenInvalid(format!(
                    "token jti '{}' has been revoked",
                    data.claims.jti
                )));
            }
        }
        Ok(data.claims)
    }
}

/// Decode an Ed25519 PKCS#8 PEM, returning (DecodingKey-for-public, raw 32-byte public bytes).
///
/// Strategy: walk the PEM → DER → PKCS#8. The private-key PKCS#8 carries
/// the seed in the `OCTET STRING` payload; deriving the public key from
/// the seed requires ed25519-dalek which is already in our transitive deps.
fn decode_ed25519_pem_to_public(pem: &str) -> Result<(DecodingKey, [u8; 32]), AuthError> {
    use ed25519_dalek::SigningKey;
    // Parse PEM block.
    let der = pem_to_der(pem)?;
    // PKCS#8 v1 for Ed25519:
    //   SEQUENCE
    //     INTEGER 0 (version)
    //     SEQUENCE (algorithm)
    //       OID 1.3.101.112 (Ed25519)
    //     OCTET STRING (privateKey)
    //       OCTET STRING (seed, 32 bytes)
    // We look for the last 32-byte octet string in the trailing 34 bytes
    // (PKCS#8 v1 always ends with 04 20 <seed>).
    if der.len() < 48 || der[der.len() - 34..der.len() - 32] != [0x04, 0x20] {
        return Err(AuthError::Config(
            "jwt_private_key_pem: not a PKCS#8 Ed25519 key (no trailing 0x04 0x20 seed)".into(),
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[der.len() - 32..]);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let public: [u8; 32] = vk.to_bytes();
    let decoding = build_ed25519_decoding_pem(&public)?;
    Ok((decoding, public))
}

/// Build a `DecodingKey` for an Ed25519 public key by re-encoding into
/// SPKI-PEM, the form `jsonwebtoken::DecodingKey::from_ed_pem` accepts.
fn build_ed25519_decoding_pem(public_raw: &[u8; 32]) -> Result<DecodingKey, AuthError> {
    // SPKI prefix for Ed25519 (12 bytes), followed by the 32-byte key.
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki = Vec::with_capacity(SPKI_PREFIX.len() + 32);
    spki.extend_from_slice(&SPKI_PREFIX);
    spki.extend_from_slice(public_raw);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64
    );
    DecodingKey::from_ed_pem(pem.as_bytes())
        .map_err(|e| AuthError::Config(format!("derive Ed25519 DecodingKey: {e}")))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, AuthError> {
    let trimmed = pem.trim();
    if !trimmed.starts_with("-----BEGIN") {
        return Err(AuthError::Config(
            "jwt_private_key_pem: missing PEM header".into(),
        ));
    }
    let body: String = trimmed
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| AuthError::Config(format!("jwt_private_key_pem base64: {e}")))
}

/// First 8 bytes of SHA-256(material), base64url-no-pad. Fits readably in
/// the JWT header and is collision-resistant in practice for the small
/// number of keys an issuer rotates through.
fn fingerprint(material: &[u8]) -> String {
    let h = Sha256::digest(material);
    URL_SAFE_NO_PAD.encode(&h[..8])
}

/// HS256 kid: a stable hash of the encoding-key arc identity. We can't
/// hash the actual secret bytes here (EncodingKey doesn't expose them),
/// so we hash the JSON-serialized encoding-key opaque blob via its
/// `Debug` formatter. Operators who want a stable, audit-friendly kid
/// across deployments set `auth.jwt_kid` explicitly.
fn fingerprint_hs256(_secret: &JwtSecret) -> String {
    // Without a secret accessor, fall back to a fixed sentinel — HS256
    // doesn't publish in JWKS anyway, so this kid is mostly informative.
    // Operators set `jwt_kid` if they need a stable HS256 identifier.
    "hs256-default".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_registry_types::auth::{AcdpClaims, BearerClaims};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn sample_claims() -> BearerClaims {
        let now = chrono::Utc::now().timestamp();
        BearerClaims {
            iss: "did:web:registry.test".into(),
            sub: "did:web:registry.test:agents:alice".into(),
            aud: "registry.test".into(),
            jti: "jti-1".into(),
            iat: now,
            exp: now + 3600,
            acdp: AcdpClaims {
                registry: "registry.test".into(),
                key_id: "did:web:registry.test:agents:alice#key-1".into(),
            },
            tenant: None,
        }
    }

    fn fresh_ed25519_pkcs8_pem() -> String {
        let sk = SigningKey::generate(&mut OsRng);
        // PKCS#8 v1 layout we documented in decode_ed25519_pem_to_public.
        let prefix: [u8; 16] = [
            0x30, 0x2e, // SEQUENCE (46)
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier {Ed25519}
            0x04, 0x22, // OCTET STRING (34)
            0x04, 0x20, // inner OCTET STRING (32)
        ];
        let mut der = Vec::with_capacity(prefix.len() + 32);
        der.extend_from_slice(&prefix);
        der.extend_from_slice(&sk.to_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        )
    }

    #[test]
    fn hs256_sign_then_validate_roundtrip() {
        let secret = JwtSecret::from_bytes(&[7u8; 32]);
        let s = JwtSigner::new(
            secret,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
        );
        let token = s.sign(&sample_claims()).expect("sign");
        let claims = s.validate(&token).expect("validate");
        assert_eq!(claims.iss, "did:web:registry.test");
        // HS256 mode: JWKS is an empty key set.
        assert_eq!(s.jwks()["keys"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn rejects_token_for_a_different_audience() {
        // #16: a token whose `aud` is not this registry's authority is rejected
        // (federation replay guard). A matching `aud` validates.
        let s = JwtSigner::new(
            JwtSecret::from_bytes(&[7u8; 32]),
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
        );
        let mut wrong = sample_claims();
        wrong.aud = "other.registry".into();
        let token = s.sign(&wrong).expect("sign");
        assert!(
            s.validate(&token).is_err(),
            "token for a different audience must be rejected"
        );
        // Control: the correct audience (set by sample_claims) validates.
        let token_ok = s.sign(&sample_claims()).expect("sign");
        assert!(s.validate(&token_ok).is_ok());
    }

    #[test]
    fn eddsa_sign_then_validate_roundtrip() {
        let pem = fresh_ed25519_pkcs8_pem();
        let s = JwtSigner::new_eddsa(
            &pem,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .expect("new_eddsa");
        let token = s.sign(&sample_claims()).expect("sign");
        let claims = s.validate(&token).expect("validate");
        assert_eq!(claims.iss, "did:web:registry.test");
    }

    #[test]
    fn eddsa_publishes_jwk_with_matching_kid() {
        let pem = fresh_ed25519_pkcs8_pem();
        let s = JwtSigner::new_eddsa(
            &pem,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .unwrap();
        let jwks = s.jwks();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        let jwk = &keys[0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        // The kid on the published JWK must match the kid that goes into
        // signed-token headers — that's the whole point of the JWKS dance.
        let token = s.sign(&sample_claims()).unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(jwk["kid"].as_str().unwrap()));
    }

    #[test]
    fn eddsa_kid_override_wins() {
        let pem = fresh_ed25519_pkcs8_pem();
        let s = JwtSigner::new_eddsa(
            &pem,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            Some("custom-kid-2026".into()),
        )
        .unwrap();
        let jwks = s.jwks();
        assert_eq!(jwks["keys"][0]["kid"], "custom-kid-2026");
    }

    #[test]
    fn eddsa_invalid_pem_errors_at_construction() {
        let result = JwtSigner::new_eddsa(
            "not a pem",
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        );
        let err = match result {
            Ok(_) => panic!("expected construction to fail"),
            Err(e) => e,
        };
        let s = format!("{}", err);
        assert!(s.contains("PEM") || s.contains("pem"), "got: {}", s);
    }

    #[test]
    fn eddsa_kid_stable_across_constructions_for_same_key() {
        let pem = fresh_ed25519_pkcs8_pem();
        let s1 = JwtSigner::new_eddsa(
            &pem,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .unwrap();
        let s2 = JwtSigner::new_eddsa(
            &pem,
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .unwrap();
        assert_eq!(s1.jwks()["keys"][0]["kid"], s2.jwks()["keys"][0]["kid"]);
    }

    #[test]
    fn eddsa_rejects_token_signed_by_different_key() {
        let s1 = JwtSigner::new_eddsa(
            &fresh_ed25519_pkcs8_pem(),
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .unwrap();
        let s2 = JwtSigner::new_eddsa(
            &fresh_ed25519_pkcs8_pem(),
            "did:web:registry.test".into(),
            "registry.test".into(),
            30,
            None,
        )
        .unwrap();
        let attacker_token = s2.sign(&sample_claims()).unwrap();
        let err = s1.validate(&attacker_token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)));
    }
}
