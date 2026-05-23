//! JWT issuance and validation (HS256 over the registry's secret).

use std::sync::Arc;

use acdp_registry_types::BearerClaims;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};

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
        use base64::{engine::general_purpose::STANDARD, Engine};
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

/// JWT signer/verifier bound to a `JwtSecret`.
#[derive(Clone)]
pub struct JwtSigner {
    secret: JwtSecret,
    pub issuer: String,
    pub registry_authority: String,
    pub leeway_seconds: u64,
}

impl JwtSigner {
    pub fn new(
        secret: JwtSecret,
        issuer: String,
        registry_authority: String,
        leeway_seconds: u64,
    ) -> Self {
        Self {
            secret,
            issuer,
            registry_authority,
            leeway_seconds,
        }
    }

    pub fn sign(&self, claims: &BearerClaims) -> Result<String, AuthError> {
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        jsonwebtoken::encode(&header, claims, &self.secret.encoding)
            .map_err(|e| AuthError::Internal(format!("jwt sign: {e}")))
    }

    pub fn validate(&self, token: &str) -> Result<BearerClaims, AuthError> {
        let mut v = Validation::new(jsonwebtoken::Algorithm::HS256);
        v.set_issuer(&[&self.issuer]);
        v.validate_exp = true;
        v.leeway = self.leeway_seconds;
        let data = jsonwebtoken::decode::<BearerClaims>(token, &self.secret.decoding, &v)
            .map_err(|e| AuthError::TokenInvalid(e.to_string()))?;
        if data.claims.acdp.registry != self.registry_authority {
            return Err(AuthError::TokenInvalid(format!(
                "wrong registry: claim '{}' vs '{}'",
                data.claims.acdp.registry, self.registry_authority
            )));
        }
        Ok(data.claims)
    }
}
