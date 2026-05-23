//! JWT revocation list — keyed by the `jti` minted on token issuance.
//!
//! Without this layer a bearer token issued to a compromised DID key lives
//! until its `exp` (default 1 hour) and the only recourse is rotating the
//! JWT secret, which invalidates every other live token. The trait is
//! consulted on every `JwtSigner::validate` call. Backends ship for the
//! same three flavors as [`crate::ChallengeStore`].

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::AuthError;

/// Tombstone record. The signer rejects any presented token whose `jti`
/// has a row here (revoked = true) and whose `expires_at` has not yet
/// elapsed (expired tokens are harmless and don't need to live forever).
#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub jti: String,
    pub agent_did: String,
    pub expires_at: DateTime<Utc>,
}

/// Persistent revocation index.
#[async_trait]
pub trait RevocationStore: Send + Sync {
    /// Mark `jti` as revoked. The `agent_did` and `expires_at` are stored
    /// alongside so a revocation endpoint can authorize the request (an
    /// agent may only revoke tokens with matching `sub`) and the eviction
    /// task can drop expired tombstones.
    async fn revoke(&self, record: RevocationRecord) -> Result<(), AuthError>;

    /// Synchronous reachability check used inside `JwtSigner::validate`
    /// (which itself is sync). DB-backed implementations bridge via
    /// `block_in_place + Handle::block_on(...)`, matching the storage
    /// layer pattern elsewhere in this workspace.
    fn is_revoked(&self, jti: &str) -> Result<bool, AuthError>;

    /// Whether a stored revocation belongs to `agent_did`. Used by the
    /// revocation endpoint to forbid cross-agent revocations.
    async fn owner_of(&self, jti: &str) -> Result<Option<String>, AuthError>;

    /// Drop tombstones whose `expires_at` has elapsed. Bounded background
    /// task — keeps the table from growing forever.
    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError>;
}

// ── In-memory ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryRevocationStore {
    inner: Mutex<HashMap<String, RevocationRecord>>,
}

impl InMemoryRevocationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RevocationStore for InMemoryRevocationStore {
    async fn revoke(&self, record: RevocationRecord) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        g.insert(record.jti.clone(), record);
        Ok(())
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(g.get(jti).is_some_and(|r| r.expires_at > Utc::now()))
    }

    async fn owner_of(&self, jti: &str) -> Result<Option<String>, AuthError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(g.get(jti).map(|r| r.agent_did.clone()))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        g.retain(|_, r| r.expires_at > now);
        Ok(())
    }
}

// ── SQLite ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SqliteRevocationStore {
    pool: sqlx::SqlitePool,
}

impl SqliteRevocationStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }

    fn block_on<F: std::future::Future<Output = T>, T>(&self, fut: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }
}

#[async_trait]
impl RevocationStore for SqliteRevocationStore {
    async fn revoke(&self, record: RevocationRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO issued_tokens (jti, agent_did, expires_at, revoked) \
             VALUES (?, ?, ?, 1) \
             ON CONFLICT(jti) DO UPDATE SET revoked = 1",
        )
        .bind(&record.jti)
        .bind(&record.agent_did)
        .bind(record.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let jti = jti.to_string();
        self.block_on(async move {
            use sqlx::Row;
            let row = sqlx::query(
                "SELECT revoked, expires_at FROM issued_tokens WHERE jti = ? AND revoked = 1",
            )
            .bind(&jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?;
            let Some(row) = row else {
                return Ok(false);
            };
            let exp: String = row
                .try_get("expires_at")
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            let exp = chrono::DateTime::parse_from_rfc3339(&exp)
                .map_err(|e| AuthError::Storage(e.to_string()))?
                .with_timezone(&Utc);
            Ok(exp > Utc::now())
        })
    }

    async fn owner_of(&self, jti: &str) -> Result<Option<String>, AuthError> {
        use sqlx::Row;
        let row = sqlx::query("SELECT agent_did FROM issued_tokens WHERE jti = ?")
            .bind(jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        Ok(row.and_then(|r| r.try_get::<String, _>("agent_did").ok()))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM issued_tokens WHERE expires_at <= ?")
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| AuthError::Storage(e.to_string()))
    }
}

// ── Postgres ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PgRevocationStore {
    pool: sqlx::PgPool,
}

impl PgRevocationStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    fn block_on<F: std::future::Future<Output = T>, T>(&self, fut: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
    }
}

#[async_trait]
impl RevocationStore for PgRevocationStore {
    async fn revoke(&self, record: RevocationRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO issued_tokens (jti, agent_did, expires_at, revoked) \
             VALUES ($1, $2, $3, true) \
             ON CONFLICT (jti) DO UPDATE SET revoked = true",
        )
        .bind(&record.jti)
        .bind(&record.agent_did)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let jti = jti.to_string();
        self.block_on(async move {
            use sqlx::Row;
            let row = sqlx::query(
                "SELECT expires_at FROM issued_tokens WHERE jti = $1 AND revoked = true",
            )
            .bind(&jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?;
            let Some(row) = row else {
                return Ok(false);
            };
            let exp: DateTime<Utc> = row
                .try_get("expires_at")
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            Ok(exp > Utc::now())
        })
    }

    async fn owner_of(&self, jti: &str) -> Result<Option<String>, AuthError> {
        use sqlx::Row;
        let row = sqlx::query("SELECT agent_did FROM issued_tokens WHERE jti = $1")
            .bind(jti)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        Ok(row.and_then(|r| r.try_get::<String, _>("agent_did").ok()))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM issued_tokens WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| AuthError::Storage(e.to_string()))
    }
}
