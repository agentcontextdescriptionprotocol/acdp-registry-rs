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
///
/// Two writes happen per token:
/// - [`Self::record_issued`] inserts a row with `revoked = false` when a
///   JWT is minted. Without this the revocation endpoint cannot look up
///   `agent_did` ownership and every revocation attempt fails with
///   "no record for jti" (the bug fixed in commit-after-798cb34).
/// - [`Self::revoke`] flips the row to `revoked = true`. Subsequent
///   `is_revoked` checks observe the flip and `JwtSigner::validate`
///   rejects the token.
#[async_trait]
pub trait RevocationStore: Send + Sync {
    /// Persist a freshly-minted JWT. Backends MUST set `revoked = false`
    /// for the inserted row and MUST NOT downgrade an existing
    /// `revoked = true` row to `revoked = false` if the same `jti` is
    /// re-inserted (which would let a revoked token come back to life
    /// via a contrived re-issuance race).
    async fn record_issued(&self, record: RevocationRecord) -> Result<(), AuthError>;

    /// Mark `jti` as revoked. Idempotent — calling twice is harmless.
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
    inner: Mutex<HashMap<String, InMemoryEntry>>,
}

impl InMemoryRevocationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

// `revoked` is tracked alongside the record so the in-memory store
// matches the DB schema semantics (`record_issued` inserts unrevoked,
// `revoke` flips the flag).
struct InMemoryEntry {
    record: RevocationRecord,
    revoked: bool,
}

#[async_trait]
impl RevocationStore for InMemoryRevocationStore {
    async fn record_issued(&self, record: RevocationRecord) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        // Do NOT downgrade `revoked = true` rows. A future `issue_token`
        // call that happens to draw the same UUIDv4 (effectively never)
        // or any operator-triggered double-issue must not resurrect a
        // tombstoned token.
        let entry = g.entry(record.jti.clone()).or_insert(InMemoryEntry {
            record: record.clone(),
            revoked: false,
        });
        if !entry.revoked {
            entry.record = record;
        }
        Ok(())
    }

    async fn revoke(&self, record: RevocationRecord) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        g.entry(record.jti.clone())
            .and_modify(|e| e.revoked = true)
            .or_insert(InMemoryEntry {
                record,
                revoked: true,
            });
        Ok(())
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(g.get(jti)
            .is_some_and(|e| e.revoked && e.record.expires_at > Utc::now()))
    }

    async fn owner_of(&self, jti: &str) -> Result<Option<String>, AuthError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        Ok(g.get(jti).map(|e| e.record.agent_did.clone()))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        g.retain(|_, e| e.record.expires_at > now);
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
    async fn record_issued(&self, record: RevocationRecord) -> Result<(), AuthError> {
        // `DO NOTHING` rather than `DO UPDATE` preserves an existing
        // `revoked = 1` row — a duplicate jti (vanishingly unlikely with
        // UUIDv4 but possible under operator error) must not resurrect a
        // revoked token.
        sqlx::query(
            "INSERT INTO issued_tokens (jti, agent_did, expires_at, revoked) \
             VALUES (?, ?, ?, 0) \
             ON CONFLICT(jti) DO NOTHING",
        )
        .bind(&record.jti)
        .bind(&record.agent_did)
        .bind(record.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| AuthError::Storage(e.to_string()))
    }

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
    async fn record_issued(&self, record: RevocationRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO issued_tokens (jti, agent_did, expires_at, revoked) \
             VALUES ($1, $2, $3, false) \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(&record.jti)
        .bind(&record.agent_did)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| AuthError::Storage(e.to_string()))
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(jti: &str) -> RevocationRecord {
        RevocationRecord {
            jti: jti.into(),
            agent_did: "did:web:agent.example".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        }
    }

    #[tokio::test]
    async fn in_memory_record_issued_then_revoke_lifecycle() {
        let s = InMemoryRevocationStore::new();
        // 1. record_issued — owner_of returns Some, is_revoked is false.
        s.record_issued(rec("t1")).await.unwrap();
        assert_eq!(
            s.owner_of("t1").await.unwrap().as_deref(),
            Some("did:web:agent.example"),
            "the issuance must be observable by the revocation endpoint"
        );
        assert!(!s.is_revoked("t1").unwrap(), "fresh token is not revoked");

        // 2. revoke — is_revoked flips to true. owner_of still works
        //    so a subsequent attempt to re-revoke is allowed.
        s.revoke(rec("t1")).await.unwrap();
        assert!(s.is_revoked("t1").unwrap());
        assert_eq!(
            s.owner_of("t1").await.unwrap().as_deref(),
            Some("did:web:agent.example")
        );

        // 3. record_issued on a revoked jti MUST NOT resurrect it —
        //    a hostile or buggy re-issuance with a colliding uuid must
        //    not make a tombstoned token usable again.
        s.record_issued(rec("t1")).await.unwrap();
        assert!(
            s.is_revoked("t1").unwrap(),
            "re-recording an issued jti must not clear the tombstone"
        );
    }

    #[tokio::test]
    async fn in_memory_revoke_unknown_jti_creates_tombstone() {
        // Direct `revoke` (without prior record_issued) still tombstones.
        // The AuthService policy enforces caller==owner before calling this.
        let s = InMemoryRevocationStore::new();
        s.revoke(rec("t2")).await.unwrap();
        assert!(s.is_revoked("t2").unwrap());
    }

    #[tokio::test]
    async fn in_memory_evict_drops_expired_rows() {
        let s = InMemoryRevocationStore::new();
        let past = RevocationRecord {
            jti: "old".into(),
            agent_did: "did:web:agent.example".into(),
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        };
        s.record_issued(past).await.unwrap();
        s.evict_expired(Utc::now()).await.unwrap();
        assert!(
            s.owner_of("old").await.unwrap().is_none(),
            "expired rows must be evicted to keep the table bounded"
        );
    }

    // `SqliteRevocationStore::is_revoked` bridges to async via
    // `block_in_place`, which is only valid in a multi-threaded runtime.
    // Match production: `#[tokio::main]` is multi-threaded by default.
    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_record_issued_then_revoke_lifecycle() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE issued_tokens (
                jti TEXT PRIMARY KEY,
                agent_did TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let s = SqliteRevocationStore::new(pool);
        s.record_issued(rec("t1")).await.unwrap();
        assert!(!s.is_revoked("t1").unwrap());
        assert_eq!(
            s.owner_of("t1").await.unwrap().as_deref(),
            Some("did:web:agent.example")
        );
        s.revoke(rec("t1")).await.unwrap();
        assert!(s.is_revoked("t1").unwrap());
        // Tombstone-preservation: re-recording must not clear `revoked`.
        s.record_issued(rec("t1")).await.unwrap();
        assert!(s.is_revoked("t1").unwrap());
    }
}
