//! Pluggable backend for the short-lived auth challenge nonces.
//!
//! Three implementations ship with this crate:
//! - [`InMemoryChallengeStore`] — `Mutex<HashMap>`-backed; suitable for the
//!   `storage-memory` configuration and tests.
//! - [`SqliteChallengeStore`] — persisted in the `auth_challenges` table.
//! - [`PgChallengeStore`] — same, Postgres-backed.
//!
//! All three implement the trait via `async-trait`; the service holds an
//! `Arc<dyn ChallengeStore>` so callers can pick a backend at runtime
//! without parameterizing the rest of the auth pipeline.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::AuthError;

/// Map a sqlx error to either `ChallengeReplay` (on a unique-constraint
/// violation — duplicate nonce) or generic `Storage`. Keeps DB backends
/// behaviorally consistent with `InMemoryChallengeStore::put`, which
/// returns `ChallengeReplay` on duplicate inserts. Without this mapping
/// log alerting and client-visible error codes diverge across backends.
fn map_insert_err(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(db_err) = &e {
        // Postgres: SQLSTATE 23505 (unique_violation).
        // SQLite: extended code 2067 / primary code 19 (constraint violation).
        let is_unique = db_err.code().as_deref() == Some("23505")
            || db_err.code().as_deref() == Some("2067")
            || db_err
                .message()
                .to_ascii_lowercase()
                .contains("unique constraint");
        if is_unique {
            return AuthError::ChallengeReplay("duplicate nonce".into());
        }
    }
    AuthError::Storage(e.to_string())
}

/// A stored challenge.
///
/// The `agent_id` is bound at issuance so a peer can't steal the nonce + signing
/// input off the wire and redeem it under their own DID. The token-issue path
/// asserts `req.agent_id == record.agent_id` before any DID resolution work.
#[derive(Debug, Clone)]
pub struct ChallengeRecord {
    pub nonce: String,
    pub agent_id: String,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Persist a new challenge. Implementations MUST refuse duplicates
    /// at the storage layer.
    async fn put(&self, record: ChallengeRecord) -> Result<(), AuthError>;

    /// Atomically consume a challenge — return `Some(_)` if the nonce
    /// existed (and was deleted) **and** is still within its expiry
    /// window. Atomicity prevents replay across racing token requests.
    async fn take(&self, nonce: &str) -> Result<Option<ChallengeRecord>, AuthError>;

    /// Evict every record whose `expires_at <= now`.
    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError>;
}

// ── In-memory ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryChallengeStore {
    inner: Mutex<HashMap<String, ChallengeRecord>>,
}

impl InMemoryChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn put(&self, record: ChallengeRecord) -> Result<(), AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        if g.contains_key(&record.nonce) {
            return Err(AuthError::ChallengeReplay("duplicate nonce".into()));
        }
        g.insert(record.nonce.clone(), record);
        Ok(())
    }

    async fn take(&self, nonce: &str) -> Result<Option<ChallengeRecord>, AuthError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AuthError::Internal("lock poisoned".into()))?;
        let rec = g.remove(nonce);
        if let Some(rec) = &rec {
            if rec.expires_at <= Utc::now() {
                return Ok(None);
            }
        }
        Ok(rec)
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
pub struct SqliteChallengeStore {
    pool: sqlx::SqlitePool,
}

impl SqliteChallengeStore {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeStore for SqliteChallengeStore {
    async fn put(&self, record: ChallengeRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_challenges (nonce, agent_id, created_at, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&record.nonce)
        .bind(&record.agent_id)
        .bind(Utc::now().to_rfc3339())
        .bind(record.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(map_insert_err)
    }

    async fn take(&self, nonce: &str) -> Result<Option<ChallengeRecord>, AuthError> {
        // DELETE … RETURNING in a single statement: SQLite serializes
        // writes, so exactly one concurrent caller wins. A previous
        // SELECT-then-DELETE-in-transaction pattern under SQLite's
        // default DEFERRED isolation could let two readers both observe
        // the row before either DELETE committed, allowing nonce replay
        // across racing token requests. SQLite supports RETURNING since
        // 3.35 (March 2021).
        use sqlx::Row;
        let row = sqlx::query(
            "DELETE FROM auth_challenges WHERE nonce = ? RETURNING agent_id, expires_at",
        )
        .bind(nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Storage(e.to_string()))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let agent_id: String = row
            .try_get("agent_id")
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        let exp: String = row
            .try_get("expires_at")
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        let expires_at = DateTime::parse_from_rfc3339(&exp)
            .map_err(|e| AuthError::Storage(e.to_string()))?
            .with_timezone(&Utc);
        if expires_at <= Utc::now() || agent_id.is_empty() {
            return Ok(None);
        }
        Ok(Some(ChallengeRecord {
            nonce: nonce.to_string(),
            agent_id,
            expires_at,
        }))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM auth_challenges WHERE expires_at <= ?")
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| AuthError::Storage(e.to_string()))
    }
}

// ── Postgres ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PgChallengeStore {
    pool: sqlx::PgPool,
}

impl PgChallengeStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeStore for PgChallengeStore {
    async fn put(&self, record: ChallengeRecord) -> Result<(), AuthError> {
        sqlx::query("INSERT INTO auth_challenges (nonce, agent_id, expires_at) VALUES ($1, $2, $3)")
            .bind(&record.nonce)
            .bind(&record.agent_id)
            .bind(record.expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_insert_err)
    }

    async fn take(&self, nonce: &str) -> Result<Option<ChallengeRecord>, AuthError> {
        // DELETE … RETURNING gives us atomic consume-or-nothing in one round-trip.
        use sqlx::Row;
        let row = sqlx::query(
            "DELETE FROM auth_challenges WHERE nonce = $1 RETURNING agent_id, expires_at",
        )
        .bind(nonce)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Storage(e.to_string()))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let agent_id: String = row
            .try_get("agent_id")
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        let expires_at: DateTime<Utc> = row
            .try_get("expires_at")
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        if expires_at <= Utc::now() || agent_id.is_empty() {
            return Ok(None);
        }
        Ok(Some(ChallengeRecord {
            nonce: nonce.to_string(),
            agent_id,
            expires_at,
        }))
    }

    async fn evict_expired(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM auth_challenges WHERE expires_at <= $1")
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

    #[tokio::test]
    async fn in_memory_take_consumes_once() {
        let store = InMemoryChallengeStore::new();
        store
            .put(ChallengeRecord {
                nonce: "n1".into(),
                agent_id: "did:web:agent.example".into(),
                expires_at: Utc::now() + chrono::Duration::seconds(60),
            })
            .await
            .unwrap();
        assert!(store.take("n1").await.unwrap().is_some());
        assert!(
            store.take("n1").await.unwrap().is_none(),
            "second take must observe the nonce as consumed (replay protection)"
        );
    }

    #[tokio::test]
    async fn in_memory_put_rejects_duplicate_nonce() {
        let store = InMemoryChallengeStore::new();
        let rec = ChallengeRecord {
            nonce: "dup".into(),
            agent_id: "did:web:agent.example".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        };
        store.put(rec.clone()).await.unwrap();
        let err = store.put(rec).await.unwrap_err();
        assert!(matches!(err, AuthError::ChallengeReplay(_)));
    }

    #[tokio::test]
    async fn sqlite_put_duplicate_nonce_returns_challenge_replay() {
        // BUG-04: the SQLite store used to surface the unique-constraint
        // violation as the generic `AuthError::Storage`, diverging from
        // `InMemoryChallengeStore::put` which returns `ChallengeReplay`.
        // After the fix the DB and in-memory variants behave identically.
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE auth_challenges (
                nonce TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = SqliteChallengeStore::new(pool);
        let rec = ChallengeRecord {
            nonce: "dup".into(),
            agent_id: "did:web:agent.example".into(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        };
        store.put(rec.clone()).await.unwrap();
        let err = store.put(rec).await.unwrap_err();
        assert!(
            matches!(err, AuthError::ChallengeReplay(_)),
            "expected ChallengeReplay, got {err:?}"
        );
    }

    #[tokio::test]
    async fn sqlite_take_is_atomic_under_contention() {
        // Regression test: previously SqliteChallengeStore::take used
        // SELECT-then-DELETE inside a DEFERRED transaction. Two concurrent
        // callers could both observe the row before either DELETE
        // committed, then return Some(rec) twice — letting an attacker
        // replay a stolen signed challenge. DELETE … RETURNING fixes that.
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE auth_challenges (\
                nonce TEXT PRIMARY KEY, \
                agent_id TEXT NOT NULL DEFAULT '', \
                created_at TEXT NOT NULL, \
                expires_at TEXT NOT NULL\
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = SqliteChallengeStore::new(pool);

        let exp = Utc::now() + chrono::Duration::seconds(60);
        store
            .put(ChallengeRecord {
                nonce: "race".into(),
                agent_id: "did:web:agent.example".into(),
                expires_at: exp,
            })
            .await
            .unwrap();

        // Fire many concurrent takes; exactly one must win.
        let store = std::sync::Arc::new(store);
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let s = store.clone();
                tokio::spawn(async move { s.take("race").await.unwrap() })
            })
            .collect();
        let mut winners = 0usize;
        for h in handles {
            if h.await.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one concurrent take must consume the nonce; got {winners}"
        );
    }
}
