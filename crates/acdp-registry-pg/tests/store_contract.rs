//! Concurrency contract tests for the atomic publish commit (REG-3.3),
//! Postgres backend.
//!
//! Same scenarios as `acdp-registry-sqlite/tests/store_contract.rs`
//! (ported from the SDK's `tests/store_contract.rs`):
//!
//! 1. **Idempotency atomicity** — N racing identical publishes sharing
//!    one `(agent_id, idempotency_key)` mint exactly ONE `ctx_id`.
//! 2. **No idempotency key** — the same N racing publishes each mint a
//!    distinct context.
//! 3. **Supersession serialization** — N racing v2 publishes over one v1
//!    produce exactly ONE winner; losers get `superseded_target`.
//!
//! In Postgres the serialization comes from `SELECT ... FOR UPDATE` on
//! the predecessor / idempotency rows plus the `ON CONFLICT DO NOTHING`
//! claim on `idempotency_records` (the SQLite backend's `BEGIN
//! IMMEDIATE` analog).
//!
//! Gated the same way as `acdp-registry-server/tests/pg_integration.rs`:
//! when `ACDP_REGISTRY_TEST_PG_URL` is unset every test prints a skip
//! line and returns success, so the suite is a no-op without a database.
//! Tests only touch rows they create (fresh producers/lineages and a
//! UUID idempotency key per run), so no truncation or `serial` gating is
//! needed.

use std::sync::Arc;

use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::store::{
    PendingIdempotencyCommit, PublishCommit, PublishCommitOutcome, RegistryStore,
};
use acdp::types::primitives::{AgentDid, ContextType, Visibility};
use acdp::types::publish::{PublishRequest, PublishResponse};
use acdp_registry_pg::PgStore;
use acdp_registry_store::ExtendedRegistryStore;

const THREADS: usize = 16;
const AUTHORITY: &str = "reg.test";

fn pg_url_or_skip() -> Option<String> {
    match std::env::var("ACDP_REGISTRY_TEST_PG_URL") {
        Ok(u) => Some(u),
        Err(_) => {
            eprintln!("ACDP_REGISTRY_TEST_PG_URL unset; skipping pg store contract test");
            None
        }
    }
}

async fn store(url: &str) -> Arc<PgStore> {
    let store = PgStore::connect(url, 8).await.expect("pg connect");
    store.migrate().await.expect("pg migrate");
    Arc::new(store)
}

fn producer(seed: u8) -> Producer {
    Producer::new(
        SigningKey::from_bytes(&[seed; 32]),
        AgentDid::new(format!("did:web:agents.test:contract-{seed}")),
        format!("did:web:agents.test:contract-{seed}#key-1"),
    )
}

fn request(p: &Producer, title: &str) -> PublishRequest {
    p.publish_request()
        .title(title)
        .context_type(ContextType::DataSnapshot)
        .visibility(Visibility::Public)
        .build()
        .expect("valid publish request")
}

fn commit(
    store: Arc<PgStore>,
    req: PublishRequest,
    idem_key: Option<String>,
) -> tokio::task::JoinHandle<Result<PublishCommitOutcome, AcdpError>> {
    tokio::task::spawn_blocking(move || {
        store.commit_publish(PublishCommit {
            req: &req,
            authority: AUTHORITY,
            idempotency: idem_key.as_deref().map(|key| PendingIdempotencyCommit {
                key,
                ttl: chrono::Duration::hours(1),
            }),
            tenant: None,
            receipt_minter: None,
        })
    })
}

fn response(outcome: &PublishCommitOutcome) -> &PublishResponse {
    match outcome {
        PublishCommitOutcome::Inserted(r) | PublishCommitOutcome::IdempotentReplay(r) => r,
    }
}

/// Race N identical publishes sharing one idempotency key: exactly one
/// context is minted; every racer observes the winner's exact response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_idempotency_key_mints_exactly_one_ctx_id() {
    let Some(url) = pg_url_or_skip() else { return };
    let store = store(&url).await;
    let p = producer(21);
    let req = request(&p, "idempotent-under-race");
    // UUID key so local reruns against a persistent database never
    // collide with a previous run's record for this (agent, key).
    let key = uuid::Uuid::new_v4().to_string();

    let handles: Vec<_> = (0..THREADS)
        .map(|_| commit(Arc::clone(&store), req.clone(), Some(key.clone())))
        .collect();
    let mut outcomes = Vec::new();
    for h in handles {
        outcomes.push(
            h.await
                .unwrap()
                .expect("every replay of an identical publish must succeed"),
        );
    }

    let winner = response(&outcomes[0]).clone();
    for o in &outcomes {
        let r = response(o);
        assert_eq!(r.ctx_id, winner.ctx_id, "all racers observe one ctx_id");
        assert_eq!(r.lineage_id, winner.lineage_id);
        assert_eq!(r.created_at, winner.created_at, "replay is byte-identical");
        assert_eq!(r.version, winner.version);
    }
    let inserted = outcomes
        .iter()
        .filter(|o| matches!(o, PublishCommitOutcome::Inserted(_)))
        .count();
    assert_eq!(inserted, 1, "exactly one publish inserts; the rest replay");

    // Exactly one context persisted under the lineage.
    let lineage = store.lineage(&winner.lineage_id).expect("lineage query");
    assert_eq!(lineage.len(), 1, "exactly one persisted context");
}

/// Without an idempotency key, the same N racing publishes all mint
/// distinct contexts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_publishes_without_idempotency_all_mint_distinct() {
    let Some(url) = pg_url_or_skip() else { return };
    let store = store(&url).await;
    let p = producer(22);
    let req = request(&p, "no-idem-under-race");

    let handles: Vec<_> = (0..THREADS)
        .map(|_| commit(Arc::clone(&store), req.clone(), None))
        .collect();
    let mut ctx_ids = Vec::new();
    for h in handles {
        let outcome = h.await.unwrap().expect("publish succeeds");
        ctx_ids.push(response(&outcome).ctx_id.as_str().to_string());
    }

    ctx_ids.sort();
    ctx_ids.dedup();
    assert_eq!(
        ctx_ids.len(),
        THREADS,
        "every racing publish mints its own ctx_id when no idempotency key is given"
    );
}

/// Race N distinct v2 publishes superseding the same v1: exactly one
/// winner; every loser fails with `superseded_target`; the stored
/// lineage is exactly [v1, winning v2].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_supersession_has_exactly_one_winner() {
    let Some(url) = pg_url_or_skip() else { return };
    let store = store(&url).await;
    let p = producer(23);

    let v1_outcome = commit(Arc::clone(&store), request(&p, "v1"), None)
        .await
        .unwrap()
        .expect("v1 publish");
    let v1_resp = response(&v1_outcome).clone();
    let v1_body = store
        .get(&v1_resp.ctx_id)
        .expect("retrieve ok")
        .expect("v1 present")
        .body;

    // N DISTINCT v2 requests (different titles → different content
    // hashes), all targeting the same predecessor.
    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let req = p
                .supersede_body(&v1_body)
                .title(format!("v2-candidate-{i}"))
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .expect("valid v2 request");
            commit(Arc::clone(&store), req, None)
        })
        .collect();
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }

    let (winners, losers): (Vec<_>, Vec<_>) = results.into_iter().partition(|r| r.is_ok());
    assert_eq!(winners.len(), 1, "exactly one supersession wins the race");
    for loser in &losers {
        let err = loser.as_ref().unwrap_err();
        assert!(
            matches!(err, AcdpError::SupersededTarget { .. }),
            "losers MUST fail with superseded_target, got {err:?}"
        );
    }

    let winner = response(&winners.into_iter().next().unwrap().unwrap()).clone();
    assert_eq!(winner.version, 2);
    assert_eq!(winner.lineage_id, v1_resp.lineage_id, "same lineage");

    // Lineage is exactly [v1 superseded, winning v2 active].
    let lineage = store.lineage(&v1_resp.lineage_id).expect("lineage query");
    assert_eq!(lineage.len(), 2, "exactly v1 + the single winning v2");
    assert_eq!(lineage[1].body.ctx_id, winner.ctx_id);
    let current = store
        .current(&v1_resp.lineage_id)
        .expect("current query")
        .expect("current exists");
    assert_eq!(current.body.ctx_id, winner.ctx_id);
}

// ─── Lifecycle events (RFC-ACDP-0013): the commit_lifecycle_event contract ───

mod lifecycle {
    use super::*;
    use acdp::registry::LifecycleCommitOutcome;
    use acdp::types::lifecycle::{LifecycleEvent, LifecycleEventType};
    use acdp::types::primitives::{CtxId, LineageId, Status};

    fn event(
        actor: &AgentDid,
        ctx_id: &CtxId,
        event_type: LifecycleEventType,
        reason: Option<&str>,
    ) -> LifecycleEvent {
        event_with_id(
            &uuid::Uuid::new_v4().to_string(),
            actor,
            ctx_id,
            event_type,
            reason,
        )
    }

    fn event_with_id(
        event_id: &str,
        actor: &AgentDid,
        ctx_id: &CtxId,
        event_type: LifecycleEventType,
        reason: Option<&str>,
    ) -> LifecycleEvent {
        // Signature verification is the SERVER's §6 step 3; the store
        // contract is exercised with unsigned events.
        LifecycleEvent::new(
            event_id.to_string(),
            ctx_id.clone(),
            event_type,
            chrono::Utc::now(),
            actor.clone(),
            reason.map(str::to_string),
        )
        .expect("valid event")
    }

    async fn published_ctx(store: &Arc<PgStore>, seed: u8, title: &str) -> (CtxId, LineageId) {
        let p = producer(seed);
        let outcome = commit(Arc::clone(store), request(&p, title), None)
            .await
            .unwrap()
            .unwrap();
        let r = response(&outcome);
        (r.ctx_id.clone(), r.lineage_id.clone())
    }

    /// Mirrors the SQLite `lifecycle_commit_contract` — see that test for
    /// the step-by-step rationale. The shared Postgres database is not
    /// truncated here, so search assertions key on a per-run unique token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lifecycle_commit_contract() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = store(&url).await;
        let actor = AgentDid::new("did:web:agents.test:contract-61".to_string());
        let token = format!("lc{}", uuid::Uuid::new_v4().simple());
        let (ctx_id, lineage_id) = published_ctx(&store, 61, &token).await;

        // Unknown ctx → NotFound (visibility is the server's job).
        let ghost = CtxId(format!(
            "acdp://{AUTHORITY}/00000000-0000-4000-8000-0000000000bb"
        ));
        let ghost_event = event(&actor, &ghost, LifecycleEventType::Retracted, None);
        assert!(matches!(
            store.commit_lifecycle_event(&ghost_event),
            Err(AcdpError::NotFound(_))
        ));

        // Retract → Applied with the §7.2-projected state.
        let retract = event(
            &actor,
            &ctx_id,
            LifecycleEventType::Retracted,
            Some("bad data"),
        );
        let ctx = match store.commit_lifecycle_event(&retract).unwrap() {
            LifecycleCommitOutcome::Applied(c) => c,
            other => panic!("expected Applied, got {other:?}"),
        };
        assert!(matches!(ctx.registry_state.status, Status::Retracted));
        assert_eq!(
            ctx.registry_state
                .lifecycle_events
                .as_deref()
                .unwrap()
                .len(),
            1
        );

        // Projections: get(), current(), and the search status filter.
        let got = store.get(&ctx_id).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Retracted));
        assert_eq!(got.body.title, token);
        assert_eq!(
            got.registry_state.lifecycle_events.as_deref().unwrap(),
            std::slice::from_ref(&retract)
        );
        assert!(store.current(&lineage_id).unwrap().is_none());
        let default_search = store
            .search(
                &acdp::types::search::SearchParams {
                    q: Some(token.clone()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert!(default_search.matches.is_empty());
        let retracted_search = store
            .search(
                &acdp::types::search::SearchParams {
                    q: Some(token.clone()),
                    status: Some("retracted".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(retracted_search.matches.len(), 1);

        // Byte-identical retry → IdempotentReplay, nothing appended.
        let ctx = match store.commit_lifecycle_event(&retract).unwrap() {
            LifecycleCommitOutcome::IdempotentReplay(c) => c,
            other => panic!("expected IdempotentReplay, got {other:?}"),
        };
        assert_eq!(
            ctx.registry_state
                .lifecycle_events
                .as_deref()
                .unwrap()
                .len(),
            1
        );

        // Same event_id, different content → SchemaViolation.
        let divergent = event_with_id(
            &retract.event_id,
            &actor,
            &ctx_id,
            LifecycleEventType::Retracted,
            Some("a different reason"),
        );
        assert!(matches!(
            store.commit_lifecycle_event(&divergent),
            Err(AcdpError::SchemaViolation(_))
        ));

        // Double retract (fresh id) → InvalidLifecycleTransition.
        let double = event(&actor, &ctx_id, LifecycleEventType::Retracted, None);
        assert!(matches!(
            store.commit_lifecycle_event(&double),
            Err(AcdpError::InvalidLifecycleTransition(_))
        ));

        // Unregistered event_type → SchemaViolation (§7.3).
        let unregistered = event(
            &actor,
            &ctx_id,
            LifecycleEventType::Other("annotated".into()),
            None,
        );
        assert!(matches!(
            store.commit_lifecycle_event(&unregistered),
            Err(AcdpError::SchemaViolation(_))
        ));

        // Republish reverses; both events retained; head restored.
        let republish = event(&actor, &ctx_id, LifecycleEventType::Republished, None);
        let ctx = store
            .commit_lifecycle_event(&republish)
            .unwrap()
            .into_context();
        assert!(matches!(ctx.registry_state.status, Status::Active));
        assert_eq!(
            ctx.registry_state
                .lifecycle_events
                .as_deref()
                .unwrap()
                .len(),
            2
        );
        assert!(store.current(&lineage_id).unwrap().is_some());

        // Republish of a not-retracted context → InvalidLifecycleTransition.
        let spurious = event(&actor, &ctx_id, LifecycleEventType::Republished, None);
        assert!(matches!(
            store.commit_lifecycle_event(&spurious),
            Err(AcdpError::InvalidLifecycleTransition(_))
        ));
    }

    /// N concurrent retracts (distinct event_ids) racing the same
    /// context: exactly ONE applies (the `FOR UPDATE` row lock is the
    /// serialization point); every loser gets the contract outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_retracts_have_exactly_one_winner() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = store(&url).await;
        let actor = AgentDid::new("did:web:agents.test:contract-62".to_string());
        let token = format!("lcrace{}", uuid::Uuid::new_v4().simple());
        let (ctx_id, _) = published_ctx(&store, 62, &token).await;

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let store = Arc::clone(&store);
                let e = event(&actor, &ctx_id, LifecycleEventType::Retracted, None);
                tokio::task::spawn_blocking(move || store.commit_lifecycle_event(&e))
            })
            .collect();
        let mut applied = 0usize;
        let mut conflicts = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(LifecycleCommitOutcome::Applied(_)) => applied += 1,
                Ok(LifecycleCommitOutcome::IdempotentReplay(_)) => {
                    panic!("distinct event_ids can never replay")
                }
                Err(AcdpError::InvalidLifecycleTransition(_)) => conflicts += 1,
                Err(other) => panic!("unexpected error under race: {other:?}"),
            }
        }
        assert_eq!(applied, 1, "exactly one retract wins");
        assert_eq!(conflicts, THREADS - 1, "every loser gets the 409 outcome");

        let ctx = store.get(&ctx_id).unwrap().unwrap();
        assert_eq!(
            ctx.registry_state
                .lifecycle_events
                .as_deref()
                .unwrap()
                .len(),
            1,
            "append-only history carries exactly the winner"
        );
    }
}

// ─── ACDP 0.3.0: transparency log (RFC-ACDP-0012) ──────────────────────────
//
// Same env-gating as the tests above. The shared truncate-less database
// accretes rows across runs, so these tests assert PER-PUBLISH and
// GLOBAL-INVARIANT properties (leaf presence, byte-exact reproducibility,
// index density) rather than absolute counts.

mod transparency_log {
    use super::*;
    use acdp::types::body::Body;
    use acdp::types::log::{decode_sha256_hex, encode_sha256_hex};
    use acdp::types::receipt::ReceiptSigner;

    const REGISTRY_DID: &str = "did:web:reg.test";

    async fn log_store(url: &str) -> Arc<PgStore> {
        let store = PgStore::connect(url, 8)
            .await
            .expect("pg connect")
            .with_transparency_log();
        store.migrate().await.expect("pg migrate");
        Arc::new(store)
    }

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[99u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
    }

    fn mint_fn(
        signer: ReceiptSigner,
    ) -> impl Fn(&Body) -> Result<serde_json::Value, AcdpError> + Send + Sync {
        move |body: &Body| {
            let receipt = signer.mint(
                &body.ctx_id,
                &body.lineage_id,
                &body.origin_registry,
                body.created_at,
                &body.content_hash,
                &format!("sha256:{}", "c".repeat(64)),
            )?;
            serde_json::to_value(receipt).map_err(AcdpError::from)
        }
    }

    /// Run-unique producer so assertions never collide with prior runs
    /// against the shared database.
    fn unique_producer() -> (Producer, String) {
        let seed: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&seed);
        key[16..].copy_from_slice(&seed);
        let did = format!("did:web:agents.test:log-{}", uuid::Uuid::new_v4().simple());
        (
            Producer::new(
                SigningKey::from_bytes(&key),
                AgentDid::new(did.clone()),
                format!("{did}#key-1"),
            ),
            did,
        )
    }

    /// §7.1 + §4/§5.1: the leaf commits with the publish, is retrievable
    /// by ctx_id and index, its stored bytes reproduce its stored hash,
    /// the global index stays dense, and the leaf's own inclusion path
    /// folds to the head root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn logged_publish_appends_reproducible_leaf() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = log_store(&url).await;
        let (p, _did) = unique_producer();
        let req = request(&p, "pg-log-leaf");
        let mint = mint_fn(signer());
        let outcome = tokio::task::block_in_place(|| {
            store.commit_publish(PublishCommit {
                req: &req,
                authority: AUTHORITY,
                idempotency: None,
                tenant: None,
                receipt_minter: Some(&mint),
            })
        })
        .expect("logged publish succeeds");
        let ctx_id = response(&outcome).ctx_id.as_str().to_string();

        let record = store
            .log_leaf_by_ctx(&ctx_id)
            .await
            .unwrap()
            .expect("leaf exists the moment the publish response does (§7.1)");
        // Byte-exact reproducibility (§5.1).
        let rehashed = acdp::crypto::merkle::leaf_hash(record.leaf_json.as_bytes());
        assert_eq!(encode_sha256_hex(&rehashed), record.leaf_hash);
        assert_eq!(
            record.leaf().unwrap().leaf_hash_hex().unwrap(),
            record.leaf_hash
        );
        let by_idx = store
            .log_leaf_by_index(record.leaf_index)
            .await
            .unwrap()
            .expect("index-addressed lookup agrees");
        assert_eq!(by_idx.ctx_id, ctx_id);

        // Global density + the leaf's inclusion path folds to the root.
        let size = store.log_tree_size().await.unwrap();
        let hashes = store.log_leaf_hashes(size).await.unwrap();
        assert_eq!(hashes.len() as u64, size, "dense indexes (§5.3)");
        let path =
            acdp::crypto::merkle::inclusion_path(record.leaf_index as usize, &hashes).unwrap();
        let root = acdp::crypto::merkle::merkle_tree_hash(&hashes);
        assert!(
            acdp::crypto::merkle::verify_inclusion(
                &decode_sha256_hex(&record.leaf_hash).unwrap(),
                record.leaf_index,
                size,
                &path,
                &root,
            ),
            "stored leaf proves against the recomputed head root (§9.1)"
        );
    }

    /// §7.1/§11 no degraded mode: no receipt → the whole publish fails,
    /// nothing persists for this producer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publish_without_receipt_minter_is_refused_entirely() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = log_store(&url).await;
        let (p, did) = unique_producer();
        let req = request(&p, "pg-log-no-receipt");
        let err = tokio::task::block_in_place(|| {
            store.commit_publish(PublishCommit {
                req: &req,
                authority: AUTHORITY,
                idempotency: None,
                tenant: None,
                receipt_minter: None,
            })
        })
        .expect_err("log-enabled publish without a receipt must fail");
        assert!(matches!(err, AcdpError::RegistryInternal(_)), "{err:?}");
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM contexts WHERE agent_id = $1")
            .bind(&did)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0, "no context row survives (§7.1)");
    }

    /// §7.1 crash-consistency: a failing minter aborts everything — no
    /// context row, no orphan leaf, density preserved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failing_minter_leaves_no_orphan_leaf() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = log_store(&url).await;
        let (p, did) = unique_producer();
        let req = request(&p, "pg-log-minter-fails");
        let failing = |_: &Body| -> Result<serde_json::Value, AcdpError> {
            Err(AcdpError::RegistryInternal("kms outage".into()))
        };
        let err = tokio::task::block_in_place(|| {
            store.commit_publish(PublishCommit {
                req: &req,
                authority: AUTHORITY,
                idempotency: None,
                tenant: None,
                receipt_minter: Some(&failing),
            })
        })
        .expect_err("failing minter must abort the publish");
        assert!(matches!(err, AcdpError::RegistryInternal(_)), "{err:?}");
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM contexts WHERE agent_id = $1")
            .bind(&did)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(n, 0);
        let size = store.log_tree_size().await.unwrap();
        assert_eq!(
            store.log_leaf_hashes(size).await.unwrap().len() as u64,
            size,
            "log stays dense — no orphan leaf (§5.3/§7.1)"
        );
    }

    /// §5.3 under concurrency: racing logged publishes serialize on the
    /// pg_advisory_xact_lock and still assign dense, unique indexes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_logged_publishes_assign_dense_indexes() {
        let Some(url) = pg_url_or_skip() else { return };
        let store = log_store(&url).await;
        let handles: Vec<_> = (0..6)
            .map(|i| {
                let store = Arc::clone(&store);
                tokio::task::spawn_blocking(move || {
                    let (p, _) = unique_producer();
                    let req = request(&p, &format!("pg-log-race-{i}"));
                    let mint = mint_fn(signer());
                    store.commit_publish(PublishCommit {
                        req: &req,
                        authority: AUTHORITY,
                        idempotency: None,
                        tenant: None,
                        receipt_minter: Some(&mint),
                    })
                })
            })
            .collect();
        let mut ctx_ids = Vec::new();
        for h in handles {
            let outcome = h.await.unwrap().expect("every racer commits");
            ctx_ids.push(response(&outcome).ctx_id.as_str().to_string());
        }
        let size = store.log_tree_size().await.unwrap();
        let hashes = store.log_leaf_hashes(size).await.unwrap();
        assert_eq!(hashes.len() as u64, size, "dense after the race (§5.3)");
        // Every racer's leaf landed at a distinct index.
        let mut indexes = Vec::new();
        for ctx_id in &ctx_ids {
            indexes.push(
                store
                    .log_leaf_by_ctx(ctx_id)
                    .await
                    .unwrap()
                    .expect("leaf per racer")
                    .leaf_index,
            );
        }
        indexes.sort_unstable();
        indexes.dedup();
        assert_eq!(indexes.len(), ctx_ids.len(), "unique leaf indexes");
    }
}
