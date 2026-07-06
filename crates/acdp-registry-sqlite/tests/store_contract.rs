//! Concurrency contract tests for the atomic publish commit (REG-3.3).
//!
//! Ports the SDK's `tests/store_contract.rs` scenarios (written against
//! the reference `InMemoryStore`) to the SQLite backend, driving the
//! same `RegistryStore::commit_publish` contract:
//!
//! 1. **Idempotency atomicity** — N concurrent publishes sharing an
//!    `(agent_id, idempotency_key)` mint exactly ONE `ctx_id`; every
//!    racer observes the winner's exact response (RFC-ACDP-0003 §6.2.2).
//! 2. **No idempotency key** — the same N racing publishes each mint a
//!    distinct context (the key is absent, not half-honored).
//! 3. **Supersession serialization** — N concurrent v2 publishes racing
//!    to supersede the same v1 produce exactly ONE winner; every loser
//!    fails with `superseded_target` (RFC-ACDP-0003 §3.1 step 6,
//!    RFC-ACDP-0008 §3.10).
//!
//! `commit_publish` is a sync API that drives async sqlx through
//! `block_in_place`, so every racer runs on the tokio blocking pool
//! (`spawn_blocking`) under a multi-threaded runtime — the same setup as
//! the crate's in-module `commit_publish` race tests.

use std::sync::Arc;

use acdp::crypto::SigningKey;
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::registry::store::{
    PendingIdempotencyCommit, PublishCommit, PublishCommitOutcome, RegistryStore,
};
use acdp::types::primitives::{AgentDid, ContextType, Visibility};
use acdp::types::publish::{PublishRequest, PublishResponse};
use acdp_registry_sqlite::SqliteStore;
use acdp_registry_store::ExtendedRegistryStore;

const THREADS: usize = 16;
const AUTHORITY: &str = "reg.test";

async fn store() -> (Arc<SqliteStore>, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let store = SqliteStore::connect(tmp.path(), 4).await.unwrap();
    store.migrate().await.unwrap();
    (Arc::new(store), tmp)
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
    store: Arc<SqliteStore>,
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
    let (store, _tmp) = store().await;
    let p = producer(21);
    let req = request(&p, "idempotent-under-race");

    let handles: Vec<_> = (0..THREADS)
        .map(|_| commit(Arc::clone(&store), req.clone(), Some("contract-key".into())))
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
    let (store, _tmp) = store().await;
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
    let (store, _tmp) = store().await;
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

    async fn published_ctx(store: &Arc<SqliteStore>, seed: u8, title: &str) -> (CtxId, LineageId) {
        let p = producer(seed);
        let outcome = commit(Arc::clone(store), request(&p, title), None)
            .await
            .unwrap()
            .unwrap();
        let r = response(&outcome);
        (r.ctx_id.clone(), r.lineage_id.clone())
    }

    /// The documented 4-step atomic contract: resolve, retry-idempotency,
    /// strict alternation, append+status-effect — plus the read-side
    /// projections (§7.2 precedence, §8.2 search exclusion, §8.3 head
    /// exclusion) driven by the same committed state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lifecycle_commit_contract() {
        let (store, _tmp) = store().await;
        let actor = AgentDid::new("did:web:agents.test:contract-61".to_string());
        let (ctx_id, lineage_id) = published_ctx(&store, 61, "lifecycle contract row").await;

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
        let applied = store.commit_lifecycle_event(&retract).unwrap();
        let ctx = match applied {
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

        // Projections: get() serves the retracted status with the body
        // intact and the events attached; current() excludes the head;
        // default search excludes, status=retracted finds.
        let got = store.get(&ctx_id).unwrap().unwrap();
        assert!(matches!(got.registry_state.status, Status::Retracted));
        assert_eq!(got.body.title, "lifecycle contract row");
        assert_eq!(
            got.registry_state.lifecycle_events.as_deref().unwrap(),
            std::slice::from_ref(&retract)
        );
        assert!(store.current(&lineage_id).unwrap().is_none());
        let default_search = store
            .search(
                &acdp::types::search::SearchParams {
                    q: Some("lifecycle contract row".into()),
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
                    q: Some("lifecycle contract row".into()),
                    status: Some("retracted".into()),
                    ..Default::default()
                },
                None,
                true,
            )
            .unwrap();
        assert_eq!(retracted_search.matches.len(), 1);

        // Byte-identical retry → IdempotentReplay, nothing appended.
        let replay = store.commit_lifecycle_event(&retract).unwrap();
        let ctx = match replay {
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
    /// context: exactly ONE applies; every loser gets the contract
    /// outcome (`invalid_lifecycle_transition`), never a lost update or
    /// a double append.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_retracts_have_exactly_one_winner() {
        let (store, _tmp) = store().await;
        let actor = AgentDid::new("did:web:agents.test:contract-62".to_string());
        let (ctx_id, _) = published_ctx(&store, 62, "race retract").await;

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

mod transparency_log {
    use super::*;
    use acdp::types::body::Body;
    use acdp::types::log::{decode_sha256_hex, encode_sha256_hex};
    use acdp::types::receipt::ReceiptSigner;

    const REGISTRY_DID: &str = "did:web:reg.test";

    async fn log_store() -> (Arc<SqliteStore>, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 4)
            .await
            .unwrap()
            .with_transparency_log();
        store.migrate().await.unwrap();
        (Arc::new(store), tmp)
    }

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new(
            acdp::crypto::SigningKey::from_bytes(&[99u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
    }

    /// RFC-ACDP-0010 minter closure of the exact shape `RegistryServer`
    /// threads through `PublishCommit::receipt_minter`.
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

    async fn counts(store: &SqliteStore) -> (i64, i64) {
        let (contexts,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM contexts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let (leaves,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM log_leaves")
            .fetch_one(store.pool())
            .await
            .unwrap();
        (contexts, leaves)
    }

    /// §7.1: the leaf commits with the publish; §5.3: dense acceptance-
    /// order indexes; §4/§5.1: the stored bytes reproduce the stored
    /// hash; leaf count always equals context count under the profile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn leaf_commits_atomically_and_is_reproducible() {
        let (store, _tmp) = log_store().await;
        let mint = mint_fn(signer());
        let mut ctx_ids = Vec::new();
        for i in 0..3u8 {
            let p = producer(140 + i);
            let req = request(&p, &format!("log-{i}"));
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
            ctx_ids.push(response(&outcome).ctx_id.as_str().to_string());
        }

        assert_eq!(store.log_tree_size().await.unwrap(), 3);
        let (contexts, leaves) = counts(&store).await;
        assert_eq!(contexts, 3);
        assert_eq!(
            leaves, 3,
            "leaf count ≡ context count under the profile (§7.1)"
        );

        let entries = store.log_entries(0, 3).await.unwrap();
        assert_eq!(entries.len(), 3);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(
                e.leaf_index, i as u64,
                "dense acceptance-order indexes (§5.3)"
            );
            assert_eq!(
                e.ctx_id, ctx_ids[i],
                "one leaf per ctx_id, in acceptance order"
            );
            // Reproducibility: rehash the exact stored bytes (§5.1).
            let rehashed = acdp::crypto::merkle::leaf_hash(e.leaf_json.as_bytes());
            assert_eq!(encode_sha256_hex(&rehashed), e.leaf_hash);
            // The stored bytes parse through the closed §4 schema and
            // hash identically through the typed path.
            assert_eq!(e.leaf().unwrap().leaf_hash_hex().unwrap(), e.leaf_hash);
            // Point lookups agree.
            let by_ctx = store.log_leaf_by_ctx(&e.ctx_id).await.unwrap().unwrap();
            assert_eq!(by_ctx.leaf_index, e.leaf_index);
            assert_eq!(by_ctx.leaf_json, e.leaf_json);
            let by_idx = store
                .log_leaf_by_index(e.leaf_index)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(by_idx.ctx_id, e.ctx_id);
        }
        // The density-checked hash projection succeeds and matches.
        let hashes = store.log_leaf_hashes(3).await.unwrap();
        assert_eq!(hashes.len(), 3);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(hashes[i], decode_sha256_hex(&e.leaf_hash).unwrap());
        }
    }

    /// §7.1/§11 no degraded mode: a log-enabled store REFUSES a publish
    /// that arrives without a receipt minter — nothing is persisted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publish_without_receipt_minter_is_refused_entirely() {
        let (store, _tmp) = log_store().await;
        let p = producer(150);
        let req = request(&p, "no-receipt");
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
        assert_eq!(counts(&store).await, (0, 0), "nothing persists (§7.1)");
    }

    /// §7.1 crash-consistency: a failing receipt minter aborts the whole
    /// publish — no context row, no orphan leaf.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failing_minter_leaves_no_orphan_leaf() {
        let (store, _tmp) = log_store().await;
        let p = producer(151);
        let req = request(&p, "minter-fails");
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
        assert_eq!(
            counts(&store).await,
            (0, 0),
            "no orphan leaf or context (§7.1)"
        );
    }

    /// §5.3 under concurrency: racing logged publishes serialize on
    /// BEGIN IMMEDIATE and still assign dense, unique leaf indexes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_logged_publishes_assign_dense_indexes() {
        let (store, _tmp) = log_store().await;
        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let store = Arc::clone(&store);
                tokio::task::spawn_blocking(move || {
                    let p = producer(160 + i);
                    let req = request(&p, &format!("race-{i}"));
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
        for h in handles {
            h.await.unwrap().expect("every racer commits");
        }
        assert_eq!(store.log_tree_size().await.unwrap(), 8);
        // log_leaf_hashes enforces density over [0, 8).
        assert_eq!(store.log_leaf_hashes(8).await.unwrap().len(), 8);
        assert_eq!(counts(&store).await, (8, 8));
    }

    // ── Witness cosignature aggregation (RFC-ACDP-0015 §6.1) ───────────

    const LOG_ID: &str = "did:web:reg.test/log/1";
    const ROOT_5: &str = "sha256:0b00000000000000000000000000000000000000000000000000000000000000";
    const WITNESS_A: &str = "did:web:witness-a.example.org";
    const WITNESS_B: &str = "did:web:witness-b.example.org";

    fn cosig_json(witness: &str, at: &str) -> String {
        // A stand-in wire object; the store treats it as opaque bytes and
        // serves it back verbatim (verification happens in the aggregator).
        format!(r#"{{"witness_id":"{witness}","witnessed_at":"{at}"}}"#)
    }

    /// Upsert + read-back by the exact tuple, distinct witnesses counted
    /// once each, and tuple isolation (a cosignature for another
    /// tree_size/root is never returned for this one).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn witness_cosignatures_store_and_read_by_tuple() {
        let (store, _tmp) = log_store().await;

        // Two witnesses over the same (log_id, 5, ROOT_5) tuple.
        store
            .upsert_witness_cosignature(
                LOG_ID,
                5,
                ROOT_5,
                WITNESS_A,
                "2026-07-05T00:00:00.000Z",
                &cosig_json(WITNESS_A, "2026-07-05T00:00:00.000Z"),
            )
            .await
            .unwrap();
        store
            .upsert_witness_cosignature(
                LOG_ID,
                5,
                ROOT_5,
                WITNESS_B,
                "2026-07-05T00:00:01.000Z",
                &cosig_json(WITNESS_B, "2026-07-05T00:00:01.000Z"),
            )
            .await
            .unwrap();
        // A cosignature over a DIFFERENT tuple (size 6) must not leak in.
        let root_6 = format!("sha256:{}", "a".repeat(64));
        store
            .upsert_witness_cosignature(
                LOG_ID,
                6,
                &root_6,
                WITNESS_A,
                "2026-07-05T00:00:02.000Z",
                &cosig_json(WITNESS_A, "2026-07-05T00:00:02.000Z"),
            )
            .await
            .unwrap();

        let got = store
            .witness_cosignatures_for(LOG_ID, 5, ROOT_5)
            .await
            .unwrap();
        assert_eq!(got.len(), 2, "both distinct witnesses over the tuple");
        // Ordered by witness_did — A before B.
        assert_eq!(got[0]["witness_id"], WITNESS_A);
        assert_eq!(got[1]["witness_id"], WITNESS_B);

        // The size-6 tuple returns only its own cosignature.
        let got6 = store
            .witness_cosignatures_for(LOG_ID, 6, &root_6)
            .await
            .unwrap();
        assert_eq!(got6.len(), 1);
        assert_eq!(got6[0]["witness_id"], WITNESS_A);

        // A tuple with no cosignatures is empty, never an error.
        assert!(store
            .witness_cosignatures_for(LOG_ID, 99, ROOT_5)
            .await
            .unwrap()
            .is_empty());
    }

    /// A fresh re-observation from the same witness at the same tuple
    /// UPSERTs (newest witnessed_at wins) — one row per witness per tuple,
    /// cosignatures being ephemeral per-observation evidence (§4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn witness_cosignature_reobservation_upserts() {
        let (store, _tmp) = log_store().await;
        store
            .upsert_witness_cosignature(
                LOG_ID,
                5,
                ROOT_5,
                WITNESS_A,
                "2026-07-05T00:00:00.000Z",
                &cosig_json(WITNESS_A, "2026-07-05T00:00:00.000Z"),
            )
            .await
            .unwrap();
        store
            .upsert_witness_cosignature(
                LOG_ID,
                5,
                ROOT_5,
                WITNESS_A,
                "2026-07-05T01:00:00.000Z",
                &cosig_json(WITNESS_A, "2026-07-05T01:00:00.000Z"),
            )
            .await
            .unwrap();
        let got = store
            .witness_cosignatures_for(LOG_ID, 5, ROOT_5)
            .await
            .unwrap();
        assert_eq!(got.len(), 1, "one row per (tuple, witness)");
        assert_eq!(
            got[0]["witnessed_at"], "2026-07-05T01:00:00.000Z",
            "newest wins"
        );
    }

    // ── log-001 golden fixture (spec schemas/conformance) ─────────────
    //
    // The fixture's ctx_ids live on registry.example.com, not this test
    // authority, so its leaves cannot arrive through publish; per the
    // fixture's own guidance the root reproduction is exercised at the
    // store layer: the pinned JCS leaf encodings are inserted as stored
    // rows and the store's hash projection must reproduce every pinned
    // §5.1 leaf hash, the pinned tree-size-5 root, and the pinned
    // inclusion path for leaf 0.

    const LOG_001_LEAVES: [&str; 5] = [
        r#"{"content_hash":"sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5","created_at":"2026-04-16T10:30:15.123Z","ctx_id":"acdp://registry.example.com/12345678-1234-4321-8123-123456781234","key_fingerprint":"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070","leaf_version":"acdp-log-leaf/1","lineage_id":"lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a","origin_registry":"registry.example.com","receipt_hash":"sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf"}"#,
        r#"{"content_hash":"sha256:5b8be477da9b3e1354ebf2868494acb702301aaa825c1c3af3f92c5536ba7bd1","created_at":"2026-07-01T01:00:00.000Z","ctx_id":"acdp://registry.example.com/00000000-0000-4000-8000-000000000001","key_fingerprint":"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070","leaf_version":"acdp-log-leaf/1","lineage_id":"lin:sha256:a65dce2bc7d3d2f52513c14c9d7262903c960490b17308b272981240a76c2d42","origin_registry":"registry.example.com","receipt_hash":"sha256:2b8fa37afe87358aa039e78802f4a9b9fb4bc5df2a814a3f7cf5200f7f64b3df"}"#,
        r#"{"content_hash":"sha256:a0c8d76890ec38db8791e82d7a8e24194f84c13ae67bdaa167540b58cb95507b","created_at":"2026-07-02T02:00:00.000Z","ctx_id":"acdp://registry.example.com/00000000-0000-4000-8000-000000000002","key_fingerprint":"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070","leaf_version":"acdp-log-leaf/1","lineage_id":"lin:sha256:518c191ba24d2fea433a768e232cb1d0ff152a39b38f28ac7f91960c9f8f7aba","origin_registry":"registry.example.com","receipt_hash":"sha256:591fa4c29669546b777bd1a4583aa724e9586b083c096d4b62f68b630dd18834"}"#,
        r#"{"content_hash":"sha256:acbd2ea0c5608db56e1bd38bb0145a6f8363b30d8610abb746014a11f1a53c55","created_at":"2026-07-03T03:00:00.000Z","ctx_id":"acdp://registry.example.com/00000000-0000-4000-8000-000000000003","key_fingerprint":"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070","leaf_version":"acdp-log-leaf/1","lineage_id":"lin:sha256:1d941fb2ecdad88db6f9f3ecd5993178ab94f72e1061e685441d11ef04d92c05","origin_registry":"registry.example.com","receipt_hash":"sha256:342e57dc6d174cc7fe974c99f16c19ba598dfa31f41e560112db3f5ef21c5d91"}"#,
        r#"{"content_hash":"sha256:6f72132b15b294cea2e753efc9b7a105d6d7ebd1527adecd9f2bfc7a677a129b","created_at":"2026-07-04T04:00:00.000Z","ctx_id":"acdp://registry.example.com/00000000-0000-4000-8000-000000000004","key_fingerprint":"sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070","leaf_version":"acdp-log-leaf/1","lineage_id":"lin:sha256:c1987e0ba3e82db332daaafd64547aa6cbb66f191d53d2023a0ff78dc6c07063","origin_registry":"registry.example.com","receipt_hash":"sha256:88ee7b664509a56dbd597ccd2f8e19c39e0aaf2c75133d0b73781ce14cf5169f"}"#,
    ];

    const LOG_001_LEAF_HASHES: [&str; 5] = [
        "sha256:95d99654d4d3de54a4d7cc04e079de61135023c78bb8192bdb79a09253afb8c1",
        "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
        "sha256:db94dd74b5c68f6d362129703ea587c8756d65cad0cc9859829021746a114451",
        "sha256:dc309b7856483acb5b2a92323dd9c1571a778bdb7b446587100022b49ee5fb3b",
        "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
    ];

    const LOG_001_ROOT: &str =
        "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731";

    const LOG_001_INCLUSION_PATH_LEAF_0: [&str; 3] = [
        "sha256:846b4d6c07ca099eea348c1e219345ddd426c0531cc30d3dd626d0fa34ec7704",
        "sha256:54d7edc4ba9d151eedd7f4bb872884f0af5ff32b39f98866d67873b00687c605",
        "sha256:6f673f8532d24869047264d89e2ad65f6ff2fa3c2674bb2fb9fa02855e090b3a",
    ];

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn log_001_fixture_leaves_reproduce_pinned_root() {
        let (store, _tmp) = log_store().await;

        for (i, leaf_json) in LOG_001_LEAVES.iter().enumerate() {
            let leaf: serde_json::Value = serde_json::from_str(leaf_json).unwrap();
            let ctx_id = leaf["ctx_id"].as_str().unwrap();
            // Stub context row to satisfy the log_leaves FK (the fixture
            // leaves did not arrive through publish).
            sqlx::query(
                "INSERT INTO contexts (ctx_id, lineage_id, agent_id, origin_registry, \
                 created_at, visibility, context_type, version, title, content_hash, body_json) \
                 VALUES (?, ?, 'did:key:fixture', 'registry.example.com', ?, 'public', \
                 'data_snapshot', 1, 'log-001 fixture', ?, '{}')",
            )
            .bind(ctx_id)
            .bind(leaf["lineage_id"].as_str().unwrap())
            .bind(leaf["created_at"].as_str().unwrap())
            .bind(leaf["content_hash"].as_str().unwrap())
            .execute(store.pool())
            .await
            .unwrap();

            // The store persists the exact canonical bytes + their hash —
            // recomputed here exactly as commit_publish computes them.
            let hash = acdp::crypto::merkle::leaf_hash(leaf_json.as_bytes());
            let hash_hex = encode_sha256_hex(&hash);
            assert_eq!(
                hash_hex, LOG_001_LEAF_HASHES[i],
                "leaf {i}: §5.1 hash over the pinned JCS bytes must match the fixture"
            );
            sqlx::query(
                "INSERT INTO log_leaves (leaf_index, ctx_id, leaf_json, leaf_hash) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(i as i64)
            .bind(ctx_id)
            .bind(leaf_json)
            .bind(&hash_hex)
            .execute(store.pool())
            .await
            .unwrap();
        }

        // Root reproduction through the store's read path.
        assert_eq!(store.log_tree_size().await.unwrap(), 5);
        let hashes = store.log_leaf_hashes(5).await.unwrap();
        let root = acdp::crypto::merkle::merkle_tree_hash(&hashes);
        assert_eq!(
            encode_sha256_hex(&root),
            LOG_001_ROOT,
            "tree-size-5 root over the stored fixture leaves must match log-001"
        );

        // Pinned inclusion path for leaf 0 at size 5.
        let path = acdp::crypto::merkle::inclusion_path(0, &hashes).unwrap();
        let path_hex: Vec<String> = path.iter().map(encode_sha256_hex).collect();
        assert_eq!(path_hex, LOG_001_INCLUSION_PATH_LEAF_0);

        // The stored rows round-trip through the typed leaf and rehash
        // identically (byte-exact reproducibility).
        for e in store.log_entries(0, 5).await.unwrap() {
            assert_eq!(
                e.leaf().unwrap().leaf_hash_hex().unwrap(),
                e.leaf_hash,
                "stored leaf bytes reproduce the stored hash"
            );
        }
    }
}
