//! Witness-cosignature **aggregation** — the registry side of
//! RFC-ACDP-0015 §6.1 (ACDP 0.4.0).
//!
//! A registry advertising `acdp-registry-transparency-log` MAY collect
//! witness cosignatures of its own checkpoints and serve them alongside a
//! checkpoint as the reserved top-level `witness_signatures` member, so a
//! consumer gets a checkpoint **and** its witness quorum in one fetch and
//! can verify N-witnessed locally (`acdp::client::evaluate_witness_quorum`).
//!
//! This module owns two things:
//!
//! - **Fetch + verify + store** ([`poll_witness_once`], driven by
//!   [`spawn_witness_pollers`]): a background poller GETs each configured
//!   witness's `GET /log/witness?log_id=<our log_id>` over an
//!   SSRF-hardened client (RFC-ACDP-0008 §4.8, DNS-rebinding-guarded), and
//!   for every returned cosignature runs the RFC-ACDP-0015 §8 verification
//!   procedure against **this registry's own checkpoint** at that
//!   `tree_size`. Only cosignatures that verify are stored.
//!
//! - **The wrong-root refusal** ([`verify_cosignature_against_own_log`]):
//!   the load-bearing check. A witness cosigning a `root_hash` that is not
//!   this registry's own root at that `tree_size` is either lying or
//!   witnessing a fork; its cosignature is rejected and never stored, so
//!   the aggregator can never serve a bogus one (§6.1). Because the
//!   registry never holds a witness key it also cannot *forge* one —
//!   aggregation adds convenience, not trust.
//!
//! Serving is a plain indexed read in the checkpoint handler
//! (`handlers::log`): `witness_signatures` is attached OUTSIDE the signed
//! checkpoint object (a sibling), never mutating it (§6.1, §11).

use std::sync::Arc;
use std::time::Duration;

use acdp::client::verify_witness_cosignature_value;
use acdp::crypto::merkle;
use acdp::did::WebResolver;
use acdp::error::AcdpError;
use acdp::registry::RegistryServer;
use acdp::safe_http::SsrfPolicy;
use acdp::types::cosignature::LogCosignature;
use acdp::types::log::{encode_sha256_hex, LogCheckpoint};
use acdp_registry_store::ExtendedRegistryStore;
use acdp_registry_types::WitnessConfig;
use chrono::Utc;
use serde::Deserialize;

use crate::log::LogState;

/// Defensive cap on how many cosignatures we verify per witness per poll —
/// a witness serving an unbounded history cannot make the poller do
/// unbounded work in one tick.
const MAX_COSIGNATURES_PER_POLL: usize = 512;

/// The `GET /log/witness` response shape (RFC-ACDP-0015 §6.2). We tolerate
/// unknown members (RFC-ACDP-0001 §6) and only read `witness_signatures`.
#[derive(Debug, Deserialize)]
struct WitnessFeed {
    #[serde(default)]
    witness_signatures: Vec<serde_json::Value>,
}

/// Recompute this registry's checkpoint at `tree_size` — the checkpoint a
/// witness MUST have observed to cosign honestly. Returns `None` when
/// `tree_size` is beyond our current head (we cannot vouch for a size we
/// have not reached; the witness is ahead of us or lying).
///
/// The minted checkpoint's `timestamp` is irrelevant to the cross-check
/// (RFC-ACDP-0015 §8 step 4 binds only `log_id`/`tree_size`/`root_hash`);
/// `root_hash` is the load-bearing field.
async fn reconstruct_checkpoint<S: ExtendedRegistryStore>(
    store: &S,
    log: &LogState,
    tree_size: u64,
) -> Result<Option<LogCheckpoint>, AcdpError> {
    let current = store.log_tree_size().await?;
    if tree_size > current {
        return Ok(None);
    }
    let hashes = store.log_leaf_hashes(tree_size).await?;
    let root = encode_sha256_hex(&merkle::merkle_tree_hash(&hashes));
    let checkpoint = log
        .signer
        .mint_log_checkpoint(&log.log_id, tree_size, &root, Utc::now())?;
    Ok(Some(checkpoint))
}

/// Verify one fetched cosignature against **this registry's own log**,
/// given the witness's resolved DID document.
///
/// Runs the RFC-ACDP-0015 §8 procedure with `expected_checkpoint` pinned
/// to the checkpoint we recompute at the cosignature's `tree_size`:
/// closed parse, witness-key signature under the witness DID's
/// `assertionMethod`/`verificationMethod`, witness binding, `witnessed_at`
/// skew — and, crucially, **checkpoint binding**: if the witness cosigned
/// a `root_hash` that is not our root at that size, §8 step 4 fails and
/// the cosignature is rejected (the fork/lie refusal, §6.1).
///
/// Pure with respect to the network: the DID document is supplied by the
/// caller, so this is unit-testable without a live witness.
pub async fn verify_cosignature_against_own_log<S: ExtendedRegistryStore>(
    store: &S,
    log: &LogState,
    witness_did_doc: &serde_json::Value,
    cosig_value: &serde_json::Value,
) -> Result<LogCosignature, AcdpError> {
    // Peek the tuple via the closed parse (RFC-ACDP-0015 §8 step 1).
    let peek = LogCosignature::from_value(cosig_value)?;
    let wc = &peek.witnessed_checkpoint;
    if wc.log_id != log.log_id {
        return Err(AcdpError::InvalidWitnessCosignature(format!(
            "cosignature witnessed_checkpoint.log_id '{}' is not this registry's log '{}' \
             (RFC-ACDP-0015 §6.1)",
            wc.log_id, log.log_id
        )));
    }
    let Some(checkpoint) = reconstruct_checkpoint(store, log, wc.tree_size).await? else {
        return Err(AcdpError::InvalidWitnessCosignature(format!(
            "cosignature witnessed_checkpoint.tree_size {} is beyond this registry's current \
             head — cannot confirm the observed root (RFC-ACDP-0015 §7 step 2)",
            wc.tree_size
        )));
    };
    // §8 steps 2–5, including the wrong-root refusal in step 4
    // (cross_check_against_checkpoint compares root_hash byte-for-byte).
    verify_witness_cosignature_value(cosig_value, witness_did_doc, &checkpoint, None, None)
}

/// Resolve the witness DID, verify one cosignature against our own log,
/// and (on success) store it. Returns `true` iff a verified cosignature
/// was stored. Never propagates a verification failure as an error — a
/// bogus cosignature from one witness must not stall the poll.
async fn verify_and_store<S: ExtendedRegistryStore>(
    store: &S,
    log: &LogState,
    resolver: &WebResolver,
    witness_did: &str,
    cosig_value: &serde_json::Value,
) -> bool {
    // The witness DID document (SSRF-guarded did:web resolution).
    let doc = match resolver.resolve(witness_did).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::warn!(witness = %witness_did, error = %e, "witness DID resolution failed");
            return false;
        }
    };
    let doc_value = match serde_json::to_value(&doc) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(witness = %witness_did, error = %e, "witness DID document not serializable");
            return false;
        }
    };
    let verified =
        match verify_cosignature_against_own_log(store, log, &doc_value, cosig_value).await {
            Ok(c) => c,
            Err(e) => {
                // The wrong-root / bad-signature / skew rejection lands here.
                // Log it (a witness cosigning a different root is evidence of
                // a fork or a lie) and drop — never store.
                tracing::warn!(
                    witness = %witness_did,
                    error = %e,
                    "rejected witness cosignature (not stored)"
                );
                crate::metrics::record_witness_cosignature("rejected");
                return false;
            }
        };
    let wc = &verified.witnessed_checkpoint;
    // The canonical witnessed_at string, as it appeared on the wire.
    let witnessed_at = cosig_value
        .get("witnessed_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let cosig_json = match serde_json::to_string(cosig_value) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(witness = %witness_did, error = %e, "cosignature not serializable");
            return false;
        }
    };
    if let Err(e) = store
        .upsert_witness_cosignature(
            &wc.log_id,
            wc.tree_size,
            &wc.root_hash,
            &verified.witness_id,
            witnessed_at,
            &cosig_json,
        )
        .await
    {
        tracing::warn!(witness = %witness_did, error = %e, "failed to store witness cosignature");
        crate::metrics::record_witness_cosignature("store_error");
        return false;
    }
    crate::metrics::record_witness_cosignature("aggregated");
    true
}

/// Fetch one witness feed and verify+store every cosignature it returns.
/// Returns `(fetched, stored)` counts. Any transport/parse error is
/// surfaced so the caller can log-and-retry; per-cosignature verification
/// failures are swallowed (they are expected and non-fatal).
pub async fn poll_witness_once<S: ExtendedRegistryStore>(
    client: &reqwest::Client,
    store: &S,
    log: &LogState,
    resolver: &WebResolver,
    witness: &WitnessConfig,
) -> Result<(usize, usize), String> {
    let resp = client
        .get(&witness.url)
        .query(&[("log_id", log.log_id.as_str())])
        .send()
        .await
        .map_err(|e| format!("transport: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let feed: WitnessFeed = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    let fetched = feed.witness_signatures.len();
    let mut stored = 0usize;
    for cosig in feed
        .witness_signatures
        .iter()
        .take(MAX_COSIGNATURES_PER_POLL)
    {
        if verify_and_store(store, log, resolver, &witness.did, cosig).await {
            stored += 1;
        }
    }
    Ok((fetched, stored))
}

/// Spawn one background poller per configured witness. Each fetches its
/// witness's cosignature feed on `poll_seconds` cadence and refills the
/// verified-cosignature store. Returns immediately; wired in `main.rs`
/// next to the revocation pollers.
pub fn spawn_witness_pollers<S: ExtendedRegistryStore + 'static>(
    witnesses: Vec<WitnessConfig>,
    server: Arc<RegistryServer<S>>,
    log: Arc<LogState>,
    resolver: Arc<WebResolver>,
) {
    for witness in witnesses {
        let server = server.clone();
        let log = log.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            witness_poll_loop(witness, server, log, resolver).await;
        });
    }
}

async fn witness_poll_loop<S: ExtendedRegistryStore + 'static>(
    witness: WitnessConfig,
    server: Arc<RegistryServer<S>>,
    log: Arc<LogState>,
    resolver: Arc<WebResolver>,
) {
    // SSRF-hardened outbound client (RFC-ACDP-0008 §4.8): HTTPS-only, no
    // redirects, and every resolved IP filtered at DNS time — the witness
    // fetch is producer-uncontrolled but still guarded (RFC-ACDP-0015 §15).
    let client = match acdp::safe_http::safe_client(&SsrfPolicy::default(), Duration::from_secs(30))
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(witness = %witness.did, error = %e, "witness poller: HTTP client build failed");
            return;
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(witness.poll_seconds.max(1)));
    loop {
        interval.tick().await;
        match poll_witness_once(&client, server.store(), &log, &resolver, &witness).await {
            Ok((fetched, stored)) => tracing::info!(
                witness = %witness.did,
                fetched,
                stored,
                "witness cosignature poll succeeded"
            ),
            Err(e) => tracing::warn!(
                witness = %witness.did,
                error = %e,
                "witness cosignature poll failed (will retry)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::registry::store::{PublishCommit, RegistryStore};
    use acdp::types::body::Body;
    use acdp::types::cosignature::WitnessSigner;
    use acdp::types::primitives::{AgentDid, ContextType, Visibility};
    use acdp::types::receipt::ReceiptSigner;
    use acdp_registry_sqlite::SqliteStore;

    const AUTHORITY: &str = "reg.test";
    const REGISTRY_DID: &str = "did:web:reg.test";
    const WITNESS_DID: &str = "did:web:witness.example.org";

    // ── Scope note for the tests below (REG-5) ─────────────────────────
    //
    // `wit-002` (`wit-002-consistency-refusal.json`) describes a WITNESS's
    // obligation: a witness MUST refuse to cosign a checkpoint whose root
    // was rewritten, BEFORE signing, and MUST persist evidence of that
    // refusal (`witness_action: "refuse"`, `evidence_persisted: true`).
    // This crate is a REGISTRY, not a witness — it never cosigns anything,
    // has no `GET /log/witness` route, and structurally cannot exhibit
    // that half of wit-002's behavior.
    //
    // What `cosignature_over_wrong_root_is_rejected` below actually covers
    // is the mirror-image defense the registry DOES own: refusing to
    // STORE/AGGREGATE a cosignature whose `root_hash` doesn't match this
    // registry's own recomputed root at that `tree_size` (RFC-ACDP-0015
    // §6.1, §8 step 4). This is **the registry-side fork-refusal test,
    // pinned to wit-002's forged root value** — it is NOT wit-002
    // coverage, and no claim of full wit-002 coverage is made anywhere.

    /// wit-002's own root-rewrite vector: `presented_checkpoint.root_hash`
    /// in `wit-002-consistency-refusal.json`. A fabricated,
    /// non-cryptographic hex string (unlike a real signature), so it is
    /// hardcoded here with this citing comment rather than plumbed through
    /// `ACDP_SPEC_DIR` fixture loading — this crate has no
    /// `spec_root()`-equivalent helper, and adding spec-dir plumbing to a
    /// library crate's unit tests just to fetch one fixed constant would
    /// be pure cost for zero benefit.
    const WIT_002_FORGED_ROOT: &str =
        "sha256:deadbeef00000000000000000000000000000000000000000000000000000000";

    fn log_state() -> LogState {
        LogState::for_test(receipt_signer(), format!("{REGISTRY_DID}/log/1"))
    }

    fn receipt_signer() -> ReceiptSigner {
        ReceiptSigner::new(
            SigningKey::from_bytes(&[99u8; 32]),
            REGISTRY_DID,
            format!("{REGISTRY_DID}#receipt-key-1"),
        )
        .unwrap()
    }

    fn witness_signer() -> WitnessSigner {
        WitnessSigner::new(
            SigningKey::from_bytes(&[0x33u8; 32]),
            WITNESS_DID,
            format!("{WITNESS_DID}#witness-key-1"),
        )
        .unwrap()
    }

    fn witness_doc() -> serde_json::Value {
        let pk = SigningKey::from_bytes(&[0x33u8; 32]).verifying_key_bytes();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let vm_id = format!("{WITNESS_DID}#witness-key-1");
        serde_json::json!({
            "id": WITNESS_DID,
            "verificationMethod": [{
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": WITNESS_DID,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(pk) }
            }],
            "assertionMethod": [vm_id],
        })
    }

    /// A log-enabled SQLite store with `n` real leaves appended through
    /// the atomic publish path — a genuine tree with a genuine root.
    async fn store_with_size(n: u8) -> (SqliteStore, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteStore::connect(tmp.path(), 4)
            .await
            .unwrap()
            .with_transparency_log();
        store.migrate().await.unwrap();
        let rsigner = receipt_signer();
        let mint = move |body: &Body| -> Result<serde_json::Value, AcdpError> {
            let receipt = rsigner.mint(
                &body.ctx_id,
                &body.lineage_id,
                &body.origin_registry,
                body.created_at,
                &body.content_hash,
                &format!("sha256:{}", "c".repeat(64)),
            )?;
            serde_json::to_value(receipt).map_err(AcdpError::from)
        };
        for i in 0..n {
            let p = Producer::new(
                SigningKey::from_bytes(&[160 + i; 32]),
                AgentDid::new(format!("did:web:agents.test:w-{i}")),
                format!("did:web:agents.test:w-{i}#key-1"),
            );
            let req = p
                .publish_request()
                .title(format!("leaf-{i}"))
                .context_type(ContextType::DataSnapshot)
                .visibility(Visibility::Public)
                .build()
                .unwrap();
            tokio::task::block_in_place(|| {
                store.commit_publish(PublishCommit {
                    req: &req,
                    authority: AUTHORITY,
                    idempotency: None,
                    tenant: None,
                    receipt_minter: Some(&mint),
                })
            })
            .expect("logged publish");
        }
        (store, tmp)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn honest_cosignature_over_our_root_verifies() {
        let (store, _tmp) = store_with_size(5).await;
        let log = log_state();
        let cp = reconstruct_checkpoint(&store, &log, 5)
            .await
            .unwrap()
            .unwrap();
        let cosig = witness_signer().mint(&cp, Utc::now()).unwrap();
        let wire = serde_json::to_value(&cosig).unwrap();

        let verified = verify_cosignature_against_own_log(&store, &log, &witness_doc(), &wire)
            .await
            .expect("a cosignature over our own root must verify");
        assert_eq!(verified.witness_id, WITNESS_DID);
        assert_eq!(verified.witnessed_checkpoint.tree_size, 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cosignature_over_wrong_root_is_rejected() {
        let (store, _tmp) = store_with_size(5).await;
        let log = log_state();
        // A checkpoint at OUR size 5 but a FORGED root, cosigned by the
        // witness — wit-002's own root-rewrite vector. See
        // `WIT_002_FORGED_ROOT` doc comment for the fixture citation and
        // the registry-vs-witness scope note.
        let forged_cp = log
            .signer
            .mint_log_checkpoint(&log.log_id, 5, WIT_002_FORGED_ROOT, Utc::now())
            .unwrap();
        let cosig = witness_signer().mint(&forged_cp, Utc::now()).unwrap();
        let wire = serde_json::to_value(&cosig).unwrap();

        let err = verify_cosignature_against_own_log(&store, &log, &witness_doc(), &wire)
            .await
            .expect_err("a witness cosigning a different root must be rejected (§6.1)");
        assert!(
            matches!(err, AcdpError::InvalidWitnessCosignature(_)),
            "got {err:?}"
        );
        // Discriminate from the beyond-head rejection below: this must be
        // the §8 step 4 checkpoint/root-mismatch, not some other
        // `InvalidWitnessCosignature` cause (see the module-level mutation
        // note in the doc comment above `WIT_002_FORGED_ROOT`).
        let msg = err.to_string();
        assert!(
            msg.contains("root_hash") && msg.contains("evaluated checkpoint"),
            "wrong-root rejection must name the root_hash/checkpoint mismatch, got: {msg}"
        );

        // And nothing was persisted: the store holds zero cosignatures for
        // this exact checkpoint tuple after the rejection — a guard against
        // this verification path ever gaining a persist-before-verify write
        // (the actual store call lives in verify_and_store, untested here),
        // so a forged cosignature can never later be served as though it
        // had been aggregated (§6.1).
        let stored = store
            .witness_cosignatures_for(&log.log_id, 5, WIT_002_FORGED_ROOT)
            .await
            .unwrap();
        assert!(
            stored.is_empty(),
            "a rejected wrong-root cosignature must not be persisted, got {stored:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cosignature_beyond_current_head_is_rejected() {
        let (store, _tmp) = store_with_size(3).await;
        let log = log_state();
        // A checkpoint at size 5 — beyond our head of 3. We cannot confirm it.
        let root5 = encode_sha256_hex(&[0x0bu8; 32]);
        let cp5 = log
            .signer
            .mint_log_checkpoint(&log.log_id, 5, &root5, Utc::now())
            .unwrap();
        let cosig = witness_signer().mint(&cp5, Utc::now()).unwrap();
        let wire = serde_json::to_value(&cosig).unwrap();

        let err = verify_cosignature_against_own_log(&store, &log, &witness_doc(), &wire)
            .await
            .unwrap_err();
        assert!(matches!(err, AcdpError::InvalidWitnessCosignature(_)));
        // Discriminate from the wrong-root rejection above: this must be
        // the beyond-head refusal specifically, not the §8 step 4
        // root-mismatch (see the mutation note above `WIT_002_FORGED_ROOT`).
        let msg = err.to_string();
        assert!(
            msg.contains("beyond this registry's current head"),
            "beyond-head rejection must name the beyond-head reason, got: {msg}"
        );

        // And nothing was persisted for this tuple either.
        let stored = store
            .witness_cosignatures_for(&log.log_id, 5, &root5)
            .await
            .unwrap();
        assert!(
            stored.is_empty(),
            "a rejected beyond-head cosignature must not be persisted, got {stored:?}"
        );
    }
}
