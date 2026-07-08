//! Transparency-log building blocks shared by the storage backends
//! (RFC-ACDP-0012, ACDP 0.3.0).
//!
//! ## Storage design (both SQL backends)
//!
//! One `log_leaves` row per accepted publish:
//!
//! | column       | contents                                                       |
//! |--------------|----------------------------------------------------------------|
//! | `leaf_index` | dense, 0-based, PRIMARY KEY — §5.3 acceptance-order positions  |
//! | `ctx_id`     | UNIQUE, references `contexts` — exactly one leaf per publish (§4) |
//! | `leaf_json`  | the **exact JCS-canonical leaf bytes** (UTF-8 JSON text)       |
//! | `leaf_hash`  | `"sha256:<hex>"` wire form of `SHA-256(0x00 ‖ leaf_json)` (§5.1) |
//!
//! **Leaf-bytes choice.** `leaf_json` stores the JCS canonicalization
//! itself (RFC 8785 output is valid UTF-8 JSON), not a re-serializable
//! projection: the §5.1 leaf hash is over those exact bytes, so storing
//! them makes the leaf reproducible byte-exactly without trusting any
//! serializer to round-trip — `SHA-256(0x00 ‖ leaf_json)` MUST equal
//! `leaf_hash` for every stored row, forever, and tests recompute it.
//!
//! **Tree computation.** Roots, inclusion paths, and consistency paths
//! are recomputed per request from the ordered `leaf_hash` column via
//! the SDK's pure Merkle functions (`acdp::crypto::merkle`) — an O(n)
//! load-all-hashes design chosen for correctness-first simplicity (the
//! ordered leaf hashes alone determine every root, §8.3). Registries
//! with very large logs can later switch to an incremental/tiled hash
//! cache without touching the wire surface; the HTTP layer additionally
//! keeps a trivial (tree_size → root) cache for the current head, which
//! is sound because the tree is strictly append-only (§5.3).

use acdp::error::AcdpError;
use acdp::types::body::Body;
use acdp::types::log::{decode_sha256_hex, encode_sha256_hex, LogLeaf, LOG_LEAF_VERSION};
use acdp::types::receipt::RegistryReceipt;

/// One stored transparency-log row, as read back from `log_leaves`.
#[derive(Debug, Clone)]
pub struct LogEntryRecord {
    /// Dense, 0-based acceptance-order position (§5.3).
    pub leaf_index: u64,
    /// The context this leaf binds (exactly one leaf per `ctx_id`, §4).
    pub ctx_id: String,
    /// `"sha256:<hex>"` wire form of the §5.1 leaf hash.
    pub leaf_hash: String,
    /// The exact JCS-canonical leaf bytes (UTF-8 JSON text).
    pub leaf_json: String,
}

impl LogEntryRecord {
    /// Parse the stored canonical bytes back into the wire JSON value
    /// (served as the `leaf` member where the requester is
    /// retrieval-authorized, §8.2/§8.3).
    pub fn leaf_value(&self) -> Result<serde_json::Value, AcdpError> {
        serde_json::from_str(&self.leaf_json).map_err(|e| {
            AcdpError::RegistryInternal(format!(
                "stored log leaf for '{}' is not valid JSON: {e}",
                self.ctx_id
            ))
        })
    }

    /// Parse into the typed [`LogLeaf`] (closed-schema checked).
    pub fn leaf(&self) -> Result<LogLeaf, AcdpError> {
        LogLeaf::from_value(&self.leaf_value()?)
    }

    /// The raw 32-byte digest `leaf_hash` encodes.
    pub fn leaf_hash_bytes(&self) -> Result<[u8; 32], AcdpError> {
        decode_sha256_hex(&self.leaf_hash)
    }
}

/// Build the RFC-ACDP-0012 §4 leaf for a freshly-assigned [`Body`] and
/// its just-minted RFC-ACDP-0010 receipt, returning
/// `(leaf_json, leaf_hash)`:
///
/// * `leaf_json` — the exact JCS-canonical leaf bytes (what the store
///   persists, and what §5.1 hashes);
/// * `leaf_hash` — `"sha256:" + hex(SHA-256(0x00 ‖ leaf_json))`.
///
/// The leaf duplicates the body's identifiers/`created_at`/
/// `content_hash` and the receipt's `key_fingerprint` deliberately
/// (§4: a verifier holding the body and its verified receipt can
/// reconstruct the leaf byte-for-byte); `receipt_hash` is the
/// RFC-ACDP-0010 §2 receipt hash — over the receipt minus `signature`,
/// so the log history survives the sanctioned post-compromise re-mint.
///
/// Called by the storage backends INSIDE the publish transaction (§7.1:
/// the body, its receipt, and its leaf commit together, or none does).
pub fn build_leaf_record(
    body: &Body,
    receipt: &serde_json::Value,
) -> Result<(String, String), AcdpError> {
    let key_fingerprint = receipt
        .get("key_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AcdpError::RegistryInternal(
                "minted receipt carries no key_fingerprint — cannot build the \
                 transparency-log leaf (RFC-ACDP-0012 §4)"
                    .into(),
            )
        })?;
    // RFC-ACDP-0010 §2 receipt hash: JCS(receipt minus signature),
    // computed from the receipt exactly as minted.
    let receipt_hash = RegistryReceipt::preimage_hash_of_value(receipt)?;
    let leaf = LogLeaf {
        leaf_version: LOG_LEAF_VERSION.to_string(),
        ctx_id: body.ctx_id.clone(),
        lineage_id: body.lineage_id.clone(),
        origin_registry: body.origin_registry.clone(),
        // Byte-identical to body.created_at and receipt.created_at by
        // construction: all three serialize the same ms-truncated
        // DateTime through the canonical three-digit-millisecond form.
        created_at: body.created_at,
        content_hash: body.content_hash.clone(),
        key_fingerprint: key_fingerprint.to_string(),
        receipt_hash: receipt_hash.0,
    };
    let bytes = leaf.canonical_bytes()?;
    let hash = acdp::crypto::merkle::leaf_hash(&bytes);
    let leaf_json = String::from_utf8(bytes).map_err(|e| {
        AcdpError::RegistryInternal(format!("JCS leaf bytes are not UTF-8 (impossible): {e}"))
    })?;
    Ok((leaf_json, encode_sha256_hex(&hash)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp::crypto::SigningKey;
    use acdp::producer::Producer;
    use acdp::types::primitives::{ContextType, CtxId, Visibility};
    use acdp::types::receipt::ReceiptSigner;
    use chrono::Utc;

    fn body() -> Body {
        let p = Producer::new_did_key(SigningKey::from_bytes(&[7u8; 32]));
        let req = p
            .publish_request()
            .title("leaf-record-test")
            .context_type(ContextType::DataSnapshot)
            .visibility(Visibility::Public)
            .build()
            .expect("valid publish request");
        let ctx_id = CtxId("acdp://reg.test/00000000-0000-4000-8000-000000000001".into());
        let lineage_id = acdp::crypto::derive_lineage_id(&ctx_id);
        Body::from_publish_request(
            &req,
            ctx_id,
            lineage_id,
            "reg.test".to_string(),
            acdp::time::trunc_ms(Utc::now()),
        )
    }

    fn receipt_for(b: &Body) -> serde_json::Value {
        let signer = ReceiptSigner::new(
            SigningKey::from_bytes(&[9u8; 32]),
            "did:web:reg.test",
            "did:web:reg.test#receipt-key-1",
        )
        .unwrap();
        let receipt = signer
            .mint(
                &b.ctx_id,
                &b.lineage_id,
                &b.origin_registry,
                b.created_at,
                &b.content_hash,
                &format!("sha256:{}", "c".repeat(64)),
            )
            .unwrap();
        serde_json::to_value(receipt).unwrap()
    }

    /// The stored bytes reproduce the stored hash (§5.1), the leaf
    /// parses through the closed schema, and its fields duplicate the
    /// body + receipt material per §4.
    #[test]
    fn leaf_record_is_reproducible_and_closed() {
        let b = body();
        let receipt = receipt_for(&b);
        let (leaf_json, leaf_hash) = build_leaf_record(&b, &receipt).unwrap();

        // Reproducibility: rehash the stored bytes.
        let rehashed = acdp::crypto::merkle::leaf_hash(leaf_json.as_bytes());
        assert_eq!(encode_sha256_hex(&rehashed), leaf_hash);

        // Closed parse + field bindings.
        let record = LogEntryRecord {
            leaf_index: 0,
            ctx_id: b.ctx_id.as_str().into(),
            leaf_hash: leaf_hash.clone(),
            leaf_json: leaf_json.clone(),
        };
        let leaf = record.leaf().unwrap();
        assert_eq!(leaf.ctx_id, b.ctx_id);
        assert_eq!(leaf.lineage_id, b.lineage_id);
        assert_eq!(leaf.origin_registry, b.origin_registry);
        assert_eq!(leaf.created_at, b.created_at);
        assert_eq!(leaf.content_hash, b.content_hash);
        assert_eq!(
            leaf.receipt_hash,
            RegistryReceipt::preimage_hash_of_value(&receipt).unwrap().0
        );
        assert_eq!(record.leaf_hash_bytes().unwrap(), rehashed);

        // The canonical bytes are the JCS form (keys sorted, no spaces).
        assert!(leaf_json.starts_with("{\"content_hash\":"));
    }

    /// A receipt without `key_fingerprint` (not a real RFC-ACDP-0010
    /// receipt) cannot produce a leaf — the publish must abort rather
    /// than log an unverifiable entry.
    #[test]
    fn missing_fingerprint_is_refused() {
        let b = body();
        let err = build_leaf_record(&b, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AcdpError::RegistryInternal(_)), "{err:?}");
    }

    /// A `LogEntryRecord` with the given stored columns (the read-back
    /// projection of one `log_leaves` row).
    fn record(leaf_json: &str, leaf_hash: &str) -> LogEntryRecord {
        LogEntryRecord {
            leaf_index: 0,
            ctx_id: "acdp://reg.test/00000000-0000-4000-8000-000000000001".into(),
            leaf_hash: leaf_hash.into(),
            leaf_json: leaf_json.into(),
        }
    }

    /// Stored `leaf_json` that is not valid JSON at all is REGISTRY
    /// corruption, not caller error: `leaf_value()` (and `leaf()`, which
    /// parses through it) reports `registry_internal`, naming the ctx_id
    /// so the broken row is findable.
    #[test]
    fn corrupt_leaf_json_is_registry_internal() {
        let r = record("not json {", &format!("sha256:{}", "a".repeat(64)));
        match r.leaf_value().unwrap_err() {
            AcdpError::RegistryInternal(msg) => {
                assert!(msg.contains(&r.ctx_id), "message names the ctx_id: {msg}");
                assert!(msg.contains("not valid JSON"), "{msg}");
            }
            other => panic!("expected RegistryInternal, got {other:?}"),
        }
        assert!(
            matches!(r.leaf(), Err(AcdpError::RegistryInternal(_))),
            "leaf() surfaces the same corruption"
        );
    }

    /// Valid JSON that is not a complete RFC-ACDP-0012 §4 leaf fails the
    /// closed-schema `leaf()` parse with `invalid_log_proof`, while
    /// `leaf_value()` (the raw wire projection) still succeeds.
    #[test]
    fn incomplete_leaf_fails_closed_schema_parse() {
        let r = record("{}", &format!("sha256:{}", "a".repeat(64)));
        assert_eq!(r.leaf_value().unwrap(), serde_json::json!({}));
        let err = r.leaf().unwrap_err();
        assert!(matches!(err, AcdpError::InvalidLogProof(_)), "{err:?}");

        // A structurally complete leaf with a wrong leaf_version is
        // rejected the same way (the schema is closed on version too).
        let (leaf_json, leaf_hash) = build_leaf_record(&body(), &receipt_for(&body())).unwrap();
        let wrong_version = leaf_json.replace("acdp-log-leaf/1", "acdp-log-leaf/9");
        let err = record(&wrong_version, &leaf_hash).leaf().unwrap_err();
        assert!(matches!(err, AcdpError::InvalidLogProof(_)), "{err:?}");
    }

    /// `leaf_hash_bytes()` decodes only the exact §2 wire form
    /// `"sha256:" + 64 lowercase hex digits`; every malformed variant is
    /// `invalid_log_proof`.
    #[test]
    fn invalid_leaf_hash_is_rejected() {
        for bad in [
            "",                                      // empty
            &"a".repeat(64),                         // missing "sha256:" prefix
            &format!("md5:{}", "a".repeat(64)),      // wrong algorithm
            &format!("sha256:{}", "a".repeat(63)),   // too short
            &format!("sha256:{}", "a".repeat(65)),   // too long
            &format!("sha256:{}", "A".repeat(64)),   // uppercase hex
            &format!("sha256:{}zz", "a".repeat(62)), // non-hex digits
        ] {
            let err = record("{}", bad).leaf_hash_bytes().unwrap_err();
            assert!(
                matches!(err, AcdpError::InvalidLogProof(_)),
                "'{bad}' must be rejected as invalid_log_proof, got {err:?}"
            );
        }
        // The well-formed wire form round-trips to the raw digest.
        assert_eq!(
            record("{}", &format!("sha256:{}", "ab".repeat(32)))
                .leaf_hash_bytes()
                .unwrap(),
            [0xabu8; 32]
        );
    }
}
