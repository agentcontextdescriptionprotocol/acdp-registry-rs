//! Receipt signing identity — key loading and registry DID document
//! generation (RFC-ACDP-0010, ACDP 0.2.0 workstream A).
//!
//! This module is the single seam between the `[receipt]` config section
//! and the `acdp` crate's [`ReceiptSigner`]. A future KMS/HSM-backed key
//! source plugs in here (by producing the signer from non-extractable key
//! material) without touching the publish path, which only ever sees the
//! constructed signer.

use acdp::crypto::SigningKey;
use acdp::did::authority_to_did_web;
use acdp::types::receipt::ReceiptSigner;
use acdp_registry_types::ReceiptConfig;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// Load the Ed25519 receipt signing key from the configured source.
///
/// Exactly one source must be set: `signing_key_seed_b64` (env-friendly)
/// or `signing_key_path` (mounted secret file containing the same base64
/// string). Errors are operator-actionable strings surfaced at startup by
/// `validate_config` — a registry must never lazily discover a bad
/// receipt key on its first publish.
pub fn load_signing_key(cfg: &ReceiptConfig) -> Result<SigningKey, String> {
    let inline = cfg.signing_key_seed_b64.trim();
    let seed_b64 = match (&cfg.signing_key_path, inline.is_empty()) {
        (Some(_), false) => {
            return Err(
                "receipt.signing_key_seed_b64 and receipt.signing_key_path are both set; \
                 configure exactly one key source"
                    .into(),
            );
        }
        (Some(path), true) => std::fs::read_to_string(path)
            .map_err(|e| format!("receipt.signing_key_path '{}': {e}", path.display()))?
            .trim()
            .to_string(),
        (None, false) => inline.to_string(),
        (None, true) => return Err("no receipt signing key configured".into()),
    };
    let bytes = B64
        .decode(&seed_b64)
        .map_err(|e| format!("receipt signing key is not valid base64: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "receipt signing key must decode to exactly 32 bytes (Ed25519 seed), got {}",
            bytes.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Validate a key-id fragment: non-empty after trimming, no '#'. Shared
/// by [`build_signer`] and [`build_did_document`] so the DID document can
/// never carry a key id the signer construction would have refused.
fn validated_fragment<'a>(fragment: &'a str, what: &str) -> Result<&'a str, String> {
    let f = fragment.trim();
    if f.is_empty() || f.contains('#') {
        return Err(format!(
            "{what} must be a non-empty fragment without '#' (got '{fragment}')"
        ));
    }
    Ok(f)
}

/// Build the [`ReceiptSigner`] for this deployment:
/// `registry_did = did:web:<authority>`,
/// `key_id = did:web:<authority>#<receipt.key_id_fragment>`.
pub fn build_signer(cfg: &ReceiptConfig, authority: &str) -> Result<ReceiptSigner, String> {
    let fragment = validated_fragment(&cfg.key_id_fragment, "receipt.key_id_fragment")?;
    let key = load_signing_key(cfg)?;
    let registry_did = authority_to_did_web(authority);
    let key_id = format!("{registry_did}#{fragment}");
    ReceiptSigner::new(key, registry_did, key_id).map_err(|e| format!("receipt signer: {e}"))
}

/// Generate the registry's own `did:web` DID document, served at
/// `GET /.well-known/did.json` so consumers can resolve the receipt
/// verification key (`did:web:<authority>` resolves to exactly that URL).
///
/// Key-retention rule (RFC-ACDP-0010 §9 — MUST): every key that ever
/// signed a receipt stays in `verificationMethod` indefinitely; rotation
/// removes it from `assertionMethod` ONLY. The active signing key appears
/// in both arrays; `receipt.retired_keys` entries appear in
/// `verificationMethod` alone. Violating this bricks every receipt the
/// removed key ever signed — the sole sanctioned removal is confirmed key
/// compromise.
pub fn build_did_document(
    cfg: &ReceiptConfig,
    authority: &str,
) -> Result<serde_json::Value, String> {
    let key = load_signing_key(cfg)?;
    let did = authority_to_did_web(authority);
    let active_fragment = validated_fragment(&cfg.key_id_fragment, "receipt.key_id_fragment")?;
    let active_id = format!("{did}#{active_fragment}");

    let mut verification_method = vec![verification_method_entry(
        &did,
        &active_id,
        &key.verifying_key_bytes(),
    )];
    for retired in &cfg.retired_keys {
        let bytes = B64
            .decode(retired.public_key_b64.trim())
            .map_err(|e| format!("retired receipt key is not valid base64: {e}"))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "retired receipt key must be a raw 32-byte Ed25519 public key, got {} bytes",
                bytes.len()
            )
        })?;
        let fragment = validated_fragment(
            &retired.key_id_fragment,
            "receipt.retired_keys.key_id_fragment",
        )?;
        let id = format!("{did}#{fragment}");
        verification_method.push(verification_method_entry(&did, &id, &arr));
    }

    Ok(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": verification_method,
        // Only the ACTIVE key may authenticate new receipts.
        "assertionMethod": [active_id],
    }))
}

fn verification_method_entry(did: &str, key_id: &str, public_key: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "id": key_id,
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyMultibase": ed25519_multibase(public_key),
    })
}

/// `publicKeyMultibase` form: base58btc (`z` prefix) over the multicodec
/// `ed25519-pub` (0xed01) prefix + raw key — exactly the encoding
/// `acdp`'s resolver expects. Reuses the crate's did:key encoder, whose
/// method-specific identifier IS that multibase string.
fn ed25519_multibase(public_key: &[u8; 32]) -> String {
    acdp::did::key::did_key_from_ed25519(public_key)
        .strip_prefix("did:key:")
        .expect("did_key_from_ed25519 always returns a did:key: prefix")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acdp_registry_types::RetiredReceiptKey;

    fn cfg_with_seed() -> ReceiptConfig {
        ReceiptConfig {
            signing_key_seed_b64: B64.encode([7u8; 32]),
            ..Default::default()
        }
    }

    #[test]
    fn seed_b64_loads_and_signer_builds() {
        let cfg = cfg_with_seed();
        match build_signer(&cfg, "registry.test") {
            Ok(signer) => assert_eq!(signer.registry_did(), "did:web:registry.test"),
            Err(e) => panic!("signer should build: {e}"),
        }
    }

    #[test]
    fn both_sources_set_is_rejected() {
        let mut cfg = cfg_with_seed();
        cfg.signing_key_path = Some("/nonexistent".into());
        let err = build_signer(&cfg, "registry.test").map(|_| ()).unwrap_err();
        assert!(err.contains("exactly one key source"));
    }

    #[test]
    fn short_seed_is_rejected() {
        let cfg = ReceiptConfig {
            signing_key_seed_b64: B64.encode([7u8; 16]),
            ..Default::default()
        };
        assert!(load_signing_key(&cfg)
            .unwrap_err()
            .contains("exactly 32 bytes"));
    }

    #[test]
    fn file_source_loads() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), format!("{}\n", B64.encode([9u8; 32]))).unwrap();
        let cfg = ReceiptConfig {
            signing_key_path: Some(f.path().to_path_buf()),
            ..Default::default()
        };
        load_signing_key(&cfg).expect("file-sourced seed loads");
    }

    #[test]
    fn did_document_retains_retired_keys_in_verification_method_only() {
        let mut cfg = cfg_with_seed();
        cfg.retired_keys = vec![RetiredReceiptKey {
            public_key_b64: B64.encode([1u8; 32]),
            key_id_fragment: "receipt-key-0".into(),
        }];
        let doc = build_did_document(&cfg, "registry.test").expect("doc");
        let vm = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vm.len(), 2, "active + retired keys both published");
        assert!(vm
            .iter()
            .any(|m| m["id"] == "did:web:registry.test#receipt-key-0"));
        // RFC-ACDP-0010 §9: assertionMethod lists ONLY the active key.
        let am = doc["assertionMethod"].as_array().unwrap();
        assert_eq!(am.len(), 1);
        assert_eq!(am[0], "did:web:registry.test#receipt-key-1");
        // The multibase form round-trips through acdp's resolver.
        let mb = vm[0]["publicKeyMultibase"].as_str().unwrap();
        assert!(mb.starts_with('z'));
        let material =
            acdp::did::key::resolve_did_key(&format!("did:key:{mb}")).expect("resolvable");
        assert!(matches!(material, acdp::did::DidKeyMaterial::Ed25519(_)));
    }
}
