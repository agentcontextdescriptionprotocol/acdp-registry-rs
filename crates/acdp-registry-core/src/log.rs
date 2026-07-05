//! Transparency-log serving state (RFC-ACDP-0012, ACDP 0.3.0).
//!
//! Built once at startup from `[log]` + `[receipt]` (the checkpoint
//! signer IS the RFC-ACDP-0010 receipt signer — §6: the log introduces
//! no new key role) and held in [`crate::state::AppState`]. The §7.1
//! append atomicity lives in the storage backends; this module owns the
//! serving side: the `log_id`, checkpoint minting, and a trivial
//! head-root cache.

use std::sync::Mutex;

use acdp::did::authority_to_did_web;
use acdp::types::receipt::ReceiptSigner;
use acdp_registry_types::RegistryConfig;

/// Per-process transparency-log serving state.
pub struct LogState {
    /// The RFC-ACDP-0010 receipt signer, reused verbatim for checkpoint
    /// signing (RFC-ACDP-0012 §6).
    pub signer: ReceiptSigner,
    /// The log instantiation identifier
    /// `"<registry_did>/log/<instance>"` (§6). One live instantiation
    /// per registry; changing the instance is an explicit history
    /// reset (§7.4).
    pub log_id: String,
    /// Trivial (tree_size → root_hash) cache for the current head.
    /// Sound because the tree is strictly append-only (§5.3): the root
    /// at a given size never changes within one instantiation. Only the
    /// most recent entry is kept (historical roots are recomputed on
    /// demand — the O(n) hash load is needed for their proof paths
    /// anyway).
    root_cache: Mutex<Option<(u64, String)>>,
}

impl LogState {
    /// Build from config: `None` when the log is disabled; `Err` on a
    /// misconfiguration (no receipt key, malformed instance) — which
    /// `validate_config` already rejects at startup, so state
    /// construction logs-and-degrades instead of panicking (the same
    /// posture as the DID-document cell).
    pub fn from_config(cfg: &RegistryConfig) -> Result<Option<Self>, String> {
        if !cfg.log.enabled {
            return Ok(None);
        }
        if !cfg.receipt.is_configured() {
            return Err(
                "log.enabled requires a [receipt] signing key (RFC-ACDP-0012 §11: the \
                 transparency-log profile's prerequisite is acdp-registry-receipts)"
                    .into(),
            );
        }
        let signer = crate::receipt::build_signer(&cfg.receipt, &cfg.registry.authority)?;
        let log_id = format!(
            "{}/log/{}",
            authority_to_did_web(&cfg.registry.authority),
            cfg.log.instance.trim()
        );
        // §6: the instance component must match [a-z0-9-]{1,32}.
        acdp::types::log::parse_log_id(&log_id)
            .map_err(|e| format!("log.instance is malformed: {e}"))?;
        Ok(Some(Self {
            signer,
            log_id,
            root_cache: Mutex::new(None),
        }))
    }

    /// Cached root for `tree_size`, if the head cache holds it.
    pub fn cached_root(&self, tree_size: u64) -> Option<String> {
        let guard = self.root_cache.lock().expect("root cache poisoned");
        guard
            .as_ref()
            .filter(|(size, _)| *size == tree_size)
            .map(|(_, root)| root.clone())
    }

    /// Record the root for `tree_size` (keeps only the newest size —
    /// append-only means larger is newer).
    pub fn cache_root(&self, tree_size: u64, root: &str) {
        let mut guard = self.root_cache.lock().expect("root cache poisoned");
        match guard.as_ref() {
            Some((size, _)) if *size > tree_size => {}
            _ => *guard = Some((tree_size, root.to_string())),
        }
    }
}
