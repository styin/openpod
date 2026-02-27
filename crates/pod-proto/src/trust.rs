//! Trust store: peer identity allow/deny management for TOFU pairing.
//!
//! The [`TrustStore`] trait abstracts how trusted and denied PodIds are
//! persisted. [`MemoryTrustStore`] provides an in-memory implementation
//! suitable for tests and short-lived processes.
//!
//! [`TrustPolicy`] controls whether unknown peers are accepted:
//! - `Strict`: only peers already in the trust set are accepted.
//! - `PairingMode`: unknown (not denied) peers are auto-trusted on first
//!   connection (Trust On First Use).
//!
//! Design references:
//! - iroh: application-level trust decisions after TLS (no built-in store)
//! - libp2p-tls: peer verification via X.509 extension, no allow/deny trait
//! - rustls: custom `ServerCertVerifier`/`ClientCertVerifier` call into this trait

use std::collections::HashSet;
use std::sync::RwLock;

use crate::identity::PodId;

/// Policy governing how unknown peers are handled during TLS verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Only peers already in the trusted set are accepted. Unknown peers
    /// are rejected even if they are not explicitly denied.
    Strict,
    /// Trust On First Use: unknown peers (not in the denied set) are
    /// automatically added to the trusted set on first connection.
    PairingMode,
}

/// Trait for checking and managing peer trust state.
///
/// Implementations must be `Send + Sync` to allow sharing via
/// `Arc<dyn TrustStore>` across async tasks and TLS verifier callbacks.
pub trait TrustStore: Send + Sync {
    /// Returns `true` if the given PodId is in the trusted set.
    fn is_trusted(&self, pod_id: &PodId) -> bool;

    /// Returns `true` if the given PodId is explicitly denied.
    fn is_denied(&self, pod_id: &PodId) -> bool;

    /// Add a PodId to the trusted set.
    fn trust(&self, pod_id: PodId);

    /// Add a PodId to the denied set. If the peer was previously trusted,
    /// it is removed from the trusted set.
    fn deny(&self, pod_id: PodId);

    /// Remove a PodId from the trusted set. No-op if not present.
    fn untrust(&self, pod_id: &PodId);

    /// Remove a PodId from the denied set. No-op if not present.
    fn undeny(&self, pod_id: &PodId);
}

/// In-memory trust store backed by `RwLock<HashSet<PodId>>`.
///
/// Suitable for tests and short-lived processes. For persistent storage,
/// implement [`TrustStore`] with file-backed or database-backed sets.
pub struct MemoryTrustStore {
    trusted: RwLock<HashSet<PodId>>,
    denied: RwLock<HashSet<PodId>>,
}

impl MemoryTrustStore {
    /// Create an empty trust store.
    pub fn new() -> Self {
        Self {
            trusted: RwLock::new(HashSet::new()),
            denied: RwLock::new(HashSet::new()),
        }
    }
}

impl Default for MemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore for MemoryTrustStore {
    fn is_trusted(&self, pod_id: &PodId) -> bool {
        self.trusted.read().unwrap().contains(pod_id)
    }

    fn is_denied(&self, pod_id: &PodId) -> bool {
        self.denied.read().unwrap().contains(pod_id)
    }

    fn trust(&self, pod_id: PodId) {
        self.trusted.write().unwrap().insert(pod_id);
    }

    fn deny(&self, pod_id: PodId) {
        // Remove from trusted if present.
        self.trusted.write().unwrap().remove(&pod_id);
        self.denied.write().unwrap().insert(pod_id);
    }

    fn untrust(&self, pod_id: &PodId) {
        self.trusted.write().unwrap().remove(pod_id);
    }

    fn undeny(&self, pod_id: &PodId) {
        self.denied.write().unwrap().remove(pod_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PodId;

    fn make_pod_id(seed: u8) -> PodId {
        PodId::from_public_key(&[seed; 32])
    }

    #[test]
    fn empty_store_trusts_nobody() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        assert!(!store.is_trusted(&id));
        assert!(!store.is_denied(&id));
    }

    #[test]
    fn trust_and_check() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.trust(id.clone());
        assert!(store.is_trusted(&id));
        assert!(!store.is_denied(&id));
    }

    #[test]
    fn deny_and_check() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.deny(id.clone());
        assert!(store.is_denied(&id));
        assert!(!store.is_trusted(&id));
    }

    #[test]
    fn deny_removes_from_trusted() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.trust(id.clone());
        assert!(store.is_trusted(&id));

        store.deny(id.clone());
        assert!(!store.is_trusted(&id));
        assert!(store.is_denied(&id));
    }

    #[test]
    fn untrust_removes_from_trusted() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.trust(id.clone());
        store.untrust(&id);
        assert!(!store.is_trusted(&id));
    }

    #[test]
    fn undeny_removes_from_denied() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.deny(id.clone());
        store.undeny(&id);
        assert!(!store.is_denied(&id));
    }

    #[test]
    fn untrust_noop_if_not_present() {
        let store = MemoryTrustStore::new();
        let id = make_pod_id(1);
        store.untrust(&id); // should not panic
        assert!(!store.is_trusted(&id));
    }

    #[test]
    fn multiple_peers_independent() {
        let store = MemoryTrustStore::new();
        let a = make_pod_id(1);
        let b = make_pod_id(2);

        store.trust(a.clone());
        store.deny(b.clone());

        assert!(store.is_trusted(&a));
        assert!(!store.is_denied(&a));
        assert!(!store.is_trusted(&b));
        assert!(store.is_denied(&b));
    }

    #[test]
    fn policy_enum_equality() {
        assert_eq!(TrustPolicy::Strict, TrustPolicy::Strict);
        assert_eq!(TrustPolicy::PairingMode, TrustPolicy::PairingMode);
        assert_ne!(TrustPolicy::Strict, TrustPolicy::PairingMode);
    }

    #[test]
    fn default_creates_empty_store() {
        let store = MemoryTrustStore::default();
        let id = make_pod_id(42);
        assert!(!store.is_trusted(&id));
        assert!(!store.is_denied(&id));
    }
}
