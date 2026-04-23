//! Per-(claimant, namespace) nonce uniqueness tracker (§5.2.2).
//!
//! Rules:
//! - **uniqueness** is required (reject duplicate).
//! - **monotonic increase** is SHOULD, not MUST — gaps are accepted.
//!
//! This is in-memory only in v0. Persistence and `(claimant, namespace)`
//! bloom/bitset compaction for long-lived chains are §5.7 / §15 concerns
//! to land alongside the pruning strategy.

use std::collections::{HashMap, HashSet};

use codex_core::namespace::Namespace;
use codex_crypto::PeerId;

/// Tracks which `(claimant, namespace, nonce)` triples have already been
/// accepted into the chain. Duplicate nonces for the same
/// `(claimant, namespace)` are rejected; any other nonce — in-order,
/// out-of-order, or with gaps — is accepted.
#[derive(Debug, Default, Clone)]
pub struct NonceTracker {
    seen: HashMap<(PeerId, Namespace), HashSet<u64>>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check without mutating whether the nonce is fresh.
    pub fn is_fresh(&self, claimant: &PeerId, namespace: &Namespace, nonce: u64) -> bool {
        !self
            .seen
            .get(&(*claimant, namespace.clone()))
            .map(|set| set.contains(&nonce))
            .unwrap_or(false)
    }

    /// Accept a nonce; returns `Err(AlreadySeen)` if duplicate.
    pub fn accept(
        &mut self,
        claimant: PeerId,
        namespace: Namespace,
        nonce: u64,
    ) -> Result<(), AlreadySeen> {
        let set = self.seen.entry((claimant, namespace)).or_default();
        if !set.insert(nonce) {
            return Err(AlreadySeen);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadySeen;

#[cfg(test)]
mod tests {
    use super::*;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    fn ns(s: &str) -> Namespace {
        Namespace::new(s).unwrap()
    }

    fn peer() -> PeerId {
        PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key())
    }

    #[test]
    fn accepts_fresh_rejects_duplicate() {
        let mut t = NonceTracker::new();
        let p = peer();
        assert!(t.accept(p, ns("tessera.game"), 0).is_ok());
        assert!(t.accept(p, ns("tessera.game"), 0).is_err());
        assert!(t.accept(p, ns("tessera.game"), 1).is_ok());
    }

    #[test]
    fn gap_tolerance() {
        let mut t = NonceTracker::new();
        let p = peer();
        // Arbitrary out-of-order nonces — all accepted since none duplicate.
        assert!(t.accept(p, ns("x"), 10).is_ok());
        assert!(t.accept(p, ns("x"), 5).is_ok());
        assert!(t.accept(p, ns("x"), 9999).is_ok());
        assert!(t.accept(p, ns("x"), 1).is_ok());
        assert!(t.accept(p, ns("x"), 9999).is_err()); // 9999 now a duplicate
    }

    #[test]
    fn per_namespace_partitioned() {
        let mut t = NonceTracker::new();
        let p = peer();
        assert!(t.accept(p, ns("a"), 1).is_ok());
        // Same nonce under a different namespace is fresh.
        assert!(t.accept(p, ns("b"), 1).is_ok());
    }

    #[test]
    fn per_peer_partitioned() {
        let mut t = NonceTracker::new();
        let p1 = peer();
        let p2 = peer();
        assert!(t.accept(p1, ns("x"), 1).is_ok());
        assert!(t.accept(p2, ns("x"), 1).is_ok());
    }

    #[test]
    fn is_fresh_does_not_consume() {
        let mut t = NonceTracker::new();
        let p = peer();
        assert!(t.is_fresh(&p, &ns("x"), 42));
        assert!(t.is_fresh(&p, &ns("x"), 42)); // still fresh after observation
        t.accept(p, ns("x"), 42).unwrap();
        assert!(!t.is_fresh(&p, &ns("x"), 42));
    }
}
