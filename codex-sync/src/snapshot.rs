//! State snapshots for fast sync.
//!
//! A `StateSnapshot` is the full set of `(namespace, key_hash, value)`
//! leaves of a state tree at a specific height. It is postcard-encoded,
//! shipped over the transport, and verified by rebuilding the state
//! tree and checking that its `root()` matches the expected
//! `state_root` (which the receiver trusts via the signed block
//! header).
//!
//! v0 ships the full leaf set. Delta snapshots (difference from the
//! previous snapshot) are §7.3 fast-sync future work.

use codex_core::namespace::Namespace;
use codex_state::merkle::HASH_LEN;
use codex_state::{state::StateEntry, StateTree};
use serde::{Deserialize, Serialize};

use crate::error::SyncError;

/// Serializable state snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub at_height: u64,
    pub at_state_root: [u8; HASH_LEN],
    pub leaves: Vec<StateEntry>,
}

impl StateSnapshot {
    /// Build a snapshot from a mutable reference (required because
    /// computing the root mutates the cache).
    pub fn from_state(at_height: u64, state: &mut StateTree) -> Self {
        Self {
            at_height,
            at_state_root: state.root(),
            leaves: state.iter().cloned().collect(),
        }
    }

    /// Rebuild a fresh state tree from this snapshot and assert that
    /// its root matches the snapshot's declared `at_state_root`.
    /// Returns the rebuilt tree on success.
    pub fn rebuild(&self) -> Result<StateTree, SyncError> {
        let mut tree = StateTree::new();
        for entry in &self.leaves {
            tree.insert(entry.namespace.clone(), entry.key_hash, entry.value.clone());
        }
        let actual = tree.root();
        if actual != self.at_state_root {
            return Err(SyncError::Transport(format!(
                "snapshot root mismatch: got {}, expected {}",
                hex::encode(actual),
                hex::encode(self.at_state_root)
            )));
        }
        Ok(tree)
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Number of entries in the snapshot that fall under `namespace`.
    pub fn count_in_namespace(&self, ns: &Namespace) -> usize {
        self.leaves.iter().filter(|e| &e.namespace == ns).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_crypto::Blake3Hasher;

    fn key(tag: u64) -> [u8; HASH_LEN] {
        let mut h = Blake3Hasher::new();
        h.update(&tag.to_le_bytes());
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    #[test]
    fn round_trip_preserves_root() {
        let ns = Namespace::new("x").unwrap();
        let mut src = StateTree::new();
        for i in 0..25u64 {
            src.insert(ns.clone(), key(i), vec![i as u8; 16]);
        }
        let expected_root = src.root();

        let snap = StateSnapshot::from_state(42, &mut src);
        let bytes = postcard::to_allocvec(&snap).unwrap();
        let parsed: StateSnapshot = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(snap, parsed);

        let mut rebuilt = parsed.rebuild().unwrap();
        assert_eq!(rebuilt.root(), expected_root);
    }

    #[test]
    fn tampered_snapshot_rejected() {
        let ns = Namespace::new("x").unwrap();
        let mut src = StateTree::new();
        src.insert(ns.clone(), key(1), b"v".to_vec());
        let mut snap = StateSnapshot::from_state(1, &mut src);
        snap.leaves[0].value = b"tampered".to_vec();
        assert!(snap.rebuild().is_err());
    }

    #[test]
    fn empty_snapshot_round_trip() {
        let mut src = StateTree::new();
        let snap = StateSnapshot::from_state(0, &mut src);
        let bytes = postcard::to_allocvec(&snap).unwrap();
        let parsed: StateSnapshot = postcard::from_bytes(&bytes).unwrap();
        let mut rebuilt = parsed.rebuild().unwrap();
        assert_eq!(rebuilt.root(), src.root());
    }
}
