//! Sorted-key binary merkle state tree.
//!
//! v0 uses a sorted flat `Vec` of leaves keyed by
//! `(Namespace, [u8; 32] key_hash)`. Every mutation rebuilds the internal
//! hash list; `compute_root` runs over the full leaf set on each call.
//!
//! This is deliberately simple. The use case sized in `docs/DESIGN.md`
//! §2.4 / §5.7 is low-write, high-read with ~10⁸ lifetime entries.
//! Read-heavy access patterns benefit more from eventual pruning and
//! snapshotting (§5.7 `Hot / Warm / Cold`) than from clever in-memory
//! indexing. A persistent merkle tree (M4+) is the natural upgrade path
//! when write rates demand it.

use codex_core::namespace::Namespace;
use serde::{Deserialize, Serialize};

use crate::merkle::{compute_root, compute_siblings, leaf_hash, state_root_commit, HASH_LEN};
use crate::proof::{tuple_lt, ExistenceProof, NonExistenceProof};

/// A single state-tree entry. Kept public so that namespace handlers
/// can iterate over a snapshot if they need to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEntry {
    pub namespace: Namespace,
    pub key_hash: [u8; HASH_LEN],
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// The state tree.
///
/// Leaves are kept in sorted order over `(namespace_bytes, key_hash)`.
/// `root_cache` is invalidated on any mutation.
#[derive(Debug, Clone, Default)]
pub struct StateTree {
    leaves: Vec<StateEntry>,
    root_cache: Option<[u8; HASH_LEN]>,
}

impl StateTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Look up a value by `(namespace, key_hash)`. Returns `None` if
    /// not present.
    pub fn get(&self, namespace: &Namespace, key_hash: &[u8; HASH_LEN]) -> Option<&[u8]> {
        self.find(namespace, key_hash)
            .ok()
            .map(|i| self.leaves[i].value.as_slice())
    }

    /// Insert or update. Returns the previous value if one was present.
    pub fn insert(
        &mut self,
        namespace: Namespace,
        key_hash: [u8; HASH_LEN],
        value: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.root_cache = None;
        match self.find(&namespace, &key_hash) {
            Ok(i) => {
                let old = std::mem::replace(&mut self.leaves[i].value, value);
                Some(old)
            }
            Err(pos) => {
                self.leaves.insert(
                    pos,
                    StateEntry {
                        namespace,
                        key_hash,
                        value,
                    },
                );
                None
            }
        }
    }

    /// Remove by `(namespace, key_hash)`. Returns the removed value or
    /// `None` if not present.
    pub fn remove(&mut self, namespace: &Namespace, key_hash: &[u8; HASH_LEN]) -> Option<Vec<u8>> {
        match self.find(namespace, key_hash) {
            Ok(i) => {
                self.root_cache = None;
                Some(self.leaves.remove(i).value)
            }
            Err(_) => None,
        }
    }

    /// State root of the current tree. Cached between mutations.
    /// `state_root = blake3(dom::STATE_ROOT ‖ u64_le(leaf_count) ‖ merkle_root)`
    /// per §5.4.3 — commits to leaf count so proof indices are verifiable.
    pub fn root(&mut self) -> [u8; HASH_LEN] {
        if let Some(r) = self.root_cache {
            return r;
        }
        let r = state_root_commit(self.leaves.len() as u64, &self.raw_merkle_root());
        self.root_cache = Some(r);
        r
    }

    fn raw_merkle_root(&self) -> [u8; HASH_LEN] {
        let hashes: Vec<[u8; HASH_LEN]> = self
            .leaves
            .iter()
            .map(|e| leaf_hash(e.namespace.as_str(), &e.key_hash, &e.value))
            .collect();
        compute_root(&hashes)
    }

    /// Number of leaves in the tree (public for serializing snapshots).
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Iterate over the sorted leaves. Used by [`crate::snapshot`] and
    /// tooling that needs to serialize state.
    pub fn iter(&self) -> impl Iterator<Item = &StateEntry> {
        self.leaves.iter()
    }

    /// Produce an `ExistenceProof` for a key that is present.
    /// Returns `None` if the key is absent.
    pub fn existence_proof(
        &self,
        namespace: &Namespace,
        key_hash: &[u8; HASH_LEN],
    ) -> Option<ExistenceProof> {
        let idx = self.find(namespace, key_hash).ok()?;
        let hashes = self.leaf_hashes();
        let siblings = compute_siblings(&hashes, idx)?;
        let entry = &self.leaves[idx];
        Some(ExistenceProof {
            namespace: entry.namespace.clone(),
            key_hash: entry.key_hash,
            value: entry.value.clone(),
            siblings,
            index: idx as u64,
            total_leaves: self.leaves.len() as u64,
        })
    }

    /// Produce a `NonExistenceProof` for a key that is absent.
    /// Returns `None` if the key actually exists.
    pub fn non_existence_proof(
        &self,
        namespace: &Namespace,
        key_hash: &[u8; HASH_LEN],
    ) -> Option<NonExistenceProof> {
        let pos = match self.find(namespace, key_hash) {
            Ok(_) => return None,
            Err(p) => p,
        };
        let hashes = self.leaf_hashes();
        let total_leaves = self.leaves.len() as u64;

        let left = if pos == 0 {
            None
        } else {
            let i = pos - 1;
            let e = &self.leaves[i];
            Some(ExistenceProof {
                namespace: e.namespace.clone(),
                key_hash: e.key_hash,
                value: e.value.clone(),
                siblings: compute_siblings(&hashes, i).unwrap(),
                index: i as u64,
                total_leaves,
            })
        };
        let right = if pos >= self.leaves.len() {
            None
        } else {
            let e = &self.leaves[pos];
            Some(ExistenceProof {
                namespace: e.namespace.clone(),
                key_hash: e.key_hash,
                value: e.value.clone(),
                siblings: compute_siblings(&hashes, pos).unwrap(),
                index: pos as u64,
                total_leaves,
            })
        };

        Some(NonExistenceProof {
            queried_namespace: namespace.clone(),
            queried_key_hash: *key_hash,
            left_neighbor: left,
            right_neighbor: right,
            total_leaves,
        })
    }

    fn leaf_hashes(&self) -> Vec<[u8; HASH_LEN]> {
        self.leaves
            .iter()
            .map(|e| leaf_hash(e.namespace.as_str(), &e.key_hash, &e.value))
            .collect()
    }

    /// Binary-search position. `Ok(i)` if present, `Err(pos)` if absent
    /// where `pos` is the insertion index that preserves order.
    fn find(&self, namespace: &Namespace, key_hash: &[u8; HASH_LEN]) -> Result<usize, usize> {
        self.leaves.binary_search_by(|entry| {
            if tuple_lt(
                entry.namespace.as_str(),
                &entry.key_hash,
                namespace.as_str(),
                key_hash,
            ) {
                core::cmp::Ordering::Less
            } else if tuple_lt(
                namespace.as_str(),
                key_hash,
                entry.namespace.as_str(),
                &entry.key_hash,
            ) {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::state_empty_root;
    use crate::proof::{verify_existence, verify_non_existence};

    fn ns(s: &str) -> Namespace {
        Namespace::new(s).unwrap()
    }

    fn key(tag: u8) -> [u8; HASH_LEN] {
        [tag; HASH_LEN]
    }

    #[test]
    fn fresh_tree_is_empty_root() {
        let mut t = StateTree::new();
        assert!(t.is_empty());
        assert_eq!(t.root(), state_empty_root());
    }

    #[test]
    fn insert_get_remove_round_trip() {
        let mut t = StateTree::new();
        assert!(t.get(&ns("a"), &key(1)).is_none());
        assert_eq!(t.insert(ns("a"), key(1), b"v1".to_vec()), None);
        assert_eq!(
            t.get(&ns("a"), &key(1)).map(|s| s.to_vec()),
            Some(b"v1".to_vec())
        );
        // Update.
        assert_eq!(
            t.insert(ns("a"), key(1), b"v2".to_vec()),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            t.get(&ns("a"), &key(1)).map(|s| s.to_vec()),
            Some(b"v2".to_vec())
        );
        // Remove.
        assert_eq!(t.remove(&ns("a"), &key(1)), Some(b"v2".to_vec()));
        assert!(t.get(&ns("a"), &key(1)).is_none());
    }

    #[test]
    fn root_changes_on_mutation() {
        let mut t = StateTree::new();
        let r0 = t.root();
        t.insert(ns("a"), key(1), b"v".to_vec());
        let r1 = t.root();
        assert_ne!(r0, r1);
        t.insert(ns("a"), key(1), b"v".to_vec()); // idempotent update
        let r2 = t.root();
        assert_eq!(r1, r2);
        t.insert(ns("a"), key(1), b"v2".to_vec());
        let r3 = t.root();
        assert_ne!(r2, r3);
        t.remove(&ns("a"), &key(1));
        let r4 = t.root();
        assert_eq!(r4, state_empty_root());
    }

    #[test]
    fn root_differs_across_leaf_counts() {
        // state_root_commit binds leaf count, so trees of different size
        // cannot share a root even if their raw merkle_roots coincided.
        let mut a = StateTree::new();
        a.insert(ns("x"), key(1), b"v".to_vec());
        let mut b = a.clone();
        b.insert(ns("y"), key(2), b"v".to_vec());
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn namespaces_are_partitioned() {
        let mut t = StateTree::new();
        t.insert(ns("a"), key(1), b"in a".to_vec());
        t.insert(ns("b"), key(1), b"in b".to_vec());
        assert_eq!(
            t.get(&ns("a"), &key(1)).map(|s| s.to_vec()),
            Some(b"in a".to_vec())
        );
        assert_eq!(
            t.get(&ns("b"), &key(1)).map(|s| s.to_vec()),
            Some(b"in b".to_vec())
        );
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn existence_proof_verifies() {
        let mut t = StateTree::new();
        for i in 1..=5u8 {
            t.insert(ns(&format!("ns.{i}")), key(i), format!("v{i}").into_bytes());
        }
        let root = t.root();
        for i in 1..=5u8 {
            let proof = t.existence_proof(&ns(&format!("ns.{i}")), &key(i)).unwrap();
            verify_existence(&proof, &root).unwrap();
        }
    }

    #[test]
    fn non_existence_proof_verifies_in_middle() {
        let mut t = StateTree::new();
        t.insert(ns("a"), key(1), b"va".to_vec());
        t.insert(ns("c"), key(3), b"vc".to_vec());
        let root = t.root();
        let proof = t.non_existence_proof(&ns("b"), &key(2)).unwrap();
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_proof_verifies_below_min() {
        let mut t = StateTree::new();
        t.insert(ns("m"), key(1), b"v".to_vec());
        let root = t.root();
        let proof = t.non_existence_proof(&ns("a"), &key(0)).unwrap();
        assert!(proof.left_neighbor.is_none());
        assert!(proof.right_neighbor.is_some());
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_proof_verifies_above_max() {
        let mut t = StateTree::new();
        t.insert(ns("m"), key(1), b"v".to_vec());
        let root = t.root();
        let proof = t.non_existence_proof(&ns("z"), &key(0xff)).unwrap();
        assert!(proof.left_neighbor.is_some());
        assert!(proof.right_neighbor.is_none());
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_returns_none_when_key_exists() {
        let mut t = StateTree::new();
        t.insert(ns("x"), key(1), b"v".to_vec());
        assert!(t.non_existence_proof(&ns("x"), &key(1)).is_none());
    }

    #[test]
    fn existence_returns_none_for_missing_key() {
        let t = StateTree::new();
        assert!(t.existence_proof(&ns("x"), &key(1)).is_none());
    }

    #[test]
    fn root_is_deterministic_across_clones() {
        let mut a = StateTree::new();
        a.insert(ns("a"), key(1), b"x".to_vec());
        a.insert(ns("b"), key(2), b"y".to_vec());
        let ra = a.root();

        let mut b = StateTree::new();
        b.insert(ns("b"), key(2), b"y".to_vec());
        b.insert(ns("a"), key(1), b"x".to_vec());
        let rb = b.root();

        assert_eq!(ra, rb, "sorted-key merkle must be insert-order-independent");
    }
}
