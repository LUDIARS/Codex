//! Existence and non-existence proofs for the state tree.
//!
//! Proofs are `Serialize + Deserialize` so they can be shipped to light
//! clients (§8). Verification is ambient — it doesn't need the full tree
//! nor any indexes, just the trusted `state_root` from a signed block
//! header.
//!
//! # Design references
//! - `docs/DESIGN.md` §5.4.3 (proof structure)
//!
//! # Structural adjacency
//!
//! `state_root` commits to the leaf count (`state_root_commit(count,
//! merkle_root)`). Every `ExistenceProof` carries `index` and
//! `total_leaves`; verification rejects mismatches. Non-existence
//! proofs are therefore structurally sound: the verifier checks
//! `left.index + 1 == right.index` and both proofs validate against
//! the same `(total_leaves, merkle_root)` pair, which the producer
//! cannot forge without breaking the leaf-count commitment.

use codex_core::namespace::Namespace;
use serde::{Deserialize, Serialize};

use crate::error::ProofError;
use crate::merkle::{fold_path, leaf_hash, state_root_commit, Direction, HASH_LEN};

/// Proof that `(namespace, key_hash) → value` is present at a known
/// state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistenceProof {
    pub namespace: Namespace,
    pub key_hash: [u8; HASH_LEN],
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
    pub siblings: Vec<(Direction, [u8; HASH_LEN])>,
    /// Position of this leaf in the sorted leaf list (0-based).
    pub index: u64,
    /// Total number of leaves in the tree. Committed into `state_root`.
    pub total_leaves: u64,
}

/// Proof that `(namespace, key_hash)` is *not* present at a known state
/// root. Either neighbor may be `None` if the queried key is below all
/// existing keys, above all, or the tree is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonExistenceProof {
    pub queried_namespace: Namespace,
    pub queried_key_hash: [u8; HASH_LEN],
    pub left_neighbor: Option<ExistenceProof>,
    pub right_neighbor: Option<ExistenceProof>,
    /// Total leaves in the tree at proof time. Must match both
    /// neighbors' `total_leaves`.
    pub total_leaves: u64,
}

/// Verify that `proof` folds to `expected_root` and that the claimed
/// index is consistent with the sibling directions.
pub fn verify_existence(
    proof: &ExistenceProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    if proof.index >= proof.total_leaves {
        return Err(ProofError::InvalidOrdering);
    }
    // Verify sibling directions are consistent with the claimed index.
    // At level L the sibling appears iff the node at that level has one;
    // when present, its direction is determined by bit L of `index`.
    let mut cursor = proof.index;
    let mut level_size = proof.total_leaves;
    let mut expected_directions: Vec<Direction> = Vec::new();
    while level_size > 1 {
        let even = cursor.is_multiple_of(2);
        let sibling_index = if even { cursor + 1 } else { cursor - 1 };
        if sibling_index < level_size {
            let dir = if even {
                Direction::Right
            } else {
                Direction::Left
            };
            expected_directions.push(dir);
        }
        cursor /= 2;
        level_size = level_size.div_ceil(2);
    }
    if proof.siblings.len() != expected_directions.len() {
        return Err(ProofError::RootMismatch);
    }
    for (i, (dir, _)) in proof.siblings.iter().enumerate() {
        if *dir != expected_directions[i] {
            return Err(ProofError::RootMismatch);
        }
    }
    let leaf = leaf_hash(proof.namespace.as_str(), &proof.key_hash, &proof.value);
    let merkle_root = fold_path(leaf, &proof.siblings);
    let computed = state_root_commit(proof.total_leaves, &merkle_root);
    if &computed == expected_root {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}

/// Verify a non-existence proof against `expected_root`.
///
/// Rules:
/// - empty tree → both neighbors `None`, root must equal
///   [`state_empty_root`](crate::merkle::state_empty_root)
/// - both neighbors → both verify; `left < query < right`;
///   `left.index + 1 == right.index`; same `total_leaves`
/// - only right → verify; `query < right`; `right.index == 0`
/// - only left → verify; `left < query`; `left.index == total_leaves - 1`
///
/// The `total_leaves` commitment inside each `ExistenceProof` (and
/// consequently inside the state root) is what makes adjacency
/// cryptographically binding.
pub fn verify_non_existence(
    proof: &NonExistenceProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    use crate::merkle::state_empty_root;
    match (&proof.left_neighbor, &proof.right_neighbor) {
        (None, None) => {
            if proof.total_leaves != 0 {
                return Err(ProofError::InvalidNonExistence);
            }
            if expected_root != &state_empty_root() {
                return Err(ProofError::InvalidNonExistence);
            }
            Ok(())
        }
        (Some(left), Some(right)) => {
            if left.total_leaves != right.total_leaves || left.total_leaves != proof.total_leaves {
                return Err(ProofError::InvalidNonExistence);
            }
            if left.index + 1 != right.index {
                return Err(ProofError::InvalidNonExistence);
            }
            verify_existence(left, expected_root)?;
            verify_existence(right, expected_root)?;
            ensure_lt(
                left.namespace.as_str(),
                &left.key_hash,
                proof.queried_namespace.as_str(),
                &proof.queried_key_hash,
            )?;
            ensure_lt(
                proof.queried_namespace.as_str(),
                &proof.queried_key_hash,
                right.namespace.as_str(),
                &right.key_hash,
            )?;
            Ok(())
        }
        (Some(left), None) => {
            if left.total_leaves != proof.total_leaves {
                return Err(ProofError::InvalidNonExistence);
            }
            if left.index + 1 != proof.total_leaves {
                return Err(ProofError::InvalidNonExistence);
            }
            verify_existence(left, expected_root)?;
            ensure_lt(
                left.namespace.as_str(),
                &left.key_hash,
                proof.queried_namespace.as_str(),
                &proof.queried_key_hash,
            )?;
            Ok(())
        }
        (None, Some(right)) => {
            if right.total_leaves != proof.total_leaves {
                return Err(ProofError::InvalidNonExistence);
            }
            if right.index != 0 {
                return Err(ProofError::InvalidNonExistence);
            }
            verify_existence(right, expected_root)?;
            ensure_lt(
                proof.queried_namespace.as_str(),
                &proof.queried_key_hash,
                right.namespace.as_str(),
                &right.key_hash,
            )?;
            Ok(())
        }
    }
}

fn ensure_lt(
    a_ns: &str,
    a_key: &[u8; HASH_LEN],
    b_ns: &str,
    b_key: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    if tuple_lt(a_ns, a_key, b_ns, b_key) {
        Ok(())
    } else {
        Err(ProofError::InvalidOrdering)
    }
}

/// Strict-less-than over `(namespace, key_hash)`. Lexicographic on
/// namespace bytes, then on key_hash bytes.
pub(crate) fn tuple_lt(
    a_ns: &str,
    a_key: &[u8; HASH_LEN],
    b_ns: &str,
    b_key: &[u8; HASH_LEN],
) -> bool {
    match a_ns.as_bytes().cmp(b_ns.as_bytes()) {
        core::cmp::Ordering::Less => true,
        core::cmp::Ordering::Greater => false,
        core::cmp::Ordering::Equal => a_key < b_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(s: &str) -> Namespace {
        Namespace::new(s).unwrap()
    }

    fn key(tag: u8) -> [u8; HASH_LEN] {
        [tag; HASH_LEN]
    }

    #[test]
    fn tuple_lt_compares_namespace_first() {
        let k = key(1);
        assert!(tuple_lt("a", &k, "b", &k));
        assert!(!tuple_lt("b", &k, "a", &k));
        assert!(!tuple_lt("a", &k, "a", &k));
    }

    #[test]
    fn tuple_lt_breaks_ties_by_key() {
        let k1 = key(1);
        let k2 = key(2);
        assert!(tuple_lt("x", &k1, "x", &k2));
        assert!(!tuple_lt("x", &k2, "x", &k1));
    }

    // Tests now drive proofs through `StateTree` so that `index` and
    // `total_leaves` are set consistently. The bare-struct construction
    // style was error-prone once those fields existed.
    use crate::state::StateTree;

    fn build_tree(pairs: &[(&str, u8, &[u8])]) -> StateTree {
        let mut t = StateTree::new();
        for (n, k, v) in pairs {
            t.insert(ns(n), key(*k), v.to_vec());
        }
        t
    }

    #[test]
    fn existence_round_trip_for_all_positions() {
        let pairs: Vec<(&str, u8, &[u8])> = vec![
            ("a.b", 1, b"v1"),
            ("a.c", 2, b"v2"),
            ("d.e", 3, b"v3"),
            ("m.n", 4, b"v4"),
            ("z.z", 5, b"v5"),
        ];
        let mut tree = build_tree(&pairs);
        let root = tree.root();
        for (n, k, _) in &pairs {
            let proof = tree.existence_proof(&ns(n), &key(*k)).unwrap();
            verify_existence(&proof, &root).unwrap();
        }
    }

    #[test]
    fn existence_detects_tampered_value() {
        let mut tree = build_tree(&[("x", 1, b"orig")]);
        let root = tree.root();
        let mut proof = tree.existence_proof(&ns("x"), &key(1)).unwrap();
        proof.value = b"tampered".to_vec();
        assert!(matches!(
            verify_existence(&proof, &root),
            Err(ProofError::RootMismatch)
        ));
    }

    #[test]
    fn existence_detects_bogus_index() {
        let mut tree = build_tree(&[
            ("a", 1, b"v"),
            ("b", 2, b"v"),
            ("c", 3, b"v"),
            ("d", 4, b"v"),
        ]);
        let root = tree.root();
        let mut proof = tree.existence_proof(&ns("a"), &key(1)).unwrap();
        proof.index = 3; // lie about position
        assert!(verify_existence(&proof, &root).is_err());
    }

    #[test]
    fn existence_detects_wrong_total_leaves() {
        let mut tree = build_tree(&[("a", 1, b"v"), ("b", 2, b"v")]);
        let root = tree.root();
        let mut proof = tree.existence_proof(&ns("a"), &key(1)).unwrap();
        proof.total_leaves = 7; // lie
        assert!(verify_existence(&proof, &root).is_err());
    }

    #[test]
    fn non_existence_empty_tree() {
        let mut tree = StateTree::new();
        let root = tree.root();
        let proof = tree.non_existence_proof(&ns("x"), &key(1)).unwrap();
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_empty_tree_rejects_wrong_root() {
        let mut tree = StateTree::new();
        let proof = tree.non_existence_proof(&ns("x"), &key(1)).unwrap();
        let wrong = [0xffu8; HASH_LEN];
        assert!(matches!(
            verify_non_existence(&proof, &wrong),
            Err(ProofError::InvalidNonExistence)
        ));
        // Sanity: root() returns the correct non-zero empty root.
        let _ = tree.root();
    }

    #[test]
    fn non_existence_below_all() {
        let mut tree = build_tree(&[("b", 2, b"v")]);
        let root = tree.root();
        let proof = tree.non_existence_proof(&ns("a"), &key(1)).unwrap();
        assert!(proof.left_neighbor.is_none());
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_between_two() {
        let mut tree = build_tree(&[("a", 1, b"va"), ("c", 3, b"vc")]);
        let root = tree.root();
        let proof = tree.non_existence_proof(&ns("b"), &key(2)).unwrap();
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_rejects_bad_ordering() {
        let mut tree = build_tree(&[("a", 1, b"v"), ("c", 3, b"v")]);
        let root = tree.root();
        let mut proof = tree.non_existence_proof(&ns("b"), &key(2)).unwrap();
        // Lie: the queried key is now beyond the right neighbor.
        proof.queried_namespace = ns("d");
        proof.queried_key_hash = key(4);
        assert!(matches!(
            verify_non_existence(&proof, &root),
            Err(ProofError::InvalidOrdering)
        ));
    }

    #[test]
    fn non_existence_rejects_non_adjacent_neighbors() {
        // Tree has 4 leaves; a naive attacker picks neighbors at
        // positions 0 and 3 to "prove" nothing exists at position 1 or 2.
        let mut tree = build_tree(&[
            ("a", 1, b"va"),
            ("b", 2, b"vb"),
            ("c", 3, b"vc"),
            ("d", 4, b"vd"),
        ]);
        let root = tree.root();
        let left = tree.existence_proof(&ns("a"), &key(1)).unwrap();
        let right = tree.existence_proof(&ns("d"), &key(4)).unwrap();
        let bogus = NonExistenceProof {
            queried_namespace: ns("bb"),
            queried_key_hash: [0x22u8; HASH_LEN],
            left_neighbor: Some(left),
            right_neighbor: Some(right),
            total_leaves: tree.leaf_count(),
        };
        // left.index + 1 != right.index → adjacency violation.
        assert!(matches!(
            verify_non_existence(&bogus, &root),
            Err(ProofError::InvalidNonExistence)
        ));
    }

    #[test]
    fn proof_serde_round_trip() {
        let mut tree = build_tree(&[("x", 1, b"v")]);
        let root = tree.root();
        let proof = tree.existence_proof(&ns("x"), &key(1)).unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let parsed: ExistenceProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(proof, parsed);
        verify_existence(&parsed, &root).unwrap();
    }
}
