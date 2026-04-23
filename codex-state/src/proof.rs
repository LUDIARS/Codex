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
//! # v0 non-existence note
//!
//! v0 non-existence relies on:
//! 1. cryptographic verification of the two neighbor existence proofs
//! 2. strict key ordering (`left.key < query.key < right.key`)
//!
//! Structural adjacency — proving that no third leaf sits between the
//! neighbors in the sorted order — is *not* yet enforced in v0. In a
//! PoA / committee setting the block producer is authorized to generate
//! proofs and answers are auditable post-hoc via the mempool log
//! (§5.8.2). An adjacency-by-merkle-structure check is a v1+ hardening
//! (§15, merkle Upgrade path).

use codex_core::namespace::Namespace;
use serde::{Deserialize, Serialize};

use crate::error::ProofError;
use crate::merkle::{fold_path, leaf_hash, Direction, EMPTY_ROOT, HASH_LEN};

/// Proof that `(namespace, key_hash) → value` is present at a known
/// state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistenceProof {
    pub namespace: Namespace,
    pub key_hash: [u8; HASH_LEN],
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
    pub siblings: Vec<(Direction, [u8; HASH_LEN])>,
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
}

/// Verify that `proof` folds to `expected_root`.
pub fn verify_existence(
    proof: &ExistenceProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    let leaf = leaf_hash(proof.namespace.as_str(), &proof.key_hash, &proof.value);
    let folded = fold_path(leaf, &proof.siblings);
    if &folded == expected_root {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}

/// Verify a non-existence proof against `expected_root`.
///
/// Rules (v0):
/// - empty tree → both neighbors `None`, root must equal [`EMPTY_ROOT`]
/// - both neighbors present → verify both, and check `left < query < right`
/// - only right → verify it, check `query < right`
/// - only left → verify it, check `left < query`
///
/// Ordering compares `(namespace_bytes, key_hash)` lexicographically.
pub fn verify_non_existence(
    proof: &NonExistenceProof,
    expected_root: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    match (&proof.left_neighbor, &proof.right_neighbor) {
        (None, None) => {
            if expected_root == &EMPTY_ROOT {
                Ok(())
            } else {
                Err(ProofError::InvalidNonExistence)
            }
        }
        (Some(left), Some(right)) => {
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
    use crate::merkle::{compute_root, compute_siblings};

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

    #[test]
    fn verify_existence_round_trip() {
        // Build a small sorted-leaves tree and verify every leaf's proof.
        let namespaces = ["a.b", "a.c", "d.e", "m.n", "z.z"];
        let leaf_hashes: Vec<[u8; HASH_LEN]> = namespaces
            .iter()
            .enumerate()
            .map(|(i, n)| leaf_hash(n, &key(i as u8 + 1), b"v"))
            .collect();
        let root = compute_root(&leaf_hashes);

        for (i, n) in namespaces.iter().enumerate() {
            let siblings = compute_siblings(&leaf_hashes, i).unwrap();
            let proof = ExistenceProof {
                namespace: ns(n),
                key_hash: key(i as u8 + 1),
                value: b"v".to_vec(),
                siblings,
            };
            verify_existence(&proof, &root).unwrap_or_else(|e| {
                panic!("proof {i} failed: {e:?}");
            });
        }
    }

    #[test]
    fn verify_existence_detects_tampered_value() {
        let leaves = vec![leaf_hash("x", &key(1), b"orig")];
        let root = compute_root(&leaves);
        let proof = ExistenceProof {
            namespace: ns("x"),
            key_hash: key(1),
            value: b"tampered".to_vec(),
            siblings: vec![],
        };
        assert!(matches!(
            verify_existence(&proof, &root),
            Err(ProofError::RootMismatch)
        ));
    }

    #[test]
    fn non_existence_empty_tree() {
        let proof = NonExistenceProof {
            queried_namespace: ns("x"),
            queried_key_hash: key(1),
            left_neighbor: None,
            right_neighbor: None,
        };
        verify_non_existence(&proof, &EMPTY_ROOT).unwrap();
    }

    #[test]
    fn non_existence_empty_tree_rejects_wrong_root() {
        let proof = NonExistenceProof {
            queried_namespace: ns("x"),
            queried_key_hash: key(1),
            left_neighbor: None,
            right_neighbor: None,
        };
        let wrong = [0xffu8; HASH_LEN];
        assert!(matches!(
            verify_non_existence(&proof, &wrong),
            Err(ProofError::InvalidNonExistence)
        ));
    }

    #[test]
    fn non_existence_below_all() {
        // Single-leaf tree with key "b"; query "a" → only right neighbor.
        let leaves = vec![leaf_hash("b", &key(2), b"v")];
        let root = compute_root(&leaves);
        let right_siblings = compute_siblings(&leaves, 0).unwrap();
        let right = ExistenceProof {
            namespace: ns("b"),
            key_hash: key(2),
            value: b"v".to_vec(),
            siblings: right_siblings,
        };
        let proof = NonExistenceProof {
            queried_namespace: ns("a"),
            queried_key_hash: key(1),
            left_neighbor: None,
            right_neighbor: Some(right),
        };
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_between_two() {
        // Tree: [("a", k1), ("c", k3)] — query ("b", k2) lives between.
        let leaves = vec![
            leaf_hash("a", &key(1), b"va"),
            leaf_hash("c", &key(3), b"vc"),
        ];
        let root = compute_root(&leaves);
        let left = ExistenceProof {
            namespace: ns("a"),
            key_hash: key(1),
            value: b"va".to_vec(),
            siblings: compute_siblings(&leaves, 0).unwrap(),
        };
        let right = ExistenceProof {
            namespace: ns("c"),
            key_hash: key(3),
            value: b"vc".to_vec(),
            siblings: compute_siblings(&leaves, 1).unwrap(),
        };
        let proof = NonExistenceProof {
            queried_namespace: ns("b"),
            queried_key_hash: key(2),
            left_neighbor: Some(left),
            right_neighbor: Some(right),
        };
        verify_non_existence(&proof, &root).unwrap();
    }

    #[test]
    fn non_existence_rejects_bad_ordering() {
        let leaves = vec![leaf_hash("a", &key(1), b"v"), leaf_hash("c", &key(3), b"v")];
        let root = compute_root(&leaves);
        let left = ExistenceProof {
            namespace: ns("a"),
            key_hash: key(1),
            value: b"v".to_vec(),
            siblings: compute_siblings(&leaves, 0).unwrap(),
        };
        let right = ExistenceProof {
            namespace: ns("c"),
            key_hash: key(3),
            value: b"v".to_vec(),
            siblings: compute_siblings(&leaves, 1).unwrap(),
        };
        // Query "d" is beyond the right neighbor → ordering violation.
        let proof = NonExistenceProof {
            queried_namespace: ns("d"),
            queried_key_hash: key(4),
            left_neighbor: Some(left),
            right_neighbor: Some(right),
        };
        assert!(matches!(
            verify_non_existence(&proof, &root),
            Err(ProofError::InvalidOrdering)
        ));
    }

    #[test]
    fn proof_serde_round_trip() {
        let leaves = vec![leaf_hash("x", &key(1), b"v")];
        let root = compute_root(&leaves);
        let siblings = compute_siblings(&leaves, 0).unwrap();
        let proof = ExistenceProof {
            namespace: ns("x"),
            key_hash: key(1),
            value: b"v".to_vec(),
            siblings,
        };
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let parsed: ExistenceProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(proof, parsed);
        verify_existence(&parsed, &root).unwrap();
    }
}
