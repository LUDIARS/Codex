//! Sorted-key binary merkle primitives.
//!
//! Used for two distinct trees in Codex:
//! - **State tree** — leaves are `(namespace, key_hash, value)` tuples
//!   kept in sorted order; exposed via [`crate::state::StateTree`].
//! - **Events root** — leaves are the `event_hash()` values of the events
//!   in a block, in producer-chosen order (§5.8); exposed via
//!   [`crate::events::compute_events_root`].
//!
//! Both trees share the same internal hashing (domain-separated via
//! `dom::LEAF` and `dom::INTERNAL`; §5.4.2) and the same pair-and-hash
//! promotion rule: at each level, pairs are hashed; an unpaired trailing
//! node is promoted unchanged to the next level.
//!
//! # Design references
//! - `docs/DESIGN.md` §5.4.1 (sorted-key binary merkle rationale)
//! - `docs/DESIGN.md` §5.4.2 (leaf / internal encoding)
//! - `docs/DESIGN.md` §5.4.3 (proof shape)

use codex_crypto::{dom, Blake3Hasher};
use serde::{Deserialize, Serialize};

/// Fixed hash length used across Codex. Re-exported here for consumers
/// that want merkle-centric naming.
pub const HASH_LEN: usize = 32;

/// Root hash of an empty *ordered* merkle (used for `events_root` when
/// a block has no events). State trees use [`state_root_commit`], which
/// wraps the merkle root with the leaf count.
pub const EMPTY_ROOT: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Wrap a raw merkle root with a leaf-count commitment per §5.4.3.
///
/// `state_root = blake3(dom::STATE_ROOT ‖ u64_le(leaf_count) ‖ merkle_root)`.
///
/// Binding the count into the root means an adversary can't claim a
/// forged `index` for an `ExistenceProof`: the index is verified against
/// the count, and the count is part of the root the verifier already
/// trusts (via the signed block header).
pub fn state_root_commit(leaf_count: u64, merkle_root: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(dom::STATE_ROOT);
    hasher.update(&leaf_count.to_le_bytes());
    hasher.update(merkle_root);
    finalize(hasher)
}

/// State root of an empty tree: `state_root_commit(0, &EMPTY_ROOT)`.
pub fn state_empty_root() -> [u8; HASH_LEN] {
    state_root_commit(0, &EMPTY_ROOT)
}

/// Direction of the sibling at a given merkle level relative to the
/// current node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// The sibling hash is the left operand; current node is the right.
    Left,
    /// The sibling hash is the right operand; current node is the left.
    Right,
}

/// Hash a state-tree leaf. Deterministic, domain-separated.
///
/// Layout: `dom::LEAF ‖ u32_le(ns_len) ‖ ns_bytes ‖ key_hash ‖ u64_le(value_len) ‖ value`.
pub fn leaf_hash(namespace: &str, key_hash: &[u8; HASH_LEN], value: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(dom::LEAF);
    let ns = namespace.as_bytes();
    hasher.update(&(ns.len() as u32).to_le_bytes());
    hasher.update(ns);
    hasher.update(key_hash);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
    finalize(hasher)
}

/// Hash a merkle internal node: `blake3(dom::INTERNAL ‖ left ‖ right)`.
pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(dom::INTERNAL);
    hasher.update(left);
    hasher.update(right);
    finalize(hasher)
}

fn finalize(hasher: Blake3Hasher) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// Compute the merkle root of a slice of pre-hashed leaves.
///
/// Empty input returns [`EMPTY_ROOT`]. Single-leaf input returns that
/// leaf. Multi-leaf input pairs adjacent nodes at each level; any
/// unpaired trailing node is promoted unchanged to the next level.
pub fn compute_root(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut level: Vec<[u8; HASH_LEN]> = leaves.to_vec();
    while level.len() > 1 {
        level = reduce_level(&level);
    }
    level[0]
}

fn reduce_level(level: &[[u8; HASH_LEN]]) -> Vec<[u8; HASH_LEN]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(node_hash(&level[i], &level[i + 1]));
            i += 2;
        } else {
            next.push(level[i]);
            i += 1;
        }
    }
    next
}

/// Collect the sibling hashes needed to prove the leaf at `index` is
/// part of the tree, together with the direction of each sibling.
///
/// Returns an empty `Vec` if there is only one leaf, or `None` if
/// `index` is out of range.
pub fn compute_siblings(
    leaves: &[[u8; HASH_LEN]],
    index: usize,
) -> Option<Vec<(Direction, [u8; HASH_LEN])>> {
    if index >= leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    if leaves.len() == 1 {
        return Some(out);
    }
    let mut level: Vec<[u8; HASH_LEN]> = leaves.to_vec();
    let mut cursor = index;
    while level.len() > 1 {
        let cursor_even = cursor.is_multiple_of(2);
        let sibling_index = if cursor_even { cursor + 1 } else { cursor - 1 };
        if sibling_index < level.len() {
            let dir = if cursor_even {
                Direction::Right
            } else {
                Direction::Left
            };
            out.push((dir, level[sibling_index]));
        }
        // If no sibling (odd trailing node), nothing is added; the node
        // promotes unchanged to the next level and cursor stays.
        level = reduce_level(&level);
        cursor /= 2;
    }
    Some(out)
}

/// Walk a merkle path, folding the leaf through the given siblings to
/// arrive at a computed root.
pub fn fold_path(leaf: [u8; HASH_LEN], siblings: &[(Direction, [u8; HASH_LEN])]) -> [u8; HASH_LEN] {
    let mut current = leaf;
    for (dir, sib) in siblings {
        current = match dir {
            Direction::Left => node_hash(sib, &current),
            Direction::Right => node_hash(&current, sib),
        };
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(tag: u8) -> [u8; HASH_LEN] {
        [tag; HASH_LEN]
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(compute_root(&[]), EMPTY_ROOT);
    }

    #[test]
    fn single_leaf_is_root() {
        let only = h(42);
        assert_eq!(compute_root(&[only]), only);
    }

    #[test]
    fn two_leaves_hash_as_pair() {
        let a = h(1);
        let b = h(2);
        assert_eq!(compute_root(&[a, b]), node_hash(&a, &b));
    }

    #[test]
    fn three_leaves_promote_unpaired() {
        // Level 0: [a, b, c]  → pair (a,b) into p, c promotes → [p, c]
        // Level 1: [p, c]     → pair (p, c) → root
        let a = h(1);
        let b = h(2);
        let c = h(3);
        let p = node_hash(&a, &b);
        let expected = node_hash(&p, &c);
        assert_eq!(compute_root(&[a, b, c]), expected);
    }

    #[test]
    fn root_is_deterministic() {
        let ls: Vec<[u8; HASH_LEN]> = (0..17).map(h).collect();
        assert_eq!(compute_root(&ls), compute_root(&ls));
    }

    #[test]
    fn different_input_gives_different_root() {
        let ls1: Vec<[u8; HASH_LEN]> = (0..8).map(h).collect();
        let mut ls2 = ls1.clone();
        ls2[0][0] ^= 0xff;
        assert_ne!(compute_root(&ls1), compute_root(&ls2));
    }

    #[test]
    fn order_matters() {
        let a = h(1);
        let b = h(2);
        assert_ne!(compute_root(&[a, b]), compute_root(&[b, a]));
    }

    #[test]
    fn siblings_match_fold_for_various_sizes() {
        for n in [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 33] {
            let leaves: Vec<[u8; HASH_LEN]> = (0..n).map(|i| h(i as u8 + 1)).collect();
            let root = compute_root(&leaves);
            for i in 0..n {
                let siblings = compute_siblings(&leaves, i).unwrap();
                let folded = fold_path(leaves[i], &siblings);
                assert_eq!(
                    folded,
                    root,
                    "fold mismatch for n={n}, i={i}: folded={} expected={}",
                    hex::encode(folded),
                    hex::encode(root)
                );
            }
        }
    }

    #[test]
    fn leaf_hash_is_domain_separated() {
        // leaf_hash must differ from node_hash even with the same bytes.
        let key = [0xabu8; HASH_LEN];
        let lh = leaf_hash("tessera.game", &key, b"");
        let nh = node_hash(&key, &[0u8; HASH_LEN]);
        assert_ne!(lh, nh);
    }

    #[test]
    fn leaf_hash_namespace_matters() {
        let key = [0x11u8; HASH_LEN];
        let a = leaf_hash("a", &key, b"same");
        let b = leaf_hash("b", &key, b"same");
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_hash_value_matters() {
        let key = [0x11u8; HASH_LEN];
        let a = leaf_hash("ns", &key, b"v1");
        let b = leaf_hash("ns", &key, b"v2");
        assert_ne!(a, b);
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let key = [0x11u8; HASH_LEN];
        let a = leaf_hash("ns", &key, b"v");
        let b = leaf_hash("ns", &key, b"v");
        assert_eq!(a, b);
    }

    #[test]
    fn siblings_index_out_of_range() {
        let leaves = vec![h(1), h(2)];
        assert!(compute_siblings(&leaves, 2).is_none());
    }
}
