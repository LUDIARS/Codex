//! Events-root merkle: the merkle tree over a block's events, in
//! producer-chosen order.
//!
//! Distinct from the state tree in key ways:
//! - leaves are `event_hash()` values, not arbitrary (namespace, key)
//!   tuples
//! - ordering is insertion order (the producer's FCFS, §5.8), not
//!   sorted-by-key
//! - inclusion proofs quote the event's *position* in the block
//!
//! The underlying merkle primitives are shared with the state tree
//! ([`crate::merkle`]): both rely on `dom::INTERNAL` for internal node
//! hashing, and this module's leaf is already the event's own
//! `event_hash()` — itself `dom::EVENT_SIG`-tagged — so we don't apply
//! a second `dom::LEAF` prefix here.

use codex_core::event::Event;
use serde::{Deserialize, Serialize};

use crate::error::ProofError;
use crate::merkle::{compute_root, compute_siblings, fold_path, Direction, HASH_LEN};

/// Compute the events_root for a slice of events in block order.
pub fn compute_events_root(events: &[Event]) -> [u8; HASH_LEN] {
    let leaves: Vec<[u8; HASH_LEN]> = events.iter().map(|e| e.event_hash().0).collect();
    compute_root(&leaves)
}

/// Proof that a specific event was at position `index` in a block with
/// the given `events_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventInclusionProof {
    pub index: u32,
    pub event: Event,
    pub siblings: Vec<(Direction, [u8; HASH_LEN])>,
}

/// Build an `EventInclusionProof` for a single event position.
pub fn compute_event_inclusion_proof(
    events: &[Event],
    index: usize,
) -> Option<EventInclusionProof> {
    if index >= events.len() {
        return None;
    }
    let leaves: Vec<[u8; HASH_LEN]> = events.iter().map(|e| e.event_hash().0).collect();
    let siblings = compute_siblings(&leaves, index)?;
    Some(EventInclusionProof {
        index: index as u32,
        event: events[index].clone(),
        siblings,
    })
}

/// Verify that a proof folds to `expected_events_root`.
pub fn verify_event_inclusion(
    proof: &EventInclusionProof,
    expected_events_root: &[u8; HASH_LEN],
) -> Result<(), ProofError> {
    let leaf = proof.event.event_hash().0;
    let folded = fold_path(leaf, &proof.siblings);
    if &folded == expected_events_root {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::event::EventPayload;
    use codex_core::namespace::Namespace;
    use codex_crypto::{PeerId, SigningKey};
    use rand_core::OsRng;

    fn signed_event(nonce: u64, body: &[u8]) -> Event {
        let sk = SigningKey::generate(&mut OsRng);
        let payload = EventPayload {
            version: 1,
            namespace: Namespace::new("tessera.game").unwrap(),
            claimant: PeerId::from_verifying_key(&sk.verifying_key()),
            nonce,
            body: body.to_vec(),
            timestamp: 1,
        };
        payload.sign(&sk)
    }

    #[test]
    fn empty_events_root_is_empty() {
        assert_eq!(compute_events_root(&[]), crate::merkle::EMPTY_ROOT);
    }

    #[test]
    fn single_event_root_is_its_hash() {
        let e = signed_event(1, b"x");
        assert_eq!(
            compute_events_root(std::slice::from_ref(&e)),
            e.event_hash().0
        );
    }

    #[test]
    fn order_matters_for_events_root() {
        let a = signed_event(1, b"a");
        let b = signed_event(2, b"b");
        let r1 = compute_events_root(&[a.clone(), b.clone()]);
        let r2 = compute_events_root(&[b, a]);
        assert_ne!(r1, r2, "events_root must reflect producer ordering (§5.8)");
    }

    #[test]
    fn inclusion_proof_round_trip() {
        let events: Vec<Event> = (1..=7).map(|n| signed_event(n, &[n as u8; 5])).collect();
        let root = compute_events_root(&events);
        for i in 0..events.len() {
            let proof = compute_event_inclusion_proof(&events, i).unwrap();
            verify_event_inclusion(&proof, &root).unwrap_or_else(|e| {
                panic!("proof {i} failed: {e:?}");
            });
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let events = vec![signed_event(1, b"x"), signed_event(2, b"y")];
        let root = compute_events_root(&events);
        let mut proof = compute_event_inclusion_proof(&events, 0).unwrap();
        // Replace the event with a different one (different signature +
        // payload ⇒ different event_hash).
        proof.event = signed_event(1, b"x_tampered");
        assert!(matches!(
            verify_event_inclusion(&proof, &root),
            Err(ProofError::RootMismatch)
        ));
    }

    #[test]
    fn proof_index_out_of_range() {
        let events = vec![signed_event(1, b"x")];
        assert!(compute_event_inclusion_proof(&events, 9).is_none());
    }

    #[test]
    fn serde_round_trip_of_proof() {
        let events: Vec<Event> = (1..=4).map(|n| signed_event(n, b"b")).collect();
        let root = compute_events_root(&events);
        let proof = compute_event_inclusion_proof(&events, 2).unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let parsed: EventInclusionProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(proof, parsed);
        verify_event_inclusion(&parsed, &root).unwrap();
    }
}
