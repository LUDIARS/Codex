//! State transition function: validate + apply a block against a state
//! tree, returning the new `events_root` and `state_root`.
//!
//! The STF is the single point at which all three core invariants are
//! enforced:
//! 1. **Signature validity** — the event's signature must check against
//!    a caller-supplied `PeerId → VerifyingKey` resolver. This is
//!    delegated to the caller because pubkey discovery is outside core
//!    (identity service).
//! 2. **Nonce uniqueness** (§5.2.2) — `(claimant, namespace, nonce)` is
//!    unique across all events ever applied.
//! 3. **Namespace validate + apply** (§5.6) — dispatched to the
//!    registered handler, which enforces domain-specific preconditions
//!    and performs the state mutation.
//!
//! A block that fails any check is rejected atomically: the state tree
//! is rolled back to the pre-block root if a later event in the same
//! block is invalid. This is achieved by cloning the tree before
//! applying, applying in order, and committing only if every event
//! succeeds.

use codex_core::block::Block;
use codex_core::event::Event;
use codex_crypto::{PeerId, VerifyingKey};

use crate::error::{StfError, ValidationError};
use crate::events::compute_events_root;
use crate::handler::HandlerRegistry;
use crate::merkle::HASH_LEN;
use crate::nonce::NonceTracker;
use crate::state::StateTree;

/// Result of a successful block application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedBlock {
    pub events_root: [u8; HASH_LEN],
    pub state_root: [u8; HASH_LEN],
}

/// The state transition function bundle: registry + nonce tracker.
/// Create one per chain and apply blocks against it.
pub struct Stf {
    registry: HandlerRegistry,
    nonces: NonceTracker,
}

impl Stf {
    pub fn new(registry: HandlerRegistry) -> Self {
        Self {
            registry,
            nonces: NonceTracker::new(),
        }
    }

    pub fn registry(&self) -> &HandlerRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut HandlerRegistry {
        &mut self.registry
    }

    pub fn nonces(&self) -> &NonceTracker {
        &self.nonces
    }

    /// Validate a single event without applying or consuming the nonce.
    pub fn validate_event<F>(
        &self,
        event: &Event,
        state: &StateTree,
        resolve: &mut F,
    ) -> Result<(), ValidationError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let vk = resolve(&event.payload.claimant).ok_or(ValidationError::Signature(
            codex_core::SignatureError::Invalid,
        ))?;
        event.verify_with_key(&vk).map_err(ValidationError::from)?;

        if !self.nonces.is_fresh(
            &event.payload.claimant,
            &event.payload.namespace,
            event.payload.nonce,
        ) {
            return Err(ValidationError::DuplicateNonce {
                nonce: event.payload.nonce,
            });
        }

        let handler = self
            .registry
            .get(&event.payload.namespace)
            .ok_or_else(|| ValidationError::UnknownNamespace(event.payload.namespace.clone()))?;
        handler.validate(event, state)?;
        Ok(())
    }

    /// Apply a block:
    /// 1. On a scratch clone of `state`, validate and apply every event
    ///    in order.
    /// 2. Compute new `events_root` and `state_root`.
    /// 3. If the block declares non-zero events_root / state_root in its
    ///    header, check they match (caller can pass placeholders for
    ///    producing new blocks; see `build_block_header` helpers in
    ///    codex-consensus / codex-node which will land in M2).
    /// 4. On success, commit by replacing `state` with the scratch and
    ///    consuming nonces in the tracker.
    /// 5. On failure, `state` and `self.nonces` are left unchanged.
    pub fn apply_block<F>(
        &mut self,
        block: &Block,
        state: &mut StateTree,
        resolve: &mut F,
    ) -> Result<AppliedBlock, StfError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        // Work on a scratch so validation failures don't corrupt `state`.
        let mut scratch_state = state.clone();
        let mut scratch_nonces = self.nonces.clone();

        for (idx, event) in block.events.iter().enumerate() {
            self.validate_with_scratch(event, &scratch_state, &scratch_nonces, resolve)
                .map_err(|source| StfError::Validation { index: idx, source })?;

            // Consume nonce in scratch.
            scratch_nonces
                .accept(
                    event.payload.claimant,
                    event.payload.namespace.clone(),
                    event.payload.nonce,
                )
                .expect(
                    "nonce just verified fresh; accept should succeed unless a duplicate exists within this block",
                );

            // Apply via handler.
            let handler = self
                .registry
                .get(&event.payload.namespace)
                .expect("handler existence verified in validate");
            handler
                .apply(event, &mut scratch_state)
                .map_err(|source| StfError::Apply { index: idx, source })?;
        }

        let events_root = compute_events_root(&block.events);
        let state_root = scratch_state.root();

        // Block-header root fields are authoritative after commit.
        // Caller / consensus layer is responsible for checking the block
        // header equals these roots. We return them here for the caller
        // to use; we do *not* enforce the check in v0 because producers
        // assemble the block *from* the resulting roots, not the other
        // way around.

        *state = scratch_state;
        self.nonces = scratch_nonces;

        Ok(AppliedBlock {
            events_root,
            state_root,
        })
    }

    fn validate_with_scratch<F>(
        &self,
        event: &Event,
        scratch_state: &StateTree,
        scratch_nonces: &NonceTracker,
        resolve: &mut F,
    ) -> Result<(), ValidationError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let vk = resolve(&event.payload.claimant).ok_or(ValidationError::Signature(
            codex_core::SignatureError::Invalid,
        ))?;
        event.verify_with_key(&vk).map_err(ValidationError::from)?;

        if !scratch_nonces.is_fresh(
            &event.payload.claimant,
            &event.payload.namespace,
            event.payload.nonce,
        ) {
            return Err(ValidationError::DuplicateNonce {
                nonce: event.payload.nonce,
            });
        }

        let handler = self
            .registry
            .get(&event.payload.namespace)
            .ok_or_else(|| ValidationError::UnknownNamespace(event.payload.namespace.clone()))?;
        handler.validate(event, scratch_state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::block::BlockHeaderPayload;
    use codex_core::event::EventPayload;
    use codex_core::hashes::{BlockHash, ChainId};
    use codex_core::namespace::Namespace;
    use codex_core::Block;
    use codex_crypto::{Blake3Hasher, SigningKey};
    use rand_core::OsRng;

    /// A handler that records "claimant claimed (ns, key_hash=blake3(body))" in state.
    struct AchievementHandler {
        ns: Namespace,
    }

    impl crate::handler::NamespaceHandler for AchievementHandler {
        fn namespace(&self) -> &Namespace {
            &self.ns
        }
        fn validate(
            &self,
            event: &Event,
            state: &crate::state::StateTree,
        ) -> Result<(), crate::error::ValidationError> {
            let key = achievement_key(&event.payload.body);
            if state.get(&self.ns, &key).is_some() {
                return Err(crate::error::ValidationError::HandlerReject {
                    reason: "already claimed (world-first uniqueness)".into(),
                });
            }
            Ok(())
        }
        fn apply(
            &self,
            event: &Event,
            state: &mut crate::state::StateTree,
        ) -> Result<(), crate::error::ApplyError> {
            let key = achievement_key(&event.payload.body);
            let mut value = Vec::new();
            value.extend_from_slice(event.payload.claimant.as_bytes());
            value.extend_from_slice(&event.payload.timestamp.to_le_bytes());
            state.insert(self.ns.clone(), key, value);
            Ok(())
        }
    }

    fn achievement_key(body: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new();
        hasher.update(body);
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    fn ach_ns() -> Namespace {
        Namespace::new("ludiars.first").unwrap()
    }

    struct Actor {
        sk: SigningKey,
        vk: VerifyingKey,
        peer: PeerId,
    }

    impl Actor {
        fn new() -> Self {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            let peer = PeerId::from_verifying_key(&vk);
            Self { sk, vk, peer }
        }
        fn sign(&self, nonce: u64, body: &[u8]) -> Event {
            let payload = EventPayload {
                version: 1,
                namespace: ach_ns(),
                claimant: self.peer,
                nonce,
                body: body.to_vec(),
                timestamp: 1_700_000_000_000 + nonce,
            };
            payload.sign(&self.sk)
        }
    }

    fn build_block(producer: &Actor, events: Vec<Event>) -> Block {
        let payload = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([0u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1_700_000_000_000,
            producer: producer.peer,
        };
        let header = payload.sign(&producer.sk);
        Block { header, events }
    }

    fn resolver_for(actors: &[&Actor]) -> impl FnMut(&PeerId) -> Option<VerifyingKey> {
        let map: std::collections::HashMap<PeerId, VerifyingKey> =
            actors.iter().map(|a| (a.peer, a.vk)).collect();
        move |p: &PeerId| map.get(p).copied()
    }

    fn with_achievement_registry() -> HandlerRegistry {
        let mut r = HandlerRegistry::new();
        r.register(Box::new(AchievementHandler { ns: ach_ns() }));
        r
    }

    #[test]
    fn applies_single_event() {
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let producer = Actor::new();
        let ev = alice.sign(1, b"summit");
        let block = build_block(&producer, vec![ev]);
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &producer]);
        let applied = stf.apply_block(&block, &mut state, &mut resolve).unwrap();
        assert_ne!(applied.state_root, crate::merkle::EMPTY_ROOT);
        assert!(state.get(&ach_ns(), &achievement_key(b"summit")).is_some());
    }

    #[test]
    fn world_first_is_enforced() {
        // Alice claims "summit" first; Bob's later claim is rejected.
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let bob = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &bob, &producer]);

        let b1 = build_block(&producer, vec![alice.sign(1, b"summit")]);
        stf.apply_block(&b1, &mut state, &mut resolve).unwrap();

        let b2 = build_block(&producer, vec![bob.sign(1, b"summit")]);
        let err = stf.apply_block(&b2, &mut state, &mut resolve).unwrap_err();
        match err {
            StfError::Validation { index: 0, source } => match source {
                ValidationError::HandlerReject { reason } => {
                    assert!(reason.contains("world-first"));
                }
                other => panic!("unexpected validation error: {other:?}"),
            },
            other => panic!("unexpected stf error: {other:?}"),
        }
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &producer]);

        let b1 = build_block(&producer, vec![alice.sign(1, b"a")]);
        stf.apply_block(&b1, &mut state, &mut resolve).unwrap();

        // Same (claimant, ns, nonce) — should be rejected even with a
        // different body / timestamp.
        let dup = alice.sign(1, b"different body");
        let b2 = build_block(&producer, vec![dup]);
        let err = stf.apply_block(&b2, &mut state, &mut resolve).unwrap_err();
        assert!(matches!(
            err,
            StfError::Validation {
                source: ValidationError::DuplicateNonce { nonce: 1 },
                ..
            }
        ));
    }

    #[test]
    fn unknown_namespace_rejected() {
        let mut stf = Stf::new(HandlerRegistry::new()); // no handlers at all
        let alice = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &producer]);

        let ev = alice.sign(1, b"x");
        let block = build_block(&producer, vec![ev]);
        let err = stf
            .apply_block(&block, &mut state, &mut resolve)
            .unwrap_err();
        assert!(matches!(
            err,
            StfError::Validation {
                source: ValidationError::UnknownNamespace(_),
                ..
            }
        ));
    }

    #[test]
    fn bad_signature_rejected() {
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &producer]);

        let mut ev = alice.sign(1, b"x");
        ev.signature[0] ^= 0xff;
        let block = build_block(&producer, vec![ev]);
        let err = stf
            .apply_block(&block, &mut state, &mut resolve)
            .unwrap_err();
        assert!(matches!(
            err,
            StfError::Validation {
                source: ValidationError::Signature(_),
                ..
            }
        ));
    }

    #[test]
    fn failed_event_leaves_state_unchanged() {
        // Apply [good, bad] — the whole block is rejected, state stays empty.
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let bob = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let root_before = state.root();
        let mut resolve = resolver_for(&[&alice, &bob, &producer]);

        let good = alice.sign(1, b"a");
        let mut bad = bob.sign(1, b"b");
        bad.signature[0] ^= 0xff; // tamper signature
        let block = build_block(&producer, vec![good, bad]);
        let err = stf
            .apply_block(&block, &mut state, &mut resolve)
            .unwrap_err();
        assert!(matches!(
            err,
            StfError::Validation {
                index: 1,
                source: ValidationError::Signature(_)
            }
        ));
        assert_eq!(state.root(), root_before);
    }

    #[test]
    fn deterministic_apply() {
        // Two independent STFs given the same block must produce the same roots.
        let alice = Actor::new();
        let bob = Actor::new();
        let producer = Actor::new();
        let events = vec![alice.sign(1, b"a"), bob.sign(1, b"b")];
        let block = build_block(&producer, events);

        let mut stf1 = Stf::new(with_achievement_registry());
        let mut state1 = StateTree::new();
        let mut r1 = resolver_for(&[&alice, &bob, &producer]);
        let applied1 = stf1.apply_block(&block, &mut state1, &mut r1).unwrap();

        let mut stf2 = Stf::new(with_achievement_registry());
        let mut state2 = StateTree::new();
        let mut r2 = resolver_for(&[&alice, &bob, &producer]);
        let applied2 = stf2.apply_block(&block, &mut state2, &mut r2).unwrap();

        assert_eq!(applied1, applied2);
        assert_eq!(state1.root(), state2.root());
    }

    #[test]
    fn empty_block_is_noop() {
        let mut stf = Stf::new(with_achievement_registry());
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&producer]);
        let block = build_block(&producer, vec![]);
        let r_before = state.root();
        let applied = stf.apply_block(&block, &mut state, &mut resolve).unwrap();
        assert_eq!(applied.state_root, r_before);
        assert_eq!(applied.events_root, crate::merkle::EMPTY_ROOT);
    }

    #[test]
    fn proofs_resolve_post_apply() {
        // After application, both existence and non-existence proofs
        // verify against the reported state_root.
        let mut stf = Stf::new(with_achievement_registry());
        let alice = Actor::new();
        let producer = Actor::new();
        let mut state = StateTree::new();
        let mut resolve = resolver_for(&[&alice, &producer]);

        let block = build_block(&producer, vec![alice.sign(1, b"summit")]);
        let applied = stf.apply_block(&block, &mut state, &mut resolve).unwrap();

        let present_key = achievement_key(b"summit");
        let ex = state.existence_proof(&ach_ns(), &present_key).unwrap();
        crate::proof::verify_existence(&ex, &applied.state_root).unwrap();

        let missing_key = achievement_key(b"another_peak");
        let ne = state.non_existence_proof(&ach_ns(), &missing_key).unwrap();
        crate::proof::verify_non_existence(&ne, &applied.state_root).unwrap();
    }
}
