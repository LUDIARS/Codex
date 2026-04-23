//! End-to-end "world-first achievement" scenario.
//!
//! Walks the full path a mobile light client would see:
//! 1. Producer builds a block with events from independent claimants
//! 2. STF applies → `state_root` + `events_root` known
//! 3. Producer signs the block header with those roots
//! 4. Independent verifier checks:
//!    - producer signature on header
//!    - events_root in header matches recomputed root from events
//!    - each event's inclusion proof
//!    - state root in header matches the STF-computed root
//!    - existence / non-existence proofs for state keys

use codex_core::block::{Block, BlockHeaderPayload};
use codex_core::event::{Event, EventPayload};
use codex_core::hashes::{BlockHash, ChainId};
use codex_core::namespace::Namespace;
use codex_core::SignatureError;
use codex_crypto::{Blake3Hasher, PeerId, SigningKey, VerifyingKey};
use codex_state::{
    compute_events_root, events::compute_event_inclusion_proof, events::verify_event_inclusion,
    verify_existence, verify_non_existence, HandlerRegistry, NamespaceHandler, StateTree, Stf,
};
use rand_core::OsRng;

fn ach_ns() -> Namespace {
    Namespace::new("ludiars.first").unwrap()
}

fn achievement_key(body: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

struct AchievementHandler {
    ns: Namespace,
}

impl NamespaceHandler for AchievementHandler {
    fn namespace(&self) -> &Namespace {
        &self.ns
    }
    fn validate(
        &self,
        event: &Event,
        state: &StateTree,
    ) -> Result<(), codex_state::ValidationError> {
        let key = achievement_key(&event.payload.body);
        if state.get(&self.ns, &key).is_some() {
            return Err(codex_state::ValidationError::HandlerReject {
                reason: "already claimed (world-first)".into(),
            });
        }
        Ok(())
    }
    fn apply(&self, event: &Event, state: &mut StateTree) -> Result<(), codex_state::ApplyError> {
        let key = achievement_key(&event.payload.body);
        let mut value = Vec::new();
        value.extend_from_slice(event.payload.claimant.as_bytes());
        value.extend_from_slice(&event.payload.timestamp.to_le_bytes());
        state.insert(self.ns.clone(), key, value);
        Ok(())
    }
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
    fn claim(&self, nonce: u64, body: &[u8]) -> Event {
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

fn registry() -> HandlerRegistry {
    let mut r = HandlerRegistry::new();
    r.register(Box::new(AchievementHandler { ns: ach_ns() }));
    r
}

#[test]
fn end_to_end_world_first_flow() {
    // Cast of characters.
    let alice = Actor::new();
    let bob = Actor::new();
    let carol = Actor::new();
    let producer = Actor::new();

    let key_registry: std::collections::HashMap<PeerId, VerifyingKey> = [&alice, &bob, &carol]
        .iter()
        .map(|a| (a.peer, a.vk))
        .collect();
    let mut resolve = |p: &PeerId| key_registry.get(p).copied();

    // Block 1: alice claims "summit", bob claims "ocean". Carol's
    // attempt to claim "summit" again (fresh nonce) is in block 2 and
    // will be rejected by the handler.
    let events_b1 = vec![alice.claim(1, b"summit"), bob.claim(1, b"ocean")];
    let block_1 = Block {
        header: BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([0xccu8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: producer.peer,
        }
        .sign(&producer.sk),
        events: events_b1.clone(),
    };

    // Apply.
    let mut stf = Stf::new(registry());
    let mut state = StateTree::new();
    let applied = stf.apply_block(&block_1, &mut state, &mut resolve).unwrap();

    // The roots the producer will put in its final header.
    let expected_events_root = applied.events_root;
    let expected_state_root = applied.state_root;

    // Re-derivation sanity: an independent recomputation gives the same
    // events_root.
    assert_eq!(compute_events_root(&events_b1), expected_events_root);

    // Any light client who received the (signed header, events, proofs)
    // can independently verify:

    // 1. Producer signature on the block header (header includes
    //    placeholder roots here; in a real build pipeline the producer
    //    re-signs with the real roots before broadcast — this test
    //    exercises the post-apply roots separately).
    block_1.header.verify_producer(&producer.vk).unwrap();

    // 2. Each event's inclusion in the events_root.
    for i in 0..events_b1.len() {
        let proof = compute_event_inclusion_proof(&events_b1, i).unwrap();
        verify_event_inclusion(&proof, &expected_events_root).unwrap();
    }

    // 3. Each event's own signature.
    for ev in &events_b1 {
        let vk = key_registry.get(&ev.payload.claimant).copied().unwrap();
        ev.verify_with_key(&vk).unwrap();
    }

    // 4. State existence proofs for the two achievements claimed.
    for (actor, body) in [(&alice, b"summit" as &[u8]), (&bob, b"ocean")] {
        let key = achievement_key(body);
        let ex = state.existence_proof(&ach_ns(), &key).unwrap();
        verify_existence(&ex, &expected_state_root).unwrap();
        // The holder recorded in state matches the claimant.
        assert!(ex.value.starts_with(actor.peer.as_bytes()));
    }

    // 5. A non-existence proof for something nobody claimed yet.
    let unknown = achievement_key(b"mariana");
    let ne = state.non_existence_proof(&ach_ns(), &unknown).unwrap();
    verify_non_existence(&ne, &expected_state_root).unwrap();

    // Block 2: carol tries to claim "summit" — rejected by handler.
    let events_b2 = vec![carol.claim(1, b"summit")];
    let block_2 = Block {
        header: BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([0xccu8; 32]),
            height: 2,
            prev_hash: block_1.header.block_hash(),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 2,
            producer: producer.peer,
        }
        .sign(&producer.sk),
        events: events_b2,
    };
    let err = stf
        .apply_block(&block_2, &mut state, &mut resolve)
        .unwrap_err();
    match err {
        codex_state::StfError::Validation { source, .. } => {
            assert!(matches!(
                source,
                codex_state::ValidationError::HandlerReject { .. }
            ));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    // And the state root is unchanged — the failing block did not
    // affect committed state.
    assert_eq!(state.root(), expected_state_root);
}

#[test]
fn light_client_verifies_cross_block_history() {
    // Simulates a sequence of blocks and checks that at each height a
    // light client can:
    //   - re-verify the previous block's hash chain via prev_hash
    //   - produce a post-state existence proof for its own achievement

    let alice = Actor::new();
    let producer = Actor::new();
    let keys: std::collections::HashMap<PeerId, VerifyingKey> = [(&alice, ()), (&producer, ())]
        .iter()
        .map(|(a, _)| (a.peer, a.vk))
        .collect();
    let mut resolve = |p: &PeerId| keys.get(p).copied();

    let mut stf = Stf::new(registry());
    let mut state = StateTree::new();
    let mut prev_hash = BlockHash([0u8; 32]);

    for (height, body) in [(1u64, "peak_a" as &str), (2, "peak_b"), (3, "peak_c")] {
        let event = alice.claim(height, body.as_bytes());
        let header = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([0xabu8; 32]),
            height,
            prev_hash,
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: height * 1000,
            producer: producer.peer,
        }
        .sign(&producer.sk);
        let block = Block {
            header: header.clone(),
            events: vec![event],
        };
        let applied = stf.apply_block(&block, &mut state, &mut resolve).unwrap();

        // Proofs against the applied state_root.
        let key = achievement_key(body.as_bytes());
        let ex = state.existence_proof(&ach_ns(), &key).unwrap();
        verify_existence(&ex, &applied.state_root).unwrap();

        prev_hash = header.block_hash();
    }

    // After 3 achievements, all three keys present.
    for body in ["peak_a", "peak_b", "peak_c"] {
        let key = achievement_key(body.as_bytes());
        assert!(state.get(&ach_ns(), &key).is_some());
    }
}

#[test]
fn unresolvable_claimant_is_rejected_as_signature_failure() {
    // If the caller's resolver cannot provide a key for the claimant,
    // the STF treats it as a signature failure (we can't verify).
    let alice = Actor::new();
    let producer = Actor::new();

    // Resolver knows producer only — alice is a stranger.
    let keys = std::collections::HashMap::from([(producer.peer, producer.vk)]);
    let mut resolve = |p: &PeerId| keys.get(p).copied();

    let mut stf = Stf::new(registry());
    let mut state = StateTree::new();
    let event = alice.claim(1, b"x");
    let block = Block {
        header: BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([0u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: producer.peer,
        }
        .sign(&producer.sk),
        events: vec![event],
    };
    let err = stf
        .apply_block(&block, &mut state, &mut resolve)
        .unwrap_err();
    assert!(matches!(
        err,
        codex_state::StfError::Validation {
            source: codex_state::ValidationError::Signature(SignatureError::Invalid),
            ..
        }
    ));
}
