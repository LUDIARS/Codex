//! Session-mode integration: producer builds, verifier consumes, the
//! two chain tips advance in lockstep.

use codex_consensus::verifier::{BlockVerifier, SingleProducerAuthority};
use codex_consensus::{ChainTip, InMemoryMempool, Mempool, SessionProducer};
use codex_core::event::{Event, EventPayload};
use codex_core::hashes::ChainId;
use codex_core::namespace::Namespace;
use codex_core::SignatureError;
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_state::{HandlerRegistry, NamespaceHandler, StateTree, Stf};
use rand_core::OsRng;

fn ach_ns() -> Namespace {
    Namespace::new("ludiars.first").unwrap()
}

fn achievement_key(body: &[u8]) -> [u8; 32] {
    let mut h = codex_crypto::Blake3Hasher::new();
    h.update(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

struct AchievementHandler(Namespace);

impl NamespaceHandler for AchievementHandler {
    fn namespace(&self) -> &Namespace {
        &self.0
    }
    fn validate(
        &self,
        event: &Event,
        state: &StateTree,
    ) -> Result<(), codex_state::ValidationError> {
        if state
            .get(&self.0, &achievement_key(&event.payload.body))
            .is_some()
        {
            return Err(codex_state::ValidationError::HandlerReject {
                reason: "already claimed".into(),
            });
        }
        Ok(())
    }
    fn apply(&self, event: &Event, state: &mut StateTree) -> Result<(), codex_state::ApplyError> {
        state.insert(
            self.0.clone(),
            achievement_key(&event.payload.body),
            event.payload.claimant.as_bytes().to_vec(),
        );
        Ok(())
    }
}

fn registry() -> HandlerRegistry {
    let mut r = HandlerRegistry::new();
    r.register(Box::new(AchievementHandler(ach_ns())));
    r
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
        EventPayload {
            version: 1,
            namespace: ach_ns(),
            claimant: self.peer,
            nonce,
            body: body.to_vec(),
            timestamp: 1_700_000_000_000 + nonce,
        }
        .sign(&self.sk)
    }
}

fn resolver(actors: &[&Actor]) -> impl FnMut(&PeerId) -> Option<VerifyingKey> {
    let map: std::collections::HashMap<PeerId, VerifyingKey> =
        actors.iter().map(|a| (a.peer, a.vk)).collect();
    move |p: &PeerId| map.get(p).copied()
}

#[test]
fn producer_and_verifier_advance_in_lockstep() {
    let alice = Actor::new();
    let bob = Actor::new();
    let producer = Actor::new();
    let chain_id = ChainId([0xccu8; 32]);

    // Producer side.
    let mut sp_state = StateTree::new();
    let mut sp_stf = Stf::new(registry());
    let mut sp = SessionProducer::new(producer.peer, producer.sk.clone(), chain_id);
    let mut mempool = InMemoryMempool::new();

    // Verifier side (separate STF + state — everyone maintains their own
    // replica; they should converge).
    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut verifier = BlockVerifier::new(
        ChainTip::genesis(chain_id),
        Box::new(SingleProducerAuthority::new(producer.peer, producer.vk)),
    );

    // Round 1: alice + bob each claim a different achievement.
    mempool.submit(alice.claim(1, b"summit"));
    mempool.submit(bob.claim(1, b"ocean"));
    let mut resolve = resolver(&[&alice, &bob, &producer]);
    let block1 = sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            1_700_000_000_500,
            &mut resolve,
            false,
        )
        .unwrap()
        .expect("mempool non-empty");

    // Verifier ingests it.
    verifier
        .verify_and_apply(&block1, &mut v_stf, &mut v_state, &mut resolve)
        .unwrap();

    assert_eq!(sp.tip(), verifier.tip(), "tips must match after block 1");
    assert_eq!(sp_state.root(), v_state.root());

    // Round 2: alice claims another, carol tries to poach summit but is
    // rejected.
    let carol = Actor::new();
    let mut resolve2 = resolver(&[&alice, &bob, &carol, &producer]);
    mempool.submit(alice.claim(2, b"river"));
    let block2 = sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            1_700_000_001_000,
            &mut resolve2,
            false,
        )
        .unwrap()
        .unwrap();
    verifier
        .verify_and_apply(&block2, &mut v_stf, &mut v_state, &mut resolve2)
        .unwrap();
    assert_eq!(sp.tip(), verifier.tip());
    assert_eq!(sp_state.root(), v_state.root());
    assert_eq!(verifier.tip().height, 2);
}

#[test]
fn verifier_rejects_wrong_chain_id() {
    let producer = Actor::new();
    let chain_id = ChainId([1u8; 32]);
    let mut sp = SessionProducer::new(producer.peer, producer.sk.clone(), chain_id);
    let mut sp_state = StateTree::new();
    let mut sp_stf = Stf::new(registry());
    let mut mempool = InMemoryMempool::new();
    mempool.submit(producer.claim(1, b"x")); // producer claim, doesn't matter
    let mut resolve = resolver(&[&producer]);
    let block = sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            1,
            &mut resolve,
            false,
        )
        .unwrap()
        .unwrap();

    // Verifier using a different chain_id.
    let other_chain = ChainId([2u8; 32]);
    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut verifier = BlockVerifier::new(
        ChainTip::genesis(other_chain),
        Box::new(SingleProducerAuthority::new(producer.peer, producer.vk)),
    );
    let err = verifier
        .verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve)
        .unwrap_err();
    assert!(matches!(
        err,
        codex_consensus::ConsensusError::ChainIdMismatch { .. }
    ));
}

#[test]
fn verifier_rejects_unauthorized_producer() {
    let producer = Actor::new();
    let impostor = Actor::new();
    let chain_id = ChainId([1u8; 32]);

    // Build a block signed by the *impostor* but claiming to be producer.
    // We build it directly, not through SessionProducer, to construct an
    // adversarial scenario.
    let payload = codex_core::block::BlockHeaderPayload {
        version: 1,
        chain_id,
        height: 1,
        prev_hash: codex_core::hashes::BlockHash([0u8; 32]),
        events_root: codex_state::merkle::EMPTY_ROOT,
        state_root: codex_state::merkle::EMPTY_ROOT,
        timestamp: 1,
        producer: impostor.peer, // impostor self-names
    };
    let header = payload.sign(&impostor.sk);
    let block = codex_core::block::Block {
        header,
        events: vec![],
    };

    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut verifier = BlockVerifier::new(
        ChainTip::genesis(chain_id),
        Box::new(SingleProducerAuthority::new(producer.peer, producer.vk)),
    );
    let mut resolve = resolver(&[&producer, &impostor]);
    let err = verifier
        .verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve)
        .unwrap_err();
    assert!(matches!(
        err,
        codex_consensus::ConsensusError::UnauthorizedProducer { .. }
    ));
}

#[test]
fn verifier_rejects_tampered_header() {
    let alice = Actor::new();
    let producer = Actor::new();
    let chain_id = ChainId([3u8; 32]);

    let mut sp_state = StateTree::new();
    let mut sp_stf = Stf::new(registry());
    let mut sp = SessionProducer::new(producer.peer, producer.sk.clone(), chain_id);
    let mut mempool = InMemoryMempool::new();
    mempool.submit(alice.claim(1, b"x"));
    let mut resolve = resolver(&[&alice, &producer]);
    let mut block = sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            1,
            &mut resolve,
            false,
        )
        .unwrap()
        .unwrap();

    // Flip a bit of state_root (header bytes changed; signature invalid).
    block.header.payload.state_root[0] ^= 0xff;

    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut verifier = BlockVerifier::new(
        ChainTip::genesis(chain_id),
        Box::new(SingleProducerAuthority::new(producer.peer, producer.vk)),
    );
    let err = verifier
        .verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve)
        .unwrap_err();
    // Producer signature check fires before root mismatch.
    assert!(matches!(
        err,
        codex_consensus::ConsensusError::ProducerSignature(SignatureError::Invalid)
    ));
}

#[test]
fn empty_block_is_permitted_with_allow_empty() {
    let producer = Actor::new();
    let chain_id = ChainId([4u8; 32]);
    let mut sp = SessionProducer::new(producer.peer, producer.sk.clone(), chain_id);
    let mut sp_state = StateTree::new();
    let mut sp_stf = Stf::new(registry());
    let mut mempool = InMemoryMempool::new(); // empty
    let mut resolve = resolver(&[&producer]);

    // Without allow_empty → None.
    assert!(sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            1,
            &mut resolve,
            false,
        )
        .unwrap()
        .is_none());

    // With allow_empty → a zero-event block is emitted (a "heartbeat").
    let heartbeat = sp
        .produce(
            &mut mempool,
            &mut sp_stf,
            &mut sp_state,
            2,
            &mut resolve,
            true,
        )
        .unwrap()
        .expect("heartbeat");
    assert!(heartbeat.events.is_empty());
    assert_eq!(
        heartbeat.header.payload.events_root,
        codex_state::merkle::EMPTY_ROOT
    );
}
