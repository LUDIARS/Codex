//! End-to-end SessionNode pipeline:
//! - producer node emits blocks
//! - follower node ingests them
//! - state roots converge
//! - world-first uniqueness survives cross-node replication

use codex_consensus::ChainTip;
use codex_core::event::EventPayload;
use codex_core::hashes::ChainId;
use codex_core::namespace::Namespace;
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_domain_examples::game_rights::{
    achievement_key, AchievementHandler, ClaimBody, NAMESPACE,
};
use codex_node::{ProducerRole, SessionNode};
use codex_state::HandlerRegistry;
use rand_core::OsRng;

fn registry() -> HandlerRegistry {
    let mut r = HandlerRegistry::new();
    r.register(Box::new(AchievementHandler::default()));
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
    fn claim(&self, achievement: &str, nonce: u64) -> codex_core::event::Event {
        let body = postcard::to_allocvec(&ClaimBody {
            achievement_id: achievement.into(),
            evidence: vec![],
        })
        .unwrap();
        EventPayload {
            version: 1,
            namespace: Namespace::new(NAMESPACE).unwrap(),
            claimant: self.peer,
            nonce,
            body,
            timestamp: 1_000 + nonce,
        }
        .sign(&self.sk)
    }
}

fn resolver(actors: &[&Actor]) -> impl FnMut(&PeerId) -> Option<VerifyingKey> {
    let m: std::collections::HashMap<PeerId, VerifyingKey> =
        actors.iter().map(|a| (a.peer, a.vk)).collect();
    move |p: &PeerId| m.get(p).copied()
}

#[test]
fn producer_and_follower_converge() {
    let chain_id = ChainId([0x42u8; 32]);
    let prod_actor = Actor::new();
    let alice = Actor::new();
    let bob = Actor::new();

    let mut producer_node = SessionNode::new(
        chain_id,
        ProducerRole::Producer {
            producer: prod_actor.peer,
            producer_sk: prod_actor.sk.clone(),
            producer_vk: prod_actor.vk,
        },
        registry(),
    );
    let mut follower_node = SessionNode::new(
        chain_id,
        ProducerRole::Follower {
            expected_producer: prod_actor.peer,
            producer_vk: prod_actor.vk,
        },
        registry(),
    );

    let mut resolve = resolver(&[&prod_actor, &alice, &bob]);

    producer_node.submit_event(alice.claim("summit", 1));
    producer_node.submit_event(bob.claim("ocean", 1));

    let block = producer_node
        .produce(1_000, &mut resolve, false)
        .unwrap()
        .expect("producer must produce");

    follower_node
        .ingest_block(block.clone(), &mut resolve)
        .unwrap();

    assert_eq!(producer_node.tip(), follower_node.tip());
    assert_eq!(producer_node.state_root(), follower_node.state_root());
    assert_eq!(follower_node.tip().height, 1);

    // A follower cannot produce (no signing key).
    assert!(!follower_node.is_producer());
    let nothing = follower_node.produce(2_000, &mut resolve, true).unwrap();
    assert!(nothing.is_none());

    // Cross-block continuity: produce a second block and replicate.
    producer_node.submit_event(alice.claim("river", 2));
    let block2 = producer_node
        .produce(2_000, &mut resolve, false)
        .unwrap()
        .unwrap();
    follower_node.ingest_block(block2, &mut resolve).unwrap();
    assert_eq!(producer_node.tip(), follower_node.tip());
}

#[test]
fn world_first_rejects_late_duplicate_across_nodes() {
    let chain_id = ChainId([0xdeu8; 32]);
    let prod_actor = Actor::new();
    let alice = Actor::new();
    let bob = Actor::new();

    let mut producer_node = SessionNode::new(
        chain_id,
        ProducerRole::Producer {
            producer: prod_actor.peer,
            producer_sk: prod_actor.sk.clone(),
            producer_vk: prod_actor.vk,
        },
        registry(),
    );
    let mut follower_node = SessionNode::new(
        chain_id,
        ProducerRole::Follower {
            expected_producer: prod_actor.peer,
            producer_vk: prod_actor.vk,
        },
        registry(),
    );

    let mut resolve = resolver(&[&prod_actor, &alice, &bob]);

    // Block 1: alice gets "summit" first.
    producer_node.submit_event(alice.claim("summit", 1));
    let b1 = producer_node
        .produce(1_000, &mut resolve, false)
        .unwrap()
        .unwrap();
    follower_node.ingest_block(b1, &mut resolve).unwrap();

    // Block 2: bob tries the same achievement. The producer's STF
    // rejects at produce-time (mempool had both events; validate fails).
    producer_node.submit_event(bob.claim("summit", 1));

    let err = producer_node
        .produce(2_000, &mut resolve, false)
        .unwrap_err();
    // Should surface as a Stf error via NodeError.
    match err {
        codex_node::NodeError::Consensus(codex_consensus::ConsensusError::Stf(_)) => {}
        codex_node::NodeError::Stf(_) => {}
        other => panic!("unexpected error shape: {other:?}"),
    }

    // The follower never heard a second block; its view is still
    // identical to the producer's (alice holds it).
    assert_eq!(producer_node.tip(), follower_node.tip());
    let key = achievement_key("summit");
    let owner = follower_node
        .state_get(&Namespace::new(NAMESPACE).unwrap(), &key)
        .unwrap();
    // Owner bytes layout per game_rights::encode_value: 20B digest
    // prefix + 20B claimant peer + 8B timestamp. Check claimant slice.
    assert_eq!(&owner[20..40], alice.peer.as_bytes());
}

#[test]
fn tip_advances_across_multiple_blocks() {
    let chain_id = ChainId([0x77u8; 32]);
    let prod_actor = Actor::new();
    let alice = Actor::new();
    let mut node = SessionNode::new(
        chain_id,
        ProducerRole::Producer {
            producer: prod_actor.peer,
            producer_sk: prod_actor.sk.clone(),
            producer_vk: prod_actor.vk,
        },
        registry(),
    );
    assert_eq!(node.tip().height, 0);
    assert_eq!(node.tip(), &ChainTip::genesis(chain_id));

    let mut resolve = resolver(&[&prod_actor, &alice]);
    for n in 1..=5u64 {
        let achievement = format!("peak_{n}");
        node.submit_event(alice.claim(&achievement, n));
        node.produce(1_000 * n, &mut resolve, false)
            .unwrap()
            .unwrap();
    }
    assert_eq!(node.tip().height, 5);
    assert_eq!(node.store().len(), 5);

    // Inclusion proof for event #0 in block #3 must verify.
    let proof = node.event_inclusion_proof(3, 0).unwrap();
    let block3 = node.store().get_by_height(3).unwrap();
    codex_state::events::verify_event_inclusion(&proof, &block3.header.payload.events_root)
        .unwrap();
}
