//! Two-node full-sync convergence.

use codex_core::event::EventPayload;
use codex_core::hashes::ChainId;
use codex_core::namespace::Namespace;
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_domain_examples::game_rights::{AchievementHandler, ClaimBody, NAMESPACE};
use codex_node::{ProducerRole, SessionNode};
use codex_state::HandlerRegistry;
use codex_sync::{full_sync, header_sync, InMemoryTransport};
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
        Self {
            peer: PeerId::from_verifying_key(&vk),
            sk,
            vk,
        }
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
            timestamp: nonce,
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
fn late_joiner_full_syncs_to_producer_tip() {
    let chain = ChainId([0x42u8; 32]);
    let prod = Actor::new();
    let alice = Actor::new();
    let bob = Actor::new();

    let mut producer_node = SessionNode::new(
        chain,
        ProducerRole::Producer {
            producer: prod.peer,
            producer_sk: prod.sk.clone(),
            producer_vk: prod.vk,
        },
        registry(),
    );
    let mut resolve = resolver(&[&prod, &alice, &bob]);
    for n in 1..=6u64 {
        producer_node.submit_event(alice.claim(&format!("peak_{n}"), n));
        producer_node
            .produce(n * 1000, &mut resolve, false)
            .unwrap();
    }
    assert_eq!(producer_node.tip().height, 6);

    // A brand-new follower joins — must full-sync.
    let mut follower_node = SessionNode::new(
        chain,
        ProducerRole::Follower {
            expected_producer: prod.peer,
            producer_vk: prod.vk,
        },
        registry(),
    );
    assert_eq!(follower_node.tip().height, 0);

    let transport = InMemoryTransport::new(producer_node.store(), producer_node.tip().clone());
    let applied = full_sync(&mut follower_node, &transport, &mut resolve).unwrap();
    assert_eq!(applied, 6);
    assert_eq!(follower_node.tip(), producer_node.tip());
    assert_eq!(follower_node.state_root(), producer_node.state_root());
}

#[test]
fn header_sync_returns_range() {
    let chain = ChainId([0x99u8; 32]);
    let prod = Actor::new();
    let mut producer_node = SessionNode::new(
        chain,
        ProducerRole::Producer {
            producer: prod.peer,
            producer_sk: prod.sk.clone(),
            producer_vk: prod.vk,
        },
        registry(),
    );
    let alice = Actor::new();
    let mut resolve = resolver(&[&prod, &alice]);
    for n in 1..=4u64 {
        producer_node.submit_event(alice.claim(&format!("a{n}"), n));
        producer_node.produce(n, &mut resolve, false).unwrap();
    }
    let transport = InMemoryTransport::new(producer_node.store(), producer_node.tip().clone());
    let headers = header_sync(&transport, 2, 3).unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].payload.height, 2);
    assert_eq!(headers[1].payload.height, 3);
}

#[test]
fn sync_noop_when_peer_behind() {
    let chain = ChainId([0x11u8; 32]);
    let prod = Actor::new();
    let mut producer = SessionNode::new(
        chain,
        ProducerRole::Producer {
            producer: prod.peer,
            producer_sk: prod.sk.clone(),
            producer_vk: prod.vk,
        },
        registry(),
    );
    let alice = Actor::new();
    let mut resolve = resolver(&[&prod, &alice]);
    producer.submit_event(alice.claim("x", 1));
    producer.produce(1, &mut resolve, false).unwrap();

    // Follower is at height 1 (simulate via syncing first), peer only
    // has height 1 too. full_sync should be a no-op.
    let mut follower = SessionNode::new(
        chain,
        ProducerRole::Follower {
            expected_producer: prod.peer,
            producer_vk: prod.vk,
        },
        registry(),
    );
    let t1 = InMemoryTransport::new(producer.store(), producer.tip().clone());
    full_sync(&mut follower, &t1, &mut resolve).unwrap();
    assert_eq!(follower.tip().height, 1);

    // Second call finds nothing new.
    let t2 = InMemoryTransport::new(producer.store(), producer.tip().clone());
    let applied = full_sync(&mut follower, &t2, &mut resolve).unwrap();
    assert_eq!(applied, 0);
}
