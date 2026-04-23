//! Light client SPV scenario.

use codex_consensus::verifier::SingleProducerAuthority;
use codex_core::event::EventPayload;
use codex_core::hashes::ChainId;
use codex_core::namespace::Namespace;
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_domain_examples::game_rights::{
    achievement_key, AchievementHandler, ClaimBody, NAMESPACE,
};
use codex_light::LightClient;
use codex_node::{ProducerRole, SessionNode};
use codex_state::HandlerRegistry;
use codex_sync::{header_sync, InMemoryTransport, SyncTransport};
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
fn light_client_follows_headers_and_verifies_state_proof() {
    let chain = ChainId([0x55u8; 32]);
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

    producer_node.submit_event(alice.claim("summit", 1));
    producer_node.submit_event(bob.claim("ocean", 1));
    producer_node.produce(1000, &mut resolve, false).unwrap();
    producer_node.submit_event(alice.claim("river", 2));
    producer_node.produce(2000, &mut resolve, false).unwrap();

    // Light client only pulls headers.
    let mut light = LightClient::new(
        chain,
        Box::new(SingleProducerAuthority::new(prod.peer, prod.vk)),
    );
    let transport = InMemoryTransport::new(producer_node.store(), producer_node.tip().clone());
    let headers = header_sync(&transport, 1, 2).unwrap();
    light.apply_headers(headers).unwrap();
    assert_eq!(light.tip().height, 2);

    // Light client asks for a state proof about "summit" and verifies
    // it against height 1's state_root.
    let key = achievement_key("summit");
    let ns = Namespace::new(NAMESPACE).unwrap();
    let proof = producer_node.existence_proof(&ns, &key).unwrap();
    // Current state_root is at height 2; use that for verification.
    light.verify_state_existence(2, &proof).unwrap();

    // Non-existence proof for "mariana".
    let missing = achievement_key("mariana");
    let nproof = producer_node.non_existence_proof(&ns, &missing).unwrap();
    light.verify_state_non_existence(2, &nproof).unwrap();

    // Event-inclusion proof for event 0 of block 1.
    let ev_proof = producer_node.event_inclusion_proof(1, 0).unwrap();
    light.verify_event_inclusion_at(1, &ev_proof).unwrap();
}

#[test]
fn light_client_rejects_out_of_order_header() {
    let chain = ChainId([0x11u8; 32]);
    let prod = Actor::new();
    let alice = Actor::new();
    let mut producer_node = SessionNode::new(
        chain,
        ProducerRole::Producer {
            producer: prod.peer,
            producer_sk: prod.sk.clone(),
            producer_vk: prod.vk,
        },
        registry(),
    );
    let mut resolve = resolver(&[&prod, &alice]);
    for n in 1..=2u64 {
        producer_node.submit_event(alice.claim(&format!("a{n}"), n));
        producer_node.produce(n, &mut resolve, false).unwrap();
    }
    let mut light = LightClient::new(
        chain,
        Box::new(SingleProducerAuthority::new(prod.peer, prod.vk)),
    );
    let transport = InMemoryTransport::new(producer_node.store(), producer_node.tip().clone());
    // Apply height 2 first — should reject.
    let header2 = transport.fetch_header(2).unwrap();
    let err = light.apply_header(header2).unwrap_err();
    assert!(matches!(err, codex_light::LightError::OutOfOrder { .. }));
}

#[test]
fn light_client_rejects_foreign_chain_id() {
    let chain = ChainId([0x22u8; 32]);
    let other = ChainId([0x33u8; 32]);
    let prod = Actor::new();
    let alice = Actor::new();
    let mut producer_node = SessionNode::new(
        chain,
        ProducerRole::Producer {
            producer: prod.peer,
            producer_sk: prod.sk.clone(),
            producer_vk: prod.vk,
        },
        registry(),
    );
    let mut resolve = resolver(&[&prod, &alice]);
    producer_node.submit_event(alice.claim("x", 1));
    producer_node.produce(1, &mut resolve, false).unwrap();

    let mut light = LightClient::new(
        other, // different chain
        Box::new(SingleProducerAuthority::new(prod.peer, prod.vk)),
    );
    let transport = InMemoryTransport::new(producer_node.store(), producer_node.tip().clone());
    let h1 = transport.fetch_header(1).unwrap();
    let err = light.apply_header(h1).unwrap_err();
    assert!(matches!(err, codex_light::LightError::ChainIdMismatch));
}
