//! Codex end-to-end demo.
//!
//! Walks through the design goal stated in DESIGN §2.4: cryptographically
//! guaranteeing "only one person in the world did X" across multiple
//! nodes plus a mobile-style light client.
//!
//! Steps:
//! 1. Producer node + two follower nodes set up with the
//!    `ludiars.first` achievement namespace.
//! 2. Three players — Alice, Bob, and Carol — each try to claim an
//!    achievement. Alice claims "summit_of_fuji" first.
//! 3. Producer emits block 1; followers ingest; all three nodes agree
//!    on the state root.
//! 4. Bob tries to claim "summit_of_fuji" — the producer rejects
//!    before even signing a block.
//! 5. Carol claims "dive_mariana" (new achievement) — block 2
//!    emitted, followers ingest.
//! 6. A **light client** (header-only) full-syncs via the sync
//!    protocol, then verifies:
//!    - an ExistenceProof for Alice's summit claim
//!    - a NonExistenceProof for a never-claimed "moon_landing_2030"
//! 7. A state **snapshot** is taken at the current height, serialized
//!    via postcard, rebuilt on a fresh node, and the rebuilt state
//!    root matches.
//!
//! Run with: `cargo run -p codex-demo --release`.

use std::collections::HashMap;

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
use codex_sync::{full_sync, header_sync, InMemoryTransport, StateSnapshot};
use rand_core::OsRng;

struct Actor {
    name: &'static str,
    sk: SigningKey,
    vk: VerifyingKey,
    peer: PeerId,
}

impl Actor {
    fn new(name: &'static str) -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Self {
            name,
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
        .expect("serialize claim body");
        EventPayload {
            version: 1,
            namespace: Namespace::new(NAMESPACE).unwrap(),
            claimant: self.peer,
            nonce,
            body,
            timestamp: 1_700_000_000_000 + nonce,
        }
        .sign(&self.sk)
    }
}

fn registry() -> HandlerRegistry {
    let mut r = HandlerRegistry::new();
    r.register(Box::new(AchievementHandler::default()));
    r
}

fn banner(s: &str) {
    println!("\n\x1b[1;36m── {s}\x1b[0m");
}

fn main() {
    println!("\x1b[1mCodex end-to-end demo\x1b[0m");
    println!("Target: «only one person in the world did X» (DESIGN §2.4)\n");

    // Actors
    let producer_actor = Actor::new("producer");
    let alice = Actor::new("Alice");
    let bob = Actor::new("Bob");
    let carol = Actor::new("Carol");
    let chain_id = ChainId([0xabu8; 32]);

    let keys: HashMap<PeerId, VerifyingKey> = [&producer_actor, &alice, &bob, &carol]
        .iter()
        .map(|a| (a.peer, a.vk))
        .collect();
    let mut resolve = |p: &PeerId| keys.get(p).copied();

    // Nodes
    banner("Step 1: spin up 1 producer + 2 followers");
    let mut producer = SessionNode::new(
        chain_id,
        ProducerRole::Producer {
            producer: producer_actor.peer,
            producer_sk: producer_actor.sk.clone(),
            producer_vk: producer_actor.vk,
        },
        registry(),
    );
    let mut follower_a = SessionNode::new(
        chain_id,
        ProducerRole::Follower {
            expected_producer: producer_actor.peer,
            producer_vk: producer_actor.vk,
        },
        registry(),
    );
    let mut follower_b = SessionNode::new(
        chain_id,
        ProducerRole::Follower {
            expected_producer: producer_actor.peer,
            producer_vk: producer_actor.vk,
        },
        registry(),
    );
    println!(
        "  producer peer: {}\n  follower-A peer: tracks producer {}\n  follower-B peer: same",
        producer_actor.peer, producer_actor.peer,
    );

    // Block 1
    banner("Step 2: Alice claims «summit_of_fuji»");
    producer.submit_event(alice.claim("summit_of_fuji", 1));
    let block1 = producer
        .produce(1_001, &mut resolve, false)
        .expect("produce ok")
        .expect("non-empty mempool");
    println!(
        "  block 1 mined: height={} events={} state_root={}",
        block1.header.payload.height,
        block1.events.len(),
        hex::encode(&block1.header.payload.state_root[..8])
    );

    follower_a
        .ingest_block(block1.clone(), &mut resolve)
        .unwrap();
    follower_b
        .ingest_block(block1.clone(), &mut resolve)
        .unwrap();
    assert_eq!(producer.state_root(), follower_a.state_root());
    assert_eq!(producer.state_root(), follower_b.state_root());
    println!("  state roots match across 3 nodes ✓");

    // Block 2 attempts
    banner("Step 3: Bob attempts the SAME achievement");
    producer.submit_event(bob.claim("summit_of_fuji", 1));
    let err = producer
        .produce(2_000, &mut resolve, false)
        .expect_err("producer must reject");
    println!("  producer rejected: {err}");
    println!("  (world-first uniqueness enforced by AchievementHandler::validate)");

    // Block 2 success
    banner("Step 4: Carol claims a NEW achievement «dive_mariana»");
    producer.submit_event(carol.claim("dive_mariana", 1));
    let block2 = producer
        .produce(3_000, &mut resolve, false)
        .unwrap()
        .unwrap();
    follower_a
        .ingest_block(block2.clone(), &mut resolve)
        .unwrap();
    follower_b
        .ingest_block(block2.clone(), &mut resolve)
        .unwrap();
    println!(
        "  block 2 mined: height={} state_root={}",
        block2.header.payload.height,
        hex::encode(&block2.header.payload.state_root[..8])
    );
    println!("  all 3 nodes still in sync ✓");

    // Light client
    banner("Step 5: mobile light client joins, SPVs two rights");
    let mut light = LightClient::new(
        chain_id,
        Box::new(SingleProducerAuthority::new(
            producer_actor.peer,
            producer_actor.vk,
        )),
    );
    let peer_tip = producer.tip().clone();
    let transport = InMemoryTransport::new(producer.store(), peer_tip.clone());
    let headers = header_sync(&transport, 1, peer_tip.height).unwrap();
    light.apply_headers(headers).unwrap();
    println!(
        "  light client synced to height {} (block hash {})",
        light.tip().height,
        hex::encode(&light.tip().tip_hash.as_bytes()[..8])
    );

    // Existence proof: Alice owns summit_of_fuji.
    let ns = Namespace::new(NAMESPACE).unwrap();
    let key = achievement_key("summit_of_fuji");
    let proof = producer.existence_proof(&ns, &key).unwrap();
    light
        .verify_state_existence(light.tip().height, &proof)
        .unwrap();
    let owner_slice = &proof.value[20..40];
    let owner_name = if owner_slice == alice.peer.as_bytes() {
        alice.name
    } else if owner_slice == bob.peer.as_bytes() {
        bob.name
    } else if owner_slice == carol.peer.as_bytes() {
        carol.name
    } else {
        "unknown"
    };
    println!("  ExistenceProof verified ✓  →  «summit_of_fuji» belongs to {owner_name}");

    // Non-existence proof: nobody claimed moon_landing_2030.
    let missing = achievement_key("moon_landing_2030");
    let ne_proof = producer.non_existence_proof(&ns, &missing).unwrap();
    light
        .verify_state_non_existence(light.tip().height, &ne_proof)
        .unwrap();
    println!("  NonExistenceProof verified ✓  →  «moon_landing_2030» is unclaimed");

    // Full sync to a cold joiner
    banner("Step 6: cold joiner full-syncs from scratch");
    let mut cold = SessionNode::new(
        chain_id,
        ProducerRole::Follower {
            expected_producer: producer_actor.peer,
            producer_vk: producer_actor.vk,
        },
        registry(),
    );
    let applied = full_sync(
        &mut cold,
        &InMemoryTransport::new(producer.store(), producer.tip().clone()),
        &mut resolve,
    )
    .unwrap();
    assert_eq!(applied, 2);
    assert_eq!(cold.state_root(), producer.state_root());
    println!(
        "  applied {} blocks; cold.state_root == producer.state_root ✓",
        applied
    );

    // Snapshot
    banner("Step 7: fast-sync snapshot round-trip");
    let height = producer.tip().height;
    let snap = StateSnapshot::from_state(height, producer.state_mut());
    let snap_bytes = postcard::to_allocvec(&snap).unwrap();
    let parsed: StateSnapshot = postcard::from_bytes(&snap_bytes).unwrap();
    let mut rebuilt = parsed.rebuild().expect("rebuild");
    assert_eq!(rebuilt.root(), producer.state_root());
    println!(
        "  snapshot: {} leaves, {} bytes, rebuilt root matches ✓",
        snap.leaf_count(),
        snap_bytes.len()
    );

    banner("Done");
    println!(
        "Codex guaranteed, cryptographically:\n  \
         • Alice is the sole owner of «summit_of_fuji»\n  \
         • Carol is the sole owner of «dive_mariana»\n  \
         • Bob's duplicate claim never made it into a block\n  \
         • «moon_landing_2030» is provably unclaimed (NonExistenceProof)\n  \
         • A mobile light client reached these conclusions using only\n    \
           block headers + ~1 KB of proof data per query."
    );
}
