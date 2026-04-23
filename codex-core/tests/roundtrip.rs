//! End-to-end round-trip tests that cross module boundaries.
//!
//! Unit tests live beside the code they exercise (`src/*/tests`). The
//! tests here are deliberately closer to user-visible scenarios: sign
//! events with different keys, bundle them into a block, round-trip the
//! whole block through postcard, and verify signatures on the parsed
//! copy.

use codex_core::codex_crypto::{PeerId, SigningKey};
use codex_core::{Block, BlockHeader, BlockHeaderPayload, ChainId, Event, EventPayload, Namespace};
use rand_core::OsRng;

const HASH_LEN: usize = 32;

fn make_event(nonce: u64, body: Vec<u8>) -> (Event, SigningKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let claimant = PeerId::from_verifying_key(&sk.verifying_key());
    let payload = EventPayload {
        version: 1,
        namespace: Namespace::new("tessera.game").unwrap(),
        claimant,
        nonce,
        body,
        timestamp: 1_700_000_000_000 + nonce,
    };
    (payload.sign(&sk), sk)
}

#[test]
fn multi_event_block_round_trip() {
    // Build a block with a producer-signed header and three events from
    // independent claimants. Serialize the full block, deserialize, then
    // re-verify every signature.

    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());

    let (e1, k1) = make_event(1, b"alpha".to_vec());
    let (e2, k2) = make_event(2, b"beta".to_vec());
    let (e3, k3) = make_event(3, b"gamma-".repeat(10));

    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: ChainId([7u8; HASH_LEN]),
        height: 42,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0x11u8; HASH_LEN], // placeholder (computed in codex-state, future M1)
        state_root: [0x22u8; HASH_LEN],
        timestamp: 1_700_000_000_042,
        producer,
    };
    let header = payload.sign(&producer_sk);
    let block = Block {
        header,
        events: vec![e1.clone(), e2.clone(), e3.clone()],
    };

    let bytes = postcard::to_allocvec(&block).expect("serialize");
    let parsed: Block = postcard::from_bytes(&bytes).expect("deserialize");
    assert_eq!(block, parsed);

    // Producer signature survives round-trip.
    parsed
        .header
        .verify_producer(&producer_sk.verifying_key())
        .unwrap();

    // Event signatures survive round-trip.
    parsed.events[0]
        .verify_with_key(&k1.verifying_key())
        .unwrap();
    parsed.events[1]
        .verify_with_key(&k2.verifying_key())
        .unwrap();
    parsed.events[2]
        .verify_with_key(&k3.verifying_key())
        .unwrap();
}

#[test]
fn block_with_committee_attestations_round_trip() {
    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());

    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: ChainId([7u8; HASH_LEN]),
        height: 1,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0u8; HASH_LEN],
        state_root: [0u8; HASH_LEN],
        timestamp: 1_700_000_000_000,
        producer,
    };
    let mut header = payload.sign(&producer_sk);

    // Add 4 attestations (simulating a committee of 5 where producer is
    // one signer and 4 others attest).
    let mut committee = std::collections::HashMap::new();
    for _ in 0..4 {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let pid = PeerId::from_verifying_key(&vk);
        header.add_attestation(pid, &vk, &sk).unwrap();
        committee.insert(pid, vk);
    }

    let block = Block {
        header,
        events: Vec::new(),
    };

    let bytes = postcard::to_allocvec(&block).unwrap();
    let parsed: Block = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(block, parsed);

    parsed
        .header
        .verify_attestations(|p| committee.get(p).copied())
        .expect("all attestations valid after round-trip");
}

#[test]
fn session_chain_id_integration_with_block() {
    // A session chain's deterministic id (§6.6.2) is then used as the
    // chain_id in its block headers. Two independent parties must be able
    // to verify "this block belongs to the session that started at T with
    // producer P".

    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());
    let domain = ChainId([0xcd; HASH_LEN]);
    let start_ms: u64 = 1_700_000_000_000;

    let session_id_a = ChainId::derive_session(&domain, start_ms, &producer);
    let session_id_b = ChainId::derive_session(&domain, start_ms, &producer);
    assert_eq!(session_id_a, session_id_b);

    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: session_id_a,
        height: 1,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0u8; HASH_LEN],
        state_root: [0u8; HASH_LEN],
        timestamp: start_ms + 500,
        producer,
    };
    let header = payload.sign(&producer_sk);

    let bytes = postcard::to_allocvec(&header).unwrap();
    let parsed: BlockHeader = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(header, parsed);
    assert_eq!(parsed.payload.chain_id, session_id_b);
}

#[test]
fn tampered_attestation_rejected() {
    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());
    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: ChainId([7u8; HASH_LEN]),
        height: 1,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0u8; HASH_LEN],
        state_root: [0u8; HASH_LEN],
        timestamp: 1,
        producer,
    };
    let mut header = payload.sign(&producer_sk);

    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let pid = PeerId::from_verifying_key(&vk);
    header.add_attestation(pid, &vk, &sk).unwrap();

    // Flip one bit in the first attestation's signature.
    header.attestations[0].signature[0] ^= 0x01;

    assert!(header.verify_attestations(|_| Some(vk)).is_err());
}

#[test]
fn attestation_with_unknown_signer_rejected() {
    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());
    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: ChainId([7u8; HASH_LEN]),
        height: 1,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0u8; HASH_LEN],
        state_root: [0u8; HASH_LEN],
        timestamp: 1,
        producer,
    };
    let mut header = payload.sign(&producer_sk);

    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let pid = PeerId::from_verifying_key(&vk);
    header.add_attestation(pid, &vk, &sk).unwrap();

    // Resolver returns None for every PeerId — signer is "unknown".
    assert!(header.verify_attestations(|_| None).is_err());
}

#[test]
fn event_signed_by_one_key_rejects_other_peer_id() {
    // Guard: the identity/pubkey binding is the caller's responsibility,
    // but this test documents that swapping the claimant doesn't magically
    // validate — the signature is over the original payload including the
    // original claimant.

    let sk = SigningKey::generate(&mut OsRng);
    let original_claimant = PeerId::from_verifying_key(&sk.verifying_key());
    let impostor = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());

    let payload = EventPayload {
        version: 1,
        namespace: Namespace::new("tessera.game").unwrap(),
        claimant: original_claimant,
        nonce: 1,
        body: b"x".to_vec(),
        timestamp: 1,
    };
    let event = payload.sign(&sk);

    // Tamper the claimant post-signing.
    let mut tampered = event.clone();
    tampered.payload.claimant = impostor;
    assert!(tampered.verify_with_key(&sk.verifying_key()).is_err());
}

#[test]
fn empty_block_serializes_compactly() {
    let producer_sk = SigningKey::generate(&mut OsRng);
    let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());
    let payload = BlockHeaderPayload {
        version: 1,
        chain_id: ChainId([7u8; HASH_LEN]),
        height: 0,
        prev_hash: codex_core::BlockHash([0u8; HASH_LEN]),
        events_root: [0u8; HASH_LEN],
        state_root: [0u8; HASH_LEN],
        timestamp: 0,
        producer,
    };
    let header = payload.sign(&producer_sk);
    let block = Block {
        header,
        events: Vec::new(),
    };

    let bytes = postcard::to_allocvec(&block).unwrap();
    // Design goal §3: block header ~300 bytes. Empty block serialized
    // size should be under 512 B as an easy-to-hit ceiling that still
    // catches regressions (e.g. accidental per-field length tagging).
    assert!(
        bytes.len() < 512,
        "empty block unexpectedly large: {} bytes",
        bytes.len()
    );
}
