//! Committee-mode integration: 5 validators produce and attest in
//! round-robin; verifier accepts only when ≥ 2/3 signed.

use codex_consensus::committee::{
    sign_attestation, CommitteeProducer, CommitteeRules, CommitteeVerifier, ValidatorSet,
};
use codex_consensus::ChainTip;
use codex_core::block::{Attestation, Block};
use codex_core::event::{Event, EventPayload};
use codex_core::hashes::ChainId;
use codex_core::namespace::Namespace;
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
                reason: "dup".into(),
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

struct Member {
    sk: SigningKey,
    vk: VerifyingKey,
    peer: PeerId,
}

impl Member {
    fn new() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let peer = PeerId::from_verifying_key(&vk);
        Self { sk, vk, peer }
    }
}

fn claim(m: &Member, nonce: u64, body: &[u8]) -> Event {
    EventPayload {
        version: 1,
        namespace: ach_ns(),
        claimant: m.peer,
        nonce,
        body: body.to_vec(),
        timestamp: 1_700_000_000_000 + nonce,
    }
    .sign(&m.sk)
}

fn resolver(actors: &[&Member]) -> impl FnMut(&PeerId) -> Option<VerifyingKey> {
    let map: std::collections::HashMap<PeerId, VerifyingKey> =
        actors.iter().map(|a| (a.peer, a.vk)).collect();
    move |p: &PeerId| map.get(p).copied()
}

fn attach_attestations_from(block: &mut Block, signers: &[&Member]) {
    let payload = block.header.payload.clone();
    for s in signers {
        let sig = sign_attestation(&payload, &s.sk);
        block.header.attestations.push(Attestation {
            signer: s.peer,
            signature: sig,
        });
    }
}

#[test]
fn five_node_committee_round_trip() {
    // 5 validators, threshold = ceil(10/3) = 4 total support. Producer
    // counts as 1; we need 3 attestations.
    let committee: Vec<Member> = (0..5).map(|_| Member::new()).collect();
    let set = ValidatorSet::sorted(committee.iter().map(|m| (m.peer, m.vk)).collect()).unwrap();
    let chain_id = ChainId([0xaa; 32]);

    // Figure out the proposer for height 1.
    let proposer_peer = set.proposer(1);
    let proposer_idx = committee
        .iter()
        .position(|m| m.peer == proposer_peer)
        .unwrap();
    let proposer = &committee[proposer_idx];
    let attesters: Vec<&Member> = committee
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != proposer_idx)
        .take(3) // satisfy attestation_threshold (4) with producer + 3
        .map(|(_, m)| m)
        .collect();

    // Build an event author who is outside the committee.
    let author = Member::new();
    let mut resolve_all = resolver(
        &committee
            .iter()
            .chain(std::iter::once(&author))
            .collect::<Vec<_>>(),
    );

    // Producer path.
    let mut state = StateTree::new();
    let mut stf = Stf::new(registry());
    let mut cp = CommitteeProducer::new(
        proposer.peer,
        proposer.sk.clone(),
        set.clone(),
        ChainTip::genesis(chain_id),
    );
    let mut block = cp
        .propose(
            vec![claim(&author, 1, b"summit")],
            &mut stf,
            &mut state,
            1,
            &mut resolve_all,
        )
        .unwrap();

    // Attach attestations (out-of-band collection).
    attach_attestations_from(&mut block, &attesters);

    // Verifier path.
    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut cv =
        CommitteeVerifier::new(set, ChainTip::genesis(chain_id), CommitteeRules::default());
    cv.verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve_all)
        .unwrap();

    assert_eq!(cv.tip().height, 1);
    assert_eq!(cv.tip().tip_hash, block.header.block_hash());
}

#[test]
fn below_threshold_is_rejected() {
    // 5-node committee, threshold 4. Producer + 1 attestation = 2
    // total support → reject.
    let committee: Vec<Member> = (0..5).map(|_| Member::new()).collect();
    let set = ValidatorSet::sorted(committee.iter().map(|m| (m.peer, m.vk)).collect()).unwrap();
    let chain_id = ChainId([0xbb; 32]);
    let proposer_peer = set.proposer(1);
    let proposer_idx = committee
        .iter()
        .position(|m| m.peer == proposer_peer)
        .unwrap();
    let proposer = &committee[proposer_idx];
    let one_attester: &Member = committee
        .iter()
        .enumerate()
        .find(|(i, _)| *i != proposer_idx)
        .map(|(_, m)| m)
        .unwrap();

    let author = Member::new();
    let mut resolve_all = resolver(
        &committee
            .iter()
            .chain(std::iter::once(&author))
            .collect::<Vec<_>>(),
    );
    let mut state = StateTree::new();
    let mut stf = Stf::new(registry());
    let mut cp = CommitteeProducer::new(
        proposer.peer,
        proposer.sk.clone(),
        set.clone(),
        ChainTip::genesis(chain_id),
    );
    let mut block = cp
        .propose(
            vec![claim(&author, 1, b"x")],
            &mut stf,
            &mut state,
            1,
            &mut resolve_all,
        )
        .unwrap();
    attach_attestations_from(&mut block, &[one_attester]); // only 1
    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut cv =
        CommitteeVerifier::new(set, ChainTip::genesis(chain_id), CommitteeRules::default());
    let err = cv
        .verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve_all)
        .unwrap_err();
    assert!(matches!(err, codex_consensus::ConsensusError::Committee(_)));
}

#[test]
fn producer_cant_attest_own_block() {
    let committee: Vec<Member> = (0..3).map(|_| Member::new()).collect();
    let set = ValidatorSet::sorted(committee.iter().map(|m| (m.peer, m.vk)).collect()).unwrap();
    let chain_id = ChainId([0xcc; 32]);
    let proposer_peer = set.proposer(1);
    let proposer_idx = committee
        .iter()
        .position(|m| m.peer == proposer_peer)
        .unwrap();
    let proposer = &committee[proposer_idx];
    let other_idx = (proposer_idx + 1) % committee.len();
    let other = &committee[other_idx];

    let author = Member::new();
    let mut resolve_all = resolver(
        &committee
            .iter()
            .chain(std::iter::once(&author))
            .collect::<Vec<_>>(),
    );
    let mut state = StateTree::new();
    let mut stf = Stf::new(registry());
    let mut cp = CommitteeProducer::new(
        proposer.peer,
        proposer.sk.clone(),
        set.clone(),
        ChainTip::genesis(chain_id),
    );
    let mut block = cp
        .propose(
            vec![claim(&author, 1, b"x")],
            &mut stf,
            &mut state,
            1,
            &mut resolve_all,
        )
        .unwrap();
    // Attach producer's own signature as an "attestation" — forbidden.
    attach_attestations_from(&mut block, &[proposer, other]);
    let mut v_state = StateTree::new();
    let mut v_stf = Stf::new(registry());
    let mut cv =
        CommitteeVerifier::new(set, ChainTip::genesis(chain_id), CommitteeRules::default());
    let err = cv
        .verify_and_apply(&block, &mut v_stf, &mut v_state, &mut resolve_all)
        .unwrap_err();
    assert!(matches!(err, codex_consensus::ConsensusError::Committee(_)));
}
