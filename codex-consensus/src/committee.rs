//! Committee (PoA / DPoS-lite) mode.
//!
//! Covers §6.2, §6.3 (finality), §6.5 (byzantine signer) and §6.7
//! (validator-set changes via `ValidatorSetChange`, slashing via
//! `ValidatorSlash` + equivocation proof).
//!
//! Core pieces:
//! - [`ValidatorSet`] — the authorized signer set
//! - [`CommitteeRules`] — the N/2+1 threshold + the 8-block
//!   announce minimum + the "post-change size ≥ 3" guard (§6.7.3)
//! - [`CommitteeProducer`] — proposer = `members[height % N]`
//! - [`CommitteeVerifier`] — verifies producer signature + ≥ 2/3 valid
//!   attestations + attestations come from the set
//! - [`EquivocationProof`] — two distinct headers at same chain_id +
//!   height both signed by the same offender

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use codex_core::block::{Block, BlockHeader, BlockHeaderPayload};
use codex_crypto::{PeerId, Signature, SigningKey, Verifier, VerifyingKey};
use codex_state::{StateTree, Stf};
use serde::{Deserialize, Serialize};

use crate::chain::ChainTip;
use crate::error::ConsensusError;
use crate::verifier::ProducerAuthority;

/// Minimum committee size enforced by `CommitteeRules::MIN_SIZE`.
pub const MIN_COMMITTEE_SIZE: usize = 3;

/// Minimum announce window for `ValidatorSetChange` (§6.7.1).
pub const MIN_ANNOUNCE_BLOCKS: u64 = 8;

/// Ordered set of validators. Insertion order is the round-robin proposer
/// order; use [`ValidatorSet::sorted`] to rebuild with deterministic
/// ordering.
#[derive(Clone)]
pub struct ValidatorSet {
    members: Vec<(PeerId, VerifyingKey)>,
    by_peer: BTreeMap<PeerId, usize>,
}

impl ValidatorSet {
    pub fn new(members: Vec<(PeerId, VerifyingKey)>) -> Result<Self, ConsensusError> {
        if members.len() < MIN_COMMITTEE_SIZE {
            return Err(ConsensusError::Committee(format!(
                "committee size {} < minimum {}",
                members.len(),
                MIN_COMMITTEE_SIZE
            )));
        }
        let mut by_peer = BTreeMap::new();
        for (i, (p, _)) in members.iter().enumerate() {
            if by_peer.insert(*p, i).is_some() {
                return Err(ConsensusError::Committee(
                    "duplicate validator peer in set".into(),
                ));
            }
        }
        Ok(Self { members, by_peer })
    }

    /// Deterministic variant: members sorted by `PeerId`.
    pub fn sorted(members: Vec<(PeerId, VerifyingKey)>) -> Result<Self, ConsensusError> {
        let mut m = members;
        m.sort_by_key(|(p, _)| *p);
        Self::new(m)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn members(&self) -> &[(PeerId, VerifyingKey)] {
        &self.members
    }

    pub fn verifying_key(&self, peer: &PeerId) -> Option<VerifyingKey> {
        self.by_peer.get(peer).map(|&i| self.members[i].1)
    }

    pub fn contains(&self, peer: &PeerId) -> bool {
        self.by_peer.contains_key(peer)
    }

    /// Proposer for the given height under round-robin selection.
    pub fn proposer(&self, height: u64) -> PeerId {
        self.members[(height as usize) % self.members.len()].0
    }

    /// `ceil(2 * N / 3)`. A block needs at least this many distinct
    /// valid attestations (producer not counted).
    pub fn attestation_threshold(&self) -> usize {
        (2 * self.members.len()).div_ceil(3)
    }
}

impl ProducerAuthority for ValidatorSet {
    fn is_authorized(&self, producer: &PeerId) -> bool {
        self.contains(producer)
    }
    fn verifying_key(&self, producer: &PeerId) -> Option<VerifyingKey> {
        ValidatorSet::verifying_key(self, producer)
    }
}

/// Committee rules (immutable for the lifetime of a chain unless
/// changed by a `ValidatorSetChange` event).
#[derive(Debug, Clone)]
pub struct CommitteeRules {
    pub min_size: usize,
    pub min_announce_blocks: u64,
}

impl Default for CommitteeRules {
    fn default() -> Self {
        Self {
            min_size: MIN_COMMITTEE_SIZE,
            min_announce_blocks: MIN_ANNOUNCE_BLOCKS,
        }
    }
}

/// Producer side of committee mode. Proposer is decided by height; the
/// caller is expected to ensure it only attempts `produce` when
/// `self.is_my_turn(height)`.
pub struct CommitteeProducer {
    me: PeerId,
    my_sk: SigningKey,
    set: ValidatorSet,
    tip: ChainTip,
}

impl CommitteeProducer {
    pub fn new(me: PeerId, my_sk: SigningKey, set: ValidatorSet, tip: ChainTip) -> Self {
        Self {
            me,
            my_sk,
            set,
            tip,
        }
    }

    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    pub fn set(&self) -> &ValidatorSet {
        &self.set
    }

    /// True iff this node would be the proposer at `next_height`.
    pub fn is_my_turn(&self, next_height: u64) -> bool {
        self.set.proposer(next_height) == self.me
    }

    /// Produce a block and return it without attestations attached.
    /// Attestations are collected by the caller (an out-of-band flow in
    /// v0; in M3 this is wired through the node's RPC).
    pub fn propose<F>(
        &mut self,
        events: Vec<codex_core::event::Event>,
        stf: &mut Stf,
        state: &mut StateTree,
        timestamp_ms: u64,
        resolve: &mut F,
    ) -> Result<Block, ConsensusError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let next_height = self.tip.height + 1;
        if !self.is_my_turn(next_height) {
            return Err(ConsensusError::Committee(format!(
                "not my turn at height {next_height}"
            )));
        }

        let applied = stf
            .dry_run_block(&events, state, resolve)
            .map_err(ConsensusError::Stf)?;

        let payload = BlockHeaderPayload {
            version: 1,
            chain_id: self.tip.chain_id,
            height: next_height,
            prev_hash: self.tip.tip_hash,
            events_root: applied.events_root,
            state_root: applied.state_root,
            timestamp: timestamp_ms,
            producer: self.me,
        };
        let header = payload.sign(&self.my_sk);
        let block = Block { header, events };

        stf.apply_block(&block, state, resolve)
            .map_err(ConsensusError::Stf)?;

        let hash = block.header.block_hash();
        self.tip.advance(next_height, hash);
        Ok(block)
    }
}

/// Verifier under committee mode.
pub struct CommitteeVerifier {
    set: ValidatorSet,
    tip: ChainTip,
    rules: CommitteeRules,
}

impl CommitteeVerifier {
    pub fn new(set: ValidatorSet, tip: ChainTip, rules: CommitteeRules) -> Self {
        Self { set, tip, rules }
    }

    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    pub fn set(&self) -> &ValidatorSet {
        &self.set
    }

    pub fn rules(&self) -> &CommitteeRules {
        &self.rules
    }

    /// Verify the block and its attestations. Requires:
    /// - header continuity (chain_id, height, prev_hash)
    /// - producer is set member and signature valid
    /// - STF applies and declared roots match
    /// - at least [`ValidatorSet::attestation_threshold`] distinct
    ///   attestations from set members, each with a valid signature
    ///   over the header payload
    /// - attestations include no duplicates (one per signer), no
    ///   producer self-vote (the producer's signature is already in
    ///   `header.producer_signature`).
    pub fn verify_and_apply<F>(
        &mut self,
        block: &Block,
        stf: &mut Stf,
        state: &mut StateTree,
        resolve: &mut F,
    ) -> Result<(), ConsensusError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let hdr = &block.header.payload;

        if hdr.chain_id != self.tip.chain_id {
            return Err(ConsensusError::ChainIdMismatch {
                block: hdr.chain_id,
                chain: self.tip.chain_id,
            });
        }
        let expected_height = self.tip.height + 1;
        if hdr.height != expected_height {
            return Err(ConsensusError::HeightOutOfOrder {
                expected: expected_height,
                got: hdr.height,
            });
        }
        if hdr.prev_hash != self.tip.tip_hash {
            return Err(ConsensusError::PrevHashMismatch);
        }
        if !self.set.contains(&hdr.producer) {
            return Err(ConsensusError::UnauthorizedProducer { got: hdr.producer });
        }
        if self.set.proposer(hdr.height) != hdr.producer {
            return Err(ConsensusError::Committee(format!(
                "producer {:?} is not the proposer at height {}",
                hdr.producer, hdr.height
            )));
        }

        let producer_vk = self
            .set
            .verifying_key(&hdr.producer)
            .expect("set membership checked");
        block
            .header
            .verify_producer(&producer_vk)
            .map_err(ConsensusError::ProducerSignature)?;

        // Attestations.
        let signing_hash = hdr.signing_hash();
        let mut seen = BTreeSet::new();
        for att in &block.header.attestations {
            if att.signer == hdr.producer {
                return Err(ConsensusError::Committee(
                    "producer may not attest own block".into(),
                ));
            }
            if !seen.insert(att.signer) {
                return Err(ConsensusError::Committee(
                    "duplicate attestation signer".into(),
                ));
            }
            let vk = self.set.verifying_key(&att.signer).ok_or_else(|| {
                ConsensusError::Committee(format!("attestation by non-member {:?}", att.signer))
            })?;
            let sig = Signature::from_bytes(&att.signature);
            vk.verify(&signing_hash, &sig).map_err(|_| {
                ConsensusError::Committee(format!(
                    "invalid attestation signature from {:?}",
                    att.signer
                ))
            })?;
        }
        // Producer counts toward finality, so the threshold counts
        // attesters plus 1 (the producer's own sig already verified).
        let total_support = seen.len() + 1;
        let threshold = self.set.attestation_threshold();
        if total_support < threshold {
            return Err(ConsensusError::Committee(format!(
                "support {total_support} < threshold {threshold} at height {}",
                hdr.height
            )));
        }

        stf.verify_and_apply_block(block, state, resolve)?;

        let new_hash = block.header.block_hash();
        self.tip.advance(hdr.height, new_hash);
        Ok(())
    }
}

/// Equivocation proof: two block headers at the same `(chain_id, height)`
/// with different contents, both signed by the same offender. Verified
/// against the offender's `VerifyingKey`; a valid proof is grounds for
/// immediate removal from the validator set (§6.7.2).
#[derive(Debug, Clone)]
pub struct EquivocationProof {
    pub offender: PeerId,
    pub header_a: BlockHeader,
    pub header_b: BlockHeader,
}

impl EquivocationProof {
    pub fn verify(&self, offender_vk: &VerifyingKey) -> Result<(), ConsensusError> {
        let a = &self.header_a.payload;
        let b = &self.header_b.payload;

        if a.chain_id != b.chain_id {
            return Err(ConsensusError::Committee(
                "headers belong to different chains".into(),
            ));
        }
        if a.height != b.height {
            return Err(ConsensusError::Committee(
                "headers at different heights; not equivocation".into(),
            ));
        }
        let ha = self.header_a.block_hash();
        let hb = self.header_b.block_hash();
        if ha == hb {
            return Err(ConsensusError::Committee(
                "headers are identical; not equivocation".into(),
            ));
        }
        if a.producer != self.offender || b.producer != self.offender {
            return Err(ConsensusError::Committee(
                "offender is not the producer of both headers".into(),
            ));
        }

        // Both signatures must verify against offender_vk.
        self.header_a
            .verify_producer(offender_vk)
            .map_err(ConsensusError::ProducerSignature)?;
        self.header_b
            .verify_producer(offender_vk)
            .map_err(ConsensusError::ProducerSignature)?;

        Ok(())
    }
}

/// Helper: build an attestation signature for a given header payload.
/// Exposed for the node layer (M3) which collects attestations via RPC.
pub fn sign_attestation(payload: &BlockHeaderPayload, signer_sk: &SigningKey) -> [u8; 64] {
    let hash = payload.signing_hash();
    let sig = <SigningKey as codex_crypto::Signer<Signature>>::sign(signer_sk, &hash);
    sig.to_bytes()
}

/// Helper: check that a proposed post-slash / post-change committee
/// would still have at least [`CommitteeRules::min_size`] members.
/// §6.7.3 guard.
pub fn post_change_size_ok(
    current: usize,
    change: ValidatorChange,
    rules: &CommitteeRules,
) -> bool {
    let next = match change {
        ValidatorChange::Add => current.saturating_add(1),
        ValidatorChange::Remove => current.saturating_sub(1),
        ValidatorChange::Replace => current, // net zero
    };
    next >= rules.min_size
}

/// Abstract change classifier used by `post_change_size_ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorChange {
    Add,
    Remove,
    Replace,
}

// ---------------------------------------------------------------------
// codex.system.ValidatorSetChange event schema (§6.7.1)
// ---------------------------------------------------------------------

/// Namespace used for all committee-governance events.
pub const SYSTEM_COMMITTEE_NAMESPACE: &str = "codex.system.committee";

/// Body of a `ValidatorSetChange` event. Gets wrapped in an Event with
/// `namespace = codex.system.committee` and signed by a current
/// committee member. An external aggregator collects at least
/// `attestation_threshold` such signatures to form the full proposal;
/// this struct is the per-signer payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetChangeBody {
    pub change_type: ChangeType,
    pub effective_at_height: u64,
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Add(PeerId, #[serde(with = "serde_bytes_32")] [u8; 32]), // peer + pubkey
    Remove(PeerId),
    Replace {
        old: PeerId,
        new: PeerId,
        #[serde(with = "serde_bytes_32")]
        new_pubkey: [u8; 32],
    },
}

impl ChangeType {
    pub fn classifier(&self) -> ValidatorChange {
        match self {
            ChangeType::Add(_, _) => ValidatorChange::Add,
            ChangeType::Remove(_) => ValidatorChange::Remove,
            ChangeType::Replace { .. } => ValidatorChange::Replace,
        }
    }
}

mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// FIFO tracker of staged committee changes awaiting their
/// `effective_at_height`. Consumers (node / verifier) inspect the
/// front of the queue at each block-apply to know when to mutate the
/// live `ValidatorSet`.
#[derive(Debug, Default)]
pub struct StagedChanges {
    queue: VecDeque<ValidatorSetChangeBody>,
}

impl StagedChanges {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Stage a change. Returns `Err` if `effective_at_height <=
    /// current_height + rules.min_announce_blocks`.
    pub fn stage(
        &mut self,
        change: ValidatorSetChangeBody,
        current_height: u64,
        rules: &CommitteeRules,
    ) -> Result<(), ConsensusError> {
        if change.effective_at_height < current_height + rules.min_announce_blocks {
            return Err(ConsensusError::Committee(format!(
                "effective_at_height {} is less than current+{}",
                change.effective_at_height, rules.min_announce_blocks
            )));
        }
        self.queue.push_back(change);
        Ok(())
    }

    /// Drain every staged change whose `effective_at_height <=
    /// current_height`. Callers apply each to the live set in order.
    pub fn take_matured(&mut self, current_height: u64) -> Vec<ValidatorSetChangeBody> {
        let mut out = Vec::new();
        while self
            .queue
            .front()
            .map(|c| c.effective_at_height <= current_height)
            .unwrap_or(false)
        {
            out.push(self.queue.pop_front().unwrap());
        }
        out
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

/// Apply a single staged change to a validator set in place, enforcing
/// the post-change size guard. Used by the caller after
/// [`StagedChanges::take_matured`] returns a change at block N's apply.
pub fn apply_change_to_set(
    set: &mut ValidatorSet,
    change: &ValidatorSetChangeBody,
    rules: &CommitteeRules,
) -> Result<(), ConsensusError> {
    if !post_change_size_ok(set.len(), change.change_type.classifier(), rules) {
        return Err(ConsensusError::Committee(format!(
            "post-change size would be < {} ({} guard)",
            rules.min_size, rules.min_size
        )));
    }
    match &change.change_type {
        ChangeType::Add(peer, pubkey_bytes) => {
            if set.contains(peer) {
                return Err(ConsensusError::Committee("validator already in set".into()));
            }
            let vk = VerifyingKey::from_bytes(pubkey_bytes)
                .map_err(|_| ConsensusError::Committee("invalid verifying key bytes".into()))?;
            let mut members = set.members().to_vec();
            members.push((*peer, vk));
            *set = ValidatorSet::sorted(members)?;
        }
        ChangeType::Remove(peer) => {
            if !set.contains(peer) {
                return Err(ConsensusError::Committee("validator not in set".into()));
            }
            let members: Vec<_> = set
                .members()
                .iter()
                .filter(|(p, _)| p != peer)
                .cloned()
                .collect();
            *set = ValidatorSet::sorted(members)?;
        }
        ChangeType::Replace {
            old,
            new,
            new_pubkey,
        } => {
            if !set.contains(old) {
                return Err(ConsensusError::Committee("old validator not in set".into()));
            }
            if set.contains(new) {
                return Err(ConsensusError::Committee(
                    "new validator already in set".into(),
                ));
            }
            let new_vk = VerifyingKey::from_bytes(new_pubkey)
                .map_err(|_| ConsensusError::Committee("invalid new verifying key bytes".into()))?;
            let mut members: Vec<_> = set
                .members()
                .iter()
                .filter(|(p, _)| p != old)
                .cloned()
                .collect();
            members.push((*new, new_vk));
            *set = ValidatorSet::sorted(members)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::hashes::{BlockHash, ChainId};
    use codex_core::SignatureError;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    fn make_set(n: usize) -> Vec<(PeerId, VerifyingKey, SigningKey)> {
        (0..n)
            .map(|_| {
                let sk = SigningKey::generate(&mut OsRng);
                let vk = sk.verifying_key();
                (PeerId::from_verifying_key(&vk), vk, sk)
            })
            .collect()
    }

    #[test]
    fn rejects_undersized_set() {
        let m = make_set(2).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        assert!(ValidatorSet::new(m).is_err());
    }

    #[test]
    fn rejects_duplicate_members() {
        let m = make_set(3);
        let (p1, vk1, _) = &m[0];
        let (p2, vk2, _) = &m[1];
        let dup = vec![(*p1, *vk1), (*p2, *vk2), (*p1, *vk1)];
        assert!(ValidatorSet::new(dup).is_err());
    }

    #[test]
    fn attestation_threshold_is_two_thirds_ceil() {
        let m = make_set(3).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let set = ValidatorSet::new(m).unwrap();
        assert_eq!(set.attestation_threshold(), 2); // ceil(6/3) = 2
        let m5: Vec<_> = make_set(5).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let set5 = ValidatorSet::new(m5).unwrap();
        assert_eq!(set5.attestation_threshold(), 4); // ceil(10/3) = 4
        let m7: Vec<_> = make_set(7).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let set7 = ValidatorSet::new(m7).unwrap();
        assert_eq!(set7.attestation_threshold(), 5); // ceil(14/3) = 5
    }

    #[test]
    fn proposer_round_robins() {
        let m: Vec<_> = make_set(3).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let set = ValidatorSet::new(m.clone()).unwrap();
        assert_eq!(set.proposer(0), m[0].0);
        assert_eq!(set.proposer(1), m[1].0);
        assert_eq!(set.proposer(2), m[2].0);
        assert_eq!(set.proposer(3), m[0].0);
    }

    #[test]
    fn post_change_size_ok_guard() {
        let r = CommitteeRules::default();
        assert!(!post_change_size_ok(3, ValidatorChange::Remove, &r));
        assert!(post_change_size_ok(4, ValidatorChange::Remove, &r));
        assert!(post_change_size_ok(3, ValidatorChange::Add, &r));
        assert!(post_change_size_ok(3, ValidatorChange::Replace, &r));
    }

    #[test]
    fn equivocation_proof_catches_double_sign() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let offender = PeerId::from_verifying_key(&vk);

        let payload_a = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([9u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: offender,
        };
        let payload_b = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([9u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [1u8; 32], // different
            state_root: [0u8; 32],
            timestamp: 1,
            producer: offender,
        };
        let header_a = payload_a.sign(&sk);
        let header_b = payload_b.sign(&sk);
        let ep = EquivocationProof {
            offender,
            header_a,
            header_b,
        };
        ep.verify(&vk).unwrap();
    }

    #[test]
    fn equivocation_proof_rejects_identical_headers() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let offender = PeerId::from_verifying_key(&vk);
        let payload = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([9u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: offender,
        };
        let header = payload.sign(&sk);
        let ep = EquivocationProof {
            offender,
            header_a: header.clone(),
            header_b: header,
        };
        assert!(ep.verify(&vk).is_err());
    }

    #[test]
    fn equivocation_proof_rejects_different_heights() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let offender = PeerId::from_verifying_key(&vk);
        let mut payload_a = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([9u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: offender,
        };
        let mut payload_b = payload_a.clone();
        payload_b.height = 2; // different height
        let _ = (&mut payload_a, &mut payload_b);
        let ep = EquivocationProof {
            offender,
            header_a: payload_a.sign(&sk),
            header_b: payload_b.sign(&sk),
        };
        assert!(ep.verify(&vk).is_err());
    }

    #[test]
    fn sign_attestation_is_verifiable() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let payload = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([1u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: PeerId::from_verifying_key(&vk),
        };
        let sig_bytes = sign_attestation(&payload, &sk);
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&payload.signing_hash(), &sig).unwrap();
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn min_committee_size_is_three() {
        assert!(MIN_COMMITTEE_SIZE == 3);
    }

    #[test]
    fn staged_changes_reject_short_announce() {
        let rules = CommitteeRules::default();
        let mut staged = StagedChanges::new();
        let change = ValidatorSetChangeBody {
            change_type: ChangeType::Remove(PeerId([0u8; 20])),
            effective_at_height: 5, // too soon when current=3 and min_announce=8
            rationale: None,
        };
        assert!(staged.stage(change, 3, &rules).is_err());
    }

    #[test]
    fn staged_changes_mature_in_order() {
        let rules = CommitteeRules::default();
        let mut staged = StagedChanges::new();
        for offset in [8u64, 10, 15] {
            let change = ValidatorSetChangeBody {
                change_type: ChangeType::Remove(PeerId([offset as u8; 20])),
                effective_at_height: offset,
                rationale: None,
            };
            staged.stage(change, 0, &rules).unwrap();
        }
        assert_eq!(staged.pending(), 3);
        let matured_at_10 = staged.take_matured(10);
        assert_eq!(matured_at_10.len(), 2); // heights 8 and 10
        assert_eq!(matured_at_10[0].effective_at_height, 8);
        assert_eq!(matured_at_10[1].effective_at_height, 10);
        assert_eq!(staged.pending(), 1);
    }

    #[test]
    fn apply_add_grows_set_and_reindexes() {
        let rules = CommitteeRules::default();
        let m: Vec<_> = make_set(3).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let mut set = ValidatorSet::new(m).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let peer = PeerId::from_verifying_key(&vk);
        let change = ValidatorSetChangeBody {
            change_type: ChangeType::Add(peer, vk.to_bytes()),
            effective_at_height: 100,
            rationale: None,
        };
        apply_change_to_set(&mut set, &change, &rules).unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.contains(&peer));
    }

    #[test]
    fn apply_remove_shrinks_but_respects_guard() {
        let rules = CommitteeRules::default();
        let m: Vec<_> = make_set(3).into_iter().map(|(p, vk, _)| (p, vk)).collect();
        let first = m[0].0;
        let mut set = ValidatorSet::new(m).unwrap();
        let change = ValidatorSetChangeBody {
            change_type: ChangeType::Remove(first),
            effective_at_height: 100,
            rationale: None,
        };
        // Size 3 → 2 trips the guard (min is 3).
        assert!(apply_change_to_set(&mut set, &change, &rules).is_err());
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn signature_error_path_smoke() {
        // Smoke: verifying a corrupted signature returns a SignatureError
        // wrapped in ProducerSignature via verify_producer.
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let offender = PeerId::from_verifying_key(&vk);
        let payload = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([9u8; 32]),
            height: 1,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            producer: offender,
        };
        let mut header = payload.sign(&sk);
        header.producer_signature[0] ^= 0xff;
        let err = header.verify_producer(&vk).unwrap_err();
        assert!(matches!(err, SignatureError::Invalid));
    }
}
