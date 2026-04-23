//! Session-mode block verifier.
//!
//! Receives a block off the wire and, given an authorized-producer
//! resolver + STF + state, checks:
//! 1. `chain_id` matches
//! 2. `height == tip.height + 1`
//! 3. `prev_hash == tip.tip_hash`
//! 4. producer is authorized (resolver returns a key)
//! 5. producer signature over the header payload is valid
//! 6. STF applies and the declared `events_root` / `state_root` match
//!    the recomputed values (via `Stf::verify_and_apply_block`)
//!
//! On success, advances the tip; on any failure, state is unchanged.

use codex_core::block::Block;
use codex_crypto::{PeerId, VerifyingKey};
use codex_state::{StateTree, Stf};

use crate::chain::ChainTip;
use crate::error::ConsensusError;

/// Strategy trait for "is this PeerId authorized to produce?". In session
/// mode this is a simple equality check; committee mode checks set
/// membership.
pub trait ProducerAuthority: Send + Sync {
    fn is_authorized(&self, producer: &PeerId) -> bool;
    fn verifying_key(&self, producer: &PeerId) -> Option<VerifyingKey>;
}

/// Session-mode authority: one fixed `(peer, verifying_key)`.
pub struct SingleProducerAuthority {
    peer: PeerId,
    vk: VerifyingKey,
}

impl SingleProducerAuthority {
    pub fn new(peer: PeerId, vk: VerifyingKey) -> Self {
        Self { peer, vk }
    }
}

impl ProducerAuthority for SingleProducerAuthority {
    fn is_authorized(&self, producer: &PeerId) -> bool {
        *producer == self.peer
    }
    fn verifying_key(&self, producer: &PeerId) -> Option<VerifyingKey> {
        if *producer == self.peer {
            Some(self.vk)
        } else {
            None
        }
    }
}

/// Block verifier. Maintains its own `ChainTip`.
pub struct BlockVerifier {
    tip: ChainTip,
    authority: Box<dyn ProducerAuthority>,
}

impl BlockVerifier {
    pub fn new(tip: ChainTip, authority: Box<dyn ProducerAuthority>) -> Self {
        Self { tip, authority }
    }

    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    /// Controlled tip override: used by `SessionNode` when it has
    /// also advanced its producer via `produce`. The tip invariants
    /// (`height` == tip.height + 1, `prev_hash` match) are still
    /// enforced on every subsequent `verify_and_apply`.
    pub fn tip_mut(&mut self) -> &mut ChainTip {
        &mut self.tip
    }

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

        if !self.authority.is_authorized(&hdr.producer) {
            return Err(ConsensusError::UnauthorizedProducer { got: hdr.producer });
        }

        let producer_vk = self
            .authority
            .verifying_key(&hdr.producer)
            .ok_or(ConsensusError::UnauthorizedProducer { got: hdr.producer })?;

        block
            .header
            .verify_producer(&producer_vk)
            .map_err(ConsensusError::ProducerSignature)?;

        stf.verify_and_apply_block(block, state, resolve)?;

        let new_hash = block.header.block_hash();
        self.tip.advance(hdr.height, new_hash);
        Ok(())
    }
}
