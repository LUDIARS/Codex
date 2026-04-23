//! Light client for Codex.
//!
//! Stores only block headers plus an authorized-producer set. Accepts
//! each header by verifying:
//!   - the `chain_id`
//!   - `height == current + 1`
//!   - `prev_hash == tip_hash`
//!   - the producer signature against the authority-provided key
//!
//! Exposes helpers for SPV-style proof verification against a known
//! block's `events_root` / `state_root`: these are just `codex_state`
//! proof routines, rewrapped with a nicer API that takes a height.
//!
//! Design references: `docs/DESIGN.md` §8.

use std::collections::BTreeMap;

use codex_consensus::verifier::ProducerAuthority;
use codex_consensus::ChainTip;
use codex_core::block::BlockHeader;
use codex_core::hashes::{BlockHash, ChainId};
use codex_core::SignatureError;
use codex_state::{
    events::{verify_event_inclusion, EventInclusionProof},
    verify_existence, verify_non_existence, ExistenceProof, NonExistenceProof, ProofError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LightError {
    #[error("chain_id mismatch")]
    ChainIdMismatch,

    #[error("out-of-order header: expected height {expected}, got {got}")]
    OutOfOrder { expected: u64, got: u64 },

    #[error("prev_hash does not match known tip")]
    PrevHashMismatch,

    #[error("producer not authorized")]
    UnauthorizedProducer,

    #[error("producer signature invalid: {0}")]
    Signature(SignatureError),

    #[error("unknown height {0}: cannot verify proof without the matching header")]
    HeightNotTracked(u64),

    #[error("proof invalid: {0}")]
    Proof(#[from] ProofError),
}

/// A mobile-first light client. Stores only block headers.
pub struct LightClient {
    chain_id: ChainId,
    tip: ChainTip,
    authority: Box<dyn ProducerAuthority>,
    headers: BTreeMap<u64, BlockHeader>,
}

impl LightClient {
    pub fn new(chain_id: ChainId, authority: Box<dyn ProducerAuthority>) -> Self {
        Self {
            chain_id,
            tip: ChainTip::genesis(chain_id),
            authority,
            headers: BTreeMap::new(),
        }
    }

    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    pub fn header_at(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(&height)
    }

    /// Apply the next header and advance the tip.
    pub fn apply_header(&mut self, header: BlockHeader) -> Result<(), LightError> {
        let hdr = &header.payload;
        if hdr.chain_id != self.chain_id {
            return Err(LightError::ChainIdMismatch);
        }
        if hdr.height != self.tip.height + 1 {
            return Err(LightError::OutOfOrder {
                expected: self.tip.height + 1,
                got: hdr.height,
            });
        }
        if hdr.prev_hash != self.tip.tip_hash {
            return Err(LightError::PrevHashMismatch);
        }
        let vk = self
            .authority
            .verifying_key(&hdr.producer)
            .ok_or(LightError::UnauthorizedProducer)?;
        header.verify_producer(&vk).map_err(LightError::Signature)?;
        let new_hash = header.block_hash();
        self.tip.advance(hdr.height, new_hash);
        self.headers.insert(hdr.height, header);
        Ok(())
    }

    /// Convenience: apply a slice of headers in order.
    pub fn apply_headers(
        &mut self,
        headers: impl IntoIterator<Item = BlockHeader>,
    ) -> Result<(), LightError> {
        for h in headers {
            self.apply_header(h)?;
        }
        Ok(())
    }

    /// Verify an existence proof at the given block height using that
    /// block's `state_root`.
    pub fn verify_state_existence(
        &self,
        height: u64,
        proof: &ExistenceProof,
    ) -> Result<(), LightError> {
        let h = self
            .headers
            .get(&height)
            .ok_or(LightError::HeightNotTracked(height))?;
        verify_existence(proof, &h.payload.state_root)?;
        Ok(())
    }

    pub fn verify_state_non_existence(
        &self,
        height: u64,
        proof: &NonExistenceProof,
    ) -> Result<(), LightError> {
        let h = self
            .headers
            .get(&height)
            .ok_or(LightError::HeightNotTracked(height))?;
        verify_non_existence(proof, &h.payload.state_root)?;
        Ok(())
    }

    /// Verify an event-inclusion proof at `height` using that block's
    /// `events_root`.
    pub fn verify_event_inclusion_at(
        &self,
        height: u64,
        proof: &EventInclusionProof,
    ) -> Result<(), LightError> {
        let h = self
            .headers
            .get(&height)
            .ok_or(LightError::HeightNotTracked(height))?;
        verify_event_inclusion(proof, &h.payload.events_root)?;
        Ok(())
    }

    /// The block hash at `height`, if tracked.
    pub fn block_hash_at(&self, height: u64) -> Option<BlockHash> {
        self.headers.get(&height).map(|h| h.block_hash())
    }
}
