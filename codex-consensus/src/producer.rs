//! Session-mode producer.
//!
//! Owns the signing key, the chain tip, and the per-chain parameters.
//! Given a mempool and an STF bundle, `produce` drains events, computes
//! `events_root` + `state_root` via [`Stf::dry_run_block`], builds and
//! signs the block header, then commits via [`Stf::apply_block`].

use codex_core::block::{Block, BlockHeaderPayload};
use codex_core::hashes::{BlockHash, ChainId};
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_state::{StateTree, Stf};

use crate::chain::ChainTip;
use crate::error::ConsensusError;
use crate::mempool::Mempool;

/// Maximum events a producer will pack into a single block.
pub const DEFAULT_MAX_EVENTS_PER_BLOCK: usize = 10_000;

/// Session-mode producer (§6.1).
pub struct SessionProducer {
    producer: PeerId,
    producer_sk: SigningKey,
    tip: ChainTip,
    version: u8,
    max_events_per_block: usize,
}

impl SessionProducer {
    pub fn new(producer: PeerId, producer_sk: SigningKey, chain_id: ChainId) -> Self {
        Self {
            producer,
            producer_sk,
            tip: ChainTip::genesis(chain_id),
            version: 1,
            max_events_per_block: DEFAULT_MAX_EVENTS_PER_BLOCK,
        }
    }

    pub fn with_max_events(mut self, n: usize) -> Self {
        self.max_events_per_block = n;
        self
    }

    pub fn tip(&self) -> &ChainTip {
        &self.tip
    }

    /// Allows a higher layer (e.g. `SessionNode`) to reset the tip
    /// when it has independently advanced via `ingest_block`. Use
    /// only in that controlled context.
    pub fn tip_mut(&mut self) -> &mut ChainTip {
        &mut self.tip
    }

    pub fn producer_id(&self) -> PeerId {
        self.producer
    }

    /// Drain events from the mempool and produce a signed block. If
    /// `allow_empty` is false and the mempool is empty, returns
    /// `Ok(None)`. The caller is expected to supply an accurate
    /// `timestamp_ms` (typically wall-clock unix ms).
    pub fn produce<F>(
        &mut self,
        mempool: &mut dyn Mempool,
        stf: &mut Stf,
        state: &mut StateTree,
        timestamp_ms: u64,
        resolve: &mut F,
        allow_empty: bool,
    ) -> Result<Option<Block>, ConsensusError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        if mempool.is_empty() && !allow_empty {
            return Ok(None);
        }

        let events = mempool.drain_up_to(self.max_events_per_block);

        // 1. Dry-run to learn the roots.
        let applied = stf
            .dry_run_block(&events, state, resolve)
            .map_err(ConsensusError::Stf)?;

        // 2. Build and sign the header with known roots.
        let height = self.tip.height + 1;
        let payload = BlockHeaderPayload {
            version: self.version,
            chain_id: self.tip.chain_id,
            height,
            prev_hash: self.tip.tip_hash,
            events_root: applied.events_root,
            state_root: applied.state_root,
            timestamp: timestamp_ms,
            producer: self.producer,
        };
        let header = payload.sign(&self.producer_sk);

        let block = Block { header, events };

        // 3. Commit by applying. Should never fail (dry-run succeeded,
        // same events + same state), but propagate any error just in case.
        stf.apply_block(&block, state, resolve)
            .map_err(ConsensusError::Stf)?;

        // 4. Advance the tip.
        let block_hash = block.header.block_hash();
        self.tip.advance(height, block_hash);

        Ok(Some(block))
    }

    /// Look up a block's hash by height (only works for the current tip
    /// until we add persistent chain storage). Useful in tests.
    pub fn tip_hash(&self) -> BlockHash {
        self.tip.tip_hash
    }
}
