//! ChainTip — the current head of a chain, shared state between the
//! producer and verifier paths.

use codex_core::hashes::{BlockHash, ChainId};

/// Current head of a chain.
///
/// At genesis (`height == 0`), `tip_hash` is the all-zero `BlockHash`;
/// height-1 blocks reference that value as `prev_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub chain_id: ChainId,
    pub height: u64,
    pub tip_hash: BlockHash,
}

impl ChainTip {
    /// Fresh tip at genesis.
    pub fn genesis(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            height: 0,
            tip_hash: BlockHash([0u8; 32]),
        }
    }

    /// Advance to the newly accepted block. Caller must have already
    /// verified continuity (`height == self.height + 1`, `prev_hash ==
    /// self.tip_hash`); this is a blind setter.
    pub fn advance(&mut self, new_height: u64, new_hash: BlockHash) {
        self.height = new_height;
        self.tip_hash = new_hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_tip_is_zero_hash_height_zero() {
        let tip = ChainTip::genesis(ChainId([7u8; 32]));
        assert_eq!(tip.height, 0);
        assert_eq!(tip.tip_hash, BlockHash([0u8; 32]));
    }

    #[test]
    fn advance_updates_fields() {
        let mut tip = ChainTip::genesis(ChainId([7u8; 32]));
        tip.advance(1, BlockHash([0xabu8; 32]));
        assert_eq!(tip.height, 1);
        assert_eq!(tip.tip_hash, BlockHash([0xabu8; 32]));
    }
}
