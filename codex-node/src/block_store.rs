//! Block persistence abstraction.
//!
//! In v0 a full node keeps every accepted block in memory. Eviction to
//! warm / cold tiers per §5.7 is the next step; the `BlockStore` trait
//! is the seam that swap-in.

use std::collections::BTreeMap;

use codex_core::block::Block;
use codex_core::hashes::BlockHash;

pub trait BlockStore: Send {
    fn put(&mut self, block: Block);
    fn get_by_height(&self, height: u64) -> Option<&Block>;
    fn get_by_hash(&self, hash: &BlockHash) -> Option<&Block>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Inclusive range: `[from, to]`. Caller ensures `from <= to`.
    fn range(&self, from: u64, to: u64) -> Vec<&Block>;
}

#[derive(Default)]
pub struct InMemoryBlockStore {
    by_height: BTreeMap<u64, Block>,
    by_hash: std::collections::HashMap<BlockHash, u64>,
}

impl InMemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockStore for InMemoryBlockStore {
    fn put(&mut self, block: Block) {
        let h = block.header.payload.height;
        let hash = block.header.block_hash();
        self.by_hash.insert(hash, h);
        self.by_height.insert(h, block);
    }

    fn get_by_height(&self, height: u64) -> Option<&Block> {
        self.by_height.get(&height)
    }

    fn get_by_hash(&self, hash: &BlockHash) -> Option<&Block> {
        let h = self.by_hash.get(hash)?;
        self.by_height.get(h)
    }

    fn len(&self) -> usize {
        self.by_height.len()
    }

    fn range(&self, from: u64, to: u64) -> Vec<&Block> {
        self.by_height.range(from..=to).map(|(_, b)| b).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::block::BlockHeaderPayload;
    use codex_core::hashes::{BlockHash, ChainId};
    use codex_crypto::{PeerId, SigningKey};
    use rand_core::OsRng;

    fn fake_block(height: u64) -> Block {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let header = BlockHeaderPayload {
            version: 1,
            chain_id: ChainId([1u8; 32]),
            height,
            prev_hash: BlockHash([0u8; 32]),
            events_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: height,
            producer: peer,
        }
        .sign(&sk);
        Block {
            header,
            events: vec![],
        }
    }

    #[test]
    fn put_and_get() {
        let mut s = InMemoryBlockStore::new();
        let b = fake_block(1);
        let hash = b.header.block_hash();
        s.put(b);
        assert!(s.get_by_height(1).is_some());
        assert!(s.get_by_hash(&hash).is_some());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn range_is_inclusive() {
        let mut s = InMemoryBlockStore::new();
        for i in 1..=5u64 {
            s.put(fake_block(i));
        }
        let r = s.range(2, 4);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].header.payload.height, 2);
        assert_eq!(r[2].header.payload.height, 4);
    }
}
