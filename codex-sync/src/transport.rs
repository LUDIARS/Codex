//! Sync transport abstraction.
//!
//! Real deployments will plug in an RPC / QUIC backend; tests use
//! `InMemoryTransport` wrapping a reference to another node's block
//! store.

use codex_core::block::{Block, BlockHeader};

use codex_consensus::ChainTip;
use codex_node::BlockStore;

/// Strategy trait a sync caller uses to ask "peer, give me block at
/// height H". Implementations are expected to be blocking / synchronous
/// for v0; async is future work.
pub trait SyncTransport {
    /// Peer's current chain tip.
    fn peer_tip(&self) -> ChainTip;

    /// Fetch the full block at `height` (body + header).
    fn fetch_block(&self, height: u64) -> Option<Block>;

    /// Fetch only the header at `height`. Cheaper; used by light sync.
    fn fetch_header(&self, height: u64) -> Option<BlockHeader>;
}

/// Test transport: direct reference to another node's block store.
/// Wraps a `&dyn BlockStore` + a cached tip. Pass-through semantics.
pub struct InMemoryTransport<'a> {
    store: &'a dyn BlockStore,
    tip: ChainTip,
}

impl<'a> InMemoryTransport<'a> {
    pub fn new(store: &'a dyn BlockStore, tip: ChainTip) -> Self {
        Self { store, tip }
    }
}

impl SyncTransport for InMemoryTransport<'_> {
    fn peer_tip(&self) -> ChainTip {
        self.tip.clone()
    }

    fn fetch_block(&self, height: u64) -> Option<Block> {
        self.store.get_by_height(height).cloned()
    }

    fn fetch_header(&self, height: u64) -> Option<BlockHeader> {
        self.store.get_by_height(height).map(|b| b.header.clone())
    }
}
