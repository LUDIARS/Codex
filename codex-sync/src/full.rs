//! Full sync and header sync.
//!
//! Full sync pulls every block in the gap between the local node's
//! tip and the peer's tip, ingesting each. The node's verifier
//! enforces continuity and correctness; the sync loop only coordinates
//! the pull.
//!
//! Header sync is the light-client analog: it produces a
//! `Vec<BlockHeader>` the caller can feed into a
//! `codex_light::LightClient`.

use codex_core::block::BlockHeader;
use codex_crypto::{PeerId, VerifyingKey};
use codex_node::SessionNode;

use crate::error::SyncError;
use crate::transport::SyncTransport;

/// Pull every block in the range `(local_tip..=peer_tip)` and ingest
/// it into `local_node`. Returns the number of blocks applied.
pub fn full_sync<T, F>(
    local_node: &mut SessionNode,
    transport: &T,
    resolve: &mut F,
) -> Result<u64, SyncError>
where
    T: SyncTransport,
    F: FnMut(&PeerId) -> Option<VerifyingKey>,
{
    let local_height = local_node.tip().height;
    let peer_tip = transport.peer_tip();
    if peer_tip.height <= local_height {
        return Ok(0);
    }
    let mut applied = 0;
    for h in (local_height + 1)..=peer_tip.height {
        let block = transport.fetch_block(h).ok_or(SyncError::MissingBlock(h))?;
        local_node.ingest_block(block, resolve)?;
        applied += 1;
    }
    Ok(applied)
}

/// Pull headers for `(from..=to)` inclusive. The caller is expected to
/// verify each header against the appropriate authority and extend a
/// light-client chain.
pub fn header_sync<T>(transport: &T, from: u64, to: u64) -> Result<Vec<BlockHeader>, SyncError>
where
    T: SyncTransport,
{
    if to < from {
        return Ok(Vec::new());
    }
    let mut headers = Vec::with_capacity((to - from + 1) as usize);
    for h in from..=to {
        let header = transport
            .fetch_header(h)
            .ok_or(SyncError::MissingBlock(h))?;
        headers.push(header);
    }
    Ok(headers)
}
