use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("peer reports a lower tip height ({peer}) than local ({local}); nothing to sync")]
    PeerBehind { peer: u64, local: u64 },

    #[error("peer is missing block at height {0}")]
    MissingBlock(u64),

    #[error("node error during sync apply: {0}")]
    Node(#[from] codex_node::NodeError),
}
