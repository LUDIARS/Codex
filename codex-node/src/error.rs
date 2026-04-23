use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("consensus: {0}")]
    Consensus(#[from] codex_consensus::ConsensusError),

    #[error("state transition: {0}")]
    Stf(#[from] codex_state::StfError),

    #[error("validation: {0}")]
    Validation(#[from] codex_state::ValidationError),

    #[error("block store: block at height {0} not found")]
    BlockNotFound(u64),
}
