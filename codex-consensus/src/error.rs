use thiserror::Error;

use codex_state::StfError;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("chain_id mismatch: block {block:?} vs chain {chain:?}")]
    ChainIdMismatch {
        block: codex_core::hashes::ChainId,
        chain: codex_core::hashes::ChainId,
    },

    #[error("height out of order: expected {expected}, got {got}")]
    HeightOutOfOrder { expected: u64, got: u64 },

    #[error("prev_hash does not match current tip")]
    PrevHashMismatch,

    #[error("producer PeerId not authorized: {got:?}")]
    UnauthorizedProducer { got: codex_crypto::PeerId },

    #[error("producer signature invalid: {0}")]
    ProducerSignature(codex_core::SignatureError),

    #[error("state transition failure: {0}")]
    Stf(#[from] StfError),

    #[error("committee rule violation: {0}")]
    Committee(String),
}
