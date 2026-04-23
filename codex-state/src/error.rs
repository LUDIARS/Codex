//! codex-state error types.

use thiserror::Error;

use codex_core::namespace::Namespace;
use codex_core::SignatureError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofError {
    #[error("merkle root mismatch: proof did not fold to the expected root")]
    RootMismatch,
    #[error("key ordering violation: neighbor key is not strictly on the expected side")]
    InvalidOrdering,
    #[error("non-existence proof shape is invalid for the given state root")]
    InvalidNonExistence,
    #[error("empty proof supplied where one was required")]
    EmptyProof,
}

/// Errors an event can fail validation with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
    #[error("event nonce {nonce} already seen for (claimant, namespace)")]
    DuplicateNonce { nonce: u64 },
    #[error("unknown namespace: {0}")]
    UnknownNamespace(Namespace),
    #[error("namespace handler rejected the event: {reason}")]
    HandlerReject { reason: String },
    #[error("namespace body failed to decode: {reason}")]
    BodyDecode { reason: String },
}

/// Errors that arise when applying a validated event to the state tree.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApplyError {
    #[error("handler apply failed: {reason}")]
    HandlerFailure { reason: String },
}

/// Errors returned from `Stf::apply_block`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StfError {
    #[error("event {index} validation failed: {source}")]
    Validation {
        index: usize,
        #[source]
        source: ValidationError,
    },
    #[error("event {index} apply failed: {source}")]
    Apply {
        index: usize,
        #[source]
        source: ApplyError,
    },
    #[error("block's events_root does not match computed merkle root")]
    EventsRootMismatch,
    #[error("block's state_root does not match computed merkle root")]
    StateRootMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("key not found")]
    NotFound,
}
