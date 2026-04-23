//! Crate-wide error types.

use thiserror::Error;

use crate::namespace::NamespaceError;

/// Errors that can arise from core type construction, serialization, or
/// validation before an event reaches the STF.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("namespace error: {0}")]
    Namespace(#[from] NamespaceError),

    #[error("postcard serialization error: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("signature error: {0}")]
    Signature(#[from] SignatureError),
}

/// Narrow error type for signature-side failures so that callers can
/// distinguish "bad signature" from "bad encoding".
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignatureError {
    #[error("signature verification failed")]
    Invalid,

    #[error("signing key did not produce a valid signature: {0}")]
    Sign(String),
}
