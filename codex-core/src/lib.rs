//! Codex core types.
//!
//! Event / Block / BlockHeader / Namespace / hash types and their canonical
//! (postcard) serialization. All signatures flow through `codex-crypto`.
//!
//! # Module layout
//! - [`namespace`] — `Namespace` with ASCII + dot-separator validation
//! - [`hashes`]    — 32-byte wrappers: `EventHash`, `BlockHash`, `ChainId`
//! - [`event`]     — `EventPayload` (signing preimage) and `Event` (+sig)
//! - [`block`]     — `BlockHeaderPayload`, `BlockHeader`, `Attestation`, `Block`
//! - [`error`]     — crate-wide error types
//!
//! Design references: `docs/DESIGN.md` §5.1–§5.3, §6.6.2.

pub mod block;
pub mod error;
pub mod event;
pub mod hashes;
pub mod namespace;
pub mod serde_helpers;

pub use block::{Attestation, Block, BlockHeader, BlockHeaderPayload};
pub use error::{CoreError, SignatureError};
pub use event::{Event, EventPayload};
pub use hashes::{BlockHash, ChainId, EventHash};
pub use namespace::{Namespace, NamespaceError};

/// Re-export codex-crypto so consumers have a single import path.
pub use codex_crypto;
