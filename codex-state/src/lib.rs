//! Codex state layer.
//!
//! Ties together the sorted-key binary merkle tree, proof types, state
//! mutation API, namespace handler registry, and the state transition
//! function (STF).
//!
//! # Module layout
//! - [`merkle`]  — primitive hashing (`leaf_hash`, `node_hash`,
//!   `compute_root`, `compute_siblings`) that is reused by both state
//!   roots and event roots
//! - [`proof`]   — `ExistenceProof` and `NonExistenceProof` with verify
//!   functions suitable for light clients
//! - [`state`]   — `StateTree` keyed by `(Namespace, key_hash)` with
//!   `root()`, `existence_proof`, `non_existence_proof`
//! - [`nonce`]   — per-(claimant, namespace) uniqueness tracker
//! - [`handler`] — `NamespaceHandler` trait + `HandlerRegistry`
//! - [`events`]  — ordered event merkle root + inclusion proof
//! - [`stf`]     — `Stf` wraps registry + nonce tracker and applies
//!   blocks, returning the new state root
//! - [`error`]   — crate error types
//!
//! Design references: `docs/DESIGN.md` §5.4 (merkle), §5.5 (STF),
//! §5.6 (namespace registration), §5.2.2 (nonce), §5.8 (ordering).

pub mod error;
pub mod events;
pub mod handler;
pub mod merkle;
pub mod nonce;
pub mod proof;
pub mod state;
pub mod stf;

pub use error::{ApplyError, ProofError, StateError, StfError, ValidationError};
pub use events::{compute_events_root, EventInclusionProof};
pub use handler::{HandlerRegistry, NamespaceHandler};
pub use merkle::{
    compute_root, compute_siblings, leaf_hash, node_hash, Direction, EMPTY_ROOT, HASH_LEN,
};
pub use nonce::NonceTracker;
pub use proof::{verify_existence, verify_non_existence, ExistenceProof, NonExistenceProof};
pub use state::StateTree;
pub use stf::{AppliedBlock, Stf};
