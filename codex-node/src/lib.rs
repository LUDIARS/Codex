//! Single-process Codex node.
//!
//! Wires together: a mempool, a producer (session or committee), a
//! verifier, an in-memory block store, a state replica, and the STF.
//! Exposes a narrow API that higher layers (RPC / sync / FFI in later
//! milestones) call to push events in and broadcast blocks out.
//!
//! Design references: `docs/DESIGN.md` §9.1 (full node API), §7.1
//! (mempool gossip), §6 consensus.

pub mod block_store;
pub mod error;
pub mod node;

pub use block_store::{BlockStore, InMemoryBlockStore};
pub use error::NodeError;
pub use node::{ProducerRole, SessionNode};
