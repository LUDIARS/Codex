//! Consensus layer.
//!
//! - [`session`] mode: a single authorized producer signs every block.
//!   One-block finality. Suits `Tessera` game sessions (producer =
//!   server or arbiter).
//! - [`committee`] mode (landed in M6): a federated validator set with
//!   2/3 attestations, announced set changes, and equivocation-driven
//!   slashing.
//! - [`mempool`]: minimal FIFO mempool interface + in-memory impl,
//!   FCFS per §5.8.
//! - [`chain`]: `ChainTip` data structure shared between producer and
//!   verifier.
//!
//! Design references: `docs/DESIGN.md` §6.1 session mode, §6.2 committee,
//! §6.6 checkpoints, §6.7 validator changes, §5.8 ordering.

pub mod chain;
pub mod committee;
pub mod error;
pub mod mempool;
pub mod producer;
pub mod verifier;

pub use chain::ChainTip;
pub use committee::{
    CommitteeProducer, CommitteeRules, CommitteeVerifier, EquivocationProof, ValidatorSet,
};
pub use error::ConsensusError;
pub use mempool::{InMemoryMempool, Mempool};
pub use producer::SessionProducer;
pub use verifier::BlockVerifier;
