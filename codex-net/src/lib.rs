//! Codex network wire protocol.
//!
//! Defines the request / response messages that a sync client sends
//! to a sync server. The messages are postcard-encoded framed by a
//! `u32_le` length prefix — a format that works identically on top of
//! QUIC bidirectional streams, TCP, or tokio duplex channels. v1 uses
//! `synergos-net`'s QUIC transport as the production backend; tests
//! exercise the protocol over an in-memory channel.
//!
//! Design references: `docs/DESIGN.md` §7.1 (event gossip), §7.3 (sync
//! protocols), §11 (`codex-net` crate).

pub mod error;
pub mod frame;
pub mod wire;

pub use error::NetError;
pub use frame::{read_frame, write_frame, MAX_FRAME_BYTES};
pub use wire::{Request, Response};
