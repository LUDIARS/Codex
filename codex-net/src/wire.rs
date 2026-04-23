//! Request / response messages exchanged between sync peers.
//!
//! The wire protocol is intentionally minimal:
//! - `FetchTip` → `Tip` (peer's current chain tip)
//! - `FetchBlock { height }` → `Block { block }` or `NotFound`
//! - `FetchHeader { height }` → `Header { header }` or `NotFound`
//! - `FetchSnapshot { height }` → `Snapshot { snapshot }` or `NotFound`
//!   (fast sync)
//! - `SubmitEvent { event }` → `Ack` or `Rejected { reason }`
//!   (client-to-producer forwarding)
//!
//! Every message is `postcard`-encoded and framed per `frame.rs`.

use codex_consensus::ChainTip;
use codex_core::block::{Block, BlockHeader};
use codex_core::event::Event;
use codex_sync::StateSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    FetchTip,
    FetchBlock { height: u64 },
    FetchHeader { height: u64 },
    FetchSnapshot { height: u64 },
    SubmitEvent { event: Box<Event> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Tip { tip: ChainTip },
    Block { block: Box<Block> },
    Header { header: Box<BlockHeader> },
    Snapshot { snapshot: Box<StateSnapshot> },
    Ack,
    Rejected { reason: String },
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        for req in [
            Request::FetchTip,
            Request::FetchBlock { height: 42 },
            Request::FetchHeader { height: 1 },
            Request::FetchSnapshot { height: 1000 },
        ] {
            let bytes = postcard::to_allocvec(&req).unwrap();
            let parsed: Request = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(parsed, req);
        }
    }

    #[test]
    fn response_not_found_round_trip() {
        let resp = Response::NotFound;
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let parsed: Response = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_rejected_round_trip() {
        let resp = Response::Rejected {
            reason: "duplicate nonce".into(),
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let parsed: Response = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, resp);
    }
}
