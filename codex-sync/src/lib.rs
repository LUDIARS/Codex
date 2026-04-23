//! Sync protocols.
//!
//! v0 implements:
//! - **Full sync**: request blocks `[local_tip+1 ..= peer_tip]` in
//!   order; each arriving block is verified and applied via the
//!   consumer's `SessionNode` or equivalent.
//! - **Header sync**: same but headers only — consumed by light
//!   clients.
//!
//! Fast sync (checkpoint + state snapshot) and delta checkpoint are
//! design-doc items §7.3 reserved for v1; the trait shape accepts them
//! by adding methods without breaking the full/light paths.

pub mod error;
pub mod full;
pub mod snapshot;
pub mod transport;

pub use error::SyncError;
pub use full::{full_sync, header_sync};
pub use snapshot::StateSnapshot;
pub use transport::{InMemoryTransport, SyncTransport};
