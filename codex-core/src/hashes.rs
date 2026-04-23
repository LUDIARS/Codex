//! 32-byte hash wrappers used across Codex.
//!
//! Separate newtypes keep the different kinds of hash from being
//! accidentally mixed:
//! - [`EventHash`] — hash of a fully-signed `Event` (§5.2)
//! - [`BlockHash`] — hash of a `BlockHeader` (§5.3)
//! - [`ChainId`] — chain identifier, either a domain-chain constant or a
//!   deterministic session chain id (§6.6.2)

use core::fmt;

use codex_crypto::{dom, tagged_hash, PeerId};
use serde::{Deserialize, Serialize};

/// Length in bytes of every Codex hash newtype.
pub const HASH_LEN: usize = 32;

macro_rules! hash_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub [u8; HASH_LEN]);

        impl $name {
            pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl From<[u8; HASH_LEN]> for $name {
            fn from(b: [u8; HASH_LEN]) -> Self {
                Self(b)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }
    };
}

hash_newtype!(EventHash, "Hash of a fully-signed Event (§5.2).");
hash_newtype!(BlockHash, "Hash of a BlockHeader (§5.3).");
hash_newtype!(
    ChainId,
    "Chain identifier. Either a domain-chain constant or a derived session chain id (§6.6.2)."
);

impl ChainId {
    /// Deterministic session-chain id: `blake3(dom::CHAIN_ID ‖ domain_id ‖
    /// start_ms ‖ producer)` per §6.6.2. Any participant can recompute.
    pub fn derive_session(domain_id: &ChainId, start_ms: u64, producer: &PeerId) -> Self {
        let mut buf = Vec::with_capacity(HASH_LEN + 8 + 20);
        buf.extend_from_slice(domain_id.as_bytes());
        buf.extend_from_slice(&start_ms.to_le_bytes());
        buf.extend_from_slice(producer.as_bytes());
        Self(tagged_hash(dom::CHAIN_ID, &buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    fn random_peer() -> PeerId {
        PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key())
    }

    #[test]
    fn distinct_newtypes_do_not_mix() {
        // Compile-time: different newtypes cannot be assigned to each other.
        // This test just documents the invariant.
        let e = EventHash([0u8; HASH_LEN]);
        let b = BlockHash([0u8; HASH_LEN]);
        assert_eq!(e.as_bytes(), b.as_bytes());
    }

    #[test]
    fn session_chain_id_is_deterministic() {
        let domain = ChainId([9u8; HASH_LEN]);
        let producer = random_peer();
        let a = ChainId::derive_session(&domain, 1_700_000_000_000, &producer);
        let b = ChainId::derive_session(&domain, 1_700_000_000_000, &producer);
        assert_eq!(a, b);
    }

    #[test]
    fn session_chain_id_diverges_on_different_input() {
        let domain = ChainId([9u8; HASH_LEN]);
        let producer_a = random_peer();
        let producer_b = random_peer();
        let a = ChainId::derive_session(&domain, 1_700_000_000_000, &producer_a);
        let b = ChainId::derive_session(&domain, 1_700_000_000_000, &producer_b);
        assert_ne!(a, b);

        let c = ChainId::derive_session(&domain, 1_700_000_000_000, &producer_a);
        let d = ChainId::derive_session(&domain, 1_700_000_000_001, &producer_a);
        assert_ne!(c, d);
    }

    #[test]
    fn hash_hex_round_trip_length() {
        let e = EventHash([0xabu8; HASH_LEN]);
        assert_eq!(e.to_hex().len(), HASH_LEN * 2);
    }

    #[test]
    fn hash_serde_round_trip() {
        let e = EventHash([0x55u8; HASH_LEN]);
        let bytes = postcard::to_allocvec(&e).unwrap();
        let parsed: EventHash = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(e, parsed);
    }
}
