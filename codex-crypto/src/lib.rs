//! Codex cryptographic primitives.
//!
//! Provides `PeerId`, the four domain-separation tags used across Codex
//! (`dom::*`), and re-exports of the underlying ed25519 / blake3 crates so
//! that every other Codex crate imports only through this boundary.
//!
//! # Design references
//! - `docs/DESIGN.md` §5.1 (PeerId definition)
//! - `docs/DESIGN.md` §5.4.2 (leaf / internal domain separation)
//! - `docs/DESIGN.md` §6.6.2 (chain id derivation via `dom::CHAIN_ID`)
//! - `docs/DESIGN.md` §11.1 (crate boundary: independent impl, not a
//!   Synergos facade in v0)

use core::fmt;

pub use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
pub use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

/// Codex domain-separation tags. Each is 16 bytes and prefixes the
/// corresponding hash/signature input so that a second-preimage against
/// one context cannot be replayed against another.
pub mod dom {
    /// Prefix for merkle-tree leaf hashing (§5.4.2).
    pub const LEAF: &[u8; 16] = b"LUDIARS-CDX-L001";
    /// Prefix for merkle-tree internal node hashing (§5.4.2).
    pub const INTERNAL: &[u8; 16] = b"LUDIARS-CDX-N001";
    /// Prefix for block header signing hash (§5.3 / §6).
    pub const BLOCK_SIG: &[u8; 16] = b"LUDIARS-CDX-B001";
    /// Prefix for event payload signing hash (§5.2).
    pub const EVENT_SIG: &[u8; 16] = b"LUDIARS-CDX-E001";
    /// Prefix for deterministic session chain id derivation (§6.6.2).
    pub const CHAIN_ID: &[u8; 16] = b"LUDIARS-CDX-C001";
    /// Prefix for state-root commitment `blake3(tag ‖ leaf_count_LE ‖ merkle_root)`.
    /// Binds the state tree's size into the root so that an adversary can't
    /// forge adjacency-based non-existence proofs.
    pub const STATE_ROOT: &[u8; 16] = b"LUDIARS-CDX-S001";
}

/// Length in bytes of a Codex `PeerId`.
///
/// 20 bytes (160 bits) matches Ethereum / Bitcoin address conventions and
/// is byte-for-byte compatible with Synergos's hex-string `PeerId` (which
/// encodes the same 20 bytes as 40 hex chars).
pub const PEER_ID_LEN: usize = 20;

/// 20-byte binary PeerId, derived as `blake3(ed25519_public_key)[..20]`.
///
/// This is the canonical identity used throughout Codex. Its byte-level
/// representation is identical to the 20-byte prefix that Synergos hex
/// encodes into its `PeerId(String)` — conversion is zero-loss.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub [u8; PEER_ID_LEN]);

impl PeerId {
    /// Derive a `PeerId` from a 32-byte ed25519 public key.
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let mut out = [0u8; PEER_ID_LEN];
        out.copy_from_slice(&hash.as_bytes()[..PEER_ID_LEN]);
        Self(out)
    }

    /// Derive a `PeerId` from an `ed25519_dalek::VerifyingKey`.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Self::from_public_key(vk.as_bytes())
    }

    /// Hex representation (40 lowercase chars). Compatible with Synergos
    /// `PeerId(String)`.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a lowercase hex string of exactly 40 chars back into a PeerId.
    pub fn from_hex(s: &str) -> Result<Self, PeerIdError> {
        let bytes = hex::decode(s).map_err(PeerIdError::InvalidHex)?;
        if bytes.len() != PEER_ID_LEN {
            return Err(PeerIdError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; PEER_ID_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Borrow the raw 20 bytes.
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_hex())
    }
}

impl From<[u8; PEER_ID_LEN]> for PeerId {
    fn from(bytes: [u8; PEER_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let arr = <[u8; PEER_ID_LEN] as serde::Deserialize>::deserialize(d)?;
        Ok(Self(arr))
    }
}

/// Errors that can occur while parsing a `PeerId`.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerIdError {
    InvalidHex(hex::FromHexError),
    InvalidLength(usize),
}

impl fmt::Display for PeerIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(e) => write!(f, "invalid hex: {}", e),
            Self::InvalidLength(n) => {
                write!(f, "expected {PEER_ID_LEN} bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for PeerIdError {}

/// Wall-clock hash helper: `blake3(tag ‖ data)` returning the raw 32-byte
/// digest. Used for signing-hash construction outside of the merkle tree.
pub fn tagged_hash(tag: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(tag);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn peer_id_is_deterministic_from_pubkey() {
        let signing = SigningKey::generate(&mut OsRng);
        let vk = signing.verifying_key();
        let a = PeerId::from_verifying_key(&vk);
        let b = PeerId::from_public_key(vk.as_bytes());
        assert_eq!(a, b);
    }

    #[test]
    fn peer_id_differs_for_different_keys() {
        let a = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());
        let b = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());
        assert_ne!(a, b);
    }

    #[test]
    fn peer_id_hex_round_trip() {
        let id = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());
        let h = id.to_hex();
        assert_eq!(h.len(), PEER_ID_LEN * 2);
        let parsed = PeerId::from_hex(&h).expect("round-trip");
        assert_eq!(id, parsed);
    }

    #[test]
    fn peer_id_from_hex_rejects_wrong_length() {
        assert!(matches!(
            PeerId::from_hex("deadbeef"),
            Err(PeerIdError::InvalidLength(_))
        ));
    }

    #[test]
    fn peer_id_from_hex_rejects_garbage() {
        assert!(matches!(
            PeerId::from_hex("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Err(PeerIdError::InvalidHex(_))
        ));
    }

    #[test]
    fn domain_separation_tags_are_distinct() {
        let tags = [
            dom::LEAF,
            dom::INTERNAL,
            dom::BLOCK_SIG,
            dom::EVENT_SIG,
            dom::CHAIN_ID,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "domain tags must be distinct");
            }
        }
    }

    #[test]
    fn domain_tags_are_16_bytes() {
        for tag in [
            dom::LEAF,
            dom::INTERNAL,
            dom::BLOCK_SIG,
            dom::EVENT_SIG,
            dom::CHAIN_ID,
        ] {
            assert_eq!(tag.len(), 16);
        }
    }

    #[test]
    fn tagged_hash_is_deterministic() {
        let data = b"hello world";
        let h1 = tagged_hash(dom::LEAF, data);
        let h2 = tagged_hash(dom::LEAF, data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn tagged_hash_distinguishes_tags() {
        let data = b"hello";
        let h_leaf = tagged_hash(dom::LEAF, data);
        let h_node = tagged_hash(dom::INTERNAL, data);
        assert_ne!(h_leaf, h_node);
    }

    #[test]
    fn peer_id_serde_round_trip() {
        let id = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());
        let bytes = postcard::to_allocvec(&id).expect("serialize");
        let parsed: PeerId = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(id, parsed);
    }
}
