//! Shared serde helpers.
//!
//! `serde_bytes_array_64` encodes a `[u8; 64]` (used for ed25519
//! signatures) as a single byte blob rather than 64 separate entries.
//! This keeps postcard output compact: 1 length varint + 64 bytes.

pub mod serde_bytes_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        use serde::de::Error;
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        if bytes.len() != 64 {
            return Err(D::Error::custom(format!(
                "expected 64-byte signature, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
