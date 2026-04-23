//! `u32_le length ‖ bytes` framing over any `Read`/`Write` pair.

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use crate::error::NetError;

/// Hard ceiling on a single framed message. 8 MiB is enough for a
/// state snapshot with tens of thousands of entries while keeping an
/// adversary from allocating unbounded memory.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Postcard-encode `msg` and write it as `u32_le len ‖ bytes` to
/// `writer`. Flush is the caller's responsibility.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), NetError> {
    let body = postcard::to_allocvec(msg).map_err(|e| NetError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge(body.len(), MAX_FRAME_BYTES));
    }
    let len = body.len() as u32;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|e| NetError::Io(e.to_string()))?;
    writer
        .write_all(&body)
        .map_err(|e| NetError::Io(e.to_string()))?;
    Ok(())
}

/// Read a single framed message from `reader`.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, NetError> {
    let mut lb = [0u8; 4];
    reader
        .read_exact(&mut lb)
        .map_err(|e| NetError::Io(e.to_string()))?;
    let len = u32::from_le_bytes(lb) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge(len, MAX_FRAME_BYTES));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| NetError::Io(e.to_string()))?;
    postcard::from_bytes(&buf).map_err(|e| NetError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    struct Ping {
        nonce: u64,
    }

    #[test]
    fn round_trip_over_inmemory_bytes() {
        let msg = Ping { nonce: 42 };
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        let mut reader: &[u8] = buf.as_slice();
        let got: Ping = read_frame(&mut reader).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn oversize_rejected() {
        // Synthesize a len field that claims > MAX_FRAME_BYTES.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_BYTES as u32 + 1).to_le_bytes()));
        let mut reader: &[u8] = buf.as_slice();
        let err = read_frame::<_, Ping>(&mut reader).unwrap_err();
        assert!(matches!(err, NetError::FrameTooLarge(_, _)));
    }

    #[test]
    fn incomplete_frame_returns_io_error() {
        // Only 3 bytes of a 4-byte length header.
        let buf: Vec<u8> = vec![1, 2, 3];
        let mut reader: &[u8] = buf.as_slice();
        let err = read_frame::<_, Ping>(&mut reader).unwrap_err();
        assert!(matches!(err, NetError::Io(_)));
    }
}
