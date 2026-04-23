//! C ABI surface for Codex.
//!
//! Exposes the minimal operations a mobile SDK needs:
//! - derive a `PeerId` from an ed25519 public key
//! - verify an ed25519 signature against a Codex event-signing hash
//! - verify an `ExistenceProof` / `NonExistenceProof` / `EventInclusionProof`
//!   (all postcard-encoded on the boundary)
//!
//! All functions are `extern "C"` and take `*const u8 + length` pairs
//! for variable-length inputs. They return an `i32` status code
//! (`0` = success, non-zero = failure class). No allocation crosses
//! the ABI: callers supply output buffers, or receive fixed-size
//! results via out-pointers.
//!
//! Naming convention: `codex_<area>_<verb>`.

#![allow(clippy::missing_safety_doc)]

use codex_core::event::Event;
use codex_crypto::{PeerId, Signature, Verifier, VerifyingKey};
use codex_state::{
    events::{verify_event_inclusion, EventInclusionProof},
    verify_existence, verify_non_existence, ExistenceProof, NonExistenceProof,
};

/// Status codes returned by every `extern "C"` function.
#[repr(i32)]
pub enum Status {
    Ok = 0,
    InvalidArg = -1,
    VerifyFailed = -2,
    DecodeFailed = -3,
    ProofFailed = -4,
}

impl Status {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Derive a 20-byte `PeerId` from a 32-byte ed25519 public key.
///
/// # Safety
/// - `pubkey_ptr` must point to at least 32 readable bytes.
/// - `out_peer_id_ptr` must point to a writable 20-byte buffer.
///
/// Returns 0 on success; `-1` if any pointer is null.
#[no_mangle]
pub unsafe extern "C" fn codex_peer_id_from_pubkey(
    pubkey_ptr: *const u8,
    out_peer_id_ptr: *mut u8,
) -> i32 {
    if pubkey_ptr.is_null() || out_peer_id_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let pubkey = core::slice::from_raw_parts(pubkey_ptr, 32);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pubkey);
    let peer = PeerId::from_public_key(&pk);
    let out = core::slice::from_raw_parts_mut(out_peer_id_ptr, 20);
    out.copy_from_slice(peer.as_bytes());
    Status::Ok.as_i32()
}

/// Verify an Event's signature against a 32-byte ed25519 public key.
/// `event_bytes` must be the postcard-encoded `Event`.
///
/// # Safety
/// - `event_ptr` must point to `event_len` readable bytes.
/// - `pubkey_ptr` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn codex_event_verify(
    event_ptr: *const u8,
    event_len: usize,
    pubkey_ptr: *const u8,
) -> i32 {
    if event_ptr.is_null() || pubkey_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let event_bytes = core::slice::from_raw_parts(event_ptr, event_len);
    let event: Event = match postcard::from_bytes(event_bytes) {
        Ok(e) => e,
        Err(_) => return Status::DecodeFailed.as_i32(),
    };
    let pk_bytes = core::slice::from_raw_parts(pubkey_ptr, 32);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pk_bytes);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Status::InvalidArg.as_i32(),
    };
    match event.verify_with_key(&vk) {
        Ok(()) => Status::Ok.as_i32(),
        Err(_) => Status::VerifyFailed.as_i32(),
    }
}

/// Verify a raw ed25519 signature over an arbitrary message.
#[no_mangle]
pub unsafe extern "C" fn codex_ed25519_verify(
    pubkey_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> i32 {
    if pubkey_ptr.is_null() || msg_ptr.is_null() || sig_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let pk_bytes = core::slice::from_raw_parts(pubkey_ptr, 32);
    let sig_bytes = core::slice::from_raw_parts(sig_ptr, 64);
    let msg = core::slice::from_raw_parts(msg_ptr, msg_len);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pk_bytes);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_bytes);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Status::InvalidArg.as_i32(),
    };
    let sig = Signature::from_bytes(&sig);
    match vk.verify(msg, &sig) {
        Ok(()) => Status::Ok.as_i32(),
        Err(_) => Status::VerifyFailed.as_i32(),
    }
}

/// Verify an `ExistenceProof` (postcard-encoded) against a 32-byte
/// state root.
#[no_mangle]
pub unsafe extern "C" fn codex_state_verify_existence(
    proof_ptr: *const u8,
    proof_len: usize,
    state_root_ptr: *const u8,
) -> i32 {
    if proof_ptr.is_null() || state_root_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let proof_bytes = core::slice::from_raw_parts(proof_ptr, proof_len);
    let proof: ExistenceProof = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return Status::DecodeFailed.as_i32(),
    };
    let root_bytes = core::slice::from_raw_parts(state_root_ptr, 32);
    let mut root = [0u8; 32];
    root.copy_from_slice(root_bytes);
    match verify_existence(&proof, &root) {
        Ok(()) => Status::Ok.as_i32(),
        Err(_) => Status::ProofFailed.as_i32(),
    }
}

/// Verify a `NonExistenceProof` (postcard-encoded) against a 32-byte
/// state root.
#[no_mangle]
pub unsafe extern "C" fn codex_state_verify_non_existence(
    proof_ptr: *const u8,
    proof_len: usize,
    state_root_ptr: *const u8,
) -> i32 {
    if proof_ptr.is_null() || state_root_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let proof_bytes = core::slice::from_raw_parts(proof_ptr, proof_len);
    let proof: NonExistenceProof = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return Status::DecodeFailed.as_i32(),
    };
    let root_bytes = core::slice::from_raw_parts(state_root_ptr, 32);
    let mut root = [0u8; 32];
    root.copy_from_slice(root_bytes);
    match verify_non_existence(&proof, &root) {
        Ok(()) => Status::Ok.as_i32(),
        Err(_) => Status::ProofFailed.as_i32(),
    }
}

/// Verify an `EventInclusionProof` (postcard-encoded) against a 32-byte
/// events root.
#[no_mangle]
pub unsafe extern "C" fn codex_events_verify_inclusion(
    proof_ptr: *const u8,
    proof_len: usize,
    events_root_ptr: *const u8,
) -> i32 {
    if proof_ptr.is_null() || events_root_ptr.is_null() {
        return Status::InvalidArg.as_i32();
    }
    let proof_bytes = core::slice::from_raw_parts(proof_ptr, proof_len);
    let proof: EventInclusionProof = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return Status::DecodeFailed.as_i32(),
    };
    let root_bytes = core::slice::from_raw_parts(events_root_ptr, 32);
    let mut root = [0u8; 32];
    root.copy_from_slice(root_bytes);
    match verify_event_inclusion(&proof, &root) {
        Ok(()) => Status::Ok.as_i32(),
        Err(_) => Status::ProofFailed.as_i32(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::event::EventPayload;
    use codex_core::namespace::Namespace;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn peer_id_from_pubkey_matches_rust_api() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let expected = PeerId::from_verifying_key(&vk);
        let mut out = [0u8; 20];
        let rc = unsafe { codex_peer_id_from_pubkey(vk.as_bytes().as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(&out, expected.as_bytes());
    }

    #[test]
    fn event_verify_roundtrip_through_ffi() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let peer = PeerId::from_verifying_key(&vk);
        let event = EventPayload {
            version: 1,
            namespace: Namespace::new("ffi.test").unwrap(),
            claimant: peer,
            nonce: 1,
            body: b"hi".to_vec(),
            timestamp: 1,
        }
        .sign(&sk);
        let bytes = postcard::to_allocvec(&event).unwrap();
        let rc = unsafe { codex_event_verify(bytes.as_ptr(), bytes.len(), vk.as_bytes().as_ptr()) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn event_verify_detects_tampered_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let peer = PeerId::from_verifying_key(&vk);
        let event = EventPayload {
            version: 1,
            namespace: Namespace::new("ffi.test").unwrap(),
            claimant: peer,
            nonce: 1,
            body: b"hi".to_vec(),
            timestamp: 1,
        }
        .sign(&sk);
        let mut bytes = postcard::to_allocvec(&event).unwrap();
        // Flip a bit in the body — postcard will still decode but sig
        // verification will fail.
        let last = bytes.len() - 1;
        bytes[last / 2] ^= 0x01;
        let rc = unsafe { codex_event_verify(bytes.as_ptr(), bytes.len(), vk.as_bytes().as_ptr()) };
        // Could be VerifyFailed (-2) or DecodeFailed (-3) depending on
        // which byte flipped; the important thing is it's non-zero.
        assert_ne!(rc, 0);
    }

    #[test]
    fn null_pointer_returns_invalid_arg() {
        let rc = unsafe { codex_peer_id_from_pubkey(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(rc, Status::InvalidArg.as_i32());
    }
}
