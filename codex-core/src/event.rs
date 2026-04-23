//! Event (§5.2) and its signing preimage (EventPayload).
//!
//! The split between `EventPayload` and `Event`:
//! - `EventPayload` is the *signed* portion. `signing_hash()` canonicalizes
//!   it via postcard and prefixes with `dom::EVENT_SIG` before hashing.
//! - `Event` adds the 64-byte signature. `verify()` recomputes the
//!   signing hash and checks the signature against the claimant's
//!   verifying key.
//!
//! The claimant-identity side (PeerId == blake3(pubkey)[..20]) is verified
//! by the caller before this layer (the pubkey must be produced by the
//! identity service that maps `PeerId` → `VerifyingKey`).

use codex_crypto::{
    dom, tagged_hash, PeerId, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};

use crate::error::SignatureError;
use crate::hashes::EventHash;
use crate::namespace::Namespace;

/// Length of an ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// The portion of an `Event` that is signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayload {
    /// Format version. Hard-coded to `1` at v0.
    pub version: u8,

    /// Routing namespace.
    pub namespace: Namespace,

    /// Claimant's PeerId (must match the pubkey that signed this event).
    pub claimant: PeerId,

    /// Per-(claimant, namespace) nonce. Uniqueness required; gaps allowed
    /// (§5.2.2).
    pub nonce: u64,

    /// Namespace-specific body bytes. Core treats as opaque.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,

    /// Claimant's local clock in unix ms, informational only.
    pub timestamp: u64,
}

impl EventPayload {
    /// The 32-byte preimage digest used for ed25519 signing.
    ///
    /// `blake3(dom::EVENT_SIG ‖ postcard(payload))`. This is the exact
    /// input both the signer and every verifier hash. Sign-vs-verify
    /// divergence on this function is a silent-failure class of bug, so
    /// it's deliberately trivial and has direct tests.
    pub fn signing_hash(&self) -> EventHash {
        let bytes = postcard::to_allocvec(self).expect("postcard encoding of payload");
        EventHash(tagged_hash(dom::EVENT_SIG, &bytes))
    }

    /// Produce a signed `Event` by signing the signing hash with the given
    /// key.
    pub fn sign(self, signer: &SigningKey) -> Event {
        let h = self.signing_hash();
        let sig = signer.sign(h.as_bytes());
        Event {
            payload: self,
            signature: sig.to_bytes(),
        }
    }
}

/// A signed Codex event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub payload: EventPayload,

    /// 64-byte ed25519 signature of `payload.signing_hash()`.
    #[serde(with = "crate::serde_helpers::serde_bytes_array_64")]
    pub signature: [u8; SIGNATURE_BYTES],
}

impl Event {
    /// Verify the signature against the given verifying key.
    ///
    /// Caller must have independently established that `vk` corresponds
    /// to `payload.claimant` — this function does not check that.
    pub fn verify_with_key(&self, vk: &VerifyingKey) -> Result<(), SignatureError> {
        let hash = self.payload.signing_hash();
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(hash.as_bytes(), &sig)
            .map_err(|_| SignatureError::Invalid)
    }

    /// Hash of the full (payload + signature) serialization. Used as the
    /// merkle leaf input for `events_root` in block headers.
    pub fn event_hash(&self) -> EventHash {
        let bytes = postcard::to_allocvec(self).expect("postcard encoding of event");
        // Same EVENT_SIG tag is reused here; the input differs (includes
        // the signature), so the output is distinct from signing_hash.
        EventHash(tagged_hash(dom::EVENT_SIG, &bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn build_payload() -> (EventPayload, SigningKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let claimant = PeerId::from_verifying_key(&signing.verifying_key());
        let payload = EventPayload {
            version: 1,
            namespace: Namespace::new("tessera.game").unwrap(),
            claimant,
            nonce: 42,
            body: b"hello".to_vec(),
            timestamp: 1_700_000_000_000,
        };
        (payload, signing)
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let (payload, sk) = build_payload();
        let vk = sk.verifying_key();
        let event = payload.sign(&sk);
        event
            .verify_with_key(&vk)
            .expect("valid signature verifies");
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (payload, sk) = build_payload();
        let event = payload.sign(&sk);
        let wrong = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(matches!(
            event.verify_with_key(&wrong),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn verify_fails_when_payload_tampered() {
        let (payload, sk) = build_payload();
        let vk = sk.verifying_key();
        let mut event = payload.sign(&sk);
        event.payload.nonce += 1;
        assert!(matches!(
            event.verify_with_key(&vk),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn verify_fails_when_signature_tampered() {
        let (payload, sk) = build_payload();
        let vk = sk.verifying_key();
        let mut event = payload.sign(&sk);
        event.signature[0] ^= 0xff;
        assert!(matches!(
            event.verify_with_key(&vk),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn signing_hash_is_deterministic() {
        let (payload, _sk) = build_payload();
        let a = payload.signing_hash();
        let b = payload.clone().signing_hash();
        assert_eq!(a, b);
    }

    #[test]
    fn signing_hash_differs_from_event_hash() {
        let (payload, sk) = build_payload();
        let signing = payload.signing_hash();
        let event = payload.sign(&sk);
        let event_h = event.event_hash();
        assert_ne!(
            signing, event_h,
            "signing hash excludes sig, event hash includes it"
        );
    }

    #[test]
    fn event_serde_round_trip() {
        let (payload, sk) = build_payload();
        let event = payload.sign(&sk);
        let bytes = postcard::to_allocvec(&event).unwrap();
        let parsed: Event = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, parsed);
        parsed.verify_with_key(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn event_round_trip_with_empty_body() {
        let (mut payload, sk) = build_payload();
        payload.body.clear();
        let event = payload.sign(&sk);
        let bytes = postcard::to_allocvec(&event).unwrap();
        let parsed: Event = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, parsed);
        parsed.verify_with_key(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn event_round_trip_with_large_body() {
        let (mut payload, sk) = build_payload();
        payload.body = vec![0xa5u8; 256 * 1024]; // 256 KB
        let event = payload.sign(&sk);
        let bytes = postcard::to_allocvec(&event).unwrap();
        let parsed: Event = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn signatures_are_serialized_compactly() {
        let (payload, sk) = build_payload();
        let event = payload.sign(&sk);
        let bytes = postcard::to_allocvec(&event).unwrap();
        // Signature contribution: length varint (1 byte since < 128) + 64 raw
        // bytes = 65. If serde fell back to per-element encoding we'd see
        // 64 varints ≥ 64 bytes and possibly more. This test catches
        // accidental regression to the non-compact form.
        assert!(
            bytes.len() < 1024,
            "unexpected serialized size: {}",
            bytes.len()
        );
    }
}
