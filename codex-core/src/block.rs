//! BlockHeader / Block / Attestation (§5.3, §6).
//!
//! Same split-payload pattern as `Event`:
//! - `BlockHeaderPayload` is the signed portion; `signing_hash()` yields
//!   the 32-byte preimage for the producer signature and attestations.
//! - `BlockHeader` carries the payload plus `producer_signature` and any
//!   committee-mode `attestations`.
//! - `Block` carries a header and the full list of included events.

use codex_crypto::{
    dom, tagged_hash, PeerId, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};

use crate::error::SignatureError;
use crate::event::Event;
use crate::hashes::{BlockHash, ChainId, HASH_LEN};

/// Format version for block header v0.
pub const BLOCK_VERSION: u8 = 1;

/// The signed portion of a block header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderPayload {
    pub version: u8,
    pub chain_id: ChainId,
    pub height: u64,
    pub prev_hash: BlockHash,
    pub events_root: [u8; HASH_LEN],
    pub state_root: [u8; HASH_LEN],
    pub timestamp: u64,
    pub producer: PeerId,
}

impl BlockHeaderPayload {
    /// 32-byte preimage digest used by the producer and each attester.
    pub fn signing_hash(&self) -> [u8; HASH_LEN] {
        let bytes = postcard::to_allocvec(self).expect("postcard encoding of header payload");
        tagged_hash(dom::BLOCK_SIG, &bytes)
    }

    /// Producer signs the payload to produce a finalized `BlockHeader`.
    pub fn sign(self, producer_sk: &SigningKey) -> BlockHeader {
        let h = self.signing_hash();
        let sig = producer_sk.sign(&h);
        BlockHeader {
            payload: self,
            producer_signature: sig.to_bytes(),
            attestations: Vec::new(),
        }
    }
}

/// A finalized block header: signed by the producer and, in committee
/// mode, accompanied by N/2+1 attestations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub payload: BlockHeaderPayload,

    #[serde(with = "crate::serde_helpers::serde_bytes_array_64")]
    pub producer_signature: [u8; 64],

    pub attestations: Vec<Attestation>,
}

impl BlockHeader {
    /// Verify the producer's signature against the given key.
    pub fn verify_producer(&self, vk: &VerifyingKey) -> Result<(), SignatureError> {
        let h = self.payload.signing_hash();
        let sig = Signature::from_bytes(&self.producer_signature);
        vk.verify(&h, &sig).map_err(|_| SignatureError::Invalid)
    }

    /// Hash this header (the producer-signed + attestation form).
    pub fn block_hash(&self) -> BlockHash {
        let bytes = postcard::to_allocvec(self).expect("postcard encoding of header");
        BlockHash(tagged_hash(dom::BLOCK_SIG, &bytes))
    }

    /// Add an attestation by a committee member. Returns `Err` if the
    /// signature does not verify against the provided key.
    pub fn add_attestation(
        &mut self,
        signer: PeerId,
        signer_vk: &VerifyingKey,
        signer_sk: &SigningKey,
    ) -> Result<(), SignatureError> {
        let h = self.payload.signing_hash();
        let sig = signer_sk.sign(&h);
        // Sanity-check symmetrically — catches key/pubkey mismatch at the
        // call site rather than deferring to a later verify.
        signer_vk
            .verify(&h, &sig)
            .map_err(|_| SignatureError::Invalid)?;
        self.attestations.push(Attestation {
            signer,
            signature: sig.to_bytes(),
        });
        Ok(())
    }

    /// Verify every attached attestation. Caller supplies a resolver
    /// (`PeerId → VerifyingKey`) — attestations whose signer cannot be
    /// resolved are treated as invalid.
    pub fn verify_attestations<F>(&self, mut resolve: F) -> Result<(), SignatureError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let h = self.payload.signing_hash();
        for a in &self.attestations {
            let vk = resolve(&a.signer).ok_or(SignatureError::Invalid)?;
            let sig = Signature::from_bytes(&a.signature);
            vk.verify(&h, &sig).map_err(|_| SignatureError::Invalid)?;
        }
        Ok(())
    }
}

/// A single committee attestation on a block header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub signer: PeerId,

    #[serde(with = "crate::serde_helpers::serde_bytes_array_64")]
    pub signature: [u8; 64],
}

/// A full block: header + events body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub events: Vec<Event>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::Namespace;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    fn build_payload(producer: PeerId, chain_id: ChainId) -> BlockHeaderPayload {
        BlockHeaderPayload {
            version: BLOCK_VERSION,
            chain_id,
            height: 1,
            prev_hash: BlockHash([0u8; HASH_LEN]),
            events_root: [1u8; HASH_LEN],
            state_root: [2u8; HASH_LEN],
            timestamp: 1_700_000_000_000,
            producer,
        }
    }

    #[test]
    fn producer_sign_and_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let payload = build_payload(peer, ChainId([9u8; HASH_LEN]));
        let header = payload.sign(&sk);
        header.verify_producer(&sk.verifying_key()).expect("verify");
    }

    #[test]
    fn producer_verify_fails_on_tampered_header() {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let payload = build_payload(peer, ChainId([9u8; HASH_LEN]));
        let mut header = payload.sign(&sk);
        header.payload.height += 1;
        assert!(header.verify_producer(&sk.verifying_key()).is_err());
    }

    #[test]
    fn attestations_accumulate_and_verify() {
        let producer_sk = SigningKey::generate(&mut OsRng);
        let producer = PeerId::from_verifying_key(&producer_sk.verifying_key());
        let payload = build_payload(producer, ChainId([9u8; HASH_LEN]));
        let mut header = payload.sign(&producer_sk);

        // Add 3 attestations from independent committee members.
        let mut keys: std::collections::HashMap<PeerId, VerifyingKey> =
            std::collections::HashMap::new();
        for _ in 0..3 {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            let pid = PeerId::from_verifying_key(&vk);
            header.add_attestation(pid, &vk, &sk).unwrap();
            keys.insert(pid, vk);
        }

        header
            .verify_attestations(|p| keys.get(p).copied())
            .expect("all attestations valid");
    }

    #[test]
    fn block_serde_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let payload = build_payload(peer, ChainId([9u8; HASH_LEN]));
        let header = payload.sign(&sk);

        // Empty events block.
        let block = Block {
            header: header.clone(),
            events: Vec::new(),
        };
        let bytes = postcard::to_allocvec(&block).unwrap();
        let parsed: Block = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(block, parsed);

        // Block with one signed event.
        let event_payload = crate::event::EventPayload {
            version: 1,
            namespace: Namespace::new("tessera.game").unwrap(),
            claimant: peer,
            nonce: 1,
            body: b"x".to_vec(),
            timestamp: 1_700_000_000_001,
        };
        let event = event_payload.sign(&sk);
        let block = Block {
            header,
            events: vec![event],
        };
        let bytes = postcard::to_allocvec(&block).unwrap();
        let parsed: Block = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(block, parsed);
    }

    #[test]
    fn block_hash_depends_on_attestations() {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let payload = build_payload(peer, ChainId([9u8; HASH_LEN]));
        let header = payload.sign(&sk);
        let h0 = header.block_hash();

        let mut header_with_att = header.clone();
        let att_sk = SigningKey::generate(&mut OsRng);
        let att_vk = att_sk.verifying_key();
        let att_peer = PeerId::from_verifying_key(&att_vk);
        header_with_att
            .add_attestation(att_peer, &att_vk, &att_sk)
            .unwrap();
        let h1 = header_with_att.block_hash();

        assert_ne!(h0, h1, "adding an attestation must change the block hash");
    }
}
