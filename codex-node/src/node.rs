//! Single-process node wiring.
//!
//! [`SessionNode`] is parameterized on whether it's running as the
//! producer (holds a signing key + session producer) or just as a
//! verifier (ingests blocks from elsewhere). Both variants expose the
//! same `submit_event` / `ingest_block` / state-query API so higher
//! layers (sync, RPC, FFI) don't care which role.

use codex_consensus::verifier::{BlockVerifier, SingleProducerAuthority};
use codex_consensus::{ChainTip, InMemoryMempool, Mempool, SessionProducer};
use codex_core::block::Block;
use codex_core::event::Event;
use codex_core::hashes::{BlockHash, ChainId};
use codex_core::namespace::Namespace;
use codex_crypto::{PeerId, SigningKey, VerifyingKey};
use codex_state::{
    EventInclusionProof, ExistenceProof, HandlerRegistry, NonExistenceProof, StateTree, Stf,
};

use crate::block_store::{BlockStore, InMemoryBlockStore};
use crate::error::NodeError;

/// Session-mode role: producer or bare verifier.
#[allow(clippy::large_enum_variant)]
pub enum ProducerRole {
    /// This node is the authoritative producer.
    Producer {
        producer: PeerId,
        producer_sk: SigningKey,
        producer_vk: VerifyingKey,
    },
    /// This node follows blocks produced elsewhere.
    Follower {
        expected_producer: PeerId,
        producer_vk: VerifyingKey,
    },
}

/// A single-process node wiring mempool + producer (optional) +
/// verifier + block store + state replica.
pub struct SessionNode {
    role: ProducerRole,
    chain_id: ChainId,
    mempool: Box<dyn Mempool>,
    stf: Stf,
    state: StateTree,
    store: Box<dyn BlockStore>,
    verifier: BlockVerifier,
    producer: Option<SessionProducer>,
}

impl SessionNode {
    pub fn new(chain_id: ChainId, role: ProducerRole, registry: HandlerRegistry) -> Self {
        let verifier_authority: Box<dyn codex_consensus::verifier::ProducerAuthority> = match &role
        {
            ProducerRole::Producer {
                producer,
                producer_vk,
                ..
            }
            | ProducerRole::Follower {
                expected_producer: producer,
                producer_vk,
            } => Box::new(SingleProducerAuthority::new(*producer, *producer_vk)),
        };
        let verifier = BlockVerifier::new(ChainTip::genesis(chain_id), verifier_authority);
        let producer = if let ProducerRole::Producer {
            producer,
            producer_sk,
            ..
        } = &role
        {
            Some(SessionProducer::new(
                *producer,
                producer_sk.clone(),
                chain_id,
            ))
        } else {
            None
        };
        Self {
            role,
            chain_id,
            mempool: Box::new(InMemoryMempool::new()),
            stf: Stf::new(registry),
            state: StateTree::new(),
            store: Box::new(InMemoryBlockStore::new()),
            verifier,
            producer,
        }
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn tip(&self) -> &ChainTip {
        self.verifier.tip()
    }

    pub fn is_producer(&self) -> bool {
        matches!(self.role, ProducerRole::Producer { .. })
    }

    pub fn state_root(&mut self) -> [u8; 32] {
        self.state.root()
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    pub fn store(&self) -> &dyn BlockStore {
        self.store.as_ref()
    }

    pub fn state_get(&self, namespace: &Namespace, key_hash: &[u8; 32]) -> Option<&[u8]> {
        self.state.get(namespace, key_hash)
    }

    pub fn existence_proof(
        &self,
        namespace: &Namespace,
        key_hash: &[u8; 32],
    ) -> Option<ExistenceProof> {
        self.state.existence_proof(namespace, key_hash)
    }

    pub fn non_existence_proof(
        &self,
        namespace: &Namespace,
        key_hash: &[u8; 32],
    ) -> Option<NonExistenceProof> {
        self.state.non_existence_proof(namespace, key_hash)
    }

    /// Find the event at `index` in block `height` and return an
    /// `EventInclusionProof` against that block's `events_root`.
    pub fn event_inclusion_proof(&self, height: u64, index: usize) -> Option<EventInclusionProof> {
        let block = self.store.get_by_height(height)?;
        codex_state::events::compute_event_inclusion_proof(&block.events, index)
    }

    /// Push an event into the mempool. Returns `true` if accepted,
    /// `false` if it was a duplicate. The node does *not* validate
    /// here; validation happens at block-production time through the
    /// STF. Producers typically pre-filter; follower nodes forward
    /// events to the producer.
    pub fn submit_event(&mut self, event: Event) -> bool {
        self.mempool.submit(event)
    }

    /// Producer-only: drain mempool, build and sign a block, apply to
    /// state, and store it. Broadcast is the caller's concern.
    pub fn produce<F>(
        &mut self,
        timestamp_ms: u64,
        resolve: &mut F,
        allow_empty: bool,
    ) -> Result<Option<Block>, NodeError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        let Some(producer) = self.producer.as_mut() else {
            return Ok(None);
        };
        let block = match producer.produce(
            self.mempool.as_mut(),
            &mut self.stf,
            &mut self.state,
            timestamp_ms,
            resolve,
            allow_empty,
        )? {
            Some(b) => b,
            None => return Ok(None),
        };

        // Keep the verifier's tip in sync with the producer's.
        let verifier_tip = self.verifier.tip_mut();
        *verifier_tip = producer.tip().clone();

        self.store.put(block.clone());
        Ok(Some(block))
    }

    /// Ingest a block from the wire. Runs the full verifier pipeline
    /// (continuity, authorization, signature, STF, root match), then
    /// stores it on success.
    pub fn ingest_block<F>(&mut self, block: Block, resolve: &mut F) -> Result<(), NodeError>
    where
        F: FnMut(&PeerId) -> Option<VerifyingKey>,
    {
        self.verifier
            .verify_and_apply(&block, &mut self.stf, &mut self.state, resolve)?;
        // If we're also the producer, sync its tip too so it doesn't
        // try to produce with a stale prev_hash.
        if let Some(producer) = self.producer.as_mut() {
            let h = block.header.payload.height;
            let hash = block.header.block_hash();
            let tip = producer.tip_mut();
            tip.advance(h, hash);
        }
        self.store.put(block);
        Ok(())
    }

    /// Access the latest block's hash (the tip). Equivalent to
    /// `self.tip().tip_hash`.
    pub fn tip_hash(&self) -> BlockHash {
        self.verifier.tip().tip_hash
    }
}
