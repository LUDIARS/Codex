//! Simple FIFO mempool. FCFS per §5.8: `submit` records the event in
//! order received; `drain_up_to` returns them in that order.
//!
//! Dedup is by `event.event_hash()` so the same signed event re-submitted
//! by multiple gossip routes is taken once.

use std::collections::{HashSet, VecDeque};

use codex_core::event::Event;
use codex_core::hashes::EventHash;

/// Minimal mempool contract required by the producer loop.
pub trait Mempool: Send {
    fn submit(&mut self, event: Event) -> bool;
    fn drain_up_to(&mut self, max: usize) -> Vec<Event>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Default in-memory implementation.
#[derive(Debug, Default)]
pub struct InMemoryMempool {
    queue: VecDeque<Event>,
    seen: HashSet<EventHash>,
}

impl InMemoryMempool {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Mempool for InMemoryMempool {
    /// Returns `true` if the event was accepted, `false` if it was a
    /// duplicate (same `event_hash`).
    fn submit(&mut self, event: Event) -> bool {
        let h = event.event_hash();
        if !self.seen.insert(h) {
            return false;
        }
        self.queue.push_back(event);
        true
    }

    fn drain_up_to(&mut self, max: usize) -> Vec<Event> {
        let n = self.queue.len().min(max);
        self.queue.drain(..n).collect()
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::event::EventPayload;
    use codex_core::namespace::Namespace;
    use codex_crypto::{PeerId, SigningKey};
    use rand_core::OsRng;

    fn make_event(nonce: u64) -> Event {
        let sk = SigningKey::generate(&mut OsRng);
        EventPayload {
            version: 1,
            namespace: Namespace::new("tessera.game").unwrap(),
            claimant: PeerId::from_verifying_key(&sk.verifying_key()),
            nonce,
            body: b"x".to_vec(),
            timestamp: nonce,
        }
        .sign(&sk)
    }

    #[test]
    fn submit_preserves_fifo() {
        let mut m = InMemoryMempool::new();
        let e1 = make_event(1);
        let e2 = make_event(2);
        let e3 = make_event(3);
        m.submit(e1.clone());
        m.submit(e2.clone());
        m.submit(e3.clone());
        let drained = m.drain_up_to(10);
        assert_eq!(drained, vec![e1, e2, e3]);
    }

    #[test]
    fn duplicate_is_rejected() {
        let mut m = InMemoryMempool::new();
        let e = make_event(1);
        assert!(m.submit(e.clone()));
        assert!(!m.submit(e.clone())); // dup
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn drain_respects_max() {
        let mut m = InMemoryMempool::new();
        for n in 1..=5 {
            m.submit(make_event(n));
        }
        let first = m.drain_up_to(2);
        assert_eq!(first.len(), 2);
        assert_eq!(m.len(), 3);
    }
}
