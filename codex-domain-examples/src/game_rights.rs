//! `ludiars.first` — world-first achievements.
//!
//! Body schema (postcard-encoded):
//!   struct ClaimBody { achievement_id: String, evidence: Option<Bytes> }
//!
//! State schema:
//!   key   = blake3(achievement_id_bytes)
//!   value = blake3(claimant peer ‖ nonce LE ‖ timestamp LE)[..20] ‖
//!           holder peer (20 B) ‖ commit_tick_LE (8 B)
//! The stored value is the canonical "who got it, when". The 20-byte
//! prefix is a short digest for quick equality checks; the rest is the
//! unambiguous holder + timestamp tuple.

use codex_core::event::Event;
use codex_core::namespace::Namespace;
use codex_crypto::Blake3Hasher;
use codex_state::{ApplyError, NamespaceHandler, StateTree, ValidationError};
use serde::{Deserialize, Serialize};

/// Namespace for world-first achievements.
pub const NAMESPACE: &str = "ludiars.first";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimBody {
    pub achievement_id: String,
    #[serde(with = "serde_bytes", default)]
    pub evidence: Vec<u8>,
}

pub fn achievement_key(achievement_id: &str) -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.update(achievement_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn encode_value(evt: &Event) -> Vec<u8> {
    let mut v = Vec::with_capacity(20 + 20 + 8);
    // short digest (a debug aid — first 20 bytes of a tag over claimant/nonce/timestamp)
    let mut h = Blake3Hasher::new();
    h.update(evt.payload.claimant.as_bytes());
    h.update(&evt.payload.nonce.to_le_bytes());
    h.update(&evt.payload.timestamp.to_le_bytes());
    v.extend_from_slice(&h.finalize().as_bytes()[..20]);
    v.extend_from_slice(evt.payload.claimant.as_bytes());
    v.extend_from_slice(&evt.payload.timestamp.to_le_bytes());
    v
}

pub struct AchievementHandler {
    ns: Namespace,
}

impl Default for AchievementHandler {
    fn default() -> Self {
        Self {
            ns: Namespace::new(NAMESPACE).expect("namespace literal is valid"),
        }
    }
}

impl NamespaceHandler for AchievementHandler {
    fn namespace(&self) -> &Namespace {
        &self.ns
    }

    fn validate(&self, event: &Event, state: &StateTree) -> Result<(), ValidationError> {
        let body: ClaimBody =
            postcard::from_bytes(&event.payload.body).map_err(|e| ValidationError::BodyDecode {
                reason: format!("game_rights::ClaimBody: {e}"),
            })?;
        if body.achievement_id.is_empty() {
            return Err(ValidationError::HandlerReject {
                reason: "empty achievement_id".into(),
            });
        }
        let key = achievement_key(&body.achievement_id);
        if state.get(&self.ns, &key).is_some() {
            return Err(ValidationError::HandlerReject {
                reason: format!(
                    "achievement '{}' already claimed (world-first uniqueness)",
                    body.achievement_id
                ),
            });
        }
        Ok(())
    }

    fn apply(&self, event: &Event, state: &mut StateTree) -> Result<(), ApplyError> {
        let body: ClaimBody =
            postcard::from_bytes(&event.payload.body).map_err(|e| ApplyError::HandlerFailure {
                reason: format!("game_rights::ClaimBody: {e}"),
            })?;
        let key = achievement_key(&body.achievement_id);
        let value = encode_value(event);
        state.insert(self.ns.clone(), key, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::event::EventPayload;
    use codex_crypto::{PeerId, SigningKey};
    use rand_core::OsRng;

    fn build_event(achievement: &str, nonce: u64) -> (Event, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let body = postcard::to_allocvec(&ClaimBody {
            achievement_id: achievement.into(),
            evidence: vec![],
        })
        .unwrap();
        let payload = EventPayload {
            version: 1,
            namespace: Namespace::new(NAMESPACE).unwrap(),
            claimant: peer,
            nonce,
            body,
            timestamp: 1,
        };
        (payload.sign(&sk), sk)
    }

    #[test]
    fn first_claim_succeeds() {
        let h = AchievementHandler::default();
        let mut state = StateTree::new();
        let (ev, _) = build_event("summit", 1);
        h.validate(&ev, &state).unwrap();
        h.apply(&ev, &mut state).unwrap();
        assert!(state
            .get(h.namespace(), &achievement_key("summit"))
            .is_some());
    }

    #[test]
    fn duplicate_claim_rejected() {
        let h = AchievementHandler::default();
        let mut state = StateTree::new();
        let (ev1, _) = build_event("summit", 1);
        h.apply(&ev1, &mut state).unwrap();
        let (ev2, _) = build_event("summit", 1);
        let err = h.validate(&ev2, &state).unwrap_err();
        assert!(matches!(err, ValidationError::HandlerReject { .. }));
    }

    #[test]
    fn body_decode_failure_surfaces() {
        let h = AchievementHandler::default();
        let state = StateTree::new();
        let sk = SigningKey::generate(&mut OsRng);
        let ev = EventPayload {
            version: 1,
            namespace: Namespace::new(NAMESPACE).unwrap(),
            claimant: PeerId::from_verifying_key(&sk.verifying_key()),
            nonce: 1,
            body: vec![0xffu8, 0xff, 0xff], // garbage
            timestamp: 1,
        }
        .sign(&sk);
        let err = h.validate(&ev, &state).unwrap_err();
        assert!(matches!(err, ValidationError::BodyDecode { .. }));
    }

    #[test]
    fn empty_achievement_id_rejected() {
        let h = AchievementHandler::default();
        let state = StateTree::new();
        let (ev, _) = build_event("", 1);
        let err = h.validate(&ev, &state).unwrap_err();
        assert!(matches!(err, ValidationError::HandlerReject { .. }));
    }
}
