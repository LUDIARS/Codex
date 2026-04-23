//! `curare.asset` — single-owner asset registry.
//!
//! Two event kinds, discriminated by an enum in `body`:
//! - `Mint { asset_id }` — create a new asset owned by claimant.
//!   Rejected if `asset_id` already exists.
//! - `Transfer { asset_id, new_owner }` — change ownership. Rejected
//!   if claimant is not the current owner.
//!
//! State schema:
//!   key   = blake3(asset_id_bytes)
//!   value = current owner PeerId (20 bytes)

use codex_core::event::Event;
use codex_core::namespace::Namespace;
use codex_crypto::{Blake3Hasher, PeerId};
use codex_state::{ApplyError, NamespaceHandler, StateTree, ValidationError};
use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "curare.asset";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetBody {
    Mint { asset_id: String },
    Transfer { asset_id: String, new_owner: PeerId },
}

pub fn asset_key(asset_id: &str) -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.update(asset_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

pub struct AssetHandler {
    ns: Namespace,
}

impl Default for AssetHandler {
    fn default() -> Self {
        Self {
            ns: Namespace::new(NAMESPACE).expect("namespace literal is valid"),
        }
    }
}

impl NamespaceHandler for AssetHandler {
    fn namespace(&self) -> &Namespace {
        &self.ns
    }

    fn validate(&self, event: &Event, state: &StateTree) -> Result<(), ValidationError> {
        let body: AssetBody =
            postcard::from_bytes(&event.payload.body).map_err(|e| ValidationError::BodyDecode {
                reason: format!("asset_ledger::AssetBody: {e}"),
            })?;
        match body {
            AssetBody::Mint { asset_id } => {
                if asset_id.is_empty() {
                    return Err(ValidationError::HandlerReject {
                        reason: "empty asset_id".into(),
                    });
                }
                let key = asset_key(&asset_id);
                if state.get(&self.ns, &key).is_some() {
                    return Err(ValidationError::HandlerReject {
                        reason: format!("asset '{asset_id}' already exists"),
                    });
                }
                Ok(())
            }
            AssetBody::Transfer {
                asset_id,
                new_owner: _,
            } => {
                let key = asset_key(&asset_id);
                let current =
                    state
                        .get(&self.ns, &key)
                        .ok_or_else(|| ValidationError::HandlerReject {
                            reason: format!("asset '{asset_id}' does not exist"),
                        })?;
                if current != event.payload.claimant.as_bytes() {
                    return Err(ValidationError::HandlerReject {
                        reason: format!("asset '{asset_id}' is not owned by claimant"),
                    });
                }
                Ok(())
            }
        }
    }

    fn apply(&self, event: &Event, state: &mut StateTree) -> Result<(), ApplyError> {
        let body: AssetBody =
            postcard::from_bytes(&event.payload.body).map_err(|e| ApplyError::HandlerFailure {
                reason: format!("asset_ledger::AssetBody: {e}"),
            })?;
        match body {
            AssetBody::Mint { asset_id } => {
                let key = asset_key(&asset_id);
                state.insert(
                    self.ns.clone(),
                    key,
                    event.payload.claimant.as_bytes().to_vec(),
                );
            }
            AssetBody::Transfer {
                asset_id,
                new_owner,
            } => {
                let key = asset_key(&asset_id);
                state.insert(self.ns.clone(), key, new_owner.as_bytes().to_vec());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_core::event::EventPayload;
    use codex_crypto::SigningKey;
    use rand_core::OsRng;

    fn make_event(sk: &SigningKey, nonce: u64, body: &AssetBody) -> Event {
        let peer = PeerId::from_verifying_key(&sk.verifying_key());
        let body_bytes = postcard::to_allocvec(body).unwrap();
        EventPayload {
            version: 1,
            namespace: Namespace::new(NAMESPACE).unwrap(),
            claimant: peer,
            nonce,
            body: body_bytes,
            timestamp: nonce,
        }
        .sign(sk)
    }

    #[test]
    fn mint_then_transfer_chain() {
        let h = AssetHandler::default();
        let mut state = StateTree::new();

        let alice_sk = SigningKey::generate(&mut OsRng);
        let bob_sk = SigningKey::generate(&mut OsRng);
        let bob = PeerId::from_verifying_key(&bob_sk.verifying_key());

        // alice mints "painting"
        let mint = make_event(
            &alice_sk,
            1,
            &AssetBody::Mint {
                asset_id: "painting".into(),
            },
        );
        h.validate(&mint, &state).unwrap();
        h.apply(&mint, &mut state).unwrap();

        // alice transfers to bob
        let transfer = make_event(
            &alice_sk,
            2,
            &AssetBody::Transfer {
                asset_id: "painting".into(),
                new_owner: bob,
            },
        );
        h.validate(&transfer, &state).unwrap();
        h.apply(&transfer, &mut state).unwrap();

        // State should record bob as the owner.
        assert_eq!(
            state.get(h.namespace(), &asset_key("painting")).unwrap(),
            bob.as_bytes()
        );
    }

    #[test]
    fn double_mint_rejected() {
        let h = AssetHandler::default();
        let mut state = StateTree::new();
        let alice_sk = SigningKey::generate(&mut OsRng);
        let mint1 = make_event(
            &alice_sk,
            1,
            &AssetBody::Mint {
                asset_id: "p".into(),
            },
        );
        h.apply(&mint1, &mut state).unwrap();
        let mint2 = make_event(
            &alice_sk,
            2,
            &AssetBody::Mint {
                asset_id: "p".into(),
            },
        );
        assert!(matches!(
            h.validate(&mint2, &state),
            Err(ValidationError::HandlerReject { .. })
        ));
    }

    #[test]
    fn non_owner_transfer_rejected() {
        let h = AssetHandler::default();
        let mut state = StateTree::new();

        let alice_sk = SigningKey::generate(&mut OsRng);
        let bob_sk = SigningKey::generate(&mut OsRng);
        let carol_sk = SigningKey::generate(&mut OsRng);
        let carol = PeerId::from_verifying_key(&carol_sk.verifying_key());

        let mint = make_event(
            &alice_sk,
            1,
            &AssetBody::Mint {
                asset_id: "p".into(),
            },
        );
        h.apply(&mint, &mut state).unwrap();

        // bob (not owner) tries to transfer.
        let transfer = make_event(
            &bob_sk,
            1,
            &AssetBody::Transfer {
                asset_id: "p".into(),
                new_owner: carol,
            },
        );
        assert!(matches!(
            h.validate(&transfer, &state),
            Err(ValidationError::HandlerReject { .. })
        ));
    }

    #[test]
    fn transfer_of_unknown_asset_rejected() {
        let h = AssetHandler::default();
        let state = StateTree::new();
        let sk = SigningKey::generate(&mut OsRng);
        let other = PeerId::from_verifying_key(&SigningKey::generate(&mut OsRng).verifying_key());
        let transfer = make_event(
            &sk,
            1,
            &AssetBody::Transfer {
                asset_id: "ghost".into(),
                new_owner: other,
            },
        );
        assert!(matches!(
            h.validate(&transfer, &state),
            Err(ValidationError::HandlerReject { .. })
        ));
    }
}
