//! Reference namespace handlers.
//!
//! - [`game_rights`] — `ludiars.first`: world-first achievements with
//!   uniqueness enforcement.
//! - [`asset_ledger`] — `curare.asset`: single-owner asset registry
//!   with signed transfer events.

pub mod asset_ledger;
pub mod game_rights;
