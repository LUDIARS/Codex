//! Namespace: bounded-length ASCII identifier used to route events to
//! their handler (`owner.topic` dot-separated).
//!
//! Validation rules:
//! - non-empty, <= `MAX_LEN` bytes
//! - ASCII only
//! - each character in `[A-Za-z0-9._-]`
//! - may not start or end with `.`, may not contain `..`
//!
//! These rules keep namespaces URL-safe, human-readable, and avoid hidden
//! unicode confusables that could spoof a well-known namespace.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum byte length for a namespace.
pub const MAX_LEN: usize = 128;

/// Reserved prefix for system events (§5.6.3 `codex.system`).
pub const SYSTEM_NAMESPACE: &str = "codex.system";

/// An ASCII dotted-identifier namespace.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Namespace(String);

impl Namespace {
    /// Validate and construct a namespace.
    pub fn new(s: impl Into<String>) -> Result<Self, NamespaceError> {
        let s = s.into();
        validate(&s)?;
        Ok(Self(s))
    }

    /// Access the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Is this a reserved `codex.system` namespace?
    pub fn is_system(&self) -> bool {
        self.0 == SYSTEM_NAMESPACE || self.0.starts_with("codex.system.")
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self.0)
    }
}

fn validate(s: &str) -> Result<(), NamespaceError> {
    if s.is_empty() {
        return Err(NamespaceError::Empty);
    }
    if s.len() > MAX_LEN {
        return Err(NamespaceError::TooLong(s.len()));
    }
    if !s.is_ascii() {
        return Err(NamespaceError::NonAscii);
    }
    if s.starts_with('.') || s.ends_with('.') {
        return Err(NamespaceError::DotEdge);
    }
    if s.contains("..") {
        return Err(NamespaceError::ConsecutiveDot);
    }
    for c in s.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-';
        if !ok {
            return Err(NamespaceError::InvalidChar(c));
        }
    }
    Ok(())
}

/// Namespace validation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NamespaceError {
    #[error("namespace must not be empty")]
    Empty,
    #[error("namespace too long ({0} > {MAX_LEN} bytes)")]
    TooLong(usize),
    #[error("namespace must be ASCII only")]
    NonAscii,
    #[error("invalid character '{0}' in namespace")]
    InvalidChar(char),
    #[error("namespace must not start or end with '.'")]
    DotEdge,
    #[error("namespace must not contain consecutive dots")]
    ConsecutiveDot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_accepted() {
        for s in [
            "tessera.game",
            "curare.asset",
            "codex.system",
            "a",
            "a.b.c.d.e",
            "a1_b2-c3.v1",
            "x.y_z-1",
        ] {
            Namespace::new(s).expect(s);
        }
    }

    #[test]
    fn empty_rejected() {
        assert_eq!(Namespace::new("").unwrap_err(), NamespaceError::Empty);
    }

    #[test]
    fn too_long_rejected() {
        let s = "a".repeat(MAX_LEN + 1);
        assert!(matches!(
            Namespace::new(s).unwrap_err(),
            NamespaceError::TooLong(_)
        ));
    }

    #[test]
    fn exactly_max_len_accepted() {
        let s = "a".repeat(MAX_LEN);
        Namespace::new(s).expect("max len is allowed");
    }

    #[test]
    fn non_ascii_rejected() {
        assert_eq!(
            Namespace::new("テッセラ").unwrap_err(),
            NamespaceError::NonAscii
        );
    }

    #[test]
    fn leading_or_trailing_dot_rejected() {
        assert_eq!(
            Namespace::new(".tessera").unwrap_err(),
            NamespaceError::DotEdge
        );
        assert_eq!(
            Namespace::new("tessera.").unwrap_err(),
            NamespaceError::DotEdge
        );
    }

    #[test]
    fn consecutive_dots_rejected() {
        assert_eq!(
            Namespace::new("a..b").unwrap_err(),
            NamespaceError::ConsecutiveDot
        );
    }

    #[test]
    fn invalid_chars_rejected() {
        for bad in ["a/b", "a b", "a@b", "a:b", "a,b", "a$b"] {
            assert!(matches!(
                Namespace::new(bad).unwrap_err(),
                NamespaceError::InvalidChar(_)
            ));
        }
    }

    #[test]
    fn is_system_detects_reserved() {
        assert!(Namespace::new("codex.system").unwrap().is_system());
        assert!(Namespace::new("codex.system.checkpoint")
            .unwrap()
            .is_system());
        assert!(!Namespace::new("codex.systemic").unwrap().is_system());
        assert!(!Namespace::new("tessera.game").unwrap().is_system());
    }

    #[test]
    fn serde_round_trip() {
        let ns = Namespace::new("tessera.game").unwrap();
        let bytes = postcard::to_allocvec(&ns).unwrap();
        let parsed: Namespace = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ns, parsed);
    }

    #[test]
    fn serde_rejects_invalid_on_deserialize_custom_ok() {
        // Note: serde(transparent) on Namespace means a bare invalid string
        // will deserialize without validation. This is a known limitation;
        // STF-level validate() is the authoritative gate.
        let invalid = postcard::to_allocvec(&"bad..name").unwrap();
        let parsed: Result<Namespace, _> = postcard::from_bytes(&invalid);
        // Still decodes — validation is enforced at Event::validate() time.
        // This test documents the current behaviour so future tightening is
        // a deliberate change, not an accidental one.
        assert!(parsed.is_ok());
    }
}
