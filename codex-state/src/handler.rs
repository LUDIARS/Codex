//! `NamespaceHandler` trait and the `HandlerRegistry`.
//!
//! Handlers implement the namespace-specific side of validation and
//! state mutation. The Codex core only enforces signature, nonce
//! uniqueness (§5.2.2), and dispatch; everything else — what counts as a
//! valid body, what state changes the event implies, whether it's
//! permitted given current state — is a handler decision.
//!
//! Per §5.6 handlers are compiled into the node binary; `HandlerRegistry`
//! is the runtime binding of a `Namespace` to its handler instance.

use std::collections::{HashMap, HashSet};

use codex_core::event::Event;
use codex_core::namespace::Namespace;

use crate::error::{ApplyError, ValidationError};
use crate::state::StateTree;

/// Implemented by each domain (tessera.game, curare.asset, ...).
///
/// `validate` must be a pure function of `(event, state)` — it may not
/// mutate state. `apply` is only called after `validate` has succeeded
/// at the STF level and may mutate state freely.
///
/// Both functions must be deterministic: the same `(event, state)`
/// inputs must produce identical outputs across nodes, otherwise
/// state_root divergence breaks finality.
pub trait NamespaceHandler: Send + Sync {
    fn namespace(&self) -> &Namespace;
    fn validate(&self, event: &Event, state: &StateTree) -> Result<(), ValidationError>;
    fn apply(&self, event: &Event, state: &mut StateTree) -> Result<(), ApplyError>;
}

/// Registry of `Namespace → Box<dyn NamespaceHandler>`.
///
/// A namespace can be **registered** (handler present in the binary)
/// and additionally **enabled** (STF will dispatch to it). `register()`
/// enables by default, matching the common case. `disable` / `enable`
/// exist to support §5.6.4 dynamic activation via `codex.system`
/// events without requiring handlers to be added or removed at
/// runtime.
#[derive(Default)]
pub struct HandlerRegistry {
    handlers: HashMap<Namespace, Box<dyn NamespaceHandler>>,
    enabled: HashSet<Namespace>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register and enable a handler.
    pub fn register(&mut self, handler: Box<dyn NamespaceHandler>) {
        let ns = handler.namespace().clone();
        self.enabled.insert(ns.clone());
        self.handlers.insert(ns, handler);
    }

    /// Register but leave disabled. Useful for pre-loading handlers
    /// whose activation will be gated by `codex.system.RegisterNamespace`.
    pub fn register_disabled(&mut self, handler: Box<dyn NamespaceHandler>) {
        let ns = handler.namespace().clone();
        self.handlers.insert(ns, handler);
    }

    /// Enable dispatch for a previously registered namespace.
    /// Returns `false` if the namespace isn't registered.
    pub fn enable(&mut self, namespace: &Namespace) -> bool {
        if !self.handlers.contains_key(namespace) {
            return false;
        }
        self.enabled.insert(namespace.clone());
        true
    }

    /// Disable dispatch without removing the handler.
    pub fn disable(&mut self, namespace: &Namespace) -> bool {
        self.enabled.remove(namespace)
    }

    pub fn is_enabled(&self, namespace: &Namespace) -> bool {
        self.enabled.contains(namespace)
    }

    pub fn get(&self, namespace: &Namespace) -> Option<&dyn NamespaceHandler> {
        if !self.enabled.contains(namespace) {
            return None;
        }
        self.handlers.get(namespace).map(|h| h.as_ref())
    }

    pub fn contains(&self, namespace: &Namespace) -> bool {
        self.handlers.contains_key(namespace)
    }

    pub fn enabled_namespaces(&self) -> impl Iterator<Item = &Namespace> {
        self.enabled.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopHandler {
        ns: Namespace,
    }

    impl NamespaceHandler for NoopHandler {
        fn namespace(&self) -> &Namespace {
            &self.ns
        }
        fn validate(&self, _e: &Event, _s: &StateTree) -> Result<(), ValidationError> {
            Ok(())
        }
        fn apply(&self, _e: &Event, _s: &mut StateTree) -> Result<(), ApplyError> {
            Ok(())
        }
    }

    #[test]
    fn register_and_lookup() {
        let mut r = HandlerRegistry::new();
        assert!(!r.contains(&Namespace::new("x").unwrap()));
        r.register(Box::new(NoopHandler {
            ns: Namespace::new("x").unwrap(),
        }));
        assert!(r.contains(&Namespace::new("x").unwrap()));
        assert!(r.get(&Namespace::new("x").unwrap()).is_some());
    }

    #[test]
    fn enabled_namespaces_enumerates_keys() {
        let mut r = HandlerRegistry::new();
        r.register(Box::new(NoopHandler {
            ns: Namespace::new("a").unwrap(),
        }));
        r.register(Box::new(NoopHandler {
            ns: Namespace::new("b").unwrap(),
        }));
        let mut names: Vec<String> = r.enabled_namespaces().map(|n| n.to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn disable_hides_handler_from_stf_dispatch() {
        let mut r = HandlerRegistry::new();
        let ns = Namespace::new("x").unwrap();
        r.register(Box::new(NoopHandler { ns: ns.clone() }));
        assert!(r.get(&ns).is_some());
        assert!(r.is_enabled(&ns));
        r.disable(&ns);
        assert!(r.get(&ns).is_none());
        assert!(!r.is_enabled(&ns));
        assert!(
            r.contains(&ns),
            "handler is still registered, just disabled"
        );
    }

    #[test]
    fn register_disabled_preloads_without_dispatch() {
        let mut r = HandlerRegistry::new();
        let ns = Namespace::new("preloaded").unwrap();
        r.register_disabled(Box::new(NoopHandler { ns: ns.clone() }));
        assert!(!r.is_enabled(&ns));
        assert!(r.get(&ns).is_none());
        // Later activation via codex.system.RegisterNamespace flow.
        assert!(r.enable(&ns));
        assert!(r.get(&ns).is_some());
    }

    #[test]
    fn enable_fails_for_unknown_namespace() {
        let mut r = HandlerRegistry::new();
        let missing = Namespace::new("nope").unwrap();
        assert!(!r.enable(&missing));
    }
}
