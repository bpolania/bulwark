//! Shared context for proxy request processing.
//!
//! Bundles all subsystem handles into a single struct that is cloned
//! per-connection, replacing the long parameter lists in handler/forward/tunnel.

use std::sync::Arc;

use bulwark_audit::logger::AuditLogger;
use bulwark_inspect::scanner::ContentScanner;
use bulwark_policy::engine::PolicyEngine;
use bulwark_ratelimit::cost::CostTracker;
use bulwark_ratelimit::limiter::RateLimiter;
use bulwark_vault::store::Vault;

use crate::toolmap::ToolMapper;

/// Shared context for processing a proxy request.
/// Cloned per-connection (all fields are Arc or cheap Clone).
#[derive(Clone)]
pub struct ProxyRequestContext {
    pub policy_engine: Option<Arc<PolicyEngine>>,
    pub vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    pub audit_logger: Option<AuditLogger>,
    pub content_scanner: Option<Arc<ContentScanner>>,
    pub tool_mapper: Option<Arc<ToolMapper>>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub cost_tracker: Option<Arc<CostTracker>>,
}

impl ProxyRequestContext {
    pub fn new() -> Self {
        Self {
            policy_engine: None,
            vault: None,
            audit_logger: None,
            content_scanner: None,
            tool_mapper: None,
            rate_limiter: None,
            cost_tracker: None,
        }
    }
}

impl Default for ProxyRequestContext {
    fn default() -> Self {
        Self::new()
    }
}
