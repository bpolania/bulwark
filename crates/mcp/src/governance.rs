//! Governance metadata stubs — attached to every tool call response.
//!
//! This establishes the wire format from day one.  Agents that understand
//! the `_meta.governance` field can use it; others ignore it.

/// Return stub governance metadata for a tool call response.
pub fn governance_metadata_stub() -> serde_json::Value {
    serde_json::json!({
        "governance": {
            "version": "0.1.0",
            "verdict": "allow",
            "policy_version": null,
            "session_id": null,
            "inspection_results": null,
            "audit_event_id": null
        }
    })
}
