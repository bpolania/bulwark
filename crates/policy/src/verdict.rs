//! Policy evaluation verdicts and results.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The request is allowed.
    Allow,
    /// The request is denied.
    Deny,
    /// The request requires human escalation.
    Escalate,
    /// The request should be transformed before forwarding.
    Transform,
}

/// The scope at which a policy applies, ordered from least to most specific.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum PolicyScope {
    /// Applies to all requests.
    #[default]
    Global = 0,
    /// Applies to a specific agent type.
    Agent = 1,
    /// Applies to a specific team.
    Team = 2,
    /// Applies to a specific project.
    Project = 3,
    /// Manual override — highest precedence.
    Override = 4,
}

/// Full result of evaluating a request against the policy engine.
#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    /// The verdict reached.
    pub verdict: Verdict,
    /// Name of the rule that matched (if any).
    pub matched_rule: Option<String>,
    /// Name of the policy file that contained the matched rule.
    pub matched_policy: Option<String>,
    /// Scope of the matched rule.
    pub scope: PolicyScope,
    /// Human-readable reason for the verdict.
    pub reason: String,
    /// How long the evaluation took.
    pub evaluation_time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serde_roundtrip() {
        let v = Verdict::Allow;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#""allow""#);
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Verdict::Allow);
    }

    #[test]
    fn verdict_deny_serializes() {
        let json = serde_json::to_string(&Verdict::Deny).unwrap();
        assert_eq!(json, r#""deny""#);
    }

    #[test]
    fn scope_ordering() {
        assert!(PolicyScope::Global < PolicyScope::Agent);
        assert!(PolicyScope::Agent < PolicyScope::Team);
        assert!(PolicyScope::Team < PolicyScope::Project);
        assert!(PolicyScope::Project < PolicyScope::Override);
    }

    #[test]
    fn scope_serde_roundtrip() {
        let s = PolicyScope::Override;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#""override""#);
        let back: PolicyScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PolicyScope::Override);
    }
}
