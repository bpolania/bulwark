//! YAML policy file schema definitions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::verdict::{PolicyScope, Verdict};

/// A complete policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    /// File-level metadata.
    #[serde(default)]
    pub metadata: PolicyMetadata,
    /// The rules defined in this file.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Metadata about a policy file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Human-readable name for the policy file.
    #[serde(default)]
    pub name: String,
    /// Description of what this policy covers.
    #[serde(default)]
    pub description: String,
    /// The scope at which this policy applies.
    #[serde(default)]
    pub scope: PolicyScope,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Human-readable name for the rule.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
    /// The verdict when this rule matches.
    pub verdict: Verdict,
    /// Optional reason string returned in evaluations.
    #[serde(default)]
    pub reason: String,
    /// Priority for ordering (higher = evaluated first within same scope).
    #[serde(default)]
    pub priority: i32,
    /// Whether this rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Match criteria (tool, action, resource patterns).
    #[serde(rename = "match", default)]
    pub match_criteria: MatchCriteria,
    /// Additional conditions (operators, teams, environments, etc.).
    #[serde(default)]
    pub conditions: Conditions,
}

fn default_true() -> bool {
    true
}

/// Glob-based match criteria for tools, actions, and resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Glob patterns for the tool name.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Glob patterns for the action.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Glob patterns for the resource.
    #[serde(default)]
    pub resources: Vec<String>,
}

/// Additional conditions that must be met for a rule to apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    /// Allowed operators (exact match).
    #[serde(default)]
    pub operators: Vec<String>,
    /// Allowed teams (exact match).
    #[serde(default)]
    pub teams: Vec<String>,
    /// Allowed environments (exact match).
    #[serde(default)]
    pub environments: Vec<String>,
    /// Allowed agent types (exact match).
    #[serde(default)]
    pub agent_types: Vec<String>,
    /// Required labels (all must match).
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complete_policy() {
        let yaml = r#"
metadata:
  name: "test-policy"
  description: "A test policy"
  scope: global
rules:
  - name: "allow-reads"
    verdict: allow
    reason: "Reads are safe"
    priority: 10
    match:
      tools: ["github"]
      actions: ["read_*", "list_*"]
    conditions:
      teams: ["engineering"]
  - name: "deny-deletes"
    verdict: deny
    reason: "No deletions allowed"
    match:
      actions: ["delete_*"]
"#;
        let policy: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.metadata.name, "test-policy");
        assert_eq!(policy.metadata.scope, PolicyScope::Global);
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].name, "allow-reads");
        assert_eq!(policy.rules[0].verdict, Verdict::Allow);
        assert_eq!(policy.rules[0].priority, 10);
        assert_eq!(policy.rules[0].match_criteria.tools, vec!["github"]);
        assert_eq!(policy.rules[1].verdict, Verdict::Deny);
    }

    #[test]
    fn parse_minimal_policy() {
        let yaml = r#"
rules:
  - name: "catch-all"
    verdict: deny
"#;
        let policy: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.metadata.name, "");
        assert_eq!(policy.metadata.scope, PolicyScope::Global);
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.rules[0].enabled);
        assert!(policy.rules[0].match_criteria.tools.is_empty());
    }

    #[test]
    fn defaults_are_applied() {
        let yaml = r#"
rules:
  - name: "minimal"
    verdict: allow
"#;
        let policy: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        let rule = &policy.rules[0];
        assert_eq!(rule.priority, 0);
        assert!(rule.enabled);
        assert!(rule.description.is_empty());
        assert!(rule.reason.is_empty());
        assert!(rule.conditions.operators.is_empty());
    }

    #[test]
    fn roundtrip_yaml() {
        let policy = PolicyFile {
            metadata: PolicyMetadata {
                name: "roundtrip".into(),
                description: "test".into(),
                scope: PolicyScope::Team,
            },
            rules: vec![Rule {
                name: "r1".into(),
                description: String::new(),
                verdict: Verdict::Allow,
                reason: "ok".into(),
                priority: 5,
                enabled: true,
                match_criteria: MatchCriteria {
                    tools: vec!["*".into()],
                    actions: vec![],
                    resources: vec![],
                },
                conditions: Conditions::default(),
            }],
        };
        let yaml = serde_yaml::to_string(&policy).unwrap();
        let back: PolicyFile = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.metadata.name, "roundtrip");
        assert_eq!(back.rules[0].verdict, Verdict::Allow);
    }

    #[test]
    fn invalid_yaml_errors() {
        let yaml = "this is: [not: valid: yaml: {{";
        let result = serde_yaml::from_str::<PolicyFile>(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn disabled_rule() {
        let yaml = r#"
rules:
  - name: "disabled"
    verdict: deny
    enabled: false
"#;
        let policy: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        assert!(!policy.rules[0].enabled);
    }
}
