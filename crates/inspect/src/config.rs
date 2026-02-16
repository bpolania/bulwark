//! Inspection configuration types.

use serde::{Deserialize, Serialize};

use crate::finding::{FindingAction, FindingCategory, Severity};

/// Configuration for the content inspection system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InspectionConfig {
    /// Whether inspection is enabled.
    pub enabled: bool,
    /// Whether to inspect request bodies (pre-forward).
    pub inspect_requests: bool,
    /// Whether to inspect response bodies (post-forward).
    pub inspect_responses: bool,
    /// Maximum content size to inspect (bytes). Content larger than this is skipped.
    pub max_content_size: usize,
    /// Per-rule overrides.
    #[serde(default)]
    pub rule_overrides: Vec<RuleOverride>,
    /// Custom patterns to add.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
    /// Rules to disable entirely (by ID).
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// Minimum severity to act on. Findings below this are discarded.
    #[serde(default)]
    pub min_severity: Option<Severity>,
}

impl Default for InspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            inspect_requests: true,
            inspect_responses: true,
            max_content_size: 1_048_576, // 1 MB
            rule_overrides: Vec::new(),
            custom_patterns: Vec::new(),
            disabled_rules: Vec::new(),
            min_severity: None,
        }
    }
}

/// Override settings for a built-in rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    /// The rule ID to override.
    pub rule_id: String,
    /// Override the severity.
    pub severity: Option<Severity>,
    /// Override the action.
    pub action: Option<FindingAction>,
}

/// A custom pattern defined by the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Unique ID for this pattern.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// The regex pattern.
    pub pattern: String,
    /// Severity.
    pub severity: Severity,
    /// Category.
    #[serde(default = "default_custom_category")]
    pub category: FindingCategory,
    /// Action.
    pub action: FindingAction,
}

fn default_custom_category() -> FindingCategory {
    FindingCategory::Custom("custom".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = InspectionConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.inspect_requests);
        assert!(cfg.inspect_responses);
        assert_eq!(cfg.max_content_size, 1_048_576);
        assert!(cfg.disabled_rules.is_empty());
        assert!(cfg.custom_patterns.is_empty());
        assert!(cfg.rule_overrides.is_empty());
        assert!(cfg.min_severity.is_none());
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = InspectionConfig {
            enabled: false,
            max_content_size: 512,
            disabled_rules: vec!["email-address".into()],
            ..Default::default()
        };
        let yaml = serde_json::to_string(&cfg).unwrap();
        let parsed: InspectionConfig = serde_json::from_str(&yaml).unwrap();
        assert!(!parsed.enabled);
        assert_eq!(parsed.max_content_size, 512);
        assert_eq!(parsed.disabled_rules, vec!["email-address"]);
    }

    #[test]
    fn custom_pattern_deserialization() {
        let json = r#"{
            "id": "my-rule",
            "description": "My custom rule",
            "pattern": "SECRET_[0-9]+",
            "severity": "high",
            "action": "block"
        }"#;
        let cp: CustomPattern = serde_json::from_str(json).unwrap();
        assert_eq!(cp.id, "my-rule");
        assert_eq!(cp.severity, Severity::High);
        assert_eq!(cp.action, FindingAction::Block);
        assert_eq!(cp.category, FindingCategory::Custom("custom".into()));
    }
}
