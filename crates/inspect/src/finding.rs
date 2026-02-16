//! Inspection finding types — the output of content scanning.

use serde::{Deserialize, Serialize};

/// A single finding from content inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionFinding {
    /// Which rule produced this finding.
    pub rule_id: String,
    /// Human-readable description of what was found.
    pub description: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Category of the finding.
    pub category: FindingCategory,
    /// Where in the content the finding was located.
    pub location: FindingLocation,
    /// A sanitized snippet of the matched content (truncated, partially redacted).
    pub snippet: Option<String>,
    /// The recommended action.
    pub action: FindingAction,
}

/// Severity levels for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — notable but not a problem.
    Info,
    /// Low — minor concern, log only.
    Low,
    /// Medium — should be reviewed.
    Medium,
    /// High — likely a real issue, consider blocking.
    High,
    /// Critical — almost certainly a problem, should block.
    Critical,
}

/// Categories of findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// A secret or credential found in content.
    SecretLeakage,
    /// Personally identifiable information.
    Pii,
    /// A pattern that looks like prompt injection.
    PromptInjection,
    /// Sensitive data that shouldn't be in this context.
    SensitiveData,
    /// A custom category from a user-defined rule.
    Custom(String),
}

/// Where the finding was located in the content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FindingLocation {
    /// Location in structured content (JSON pointer path).
    JsonPath {
        /// JSON pointer path (e.g. `/arguments/token`).
        path: String,
    },
    /// Byte offset range in raw content.
    ByteRange {
        /// Start byte offset (inclusive).
        start: usize,
        /// End byte offset (exclusive).
        end: usize,
    },
    /// Line number in text content.
    Line {
        /// 1-based line number.
        line: usize,
    },
    /// Location is unknown or not applicable.
    Unknown,
}

/// The recommended action for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAction {
    /// Log the finding but allow the request.
    Log,
    /// Redact the matched content before forwarding.
    Redact,
    /// Block the request entirely.
    Block,
}

/// The aggregate result of inspecting content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    /// All findings from this inspection.
    pub findings: Vec<InspectionFinding>,
    /// Whether any finding recommends blocking.
    pub should_block: bool,
    /// Whether any finding recommends redaction.
    pub should_redact: bool,
    /// The highest severity found.
    pub max_severity: Option<Severity>,
    /// Time taken to inspect (microseconds).
    pub inspection_time_us: u64,
}

impl InspectionResult {
    /// Create an empty result (no findings).
    pub fn empty(duration_us: u64) -> Self {
        Self {
            findings: Vec::new(),
            should_block: false,
            should_redact: false,
            max_severity: None,
            inspection_time_us: duration_us,
        }
    }

    /// Create from a list of findings.
    pub fn from_findings(findings: Vec<InspectionFinding>, duration_us: u64) -> Self {
        let should_block = findings.iter().any(|f| f.action == FindingAction::Block);
        let should_redact = findings.iter().any(|f| f.action == FindingAction::Redact);
        let max_severity = findings.iter().map(|f| f.severity).max();
        Self {
            findings,
            should_block,
            should_redact,
            max_severity,
            inspection_time_us: duration_us,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_result_has_no_findings() {
        let result = InspectionResult::empty(42);
        assert!(result.findings.is_empty());
        assert!(!result.should_block);
        assert!(!result.should_redact);
        assert!(result.max_severity.is_none());
        assert_eq!(result.inspection_time_us, 42);
    }

    #[test]
    fn from_findings_computes_should_block() {
        let findings = vec![InspectionFinding {
            rule_id: "test".into(),
            description: "test".into(),
            severity: Severity::High,
            category: FindingCategory::SecretLeakage,
            location: FindingLocation::Unknown,
            snippet: None,
            action: FindingAction::Block,
        }];
        let result = InspectionResult::from_findings(findings, 0);
        assert!(result.should_block);
        assert!(!result.should_redact);
    }

    #[test]
    fn from_findings_computes_should_redact() {
        let findings = vec![InspectionFinding {
            rule_id: "test".into(),
            description: "test".into(),
            severity: Severity::Medium,
            category: FindingCategory::Pii,
            location: FindingLocation::Unknown,
            snippet: None,
            action: FindingAction::Redact,
        }];
        let result = InspectionResult::from_findings(findings, 0);
        assert!(!result.should_block);
        assert!(result.should_redact);
    }

    #[test]
    fn from_findings_computes_max_severity() {
        let findings = vec![
            InspectionFinding {
                rule_id: "a".into(),
                description: "a".into(),
                severity: Severity::Low,
                category: FindingCategory::Pii,
                location: FindingLocation::Unknown,
                snippet: None,
                action: FindingAction::Log,
            },
            InspectionFinding {
                rule_id: "b".into(),
                description: "b".into(),
                severity: Severity::Critical,
                category: FindingCategory::SecretLeakage,
                location: FindingLocation::Unknown,
                snippet: None,
                action: FindingAction::Block,
            },
        ];
        let result = InspectionResult::from_findings(findings, 0);
        assert_eq!(result.max_severity, Some(Severity::Critical));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn finding_category_serialization_roundtrip() {
        let categories = vec![
            FindingCategory::SecretLeakage,
            FindingCategory::Pii,
            FindingCategory::PromptInjection,
            FindingCategory::SensitiveData,
            FindingCategory::Custom("my-rule".into()),
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let parsed: FindingCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, cat);
        }
    }
}
