//! Policy validation — checks YAML policies for common mistakes.

use std::collections::HashSet;
use std::path::Path;

use crate::glob::GlobPattern;
use crate::parser::load_policies_from_directory;
use crate::verdict::Verdict;

/// Result of validating a set of policy files.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// Hard errors that prevent the policies from being loaded.
    pub errors: Vec<String>,
    /// Warnings about potential issues.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Returns `true` if validation passed with no errors.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate all policy files in a directory.
pub fn validate_policies(dir: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();

    let policies = match load_policies_from_directory(dir) {
        Ok(p) => p,
        Err(e) => {
            result.errors.push(e);
            return result;
        }
    };

    if policies.is_empty() {
        result.warnings.push("no policy files found".to_string());
        return result;
    }

    let mut all_rule_names = HashSet::new();
    let mut has_default_deny = false;

    for (path, policy) in &policies {
        let path_str = path.display().to_string();

        if policy.rules.is_empty() {
            result
                .warnings
                .push(format!("{path_str}: policy file has no rules"));
            continue;
        }

        for rule in &policy.rules {
            // Check for duplicate rule names.
            if !all_rule_names.insert(rule.name.clone()) {
                result
                    .warnings
                    .push(format!("{path_str}: duplicate rule name '{}'", rule.name));
            }

            // Check for disabled rules.
            if !rule.enabled {
                result
                    .warnings
                    .push(format!("{path_str}: rule '{}' is disabled", rule.name));
            }

            // Validate glob patterns.
            for pattern in &rule.match_criteria.tools {
                if let Err(e) = GlobPattern::compile(pattern) {
                    result.errors.push(format!(
                        "{path_str}: rule '{}' has invalid tool glob: {e}",
                        rule.name
                    ));
                }
            }
            for pattern in &rule.match_criteria.actions {
                if let Err(e) = GlobPattern::compile(pattern) {
                    result.errors.push(format!(
                        "{path_str}: rule '{}' has invalid action glob: {e}",
                        rule.name
                    ));
                }
            }
            for pattern in &rule.match_criteria.resources {
                if let Err(e) = GlobPattern::compile(pattern) {
                    result.errors.push(format!(
                        "{path_str}: rule '{}' has invalid resource glob: {e}",
                        rule.name
                    ));
                }
            }

            // Check for a catch-all deny (default deny).
            if rule.verdict == Verdict::Deny
                && rule.enabled
                && rule.match_criteria.tools.is_empty()
                && rule.match_criteria.actions.is_empty()
                && rule.match_criteria.resources.is_empty()
                && rule.conditions.operators.is_empty()
                && rule.conditions.teams.is_empty()
                && rule.conditions.environments.is_empty()
                && rule.conditions.agent_types.is_empty()
                && rule.conditions.labels.is_empty()
            {
                has_default_deny = true;
            }
        }
    }

    if !has_default_deny {
        result.warnings.push(
            "no explicit default-deny rule found; the engine will deny by default, \
             but an explicit rule is recommended"
                .to_string(),
        );
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn valid_policies() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-reads
    verdict: allow
    match:
      tools: ["*"]
      actions: ["read_*"]
  - name: deny-all
    verdict: deny
"#,
        );

        let result = validate_policies(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_glob_detected() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: bad-glob
    verdict: allow
    match:
      tools: ["[unclosed"]
"#,
        );

        let result = validate_policies(dir.path());
        assert!(!result.is_ok());
        assert!(result.errors[0].contains("invalid tool glob"));
    }

    #[test]
    fn duplicate_names_warned() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "a.yaml",
            "rules:\n  - name: same-name\n    verdict: allow\n",
        );
        write_file(
            dir.path(),
            "b.yaml",
            "rules:\n  - name: same-name\n    verdict: deny\n",
        );

        let result = validate_policies(dir.path());
        assert!(result.warnings.iter().any(|w| w.contains("duplicate")));
    }

    #[test]
    fn no_default_deny_warned() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        );

        let result = validate_policies(dir.path());
        assert!(result.warnings.iter().any(|w| w.contains("default-deny")));
    }

    #[test]
    fn disabled_rule_warned() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "policy.yaml",
            r#"
rules:
  - name: disabled
    verdict: deny
    enabled: false
"#,
        );

        let result = validate_policies(dir.path());
        assert!(result.warnings.iter().any(|w| w.contains("disabled")));
    }

    #[test]
    fn empty_directory_warned() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_policies(dir.path());
        assert!(result.warnings.iter().any(|w| w.contains("no policy")));
    }
}
