//! YAML policy file parsing and directory loading.

use std::path::Path;

use crate::schema::PolicyFile;

/// Parse a single YAML policy file.
pub fn parse_policy_file(path: &Path) -> Result<PolicyFile, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let policy: PolicyFile = serde_yaml::from_str(&contents)
        .map_err(|e| format!("invalid YAML in {}: {e}", path.display()))?;
    Ok(policy)
}

/// Load all YAML policy files from a directory (recursive).
///
/// Returns a list of `(path, PolicyFile)` pairs.
pub fn load_policies_from_directory(
    dir: &Path,
) -> Result<Vec<(std::path::PathBuf, PolicyFile)>, String> {
    if !dir.exists() {
        return Err(format!("policies directory not found: {}", dir.display()));
    }
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", dir.display()));
    }

    let mut results = Vec::new();
    walk_recursive(dir, &mut results)?;
    results.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(results)
}

/// Recursively walk a directory collecting YAML policy files.
fn walk_recursive(
    dir: &Path,
    results: &mut Vec<(std::path::PathBuf, PolicyFile)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory {}: {e}", dir.display()))?;

    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk_recursive(&path, results)?;
        } else if is_yaml_file(&path) {
            let policy = parse_policy_file(&path)?;
            results.push((path, policy));
        }
    }

    Ok(())
}

/// Check if a path has a `.yaml` or `.yml` extension.
fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        std::fs::write(
            &path,
            r#"
metadata:
  name: test
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
        )
        .unwrap();

        let policy = parse_policy_file(&path).unwrap();
        assert_eq!(policy.metadata.name, "test");
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn parse_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "{{invalid yaml").unwrap();

        let result = parse_policy_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid YAML"));
    }

    #[test]
    fn missing_file_errors() {
        let result = parse_policy_file(Path::new("/nonexistent/policy.yaml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read"));
    }

    #[test]
    fn load_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.yaml"),
            "rules:\n  - name: r1\n    verdict: allow\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.yml"),
            "rules:\n  - name: r2\n    verdict: deny\n",
        )
        .unwrap();
        // Non-YAML file should be ignored.
        std::fs::write(dir.path().join("readme.txt"), "ignore me").unwrap();

        let policies = load_policies_from_directory(dir.path()).unwrap();
        assert_eq!(policies.len(), 2);
    }

    #[test]
    fn load_nonexistent_directory() {
        let result = load_policies_from_directory(Path::new("/nonexistent/dir"));
        assert!(result.is_err());
    }

    #[test]
    fn load_recursive_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(
            dir.path().join("root.yaml"),
            "rules:\n  - name: r1\n    verdict: allow\n",
        )
        .unwrap();
        std::fs::write(
            sub.join("nested.yaml"),
            "rules:\n  - name: r2\n    verdict: deny\n",
        )
        .unwrap();

        let policies = load_policies_from_directory(dir.path()).unwrap();
        assert_eq!(policies.len(), 2);
    }
}
