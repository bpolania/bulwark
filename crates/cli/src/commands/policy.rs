//! `bulwark policy validate` — check policy files for errors.

use std::path::Path;

use anyhow::Result;
use bulwark_policy::validation::validate_policies;

/// Validate policy files in the given directory.
pub fn validate(path: &Path) -> Result<()> {
    println!("Validating policies in {}", path.display());
    println!();

    let result = validate_policies(path);

    for error in &result.errors {
        println!("  ERROR: {error}");
    }
    for warning in &result.warnings {
        println!("  WARN:  {warning}");
    }

    if result.errors.is_empty() && result.warnings.is_empty() {
        println!("  All policies valid.");
    }

    println!();

    if result.is_ok() {
        println!("Validation passed.");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "validation failed with {} error(s)",
            result.errors.len()
        ))
    }
}
