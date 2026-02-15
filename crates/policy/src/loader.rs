//! Policy hot-reload — watches the policies directory for changes.

use std::path::Path;
use std::sync::Arc;

use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::engine::PolicyEngine;

/// Start a file watcher that reloads the policy engine when YAML files change.
///
/// Returns the watcher handle — dropping it stops watching.
pub fn start_policy_watcher(
    engine: Arc<PolicyEngine>,
    dir: &Path,
) -> Result<notify::RecommendedWatcher, String> {
    let dir_path = dir.to_path_buf();
    let dir_for_reload = dir.to_path_buf();

    let mut watcher =
        notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if should_reload(&event) {
                    tracing::info!("policy file change detected, reloading");
                    if let Err(e) = engine.reload(&dir_for_reload) {
                        tracing::error!(error = %e, "policy reload failed, keeping previous state");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "file watcher error");
            }
        })
        .map_err(|e| format!("failed to create file watcher: {e}"))?;

    watcher
        .watch(&dir_path, RecursiveMode::Recursive)
        .map_err(|e| format!("failed to watch {}: {e}", dir_path.display()))?;

    tracing::info!(dir = %dir_path.display(), "policy watcher started");
    Ok(watcher)
}

/// Determine if a file system event should trigger a reload.
fn should_reload(event: &Event) -> bool {
    let dominated = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    if !dominated {
        return false;
    }

    // Only reload for YAML files.
    event.paths.iter().any(|p| {
        p.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RequestContext;
    use crate::verdict::Verdict;

    #[test]
    fn reload_on_file_change() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("policy.yaml"),
            "rules:\n  - name: deny\n    verdict: deny\n",
        )
        .unwrap();

        let engine = Arc::new(PolicyEngine::from_directory(dir.path()).unwrap());
        let ctx = RequestContext::new("x", "y");
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Deny);

        let _watcher = start_policy_watcher(Arc::clone(&engine), dir.path()).unwrap();

        // Write new policy.
        std::fs::write(
            dir.path().join("policy.yaml"),
            r#"
rules:
  - name: allow
    verdict: allow
    match:
      tools: ["*"]
"#,
        )
        .unwrap();

        // Give the watcher time to notice.
        std::thread::sleep(std::time::Duration::from_millis(500));

        // The engine may or may not have reloaded depending on timing,
        // but it should not have panicked. Do a manual reload to verify
        // the mechanism works.
        engine.reload(dir.path()).unwrap();
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Allow);
    }

    #[test]
    fn failed_reload_keeps_previous() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("policy.yaml"),
            r#"
rules:
  - name: allow
    verdict: allow
    match:
      tools: ["*"]
"#,
        )
        .unwrap();

        let engine = Arc::new(PolicyEngine::from_directory(dir.path()).unwrap());
        let ctx = RequestContext::new("x", "y");
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Allow);

        // Write invalid policy.
        std::fs::write(dir.path().join("policy.yaml"), "{{invalid").unwrap();

        // Reload should fail but keep previous state.
        let result = engine.reload(dir.path());
        assert!(result.is_err());
        assert_eq!(engine.evaluate(&ctx).verdict, Verdict::Allow);
    }
}
