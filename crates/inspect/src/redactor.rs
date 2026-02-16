//! Content redaction — replace sensitive content with `[REDACTED]`.

use crate::finding::{FindingAction, FindingLocation, InspectionFinding};

/// The replacement string used for redacted content.
pub const REDACTED_MARKER: &str = "[REDACTED]";

/// Redact sensitive content from a text string based on findings.
///
/// Replaces matched byte-range regions with `[REDACTED]`. Only findings
/// with `ByteRange` locations and `Redact` or `Block` actions are applied.
/// Overlapping ranges are merged before replacement.
pub fn redact_text(text: &str, findings: &[InspectionFinding]) -> String {
    let mut ranges: Vec<(usize, usize)> = findings
        .iter()
        .filter(|f| matches!(f.action, FindingAction::Redact | FindingAction::Block))
        .filter_map(|f| match &f.location {
            FindingLocation::ByteRange { start, end } => Some((*start, *end)),
            _ => None,
        })
        .collect();

    if ranges.is_empty() {
        return text.to_string();
    }

    let ranges = merge_ranges(&mut ranges);

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;

    for &(start, end) in &ranges {
        let start = start.min(text.len());
        let end = end.min(text.len());
        if cursor < start {
            result.push_str(&text[cursor..start]);
        }
        result.push_str(REDACTED_MARKER);
        cursor = end;
    }

    if cursor < text.len() {
        result.push_str(&text[cursor..]);
    }

    result
}

/// Redact sensitive content from a JSON value based on findings.
///
/// Replaces the value at each `JsonPath` location with `"[REDACTED]"`.
/// Only findings with `JsonPath` locations and `Redact` or `Block` actions are applied.
pub fn redact_json(value: &serde_json::Value, findings: &[InspectionFinding]) -> serde_json::Value {
    let paths: Vec<&str> = findings
        .iter()
        .filter(|f| matches!(f.action, FindingAction::Redact | FindingAction::Block))
        .filter_map(|f| match &f.location {
            FindingLocation::JsonPath { path } => Some(path.as_str()),
            _ => None,
        })
        .collect();

    if paths.is_empty() {
        return value.clone();
    }

    let mut result = value.clone();
    for path in paths {
        set_json_path(
            &mut result,
            path,
            serde_json::Value::String(REDACTED_MARKER.to_string()),
        );
    }
    result
}

/// Set a value at a JSON Pointer path (RFC 6901).
///
/// Navigates the JSON tree following the pointer and replaces the target value.
/// If the path does not exist, the operation is silently ignored.
pub fn set_json_path(value: &mut serde_json::Value, pointer: &str, replacement: serde_json::Value) {
    if pointer.is_empty() {
        *value = replacement;
        return;
    }

    let segments: Vec<&str> = pointer
        .strip_prefix('/')
        .unwrap_or(pointer)
        .split('/')
        .collect();

    set_json_path_recursive(value, &segments, replacement);
}

fn set_json_path_recursive(
    value: &mut serde_json::Value,
    segments: &[&str],
    replacement: serde_json::Value,
) {
    if segments.is_empty() {
        return;
    }

    let key = unescape_json_pointer(segments[0]);

    if segments.len() == 1 {
        // Terminal segment — replace the value.
        match value {
            serde_json::Value::Object(map) => {
                if map.contains_key(&key) {
                    map.insert(key, replacement);
                }
            }
            serde_json::Value::Array(arr) => {
                if let Ok(idx) = key.parse::<usize>() {
                    if idx < arr.len() {
                        arr[idx] = replacement;
                    }
                }
            }
            _ => {}
        }
    } else {
        // Navigate deeper.
        match value {
            serde_json::Value::Object(map) => {
                if let Some(child) = map.get_mut(&key) {
                    set_json_path_recursive(child, &segments[1..], replacement);
                }
            }
            serde_json::Value::Array(arr) => {
                if let Ok(idx) = key.parse::<usize>() {
                    if let Some(child) = arr.get_mut(idx) {
                        set_json_path_recursive(child, &segments[1..], replacement);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Unescape a JSON Pointer segment per RFC 6901.
/// `~1` becomes `/`, `~0` becomes `~`.
fn unescape_json_pointer(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

/// Merge overlapping or adjacent byte ranges, returning a sorted, non-overlapping list.
pub fn merge_ranges(ranges: &mut [(usize, usize)]) -> Vec<(usize, usize)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    ranges.sort_by_key(|r| r.0);

    let mut merged: Vec<(usize, usize)> = Vec::new();
    merged.push(ranges[0]);

    for &(start, end) in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1 {
            // Overlapping or adjacent — extend.
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingCategory, FindingLocation, Severity};

    fn make_finding(start: usize, end: usize, action: FindingAction) -> InspectionFinding {
        InspectionFinding {
            rule_id: "test".into(),
            description: "test finding".into(),
            severity: Severity::High,
            category: FindingCategory::SecretLeakage,
            location: FindingLocation::ByteRange { start, end },
            snippet: None,
            action,
        }
    }

    fn make_json_finding(path: &str, action: FindingAction) -> InspectionFinding {
        InspectionFinding {
            rule_id: "test".into(),
            description: "test finding".into(),
            severity: Severity::High,
            category: FindingCategory::SecretLeakage,
            location: FindingLocation::JsonPath {
                path: path.to_string(),
            },
            snippet: None,
            action,
        }
    }

    #[test]
    fn redact_text_single_range() {
        let text = "my secret is AKIAIOSFODNN7EXAMPLE ok";
        let findings = vec![make_finding(13, 33, FindingAction::Block)];
        let result = redact_text(text, &findings);
        assert_eq!(result, "my secret is [REDACTED] ok");
    }

    #[test]
    fn redact_text_multiple_ranges() {
        let text = "AAA secret BBB secret CCC";
        let findings = vec![
            make_finding(4, 10, FindingAction::Redact),
            make_finding(15, 21, FindingAction::Block),
        ];
        let result = redact_text(text, &findings);
        assert_eq!(result, "AAA [REDACTED] BBB [REDACTED] CCC");
    }

    #[test]
    fn redact_text_overlapping_ranges() {
        let text = "0123456789ABCDEF";
        let findings = vec![
            make_finding(2, 8, FindingAction::Block),
            make_finding(5, 12, FindingAction::Block),
        ];
        let result = redact_text(text, &findings);
        assert_eq!(result, "01[REDACTED]CDEF");
    }

    #[test]
    fn redact_text_skips_log_action() {
        let text = "email user@example.com here";
        let findings = vec![make_finding(6, 22, FindingAction::Log)];
        let result = redact_text(text, &findings);
        assert_eq!(result, text); // Log action should not redact.
    }

    #[test]
    fn redact_text_no_findings() {
        let text = "Hello, world!";
        let result = redact_text(text, &[]);
        assert_eq!(result, text);
    }

    #[test]
    fn redact_json_single_path() {
        let json = serde_json::json!({
            "name": "Alice",
            "secret": "AKIAIOSFODNN7EXAMPLE"
        });
        let findings = vec![make_json_finding("/secret", FindingAction::Block)];
        let result = redact_json(&json, &findings);
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["secret"], REDACTED_MARKER);
    }

    #[test]
    fn redact_json_nested_path() {
        let json = serde_json::json!({
            "config": {
                "credentials": {
                    "token": "ghp_secret123456789012345678901234567890"
                }
            }
        });
        let findings = vec![make_json_finding(
            "/config/credentials/token",
            FindingAction::Redact,
        )];
        let result = redact_json(&json, &findings);
        assert_eq!(result["config"]["credentials"]["token"], REDACTED_MARKER);
    }

    #[test]
    fn redact_json_array_index() {
        let json = serde_json::json!({
            "items": ["clean", "AKIAIOSFODNN7EXAMPLE", "also clean"]
        });
        let findings = vec![make_json_finding("/items/1", FindingAction::Block)];
        let result = redact_json(&json, &findings);
        assert_eq!(result["items"][0], "clean");
        assert_eq!(result["items"][1], REDACTED_MARKER);
        assert_eq!(result["items"][2], "also clean");
    }

    #[test]
    fn redact_json_skips_log_action() {
        let json = serde_json::json!({
            "email": "user@example.com"
        });
        let findings = vec![make_json_finding("/email", FindingAction::Log)];
        let result = redact_json(&json, &findings);
        assert_eq!(result["email"], "user@example.com");
    }

    #[test]
    fn redact_json_nonexistent_path_is_noop() {
        let json = serde_json::json!({"key": "value"});
        let findings = vec![make_json_finding("/nonexistent", FindingAction::Block)];
        let result = redact_json(&json, &findings);
        assert_eq!(result, json);
    }

    #[test]
    fn merge_ranges_no_overlap() {
        let mut ranges = vec![(0, 5), (10, 15)];
        let merged = merge_ranges(&mut ranges);
        assert_eq!(merged, vec![(0, 5), (10, 15)]);
    }

    #[test]
    fn merge_ranges_overlap() {
        let mut ranges = vec![(0, 10), (5, 15)];
        let merged = merge_ranges(&mut ranges);
        assert_eq!(merged, vec![(0, 15)]);
    }

    #[test]
    fn merge_ranges_adjacent() {
        let mut ranges = vec![(0, 5), (5, 10)];
        let merged = merge_ranges(&mut ranges);
        assert_eq!(merged, vec![(0, 10)]);
    }

    #[test]
    fn merge_ranges_unsorted() {
        let mut ranges = vec![(10, 20), (0, 5), (3, 12)];
        let merged = merge_ranges(&mut ranges);
        assert_eq!(merged, vec![(0, 20)]);
    }

    #[test]
    fn merge_ranges_empty() {
        let mut ranges: Vec<(usize, usize)> = vec![];
        let merged = merge_ranges(&mut ranges);
        assert!(merged.is_empty());
    }

    #[test]
    fn set_json_path_with_escaped_key() {
        let mut json = serde_json::json!({
            "a/b": "secret"
        });
        set_json_path(
            &mut json,
            "/a~1b",
            serde_json::Value::String(REDACTED_MARKER.to_string()),
        );
        assert_eq!(json["a/b"], REDACTED_MARKER);
    }

    #[test]
    fn set_json_path_root() {
        let mut json = serde_json::json!("secret");
        set_json_path(
            &mut json,
            "",
            serde_json::Value::String(REDACTED_MARKER.to_string()),
        );
        assert_eq!(json, REDACTED_MARKER);
    }
}
