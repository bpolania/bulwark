//! Glob pattern matching — converts glob syntax to regex for matching.

use regex::Regex;

/// A compiled glob pattern backed by a regex.
#[derive(Debug, Clone)]
pub struct GlobPattern {
    regex: Regex,
    source: String,
}

impl GlobPattern {
    /// Compile a glob pattern into a `GlobPattern`.
    ///
    /// Supported syntax:
    /// - `*` matches any number of characters
    /// - `?` matches any single character
    /// - `{a,b}` matches either `a` or `b`
    /// - `[abc]` matches any character in the set
    /// - All matching is case-insensitive
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let regex_str = glob_to_regex(pattern)?;
        let regex =
            Regex::new(&regex_str).map_err(|e| format!("invalid glob pattern '{pattern}': {e}"))?;
        Ok(Self {
            regex,
            source: pattern.to_string(),
        })
    }

    /// Test whether the input matches this pattern.
    pub fn matches(&self, input: &str) -> bool {
        self.regex.is_match(input)
    }

    /// Return the original glob pattern string.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Convert a glob pattern to a regex string.
fn glob_to_regex(pattern: &str) -> Result<String, String> {
    let mut regex = String::with_capacity(pattern.len() * 2);
    regex.push_str("(?i)^");

    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        match chars[i] {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '[' => {
                // Character class — pass through to regex.
                regex.push('[');
                i += 1;
                let mut found_close = false;
                while i < len {
                    if chars[i] == ']' {
                        regex.push(']');
                        found_close = true;
                        break;
                    }
                    regex.push(chars[i]);
                    i += 1;
                }
                if !found_close {
                    return Err(format!("unclosed '[' in pattern: {pattern}"));
                }
            }
            '{' => {
                // Brace expansion: {a,b,c} → (?:a|b|c)
                regex.push_str("(?:");
                i += 1;
                let mut found_close = false;
                while i < len {
                    match chars[i] {
                        '}' => {
                            regex.push(')');
                            found_close = true;
                            break;
                        }
                        ',' => regex.push('|'),
                        c => {
                            // Escape regex-special chars within brace alternatives.
                            if is_regex_special(c) {
                                regex.push('\\');
                            }
                            regex.push(c);
                        }
                    }
                    i += 1;
                }
                if !found_close {
                    return Err(format!("unclosed '{{' in pattern: {pattern}"));
                }
            }
            c => {
                // Escape regex-special characters.
                if is_regex_special(c) {
                    regex.push('\\');
                }
                regex.push(c);
            }
        }
        i += 1;
    }

    regex.push('$');
    Ok(regex)
}

/// Returns `true` if the character has special meaning in regex and needs escaping.
fn is_regex_special(c: char) -> bool {
    matches!(
        c,
        '.' | '+' | '^' | '$' | '|' | '(' | ')' | '\\' | '/' | '-'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let pat = GlobPattern::compile("hello").unwrap();
        assert!(pat.matches("hello"));
        assert!(pat.matches("HELLO"));
        assert!(!pat.matches("hello!"));
        assert!(!pat.matches("ahello"));
    }

    #[test]
    fn wildcard_star() {
        let pat = GlobPattern::compile("read_*").unwrap();
        assert!(pat.matches("read_file"));
        assert!(pat.matches("read_"));
        assert!(pat.matches("read_anything_here"));
        assert!(!pat.matches("write_file"));
    }

    #[test]
    fn wildcard_question() {
        let pat = GlobPattern::compile("t?st").unwrap();
        assert!(pat.matches("test"));
        assert!(pat.matches("tost"));
        assert!(!pat.matches("toast"));
    }

    #[test]
    fn star_only() {
        let pat = GlobPattern::compile("*").unwrap();
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn brace_expansion() {
        let pat = GlobPattern::compile("{read,write}_file").unwrap();
        assert!(pat.matches("read_file"));
        assert!(pat.matches("write_file"));
        assert!(!pat.matches("delete_file"));
    }

    #[test]
    fn char_class() {
        let pat = GlobPattern::compile("[abc]_tool").unwrap();
        assert!(pat.matches("a_tool"));
        assert!(pat.matches("b_tool"));
        assert!(pat.matches("c_tool"));
        assert!(!pat.matches("d_tool"));
    }

    #[test]
    fn case_insensitive() {
        let pat = GlobPattern::compile("GitHub").unwrap();
        assert!(pat.matches("github"));
        assert!(pat.matches("GITHUB"));
        assert!(pat.matches("GitHub"));
    }

    #[test]
    fn special_chars_escaped() {
        let pat = GlobPattern::compile("GET /api/v1").unwrap();
        assert!(pat.matches("GET /api/v1"));
        assert!(!pat.matches("GET Xapi/v1"));
    }

    #[test]
    fn dot_escaped() {
        let pat = GlobPattern::compile("api.example.com").unwrap();
        assert!(pat.matches("api.example.com"));
        assert!(!pat.matches("apixexamplexcom"));
    }

    #[test]
    fn complex_pattern() {
        let pat = GlobPattern::compile("{GET,POST} /api/*").unwrap();
        assert!(pat.matches("GET /api/users"));
        assert!(pat.matches("POST /api/data"));
        assert!(!pat.matches("DELETE /api/users"));
    }

    #[test]
    fn empty_pattern() {
        let pat = GlobPattern::compile("").unwrap();
        assert!(pat.matches(""));
        assert!(!pat.matches("x"));
    }

    #[test]
    fn unclosed_bracket_errors() {
        let result = GlobPattern::compile("[abc");
        assert!(result.is_err());
    }

    #[test]
    fn unclosed_brace_errors() {
        let result = GlobPattern::compile("{a,b");
        assert!(result.is_err());
    }

    #[test]
    fn star_prefix() {
        let pat = GlobPattern::compile("*_file").unwrap();
        assert!(pat.matches("read_file"));
        assert!(pat.matches("_file"));
        assert!(!pat.matches("file"));
    }

    #[test]
    fn multiple_stars() {
        let pat = GlobPattern::compile("*__*").unwrap();
        assert!(pat.matches("server__tool"));
        assert!(pat.matches("a__b"));
        assert!(!pat.matches("notool"));
    }

    #[test]
    fn source_preserved() {
        let pat = GlobPattern::compile("my_pattern*").unwrap();
        assert_eq!(pat.source(), "my_pattern*");
    }
}
