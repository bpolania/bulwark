//! Bulwark config — configuration loading and validation.
//!
//! Loads [`BulwarkConfig`] from a YAML file, falling back to sensible defaults
//! when the file does not exist.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Top-level Bulwark configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BulwarkConfig {
    /// Proxy server settings.
    pub proxy: ProxyConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
    /// MCP gateway settings.
    pub mcp_gateway: McpGatewayConfig,
    /// Policy engine settings.
    pub policy: PolicyConfig,
    /// Vault settings.
    pub vault: VaultConfig,
    /// Audit settings.
    pub audit: AuditConfig,
    /// Content inspection settings.
    pub inspect: bulwark_inspect::config::InspectionConfig,
    /// Rate limiting settings.
    pub rate_limit: RateLimitConfig,
    /// Cost estimation settings.
    pub cost_estimation: CostConfig,
}

/// Configuration for the proxy listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Address to listen on (e.g. `"127.0.0.1:8080"`).
    pub listen_address: String,
    /// TLS / certificate authority settings.
    pub tls: TlsConfig,
    /// URL-to-tool mappings for semantic policy evaluation.
    pub tool_mappings: Vec<ToolMapping>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:8080".to_string(),
            tls: TlsConfig::default(),
            tool_mappings: Vec::new(),
        }
    }
}

/// Maps a URL pattern to a semantic tool name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolMapping {
    /// Glob pattern to match against the URL (host + path).
    pub url_pattern: String,
    /// Semantic tool name to use for policy evaluation.
    pub tool: String,
    /// How to derive the action from the request.
    #[serde(default)]
    pub action_from: ActionFrom,
}

/// How to derive the policy action from an HTTP request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ActionFrom {
    /// Use the URL path as the action (default).
    #[default]
    UrlPath,
    /// Use the HTTP method as the action.
    Method,
    /// Use a specific path segment (0-indexed) as the action.
    PathSegment(usize),
    /// Use a fixed string as the action.
    Static(String),
}

impl Serialize for ActionFrom {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ActionFrom::UrlPath => serializer.serialize_str("url_path"),
            ActionFrom::Method => serializer.serialize_str("method"),
            ActionFrom::PathSegment(n) => serializer.serialize_str(&format!("path_segment:{n}")),
            ActionFrom::Static(s) => serializer.serialize_str(&format!("static:{s}")),
        }
    }
}

impl<'de> Deserialize<'de> for ActionFrom {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "url_path" {
            Ok(ActionFrom::UrlPath)
        } else if s == "method" {
            Ok(ActionFrom::Method)
        } else if let Some(rest) = s.strip_prefix("path_segment:") {
            let n: usize = rest.parse().map_err(|e| {
                serde::de::Error::custom(format!("invalid path_segment index: {e}"))
            })?;
            Ok(ActionFrom::PathSegment(n))
        } else if let Some(rest) = s.strip_prefix("static:") {
            Ok(ActionFrom::Static(rest.to_string()))
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown action_from variant: '{s}'. Expected url_path, method, path_segment:N, or static:VALUE"
            )))
        }
    }
}

/// TLS-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Directory to store the generated CA certificate and key.
    pub ca_dir: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_dir: "~/.bulwark/ca".to_string(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Machine-readable JSON lines.
    #[default]
    Json,
    /// Human-readable pretty output.
    Pretty,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Output format.
    pub format: LogFormat,
    /// Minimum log level (`trace`, `debug`, `info`, `warn`, `error`).
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            level: "info".to_string(),
        }
    }
}

/// Configuration for the MCP governance gateway.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct McpGatewayConfig {
    /// Upstream MCP tool servers.
    pub upstream_servers: Vec<UpstreamServerConfig>,
}

/// Configuration for a single upstream MCP tool server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServerConfig {
    /// Logical name used for tool namespacing.
    pub name: String,
    /// Command to spawn (e.g. `"npx"`).
    pub command: String,
    /// Arguments passed to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to set for the child process.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Policy engine configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Directory containing YAML policy files.
    pub policies_dir: String,
    /// Whether to watch for policy file changes and reload automatically.
    pub hot_reload: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policies_dir: "./policies".to_string(),
            hot_reload: true,
        }
    }
}

/// Credential vault configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VaultConfig {
    /// Path to the vault key file.
    pub key_path: String,
    /// Path to the credentials directory.
    pub credentials_dir: String,
    /// Path to the bindings file.
    pub bindings_path: String,
    /// Path to the sessions database.
    pub sessions_db_path: String,
    /// Whether sessions are required (strict mode).
    /// If true, requests without a valid session token are rejected.
    /// If false, requests without a session proceed with no operator context.
    pub require_sessions: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            key_path: "~/.bulwark/vault-key.age".to_string(),
            credentials_dir: "~/.bulwark/credentials".to_string(),
            bindings_path: "~/.bulwark/bindings.yaml".to_string(),
            sessions_db_path: "~/.bulwark/sessions.db".to_string(),
            require_sessions: false,
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Path to the audit database.
    pub db_path: String,
    /// Whether audit logging is enabled.
    pub enabled: bool,
    /// Retention period in days (0 = no retention, keep everything).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.bulwark/audit.db".to_string(),
            enabled: true,
            retention_days: 90,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    pub enabled: bool,
    /// Default requests per minute.
    pub default_rpm: u32,
    /// Default burst size.
    pub default_burst: u32,
    /// Rate limit rules.
    pub rules: Vec<RateLimitRule>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_rpm: 60,
            default_burst: 10,
            rules: Vec::new(),
        }
    }
}

/// A single rate limit rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitRule {
    /// Rule name for diagnostics.
    pub name: String,
    /// Tool patterns this rule applies to.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Requests per minute.
    pub rpm: u32,
    /// Burst size.
    pub burst: u32,
    /// Dimensions to rate limit on (e.g. "session", "operator", "tool", "global").
    #[serde(default)]
    pub dimensions: Vec<String>,
}

/// Cost estimation configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CostConfig {
    /// Whether cost estimation is enabled.
    pub enabled: bool,
    /// Default cost per request.
    pub default_cost: f64,
    /// Cost rules.
    pub rules: Vec<CostRule>,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_cost: 0.01,
            rules: Vec::new(),
        }
    }
}

/// A single cost rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CostRule {
    /// Tool patterns this rule applies to.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Cost per request.
    pub cost: f64,
    /// Monthly budget limit (None = unlimited).
    #[serde(default)]
    pub monthly_budget: Option<f64>,
}

/// Resolve `${VAR_NAME}` references in a string to environment variables.
pub fn resolve_env_vars(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        std::env::var(var_name).unwrap_or_default()
    } else {
        value.to_string()
    }
}

/// Expand a leading `~` in a path to the user's home directory.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~') {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{rest}", home.display());
        }
    }
    path.to_string()
}

/// Load configuration from the given YAML file path.
///
/// Returns [`BulwarkConfig::default()`] when the file does not exist.
/// Returns an error if the file exists but cannot be parsed.
pub fn load_config(path: &Path) -> bulwark_common::Result<BulwarkConfig> {
    if !path.exists() {
        tracing::info!(?path, "config file not found, using defaults");
        return Ok(BulwarkConfig::default());
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| bulwark_common::BulwarkError::Config(format!("failed to read config: {e}")))?;
    let config: BulwarkConfig = serde_yaml::from_str(&contents)
        .map_err(|e| bulwark_common::BulwarkError::Config(format!("invalid YAML: {e}")))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = BulwarkConfig::default();
        assert_eq!(cfg.proxy.listen_address, "127.0.0.1:8080");
        assert_eq!(cfg.proxy.tls.ca_dir, "~/.bulwark/ca");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn expand_tilde_works() {
        let expanded = expand_tilde("~/.bulwark/ca");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with("/.bulwark/ca"));
    }

    #[test]
    fn missing_file_returns_defaults() {
        let cfg = load_config(Path::new("/nonexistent/bulwark.yaml")).unwrap();
        assert_eq!(cfg.proxy.listen_address, "127.0.0.1:8080");
    }

    #[test]
    fn test_tool_mapping_config() {
        let yaml = r#"
proxy:
  tool_mappings:
    - url_pattern: "api.openai.com/*"
      tool: openai
      action_from: "url_path"
    - url_pattern: "*.github.com/api/*"
      tool: github
      action_from: "method"
"#;
        let cfg: BulwarkConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.proxy.tool_mappings.len(), 2);
        assert_eq!(cfg.proxy.tool_mappings[0].tool, "openai");
        assert_eq!(cfg.proxy.tool_mappings[0].action_from, ActionFrom::UrlPath);
        assert_eq!(cfg.proxy.tool_mappings[1].action_from, ActionFrom::Method);
    }

    #[test]
    fn test_rate_limit_config() {
        let yaml = r#"
rate_limit:
  enabled: true
  default_rpm: 120
  default_burst: 20
  rules:
    - name: openai-limit
      tools: ["openai"]
      rpm: 30
      burst: 5
      dimensions: ["session", "operator"]
"#;
        let cfg: BulwarkConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.default_rpm, 120);
        assert_eq!(cfg.rate_limit.default_burst, 20);
        assert_eq!(cfg.rate_limit.rules.len(), 1);
        assert_eq!(cfg.rate_limit.rules[0].name, "openai-limit");
        assert_eq!(cfg.rate_limit.rules[0].rpm, 30);
        assert_eq!(
            cfg.rate_limit.rules[0].dimensions,
            vec!["session", "operator"]
        );
    }

    #[test]
    fn test_cost_config() {
        let yaml = r#"
cost_estimation:
  enabled: true
  default_cost: 0.05
  rules:
    - tools: ["openai"]
      cost: 0.10
      monthly_budget: 100.0
    - tools: ["github"]
      cost: 0.001
"#;
        let cfg: BulwarkConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.cost_estimation.enabled);
        assert!((cfg.cost_estimation.default_cost - 0.05).abs() < f64::EPSILON);
        assert_eq!(cfg.cost_estimation.rules.len(), 2);
        assert!((cfg.cost_estimation.rules[0].cost - 0.10).abs() < f64::EPSILON);
        assert_eq!(cfg.cost_estimation.rules[0].monthly_budget, Some(100.0));
        assert_eq!(cfg.cost_estimation.rules[1].monthly_budget, None);
    }

    #[test]
    fn test_action_from_variants() {
        // url_path
        let v: ActionFrom = serde_yaml::from_str("\"url_path\"").unwrap();
        assert_eq!(v, ActionFrom::UrlPath);

        // method
        let v: ActionFrom = serde_yaml::from_str("\"method\"").unwrap();
        assert_eq!(v, ActionFrom::Method);

        // path_segment:2
        let v: ActionFrom = serde_yaml::from_str("\"path_segment:2\"").unwrap();
        assert_eq!(v, ActionFrom::PathSegment(2));

        // static:read
        let v: ActionFrom = serde_yaml::from_str("\"static:read\"").unwrap();
        assert_eq!(v, ActionFrom::Static("read".to_string()));

        // invalid
        let result: Result<ActionFrom, _> = serde_yaml::from_str("\"bogus\"");
        assert!(result.is_err());
    }
}
