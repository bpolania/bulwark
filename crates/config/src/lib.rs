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
}

/// Configuration for the proxy listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Address to listen on (e.g. `"127.0.0.1:8080"`).
    pub listen_address: String,
    /// TLS / certificate authority settings.
    pub tls: TlsConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:8080".to_string(),
            tls: TlsConfig::default(),
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
}
