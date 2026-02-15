//! Bulwark config — configuration loading and validation.
//!
//! Loads [`BulwarkConfig`] from a YAML file, falling back to sensible defaults
//! when the file does not exist.
#![forbid(unsafe_code)]

use std::path::Path;

use serde::Deserialize;

/// Top-level Bulwark configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BulwarkConfig {
    /// Proxy server settings.
    pub proxy: ProxyConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
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
