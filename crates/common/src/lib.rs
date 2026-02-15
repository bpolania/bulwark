//! Bulwark common — shared error types and constants used across all crates.
#![forbid(unsafe_code)]

/// The current version of the Bulwark crate, set at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use thiserror::Error;

/// Top-level error type for the Bulwark project.
#[derive(Error, Debug)]
pub enum BulwarkError {
    /// A configuration-related error.
    #[error("configuration error: {0}")]
    Config(String),

    /// A TLS-related error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// A proxy-related error.
    #[error("proxy error: {0}")]
    Proxy(String),

    /// An MCP-related error.
    #[error("MCP error: {0}")]
    Mcp(String),

    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A catch-all error variant.
    #[error("{0}")]
    Other(String),
}

/// Convenience result type alias using [`BulwarkError`].
pub type Result<T> = std::result::Result<T, BulwarkError>;
