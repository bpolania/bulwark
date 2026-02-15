//! Structured request/response logging for every proxied request.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A structured log entry for a single proxied HTTP request.
#[derive(Debug, Serialize)]
pub struct RequestLog {
    /// Unique identifier for this request.
    pub id: Uuid,
    /// When the request was received.
    pub timestamp: DateTime<Utc>,
    /// HTTP method (GET, POST, …).
    pub method: String,
    /// Full URL that was requested.
    pub url: String,
    /// Target host.
    pub host: String,
    /// HTTP response status code.
    pub status: u16,
    /// Round-trip latency in milliseconds.
    pub latency_ms: f64,
    /// Size of the request body in bytes.
    pub request_bytes: u64,
    /// Size of the response body in bytes.
    pub response_bytes: u64,
    /// Whether this request was made over TLS.
    pub tls: bool,
    /// Error message, if the request failed.
    pub error: Option<String>,
}

impl RequestLog {
    /// Emit this log entry via the `tracing` infrastructure.
    pub fn emit(&self) {
        tracing::info!(
            id = %self.id,
            method = %self.method,
            url = %self.url,
            host = %self.host,
            status = self.status,
            latency_ms = self.latency_ms,
            request_bytes = self.request_bytes,
            response_bytes = self.response_bytes,
            tls = self.tls,
            error = self.error.as_deref().unwrap_or(""),
            "proxy request"
        );
    }
}
