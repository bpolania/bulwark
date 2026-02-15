//! Structured MCP event logging via tracing.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// The type of MCP event being logged.
#[derive(Debug, Serialize)]
pub enum McpEventType {
    ToolCall,
    ToolResponse,
    ServerStart,
    ServerStop,
    ServerCrash,
    Initialize,
}

/// A structured log entry for an MCP event.
#[derive(Debug, Serialize)]
pub struct McpLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: McpEventType,
    pub server_name: Option<String>,
    pub tool_name: Option<String>,
    pub method: String,
    pub latency_ms: Option<f64>,
    pub is_error: bool,
    pub error: Option<String>,
}

impl McpLog {
    pub fn emit(&self) {
        tracing::info!(
            id = %self.id,
            event_type = ?self.event_type,
            server_name = self.server_name.as_deref().unwrap_or("-"),
            tool_name = self.tool_name.as_deref().unwrap_or("-"),
            method = %self.method,
            latency_ms = self.latency_ms.unwrap_or(-1.0),
            is_error = self.is_error,
            "mcp event"
        );
    }
}
