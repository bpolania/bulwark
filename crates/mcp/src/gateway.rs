//! MCP Gateway orchestrator — intercepts tool calls, logs, forwards, responds.

use std::collections::HashMap;
use std::sync::Arc;

use bulwark_config::McpGatewayConfig;

use crate::governance::governance_metadata_stub;
use crate::types::{
    INTERNAL_ERROR, INVALID_REQUEST, InitializeResult, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, METHOD_NOT_FOUND, ServerCapabilities, ServerInfo, Tool, ToolCallParams,
    ToolsCapability,
};
use crate::upstream::UpstreamServer;

/// The MCP governance gateway — owns upstream servers and handles agent requests.
pub struct McpGateway {
    upstreams: HashMap<String, Arc<tokio::sync::Mutex<UpstreamServer>>>,
    #[allow(dead_code)]
    config: McpGatewayConfig,
}

impl McpGateway {
    /// Create the gateway and start all upstream servers.
    pub async fn new(config: McpGatewayConfig) -> bulwark_common::Result<Self> {
        let mut upstreams = HashMap::new();
        for server_config in &config.upstream_servers {
            let server = UpstreamServer::new(server_config.clone()).await?;
            upstreams.insert(
                server_config.name.clone(),
                Arc::new(tokio::sync::Mutex::new(server)),
            );
        }
        Ok(Self { upstreams, config })
    }

    /// Create a gateway with pre-built upstream servers (for testing).
    pub fn new_with_upstreams(
        upstreams: HashMap<String, Arc<tokio::sync::Mutex<UpstreamServer>>>,
    ) -> Self {
        Self {
            upstreams,
            config: McpGatewayConfig::default(),
        }
    }

    /// Handle a JSON-RPC message from the agent. Returns a response to send back.
    pub async fn handle_message(&self, msg: JsonRpcMessage) -> Option<JsonRpcMessage> {
        match msg {
            JsonRpcMessage::Request(req) => {
                let response = match req.method.as_str() {
                    "initialize" => self.handle_initialize(&req),
                    "tools/list" => self.handle_tools_list(&req).await,
                    "tools/call" => self.handle_tools_call(&req).await,
                    "ping" => self.handle_ping(&req),
                    _ => JsonRpcResponse::error(
                        req.id.clone(),
                        METHOD_NOT_FOUND,
                        format!("Unknown method: {}", req.method),
                    ),
                };
                Some(JsonRpcMessage::Response(response))
            }
            JsonRpcMessage::Notification(notif) => {
                match notif.method.as_str() {
                    "notifications/initialized" => {
                        tracing::info!("Agent initialized");
                    }
                    "notifications/cancelled" => {
                        tracing::debug!("Agent cancelled a request");
                    }
                    _ => {
                        tracing::debug!(method = %notif.method, "Unhandled notification");
                    }
                }
                None
            }
            JsonRpcMessage::Response(_) => {
                tracing::warn!("Unexpected response from agent");
                None
            }
        }
    }

    /// Get the merged tool list from all upstream servers, with namespacing.
    pub async fn merged_tools(&self) -> Vec<Tool> {
        let mut result = Vec::new();
        for (server_name, upstream) in &self.upstreams {
            let server = upstream.lock().await;
            for tool in server.tools() {
                let namespaced_name = format!("{server_name}__{}", tool.name);
                let namespaced_desc = tool
                    .description
                    .as_ref()
                    .map(|d| format!("[{server_name}] {d}"));
                result.push(Tool {
                    name: namespaced_name,
                    description: namespaced_desc,
                    input_schema: tool.input_schema.clone(),
                });
            }
        }
        result
    }

    /// Shut down all upstream servers.
    pub async fn shutdown(&self) {
        for (name, upstream) in &self.upstreams {
            tracing::info!(server = %name, "shutting down upstream server");
            upstream.lock().await.stop().await;
        }
    }

    fn handle_initialize(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        if let Some(params) = &req.params {
            if let Ok(init) =
                serde_json::from_value::<crate::types::InitializeParams>(params.clone())
            {
                tracing::info!(
                    client_name = %init.client_info.name,
                    client_version = init.client_info.version.as_deref().unwrap_or("unknown"),
                    protocol_version = %init.protocol_version,
                    "Agent connecting"
                );
            }
        }

        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: false,
                }),
            },
            server_info: ServerInfo {
                name: "bulwark".to_string(),
                version: Some(bulwark_common::VERSION.to_string()),
            },
        };

        JsonRpcResponse::success(req.id.clone(), serde_json::to_value(result).unwrap())
    }

    async fn handle_tools_list(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let tools = self.merged_tools().await;
        JsonRpcResponse::success(req.id.clone(), serde_json::json!({ "tools": tools }))
    }

    async fn handle_tools_call(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let params: ToolCallParams = match &req.params {
            Some(p) => match serde_json::from_value(p.clone()) {
                Ok(params) => params,
                Err(e) => {
                    return JsonRpcResponse::error(
                        req.id.clone(),
                        INVALID_REQUEST,
                        format!("Invalid params: {e}"),
                    );
                }
            },
            None => {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    INVALID_REQUEST,
                    "Missing params".to_string(),
                );
            }
        };

        // Split namespaced tool name.
        let (server_name, tool_name) = match params.name.split_once("__") {
            Some((s, t)) => (s, t),
            None => {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    INVALID_REQUEST,
                    format!(
                        "Tool name must be namespaced: server__tool, got: {}",
                        params.name
                    ),
                );
            }
        };

        // Find upstream server.
        let upstream = match self.upstreams.get(server_name) {
            Some(u) => u,
            None => {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    INVALID_REQUEST,
                    format!("Unknown server: {server_name}"),
                );
            }
        };

        let start = std::time::Instant::now();
        tracing::info!(
            server = %server_name,
            tool = %tool_name,
            namespaced_tool = %params.name,
            "Tool call"
        );

        // Forward to upstream.
        let mut server = upstream.lock().await;
        let result = server.call_tool(tool_name, params.arguments).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(tool_result) => {
                tracing::info!(
                    server = %server_name,
                    tool = %tool_name,
                    latency_ms = latency_ms,
                    is_error = tool_result.is_error.unwrap_or(false),
                    "Tool call complete"
                );

                // Attach governance metadata stub.
                let mut result_value = serde_json::to_value(&tool_result).unwrap();
                if let Some(obj) = result_value.as_object_mut() {
                    obj.insert("_meta".to_string(), governance_metadata_stub());
                }

                JsonRpcResponse::success(req.id.clone(), result_value)
            }
            Err(e) => {
                tracing::warn!(
                    server = %server_name,
                    tool = %tool_name,
                    latency_ms = latency_ms,
                    error = %e,
                    "Tool call failed"
                );
                JsonRpcResponse::error(req.id.clone(), INTERNAL_ERROR, e.to_string())
            }
        }
    }

    fn handle_ping(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(req.id.clone(), serde_json::json!({}))
    }
}
