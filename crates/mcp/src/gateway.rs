//! MCP Gateway orchestrator — intercepts tool calls, logs, forwards, responds.

use std::collections::HashMap;
use std::sync::Arc;

use bulwark_audit::event::{
    AuditEvent, Channel, ErrorInfo, EventOutcome, EventType, PolicyInfo, RequestInfo, SessionInfo,
};
use bulwark_audit::logger::AuditLogger;
use bulwark_config::McpGatewayConfig;
use bulwark_inspect::scanner::ContentScanner;
use bulwark_policy::engine::PolicyEngine;
use bulwark_vault::session::Session;
use bulwark_vault::store::Vault;

use crate::governance::{governance_metadata, governance_metadata_stub};
use crate::types::{
    CONTENT_BLOCKED, INTERNAL_ERROR, INVALID_REQUEST, InitializeResult, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, POLICY_DENIED, POLICY_ESCALATED,
    SESSION_REQUIRED, ServerCapabilities, ServerInfo, Tool, ToolCallParams, ToolsCapability,
};
use crate::upstream::UpstreamServer;

/// The MCP governance gateway — owns upstream servers and handles agent requests.
pub struct McpGateway {
    upstreams: HashMap<String, Arc<tokio::sync::Mutex<UpstreamServer>>>,
    #[allow(dead_code)]
    config: McpGatewayConfig,
    policy_engine: Option<Arc<PolicyEngine>>,
    vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    audit_logger: Option<AuditLogger>,
    content_scanner: Option<Arc<ContentScanner>>,
    /// Session token set by the agent (e.g. via an initialize param or header).
    session_token: parking_lot::Mutex<Option<String>>,
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
        Ok(Self {
            upstreams,
            config,
            policy_engine: None,
            vault: None,
            audit_logger: None,
            content_scanner: None,
            session_token: parking_lot::Mutex::new(None),
        })
    }

    /// Create a gateway with pre-built upstream servers (for testing).
    pub fn new_with_upstreams(
        upstreams: HashMap<String, Arc<tokio::sync::Mutex<UpstreamServer>>>,
    ) -> Self {
        Self {
            upstreams,
            config: McpGatewayConfig::default(),
            policy_engine: None,
            vault: None,
            audit_logger: None,
            content_scanner: None,
            session_token: parking_lot::Mutex::new(None),
        }
    }

    /// Attach a policy engine for request evaluation.
    pub fn with_policy_engine(mut self, engine: Arc<PolicyEngine>) -> Self {
        self.policy_engine = Some(engine);
        self
    }

    /// Attach a vault for session validation and credential injection.
    pub fn with_vault(mut self, vault: Arc<parking_lot::Mutex<Vault>>) -> Self {
        self.vault = Some(vault);
        self
    }

    /// Attach an audit logger for event logging.
    pub fn with_audit_logger(mut self, logger: AuditLogger) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Attach a content scanner for request/response inspection.
    pub fn with_content_scanner(mut self, scanner: Arc<ContentScanner>) -> Self {
        self.content_scanner = Some(scanner);
        self
    }

    /// Set the session token (called by transport layer or agent).
    pub fn set_session_token(&self, token: String) {
        *self.session_token.lock() = Some(token);
    }

    /// Validate the current session token against the vault.
    /// Returns the session if valid, or an error response if not.
    #[allow(clippy::result_large_err)]
    fn validate_session(
        &self,
        request_id: &crate::types::RequestId,
    ) -> Result<Option<Session>, JsonRpcResponse> {
        let vault = match &self.vault {
            Some(v) => v,
            None => return Ok(None),
        };

        let vault_guard = vault.lock();

        let token = self.session_token.lock().clone();
        let token = match token {
            Some(t) => t,
            None => {
                if vault_guard.require_sessions() {
                    return Err(JsonRpcResponse::error(
                        request_id.clone(),
                        SESSION_REQUIRED,
                        "Session token required. Set via X-Bulwark-Session header.".to_string(),
                    ));
                }
                return Ok(None);
            }
        };

        match vault_guard.validate_session(&token) {
            Ok(Some(session)) => Ok(Some(session)),
            Ok(None) => Err(JsonRpcResponse::error(
                request_id.clone(),
                SESSION_REQUIRED,
                "Invalid or expired session token.".to_string(),
            )),
            Err(e) => Err(JsonRpcResponse::error(
                request_id.clone(),
                INTERNAL_ERROR,
                format!("Session validation error: {e}"),
            )),
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

        let start = std::time::Instant::now();
        tracing::info!(
            server = %server_name,
            tool = %tool_name,
            namespaced_tool = %params.name,
            "Tool call"
        );

        // Validate session if vault is configured.
        let session = match self.validate_session(&req.id) {
            Ok(s) => s,
            Err(err_resp) => return err_resp,
        };

        // Build audit session info from the vault session.
        let audit_session = session.as_ref().map(|s| SessionInfo {
            session_id: s.id.clone(),
            operator: s.operator.clone(),
            team: s.team.clone(),
            project: s.project.clone(),
            environment: s.environment.clone(),
            agent_type: s.agent_type.clone(),
        });

        // Evaluate policy before upstream lookup (fail-fast on denial).
        let mut policy_info: Option<PolicyInfo> = None;
        if let Some(engine) = &self.policy_engine {
            use bulwark_policy::context::RequestContext;
            use bulwark_policy::verdict::Verdict;

            let mut ctx = RequestContext::new(server_name, tool_name);
            if let Some(ref s) = session {
                ctx = ctx.with_operator(&s.operator);
                if let Some(ref team) = s.team {
                    ctx = ctx.with_team(team);
                }
                if let Some(ref project) = s.project {
                    ctx = ctx.with_project(project);
                }
                if let Some(ref env) = s.environment {
                    ctx = ctx.with_environment(env);
                }
                if let Some(ref agent) = s.agent_type {
                    ctx = ctx.with_agent_type(agent);
                }
            }
            let eval = engine.evaluate(&ctx);

            policy_info = Some(PolicyInfo {
                verdict: format!("{:?}", eval.verdict).to_lowercase(),
                matched_rule: eval.matched_rule.clone(),
                matched_policy: eval.matched_policy.clone(),
                scope: Some(format!("{:?}", eval.scope).to_lowercase()),
                reason: eval.reason.clone(),
                evaluation_time_us: eval.evaluation_time.as_micros() as u64,
            });

            match eval.verdict {
                Verdict::Allow => {
                    tracing::debug!(
                        rule = eval.matched_rule.as_deref().unwrap_or("none"),
                        "policy: allow"
                    );
                }
                Verdict::Deny => {
                    tracing::warn!(
                        rule = eval.matched_rule.as_deref().unwrap_or("none"),
                        reason = %eval.reason,
                        "policy: deny"
                    );

                    // Emit audit event for denied request.
                    if let Some(ref logger) = self.audit_logger {
                        let mut builder =
                            AuditEvent::builder(EventType::PolicyDecision, Channel::McpGateway)
                                .outcome(EventOutcome::Denied)
                                .request(RequestInfo {
                                    tool: server_name.to_string(),
                                    action: tool_name.to_string(),
                                    resource: None,
                                    target: params.name.clone(),
                                })
                                .duration_us(start.elapsed().as_micros() as u64);
                        if let Some(ref si) = audit_session {
                            builder = builder.session(si.clone());
                        }
                        if let Some(ref pi) = policy_info {
                            builder = builder.policy(pi.clone());
                        }
                        logger.log(builder.build());
                    }

                    return JsonRpcResponse::error(
                        req.id.clone(),
                        POLICY_DENIED,
                        format!("Policy denied: {}", eval.reason),
                    );
                }
                Verdict::Escalate => {
                    tracing::warn!(
                        rule = eval.matched_rule.as_deref().unwrap_or("none"),
                        reason = %eval.reason,
                        "policy: escalate"
                    );

                    // Emit audit event for escalated request.
                    if let Some(ref logger) = self.audit_logger {
                        let mut builder =
                            AuditEvent::builder(EventType::PolicyDecision, Channel::McpGateway)
                                .outcome(EventOutcome::Escalated)
                                .request(RequestInfo {
                                    tool: server_name.to_string(),
                                    action: tool_name.to_string(),
                                    resource: None,
                                    target: params.name.clone(),
                                })
                                .duration_us(start.elapsed().as_micros() as u64);
                        if let Some(ref si) = audit_session {
                            builder = builder.session(si.clone());
                        }
                        if let Some(ref pi) = policy_info {
                            builder = builder.policy(pi.clone());
                        }
                        logger.log(builder.build());
                    }

                    return JsonRpcResponse::error(
                        req.id.clone(),
                        POLICY_ESCALATED,
                        format!("Policy escalation required: {}", eval.reason),
                    );
                }
                Verdict::Transform => {
                    tracing::info!(
                        rule = eval.matched_rule.as_deref().unwrap_or("none"),
                        "policy: transform (not yet implemented, allowing)"
                    );
                }
            }
        }

        // Inspect request arguments for sensitive content.
        let mut request_inspection = bulwark_inspect::InspectionResult::empty(0);
        let mut final_arguments = params.arguments.clone();
        if let Some(scanner) = self
            .content_scanner
            .as_ref()
            .filter(|s| s.inspect_requests())
        {
            if let Some(ref args) = params.arguments {
                request_inspection = scanner.scan_json(args);
                if request_inspection.should_block {
                    tracing::warn!(
                        tool = %params.name,
                        findings = request_inspection.findings.len(),
                        "Content inspection blocked request"
                    );

                    if let Some(ref logger) = self.audit_logger {
                        let mut builder =
                            AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway)
                                .outcome(EventOutcome::Denied)
                                .request(RequestInfo {
                                    tool: server_name.to_string(),
                                    action: tool_name.to_string(),
                                    resource: None,
                                    target: params.name.clone(),
                                })
                                .duration_us(start.elapsed().as_micros() as u64);
                        if let Some(ref si) = audit_session {
                            builder = builder.session(si.clone());
                        }
                        if let Some(ref pi) = policy_info {
                            builder = builder.policy(pi.clone());
                        }
                        logger.log(builder.build());
                    }

                    return JsonRpcResponse::error(
                        req.id.clone(),
                        CONTENT_BLOCKED,
                        "Request blocked by content inspection".to_string(),
                    );
                }

                // Redact request arguments before forwarding.
                if request_inspection.should_redact {
                    tracing::info!(
                        finding_count = request_inspection.findings.len(),
                        "redacting tool call arguments"
                    );
                    final_arguments = Some(bulwark_inspect::redact_json(
                        args,
                        &request_inspection.findings,
                    ));
                }
            }
        }

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

        // Forward to upstream with (possibly redacted) arguments.
        let mut server = upstream.lock().await;
        let result = server.call_tool(tool_name, final_arguments).await;
        let duration_us = start.elapsed().as_micros() as u64;
        let latency_ms = duration_us as f64 / 1000.0;

        match result {
            Ok(tool_result) => {
                tracing::info!(
                    server = %server_name,
                    tool = %tool_name,
                    latency_ms = latency_ms,
                    is_error = tool_result.is_error.unwrap_or(false),
                    "Tool call complete"
                );

                // Inspect response content.
                let mut response_inspection = bulwark_inspect::InspectionResult::empty(0);
                let mut result_json = serde_json::to_value(&tool_result).unwrap_or_default();
                let mut response_was_redacted = false;
                if let Some(scanner) = self
                    .content_scanner
                    .as_ref()
                    .filter(|s| s.inspect_responses())
                {
                    response_inspection = scanner.scan_json(&result_json);
                    if !response_inspection.findings.is_empty() {
                        tracing::info!(
                            findings = response_inspection.findings.len(),
                            blocked = response_inspection.should_block,
                            redacted = response_inspection.should_redact,
                            "Content inspection findings in response"
                        );
                    }

                    // Block response if critical findings.
                    if response_inspection.should_block {
                        tracing::warn!(
                            tool = %params.name,
                            findings = response_inspection.findings.len(),
                            "Content inspection blocked response"
                        );

                        if let Some(ref logger) = self.audit_logger {
                            let mut builder = AuditEvent::builder(
                                EventType::RequestProcessed,
                                Channel::McpGateway,
                            )
                            .outcome(EventOutcome::Denied)
                            .request(RequestInfo {
                                tool: server_name.to_string(),
                                action: tool_name.to_string(),
                                resource: None,
                                target: params.name.clone(),
                            })
                            .duration_us(start.elapsed().as_micros() as u64);
                            if let Some(ref si) = audit_session {
                                builder = builder.session(si.clone());
                            }
                            if let Some(ref pi) = policy_info {
                                builder = builder.policy(pi.clone());
                            }
                            logger.log(builder.build());
                        }

                        return JsonRpcResponse::error(
                            req.id.clone(),
                            CONTENT_BLOCKED,
                            "Response blocked: upstream returned dangerous content".to_string(),
                        );
                    }

                    // Redact response content if needed.
                    if response_inspection.should_redact {
                        tracing::info!(
                            finding_count = response_inspection.findings.len(),
                            "redacting tool response content"
                        );
                        result_json = bulwark_inspect::redact_json(
                            &result_json,
                            &response_inspection.findings,
                        );
                        response_was_redacted = true;
                    }
                }

                // Combine request and response findings for governance metadata.
                let all_findings: Vec<&bulwark_inspect::InspectionFinding> = request_inspection
                    .findings
                    .iter()
                    .chain(response_inspection.findings.iter())
                    .collect();

                // Build and emit audit event for successful tool call.
                let audit_event_id = if let Some(ref logger) = self.audit_logger {
                    let mut builder =
                        AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway)
                            .outcome(EventOutcome::Success)
                            .request(RequestInfo {
                                tool: server_name.to_string(),
                                action: tool_name.to_string(),
                                resource: None,
                                target: params.name.clone(),
                            })
                            .duration_us(duration_us);
                    if let Some(ref si) = audit_session {
                        builder = builder.session(si.clone());
                    }
                    if let Some(ref pi) = policy_info {
                        builder = builder.policy(pi.clone());
                    }
                    let event = builder.build();
                    let id = event.id.clone();
                    logger.log(event);
                    Some(id)
                } else {
                    None
                };

                // Attach governance metadata using the (possibly redacted) result.
                let mut result_value = result_json;
                if let Some(obj) = result_value.as_object_mut() {
                    let mut meta = if let Some(engine) = &self.policy_engine {
                        use bulwark_policy::context::RequestContext;
                        let ctx = RequestContext::new(server_name, tool_name);
                        let eval = engine.evaluate(&ctx);
                        governance_metadata(&eval)
                    } else {
                        governance_metadata_stub()
                    };
                    // Add session_id, audit_event_id, and inspection_results to governance metadata.
                    if let Some(gov) = meta.get_mut("governance") {
                        if let Some(ref s) = session {
                            gov["session_id"] = serde_json::Value::String(s.id.clone());
                        }
                        if let Some(ref id) = audit_event_id {
                            gov["audit_event_id"] = serde_json::Value::String(id.clone());
                        }
                        // Inspection summary — NO snippets to avoid leaking secrets.
                        if all_findings.is_empty() {
                            gov["inspection_results"] = serde_json::Value::Null;
                        } else {
                            use std::collections::HashSet;
                            let categories: Vec<String> = all_findings
                                .iter()
                                .map(|f| serde_json::to_value(&f.category).unwrap_or_default())
                                .map(|v| v.as_str().unwrap_or("unknown").to_string())
                                .collect::<HashSet<_>>()
                                .into_iter()
                                .collect();
                            let max_sev = all_findings.iter().map(|f| f.severity).max();
                            let any_blocked = all_findings
                                .iter()
                                .any(|f| f.action == bulwark_inspect::FindingAction::Block);
                            let any_redacted = response_was_redacted
                                || all_findings
                                    .iter()
                                    .any(|f| f.action == bulwark_inspect::FindingAction::Redact);
                            gov["inspection_results"] = serde_json::json!({
                                "finding_count": all_findings.len(),
                                "max_severity": serde_json::to_value(max_sev).unwrap_or_default(),
                                "blocked": any_blocked,
                                "redacted": any_redacted,
                                "categories": categories,
                            });
                        }
                    }
                    obj.insert("_meta".to_string(), meta);
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

                // Emit audit event for failed tool call.
                if let Some(ref logger) = self.audit_logger {
                    let mut builder =
                        AuditEvent::builder(EventType::RequestProcessed, Channel::McpGateway)
                            .outcome(EventOutcome::Failed)
                            .request(RequestInfo {
                                tool: server_name.to_string(),
                                action: tool_name.to_string(),
                                resource: None,
                                target: params.name.clone(),
                            })
                            .error(ErrorInfo {
                                category: "upstream".to_string(),
                                message: e.to_string(),
                            })
                            .duration_us(duration_us);
                    if let Some(ref si) = audit_session {
                        builder = builder.session(si.clone());
                    }
                    if let Some(ref pi) = policy_info {
                        builder = builder.policy(pi.clone());
                    }
                    logger.log(builder.build());
                }

                JsonRpcResponse::error(req.id.clone(), INTERNAL_ERROR, e.to_string())
            }
        }
    }

    fn handle_ping(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(req.id.clone(), serde_json::json!({}))
    }
}
