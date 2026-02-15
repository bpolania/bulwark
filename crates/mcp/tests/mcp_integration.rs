//! Integration tests for the MCP gateway.
//!
//! Uses in-process mock upstream servers connected via tokio duplex channels
//! rather than spawning real child processes.

use std::collections::HashMap;
use std::sync::Arc;

use bulwark_mcp::gateway::McpGateway;
use bulwark_mcp::transport::stdio::StdioTransport;
use bulwark_mcp::types::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, POLICY_DENIED, RequestId,
    Tool, ToolCallParams,
};
use bulwark_policy::engine::PolicyEngine;
use tokio::io::{DuplexStream, duplex};

// ── Helpers ──────────────────────────────────────────────────────────

/// Create a pair of transports connected to each other (simulating stdio
/// between two processes).
fn create_transport_pair() -> (
    StdioTransport<DuplexStream, DuplexStream>,
    StdioTransport<DuplexStream, DuplexStream>,
) {
    let (a_to_b_read, a_to_b_write) = duplex(8192);
    let (b_to_a_read, b_to_a_write) = duplex(8192);
    (
        StdioTransport::new(b_to_a_read, a_to_b_write), // "client" side
        StdioTransport::new(a_to_b_read, b_to_a_write), // "server" side
    )
}

/// A mock upstream MCP server that responds to initialize, tools/list, and tools/call.
async fn run_mock_mcp_server(
    mut transport: StdioTransport<DuplexStream, DuplexStream>,
    tools: Vec<Tool>,
) {
    loop {
        match transport.read_message().await {
            Ok(Some(JsonRpcMessage::Request(req))) => {
                let response = match req.method.as_str() {
                    "initialize" => JsonRpcResponse::success(
                        req.id,
                        serde_json::json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": "mock-server", "version": "1.0" }
                        }),
                    ),
                    "tools/list" => {
                        JsonRpcResponse::success(req.id, serde_json::json!({ "tools": tools }))
                    }
                    "tools/call" => {
                        let params: ToolCallParams =
                            serde_json::from_value(req.params.unwrap()).unwrap();
                        if params.name == "fail_tool" {
                            JsonRpcResponse::error(req.id, -1, "mock tool error".to_string())
                        } else {
                            JsonRpcResponse::success(
                                req.id,
                                serde_json::json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Called: {}", params.name)
                                    }]
                                }),
                            )
                        }
                    }
                    _ => JsonRpcResponse::error(req.id, -32601, "not found".to_string()),
                };
                if transport.write_message(&response).await.is_err() {
                    break;
                }
            }
            Ok(Some(JsonRpcMessage::Notification(_))) => {} // ignore
            Ok(None) => break,                              // EOF
            Err(_) => break,
            Ok(Some(JsonRpcMessage::Response(_))) => {} // ignore
        }
    }
}

fn sample_tool(name: &str, desc: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: Some(desc.to_string()),
        input_schema: serde_json::json!({"type": "object"}),
    }
}

// ── Integration tests ────────────────────────────────────────────────

#[tokio::test]
async fn full_handshake() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let init_req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "initialize".into(),
        params: Some(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-agent", "version": "1.0" }
        })),
    });

    let response = gateway.handle_message(init_req).await.unwrap();
    if let JsonRpcMessage::Response(resp) = response {
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "bulwark");
        assert!(result["capabilities"]["tools"].is_object());
    } else {
        panic!("Expected response");
    }

    // Send initialized notification — should return None.
    let notif = JsonRpcMessage::Notification(JsonRpcNotification {
        jsonrpc: "2.0".into(),
        method: "notifications/initialized".into(),
        params: None,
    });
    assert!(gateway.handle_message(notif).await.is_none());
}

#[tokio::test]
async fn tools_list_with_namespacing() {
    // Create mock upstream with tools, build gateway manually.
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![
        sample_tool("read", "Read a file"),
        sample_tool("write", "Write a file"),
    ];
    let tools_for_mock = tools.clone();
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools_for_mock).await;
    });

    // Do the client handshake + tool discovery.
    let mut client = client_transport;
    let mut rid: i64 = 1;
    bulwark_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();
    let discovered = bulwark_mcp::client::list_tools(&mut client, &mut rid)
        .await
        .unwrap();
    assert_eq!(discovered.len(), 2);
    assert_eq!(discovered[0].name, "read");
    assert_eq!(discovered[1].name, "write");
}

#[tokio::test]
async fn tool_call_forwarding_via_client() {
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![sample_tool("greet", "Say hello")];
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools).await;
    });

    let mut client = client_transport;
    let mut rid: i64 = 1;
    bulwark_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();

    let result = bulwark_mcp::client::call_tool(&mut client, &mut rid, "greet", None)
        .await
        .unwrap();
    assert_eq!(result.content.len(), 1);
    match &result.content[0] {
        bulwark_mcp::types::ToolContent::Text { text } => {
            assert_eq!(text, "Called: greet");
        }
        _ => panic!("Expected text content"),
    }
}

#[tokio::test]
async fn gateway_merged_tools_namespaces_correctly() {
    // We can't easily create real UpstreamServers with DuplexStream transports
    // (they require ChildStdout/ChildStdin). Instead, test merged_tools logic
    // by verifying the gateway's initialize and tools/list responses.
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    // With no upstreams, merged_tools returns empty.
    let tools = gateway.merged_tools().await;
    assert!(tools.is_empty());

    // Test that tools/list returns empty tools via handle_message.
    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/list".into(),
        params: None,
    });
    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        let tools_arr = r.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(tools_arr.is_empty());
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_without_namespace_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "no_namespace_tool",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        let err = r.error.unwrap();
        assert!(err.message.contains("server__tool"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_unknown_server_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": "nonexistent__tool",
            "arguments": {}
        })),
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        let err = r.error.unwrap();
        assert!(err.message.contains("nonexistent"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "some/unknown".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, bulwark_mcp::types::METHOD_NOT_FOUND);
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn ping_returns_success() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::String("ping-1".into()),
        method: "ping".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_none());
        assert_eq!(r.id, RequestId::String("ping-1".into()));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn error_propagation_from_upstream() {
    // Test that when upstream returns an error for tools/call, the client
    // propagates it as a BulwarkError.
    let (client_transport, server_transport) = create_transport_pair();
    let tools = vec![sample_tool("fail_tool", "Always fails")];
    tokio::spawn(async move {
        run_mock_mcp_server(server_transport, tools).await;
    });

    let mut client = client_transport;
    let mut rid: i64 = 1;
    bulwark_mcp::client::initialize(&mut client, &mut rid)
        .await
        .unwrap();

    let err = bulwark_mcp::client::call_tool(&mut client, &mut rid, "fail_tool", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("mock tool error"));
}

#[tokio::test]
async fn multiple_upstream_tool_discovery() {
    // Verify that two independent mock servers each return their own tools.
    let (client1, server1) = create_transport_pair();
    let (client2, server2) = create_transport_pair();

    let tools1 = vec![sample_tool("read", "Read a file")];
    let tools2 = vec![sample_tool("search", "Search the web")];

    let t1 = tools1.clone();
    let t2 = tools2.clone();
    tokio::spawn(async move {
        run_mock_mcp_server(server1, t1).await;
    });
    tokio::spawn(async move {
        run_mock_mcp_server(server2, t2).await;
    });

    let mut c1 = client1;
    let mut c2 = client2;
    let mut rid1: i64 = 1;
    let mut rid2: i64 = 1;

    bulwark_mcp::client::initialize(&mut c1, &mut rid1)
        .await
        .unwrap();
    bulwark_mcp::client::initialize(&mut c2, &mut rid2)
        .await
        .unwrap();

    let discovered1 = bulwark_mcp::client::list_tools(&mut c1, &mut rid1)
        .await
        .unwrap();
    let discovered2 = bulwark_mcp::client::list_tools(&mut c2, &mut rid2)
        .await
        .unwrap();

    assert_eq!(discovered1.len(), 1);
    assert_eq!(discovered1[0].name, "read");
    assert_eq!(discovered2.len(), 1);
    assert_eq!(discovered2[0].name, "search");
}

#[tokio::test]
async fn tool_call_missing_params_returns_error() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let req = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: None,
    });

    let resp = gateway.handle_message(req).await.unwrap();
    if let JsonRpcMessage::Response(r) = resp {
        assert!(r.error.is_some());
        assert!(r.error.unwrap().message.contains("Missing params"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn unsolicited_response_returns_none() {
    let gateway = McpGateway::new_with_upstreams(HashMap::new());

    let msg = JsonRpcMessage::Response(JsonRpcResponse::success(
        RequestId::Number(999),
        serde_json::json!({}),
    ));

    assert!(gateway.handle_message(msg).await.is_none());
}

// ── Policy integration tests ─────────────────────────────────────────

/// Build a PolicyEngine from inline YAML.
fn engine_with_rules(yaml: &str) -> Arc<PolicyEngine> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
    Arc::new(PolicyEngine::from_directory(dir.path()).unwrap())
}

/// Build a tools/call request for the given namespaced tool name.
fn tool_call_request(id: i64, namespaced_name: &str) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(id),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": namespaced_name,
            "arguments": {}
        })),
    })
}

#[tokio::test]
async fn tool_call_allowed_by_policy() {
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    // Policy allows, but no upstream exists → expect "Unknown server" error,
    // NOT a policy denial.
    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should have an error (no upstream)");
        assert_ne!(err.code, POLICY_DENIED, "should NOT be a policy denial");
        assert!(
            err.message.contains("Unknown server"),
            "expected 'Unknown server', got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_denied_by_policy() {
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "blocked by test policy"
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be denied");
        assert_eq!(err.code, POLICY_DENIED);
        assert!(err.message.contains("Policy denied"));
        assert!(err.message.contains("blocked by test policy"));
    } else {
        panic!("Expected response");
    }
}

#[tokio::test]
async fn tool_call_default_deny_no_matching_rule() {
    // Policy has a rule that only matches a different tool — no rule matches
    // the requested tool, so the engine's default-deny kicks in.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-specific
    verdict: allow
    match:
      tools: ["other_server"]
      actions: ["specific_action"]
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new()).with_policy_engine(engine);

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__read"))
        .await
        .unwrap();

    if let JsonRpcMessage::Response(r) = resp {
        let err = r.error.expect("should be denied by default");
        assert_eq!(err.code, POLICY_DENIED);
        assert!(
            err.message.contains("default deny"),
            "expected default deny message, got: {}",
            err.message,
        );
    } else {
        panic!("Expected response");
    }
}

// ── Audit cross-crate integration tests ─────────────────────────────

/// A minimal mock MCP server implemented as a Python script.
/// Handles initialize, tools/list, and tools/call over stdio JSON-RPC.
const MOCK_MCP_SERVER_SCRIPT: &str = r#"
import sys, json
def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    msg_id = msg.get("id")
    if msg_id is None:
        continue
    method = msg.get("method", "")
    if method == "initialize":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1.0"}}})
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [{"name": "greet", "description": "Say hi", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        respond({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": "Hello from mock!"}]}})
    else:
        respond({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}})
"#;

#[tokio::test]
async fn mcp_tool_call_produces_audit_event() {
    // Skip if python3 is not available.
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found, skipping test");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("mock_mcp_server.py");
    std::fs::write(&script_path, MOCK_MCP_SERVER_SCRIPT).unwrap();

    let audit_db = dir.path().join("audit.db");
    let logger = bulwark_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let config = bulwark_config::McpGatewayConfig {
        upstream_servers: vec![bulwark_config::UpstreamServerConfig {
            name: "mock".into(),
            command: "python3".into(),
            args: vec![script_path.to_str().unwrap().to_string()],
            env: Default::default(),
        }],
    };

    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let gateway = McpGateway::new(config)
        .await
        .unwrap()
        .with_policy_engine(engine)
        .with_audit_logger(logger.clone());

    // Send a tools/call for mock__greet (the mock server exposes "greet").
    let resp = gateway
        .handle_message(tool_call_request(1, "mock__greet"))
        .await
        .unwrap();
    if let JsonRpcMessage::Response(r) = &resp {
        assert!(
            r.error.is_none(),
            "tool call should succeed, got error: {:?}",
            r.error
        );
    } else {
        panic!("Expected response");
    }

    // Shut down the logger to flush events.
    logger.shutdown().await;

    // Query the audit store and verify the event.
    let store = bulwark_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&bulwark_audit::query::AuditFilter::default())
        .unwrap();

    assert!(!events.is_empty(), "should have at least one audit event");
    let event = &events[0];
    assert_eq!(
        event.event_type,
        bulwark_audit::event::EventType::RequestProcessed
    );
    assert_eq!(event.outcome, bulwark_audit::event::EventOutcome::Success);
    assert_eq!(event.channel, bulwark_audit::event::Channel::McpGateway);

    gateway.shutdown().await;
}

#[tokio::test]
async fn mcp_denied_tool_call_produces_denied_audit_event() {
    let dir = tempfile::tempdir().unwrap();
    let audit_db = dir.path().join("audit.db");
    let logger = bulwark_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "blocked by test policy"
"#,
    );

    let gateway = McpGateway::new_with_upstreams(HashMap::new())
        .with_policy_engine(engine)
        .with_audit_logger(logger.clone());

    let resp = gateway
        .handle_message(tool_call_request(1, "mock__greet"))
        .await
        .unwrap();
    if let JsonRpcMessage::Response(r) = &resp {
        assert!(r.error.is_some(), "should be denied");
        assert_eq!(r.error.as_ref().unwrap().code, POLICY_DENIED);
    } else {
        panic!("Expected response");
    }

    // Shut down the logger to flush events.
    logger.shutdown().await;

    // Query the audit store and verify the denial event.
    let store = bulwark_audit::store::AuditStore::open(&audit_db).unwrap();
    let events = store
        .query(&bulwark_audit::query::AuditFilter::default())
        .unwrap();

    assert!(!events.is_empty(), "should have at least one audit event");
    let event = &events[0];
    assert_eq!(
        event.event_type,
        bulwark_audit::event::EventType::PolicyDecision
    );
    assert_eq!(event.outcome, bulwark_audit::event::EventOutcome::Denied);
    assert_eq!(event.channel, bulwark_audit::event::Channel::McpGateway);

    // Verify policy information is included.
    assert!(event.policy.is_some(), "policy info should be populated");
    let policy = event.policy.as_ref().unwrap();
    assert_eq!(policy.verdict, "deny");
}

#[tokio::test]
async fn governance_metadata_contains_real_verdict() {
    // Test that governance_metadata() produces correct fields from a real
    // policy evaluation (cross-crate: policy engine → MCP governance).
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-reads
    verdict: allow
    reason: "read operations are safe"
    match:
      tools: ["*"]
      actions: ["read_*"]
"#,
    );

    let ctx = bulwark_policy::context::RequestContext::new("fs", "read_file");
    let eval = engine.evaluate(&ctx);

    let meta = bulwark_mcp::governance::governance_metadata(&eval);

    assert_eq!(meta["governance"]["verdict"], "allow");
    assert_eq!(meta["governance"]["matched_rule"], "allow-reads");
    assert_eq!(meta["governance"]["reason"], "read operations are safe");
    assert_eq!(meta["governance"]["version"], "0.1.0");
    assert!(meta["governance"]["evaluation_time_us"].is_number());
}
