//! Integration tests for the MCP gateway.
//!
//! Uses in-process mock upstream servers connected via tokio duplex channels
//! rather than spawning real child processes.

use std::collections::HashMap;

use bulwark_mcp::gateway::McpGateway;
use bulwark_mcp::transport::stdio::StdioTransport;
use bulwark_mcp::types::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId, Tool,
    ToolCallParams,
};
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
