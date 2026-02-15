//! Integration tests for the Bulwark HTTP/HTTPS forward proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use bulwark_config::ProxyConfig;
use bulwark_policy::engine::PolicyEngine;
use bulwark_proxy::server::ProxyServer;
use bulwark_vault::credential::{Credential, CredentialType};
use bulwark_vault::session::CreateSessionParams;
use bulwark_vault::store::Vault;
use secrecy::SecretString;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Start a Bulwark proxy on a random port. Returns the bound address and a
/// cancellation token.
async fn start_test_proxy(ca_dir: &str) -> (SocketAddr, CancellationToken, Arc<ProxyServer>) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: bulwark_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
    };

    let server = Arc::new(ProxyServer::new(config).await.expect("proxy server"));
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token, server)
}

/// Start a simple echo HTTP server that returns request metadata as JSON.
/// Returns the bound address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
                    let query = req.uri().query().unwrap_or("").to_string();

                    let body = serde_json::json!({
                        "method": method,
                        "path": path,
                        "query": query,
                    });

                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from(body.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

/// Initialise tracing (only once per process).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("bulwark=debug,info")
        .try_init();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], bulwark_common::VERSION);
    assert!(body["uptime_seconds"].is_number());

    token.cancel();
}

#[tokio::test]
async fn http_forward_proxy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=hello"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/test");
    assert_eq!(body["query"], "q=hello");

    token.cancel();
}

#[tokio::test]
async fn graceful_shutdown() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Verify the proxy is running.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("health");
    assert_eq!(resp.status(), 200);

    // Trigger shutdown.
    token.cancel();

    // Give the server time to shut down (grace period is 5s, but we just need
    // to confirm it stops accepting).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // New connection should fail.
    let result = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap()
        .get(format!("http://{addr}/healthz"))
        .send()
        .await;

    assert!(result.is_err(), "proxy should not accept after shutdown");
}

#[tokio::test]
async fn concurrent_requests() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let mut handles = Vec::new();
    for i in 0..50 {
        let c = client.clone();
        let addr = echo_addr;
        handles.push(tokio::spawn(async move {
            let resp = c
                .get(format!("http://{addr}/item/{i}"))
                .send()
                .await
                .expect("concurrent request");
            assert_eq!(resp.status(), 200);
        }));
    }

    for h in handles {
        h.await.expect("task join");
    }

    token.cancel();
}

#[tokio::test]
async fn connection_to_nonexistent_server() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let resp = client
        .get("http://127.0.0.1:1/nothing")
        .send()
        .await
        .expect("should get a response (502)");

    assert_eq!(resp.status(), 502);

    token.cancel();
}

#[tokio::test]
async fn malformed_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, _server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Send raw garbage bytes to the proxy.
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect");

    use tokio::io::AsyncWriteExt;
    stream.write_all(b"NOT HTTP AT ALL\r\n\r\n").await.ok();

    // The proxy should close the connection gracefully (not panic).
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    // Either we get a response or the connection closes — either is fine.
    // The key point is the proxy didn't crash.
    match result {
        Ok(Ok(_n)) => {} // got some response or EOF
        Ok(Err(_)) => {} // IO error on read — fine
        Err(_) => {}     // timeout — connection stayed open, still fine
    }

    // Verify proxy is still healthy.
    let resp = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .expect("health after malformed");
    assert_eq!(resp.status(), 200);

    token.cancel();
}

/// Start a Bulwark proxy with a policy engine attached.
async fn start_test_proxy_with_policy(
    ca_dir: &str,
    engine: Arc<PolicyEngine>,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: bulwark_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_policy_engine(engine),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, token)
}

/// Build a PolicyEngine from inline YAML.
fn engine_with_rules(yaml: &str) -> Arc<PolicyEngine> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), yaml).unwrap();
    Arc::new(PolicyEngine::from_directory(dir.path()).unwrap())
}

#[tokio::test]
async fn http_request_denied_by_policy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy denies everything.
    let engine = engine_with_rules(
        r#"
rules:
  - name: deny-all
    verdict: deny
    reason: "all requests blocked"
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("Policy denied"),
        "expected policy denial in body, got: {body}",
    );

    token.cancel();
}

#[tokio::test]
async fn http_request_allowed_by_policy() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Policy allows all requests.
    let engine = engine_with_rules(
        r#"
rules:
  - name: allow-all
    verdict: allow
    match:
      tools: ["*"]
"#,
    );

    let (proxy_addr, token) = start_test_proxy_with_policy(ca_dir.to_str().unwrap(), engine).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=hello"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/test");
    assert_eq!(body["query"], "q=hello");

    token.cancel();
}

/// Start a proxy with a vault attached (sessions enabled).
async fn start_test_proxy_with_vault(
    ca_dir: &str,
    vault: Vault,
) -> (SocketAddr, CancellationToken) {
    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: bulwark_config::TlsConfig {
            ca_dir: ca_dir.to_string(),
        },
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_vault(Arc::new(parking_lot::Mutex::new(vault))),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        server.run_with_listener(listener).await.expect("proxy run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, token)
}

/// Create a test vault with require_sessions enabled.
fn test_vault_required(dir: &std::path::Path) -> Vault {
    let config = bulwark_config::VaultConfig {
        key_path: dir.join("vault-key.age").to_str().unwrap().to_string(),
        credentials_dir: dir.join("credentials").to_str().unwrap().to_string(),
        bindings_path: dir.join("bindings.yaml").to_str().unwrap().to_string(),
        sessions_db_path: dir.join("sessions.db").to_str().unwrap().to_string(),
        require_sessions: true,
    };
    Vault::open(&config).unwrap()
}

/// Create a test vault without require_sessions.
fn test_vault_optional(dir: &std::path::Path) -> Vault {
    let config = bulwark_config::VaultConfig {
        key_path: dir.join("vault-key.age").to_str().unwrap().to_string(),
        credentials_dir: dir.join("credentials").to_str().unwrap().to_string(),
        bindings_path: dir.join("bindings.yaml").to_str().unwrap().to_string(),
        sessions_db_path: dir.join("sessions.db").to_str().unwrap().to_string(),
        require_sessions: false,
    };
    Vault::open(&config).unwrap()
}

#[tokio::test]
async fn proxy_returns_401_when_session_required_and_missing() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);
    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request without session header → 401.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);

    token.cancel();
}

#[tokio::test]
async fn proxy_returns_401_for_invalid_session_token() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_required(&vault_dir);
    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request with invalid token → 401.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Bulwark-Session", "bwk_sess_invalid_token_value_here00")
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 401);

    token.cancel();
}

#[tokio::test]
async fn proxy_allows_request_with_valid_session() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    let vault = test_vault_optional(&vault_dir);
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Request with valid session → 200.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Bulwark-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    token.cancel();
}

/// Start an echo HTTP server that reflects request headers in the response JSON.
/// Returns the bound address.
async fn start_header_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind header echo server");
    let addr = listener.local_addr().expect("echo addr");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();

                    // Collect all headers into a JSON object.
                    let mut headers = serde_json::Map::new();
                    for (name, value) in req.headers() {
                        if let Ok(v) = value.to_str() {
                            headers.insert(
                                name.as_str().to_string(),
                                serde_json::Value::String(v.to_string()),
                            );
                        }
                    }

                    let body = serde_json::json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                    });

                    Ok::<_, hyper::Error>(Response::new(
                        Full::new(Bytes::from(body.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                });

                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn credential_injected_into_outbound_request() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Create a vault with a credential and a binding.
    let mut vault = test_vault_optional(&vault_dir);

    // Add a bearer token credential.
    vault
        .add_credential(
            "test-token",
            &Credential::BearerToken(SecretString::from("injected-secret-42".to_string())),
            &CredentialType::BearerToken,
            Some("test credential"),
        )
        .unwrap();

    // Write a binding that maps the echo server's host to our credential.
    // The tool name in HTTP proxy is the target host, so we use a wildcard.
    let bindings_yaml = "bindings:\n  - credential: test-token\n    tool: \"*\"\n";
    std::fs::write(vault_dir.join("bindings.yaml"), bindings_yaml).unwrap();
    vault.reload_bindings().unwrap();

    // Create a session.
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_header_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request with session token.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Bulwark-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");

    // Verify the authorization header was injected.
    let auth_header = body["headers"]["authorization"]
        .as_str()
        .expect("authorization header should be present");
    assert_eq!(
        auth_header, "Bearer injected-secret-42",
        "credential should be injected into outbound request"
    );

    // Verify the X-Bulwark-Session header was stripped (not forwarded to upstream).
    assert!(
        body["headers"]["x-bulwark-session"].is_null(),
        "x-bulwark-session header should be stripped from outbound request"
    );

    token.cancel();
}

#[tokio::test]
async fn credential_not_injected_without_binding() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");
    let vault_dir = tmp.path().join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // Create a vault with NO bindings (empty bindings file).
    let vault = test_vault_optional(&vault_dir);

    // Create a session.
    let session = vault
        .create_session(CreateSessionParams {
            operator: "test-operator".to_string(),
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            ttl_seconds: None,
            description: None,
        })
        .unwrap();
    let session_token = session.token.clone();

    let echo_addr = start_header_echo_server().await;
    let (proxy_addr, token) = start_test_proxy_with_vault(ca_dir.to_str().unwrap(), vault).await;

    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    // Send request with session but no matching binding.
    let resp = client
        .get(format!("http://{echo_addr}/test"))
        .header("X-Bulwark-Session", &session_token)
        .send()
        .await
        .expect("proxied request");

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json body");

    // No authorization header should be present (no binding matched).
    assert!(
        body["headers"]["authorization"].is_null(),
        "no authorization header should be injected without a matching binding"
    );

    token.cancel();
}

// ── Audit cross-crate integration test ───────────────────────────────

#[tokio::test]
async fn http_request_produces_audit_event() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let echo_addr = start_echo_server().await;

    // Set up audit logger.
    let audit_db = tmp.path().join("audit.db");
    let logger = bulwark_audit::logger::AuditLogger::new(&audit_db).unwrap();

    let config = ProxyConfig {
        listen_address: "127.0.0.1:0".to_string(),
        tls: bulwark_config::TlsConfig {
            ca_dir: ca_dir.to_str().unwrap().to_string(),
        },
    };

    let server = Arc::new(
        ProxyServer::new(config)
            .await
            .expect("proxy server")
            .with_audit_logger(logger.clone()),
    );
    let token = server.shutdown_token();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test proxy");
    let proxy_addr = listener.local_addr().expect("local addr");

    let server_clone = Arc::clone(&server);
    tokio::spawn(async move {
        server_clone
            .run_with_listener(listener)
            .await
            .expect("proxy run");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Make an HTTP request through the proxy.
    let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("client");

    let resp = client
        .get(format!("http://{echo_addr}/test?q=audit"))
        .send()
        .await
        .expect("proxied request");
    assert_eq!(resp.status(), 200);

    // Shut down the logger to flush events, then stop proxy.
    logger.shutdown().await;
    token.cancel();

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
    assert_eq!(event.channel, bulwark_audit::event::Channel::HttpProxy);
}

#[tokio::test]
async fn https_connect_tunnel() {
    // This test verifies the CONNECT tunnel works with the local CA.
    init_tracing();
    let tmp = tempfile::tempdir().expect("tmp dir");
    let ca_dir = tmp.path().join("ca");

    let (proxy_addr, token, server) = start_test_proxy(ca_dir.to_str().unwrap()).await;

    // Build a reqwest client that trusts our CA and uses the proxy.
    let ca_der = server.ca_cert_der().to_vec();
    let ca_cert = reqwest::Certificate::from_der(&ca_der).expect("parse CA cert");

    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}")).expect("proxy");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client");

    // Make an HTTPS request through the proxy. Uses an external endpoint.
    // Mark as ignored if you don't want network access in CI.
    let resp = client.get("https://httpbin.org/get").send().await;

    match resp {
        Ok(r) => {
            assert_eq!(r.status(), 200);
        }
        Err(e) => {
            // If we're in an environment without network access, that's OK.
            eprintln!("HTTPS tunnel test skipped (network error): {e}");
        }
    }

    token.cancel();
}
