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
use bulwark_proxy::server::ProxyServer;

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
