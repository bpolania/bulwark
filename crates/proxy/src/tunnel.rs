//! HTTPS CONNECT tunnelling with TLS man-in-the-middle.
//!
//! When a client sends `CONNECT host:port`, Bulwark:
//! 1. Responds with `200 Connection Established`
//! 2. Upgrades the connection to get the raw TCP stream
//! 3. Performs a TLS handshake with the client (presenting a leaf cert for
//!    the target hostname, signed by Bulwark's CA)
//! 4. Connects to the real server over TLS using system root certs
//! 5. Reads decrypted HTTP from the client, forwards to the server, and
//!    returns the response — logging every request

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::forward::{BoxBody, error_response};
use crate::logging::RequestLog;
use crate::tls::TlsState;

/// Handle a CONNECT request: upgrade the connection, perform TLS MITM, and
/// proxy the inner HTTP traffic.
pub async fn handle_connect(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
    tls_state: Arc<TlsState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Extract the target host:port from the CONNECT URI.
    let target_authority = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "CONNECT missing authority",
            ));
        }
    };

    let target_host = req.uri().host().unwrap_or("unknown").to_string();
    let target_port = req.uri().port_u16().unwrap_or(443);

    // Spawn the MITM task after the upgrade completes.
    let tls_state_clone = Arc::clone(&tls_state);
    let target_host_clone = target_host.clone();
    let target_authority_clone = target_authority.clone();

    tokio::spawn(async move {
        // Wait for the HTTP upgrade to complete.
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(error = %e, "upgrade failed");
                return;
            }
        };

        if let Err(e) = mitm_tunnel(
            upgraded,
            &target_host_clone,
            target_port,
            &target_authority_clone,
            tls_state_clone,
        )
        .await
        {
            tracing::debug!(error = %e, host = %target_host_clone, "tunnel error");
        }
    });

    // Respond with 200 to tell the client the tunnel is established.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("valid CONNECT response"))
}

/// Perform the TLS MITM: accept TLS from the client, connect TLS to the
/// server, and proxy decrypted HTTP between them.
async fn mitm_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    target_host: &str,
    target_port: u16,
    _target_authority: &str,
    tls_state: Arc<TlsState>,
) -> bulwark_common::Result<()> {
    // --- Client-side TLS (we are the "server" to the client) ---
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&tls_state) as Arc<dyn rustls::server::ResolvesServerCert>);

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(|e| bulwark_common::BulwarkError::Tls(format!("client TLS handshake: {e}")))?;

    // --- Server-side TLS (we are the "client" to the real server) ---
    let server_name = rustls::pki_types::ServerName::try_from(target_host.to_string())
        .map_err(|e| bulwark_common::BulwarkError::Tls(format!("invalid server name: {e}")))?;

    let tcp = tokio::net::TcpStream::connect((target_host, target_port))
        .await
        .map_err(|e| {
            bulwark_common::BulwarkError::Proxy(format!(
                "connect to {target_host}:{target_port}: {e}"
            ))
        })?;

    let _server_tls = tls_state
        .server_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| bulwark_common::BulwarkError::Tls(format!("server TLS handshake: {e}")))?;

    // Set up a hyper HTTP/1 server on the client side to read decrypted
    // requests, and use a hyper client to forward them over the server TLS
    // connection.
    let target_host_owned = target_host.to_string();
    let target_port_owned = target_port;

    let service = service_fn(move |req: Request<Incoming>| {
        let host = target_host_owned.clone();
        let port = target_port_owned;
        let connector = tls_state.server_connector.clone();
        async move { forward_tls_request(req, &host, port, connector).await }
    });

    let conn = http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(client_tls), service)
        .with_upgrades();

    conn.await
        .map_err(|e| bulwark_common::BulwarkError::Proxy(format!("MITM connection: {e}")))?;

    Ok(())
}

/// Forward a single decrypted HTTP request to the real server over a fresh
/// TLS connection.
async fn forward_tls_request(
    req: Request<Incoming>,
    target_host: &str,
    target_port: u16,
    connector: TlsConnector,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("https://{target_host}{path}");
    let host = target_host.to_string();

    // Collect request body.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
            ));
        }
    };
    let request_bytes = body_bytes.len() as u64;

    // Connect to the real server.
    let tcp = match tokio::net::TcpStream::connect((target_host, target_port)).await {
        Ok(t) => t,
        Err(e) => {
            log_request(
                request_id,
                &method,
                &url,
                &host,
                502,
                start,
                request_bytes,
                0,
                true,
                Some(e.to_string()),
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("connect failed: {e}"),
            ));
        }
    };

    let server_name = match rustls::pki_types::ServerName::try_from(target_host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            log_request(
                request_id,
                &method,
                &url,
                &host,
                502,
                start,
                request_bytes,
                0,
                true,
                Some(e.to_string()),
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("invalid server name: {e}"),
            ));
        }
    };

    let tls_stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            log_request(
                request_id,
                &method,
                &url,
                &host,
                502,
                start,
                request_bytes,
                0,
                true,
                Some(e.to_string()),
            );
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("TLS connect failed: {e}"),
            ));
        }
    };

    // Use hyper to send the HTTP request over the TLS stream.
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "outbound connection closed");
        }
    });

    // Build the outbound request.
    let mut builder = Request::builder().method(parts.method).uri(&path);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name.as_str()) {
                headers.insert(name.clone(), value.clone());
            }
        }
        headers.insert(
            "host",
            target_host
                .parse()
                .unwrap_or_else(|_| "unknown".parse().unwrap()),
        );
    }

    let outbound: Request<BoxBody> = match builder.body(
        Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed(),
    ) {
        Ok(r) => r,
        Err(e) => {
            log_request(
                request_id,
                &method,
                &url,
                &host,
                500,
                start,
                request_bytes,
                0,
                true,
                Some(e.to_string()),
            );
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    match sender.send_request(outbound).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let (resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            let response_bytes = resp_bytes.len() as u64;

            log_request(
                request_id,
                &method,
                &url,
                &host,
                status,
                start,
                request_bytes,
                response_bytes,
                true,
                None,
            );

            let body = Full::new(resp_bytes)
                .map_err(|never| match never {})
                .boxed();
            Ok(Response::from_parts(resp_parts, body))
        }
        Err(e) => {
            log_request(
                request_id,
                &method,
                &url,
                &host,
                502,
                start,
                request_bytes,
                0,
                true,
                Some(e.to_string()),
            );
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream error: {e}"),
            ))
        }
    }
}

/// Emit a structured log entry for a proxied request.
#[allow(clippy::too_many_arguments)]
fn log_request(
    id: Uuid,
    method: &Method,
    url: &str,
    host: &str,
    status: u16,
    start: Instant,
    request_bytes: u64,
    response_bytes: u64,
    tls: bool,
    error: Option<String>,
) {
    RequestLog {
        id,
        timestamp: Utc::now(),
        method: method.to_string(),
        url: url.to_string(),
        host: host.to_string(),
        status,
        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        request_bytes,
        response_bytes,
        tls,
        error,
    }
    .emit();
}

/// Returns `true` for headers that must not be forwarded by a proxy.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

use tokio_rustls::TlsConnector;
