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

use bulwark_audit::event::{
    AuditEvent, Channel, EventOutcome, EventType, RequestInfo, SessionInfo,
};
use bulwark_audit::logger::AuditLogger;
use bulwark_policy::engine::PolicyEngine;
use bulwark_vault::store::Vault;

use crate::forward::{BoxBody, error_response};
use crate::logging::RequestLog;
use crate::tls::TlsState;

/// Handle a CONNECT request: upgrade the connection, perform TLS MITM, and
/// proxy the inner HTTP traffic.
pub async fn handle_connect(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
    tls_state: Arc<TlsState>,
    policy_engine: Option<Arc<PolicyEngine>>,
    vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    audit_logger: Option<AuditLogger>,
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

    // Evaluate policy on the CONNECT target if engine is configured.
    if let Some(engine) = &policy_engine {
        use bulwark_policy::context::RequestContext;
        use bulwark_policy::verdict::Verdict;

        let ctx = RequestContext::new(&target_host, format!("CONNECT {}", target_authority));
        let eval = engine.evaluate(&ctx);

        match eval.verdict {
            Verdict::Allow | Verdict::Transform => {}
            Verdict::Deny | Verdict::Escalate => {
                tracing::warn!(
                    host = %target_host,
                    verdict = ?eval.verdict,
                    reason = %eval.reason,
                    "policy denied CONNECT"
                );
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    &format!("Policy denied: {}", eval.reason),
                ));
            }
        }
    }

    // Spawn the MITM task after the upgrade completes.
    let tls_state_clone = Arc::clone(&tls_state);
    let target_host_clone = target_host.clone();
    let target_authority_clone = target_authority.clone();
    let policy_engine_clone = policy_engine;
    let vault_clone = vault;
    let audit_clone = audit_logger;

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
            policy_engine_clone,
            vault_clone,
            audit_clone,
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
#[allow(clippy::too_many_arguments)]
async fn mitm_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    target_host: &str,
    target_port: u16,
    _target_authority: &str,
    tls_state: Arc<TlsState>,
    policy_engine: Option<Arc<PolicyEngine>>,
    vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    audit_logger: Option<AuditLogger>,
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
        let policy = policy_engine.clone();
        let vault = vault.clone();
        let audit = audit_logger.clone();
        async move { forward_tls_request(req, &host, port, connector, policy, vault, audit).await }
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
    policy_engine: Option<Arc<PolicyEngine>>,
    vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    audit_logger: Option<AuditLogger>,
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

    // Validate session from X-Bulwark-Session header if vault is configured.
    let session = if let Some(ref vault) = vault {
        let vault_guard = vault.lock();
        let token = req
            .headers()
            .get("x-bulwark-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match token {
            Some(t) => match vault_guard.validate_session(&t) {
                Ok(Some(s)) => Some(s),
                Ok(None) => {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        "Invalid or expired session token",
                    ));
                }
                Err(e) => {
                    tracing::error!(error = %e, "session validation error");
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Session validation error",
                    ));
                }
            },
            None => {
                if vault_guard.require_sessions() {
                    return Ok(error_response(
                        StatusCode::UNAUTHORIZED,
                        "Session token required. Set X-Bulwark-Session header.",
                    ));
                }
                None
            }
        }
    } else {
        None
    };

    // Evaluate policy if engine is configured.
    if let Some(engine) = &policy_engine {
        use bulwark_policy::context::RequestContext;
        use bulwark_policy::verdict::Verdict;

        let action = format!("{} {}", method, path);
        let mut ctx = RequestContext::new(target_host, action);
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

        match eval.verdict {
            Verdict::Allow | Verdict::Transform => {}
            Verdict::Deny | Verdict::Escalate => {
                tracing::warn!(
                    host = %host,
                    method = %method,
                    verdict = ?eval.verdict,
                    reason = %eval.reason,
                    "policy denied HTTPS request"
                );
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    &format!("Policy denied: {}", eval.reason),
                ));
            }
        }
    }

    // Resolve credential injection if vault + session are available.
    let injection = if let (Some(vault), Some(session)) = (&vault, &session) {
        let vault_guard = vault.lock();
        match vault_guard.resolve_credential(target_host, session) {
            Ok(Some(cred)) => Some(bulwark_vault::injection::http_injection(&cred)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "credential resolution failed");
                None
            }
        }
    } else {
        None
    };

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
        // Determine which headers to strip (hop-by-hop + injection strips).
        let strip_set: std::collections::HashSet<String> = injection
            .as_ref()
            .map(|inj| inj.strip_headers.iter().cloned().collect())
            .unwrap_or_default();

        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name.as_str()) && !strip_set.contains(&name.as_str().to_lowercase()) {
                headers.insert(name.clone(), value.clone());
            }
        }
        headers.insert(
            "host",
            target_host
                .parse()
                .unwrap_or_else(|_| "unknown".parse().unwrap()),
        );

        // Inject credential headers.
        if let Some(ref inj) = injection {
            use secrecy::ExposeSecret;
            for (header_name, header_value) in &inj.headers {
                if let Ok(hv) = header_value
                    .expose_secret()
                    .parse::<hyper::header::HeaderValue>()
                {
                    if let Ok(hn) = header_name.parse::<hyper::header::HeaderName>() {
                        headers.insert(hn, hv);
                    }
                }
            }
        }
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

    // Build audit session info if available.
    let audit_session = session.as_ref().map(|s| SessionInfo {
        session_id: s.id.clone(),
        operator: s.operator.clone(),
        team: s.team.clone(),
        project: s.project.clone(),
        environment: s.environment.clone(),
        agent_type: s.agent_type.clone(),
    });

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

            // Emit audit event.
            if let Some(ref logger) = audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpsProxy)
                        .outcome(EventOutcome::Success)
                        .request(RequestInfo {
                            tool: host.clone(),
                            action: method.to_string(),
                            resource: None,
                            target: url.clone(),
                        })
                        .duration_us(start.elapsed().as_micros() as u64);
                if let Some(ref si) = audit_session {
                    builder = builder.session(si.clone());
                }
                logger.log(builder.build());
            }

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

            // Emit audit event for failed request.
            if let Some(ref logger) = audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpsProxy)
                        .outcome(EventOutcome::Failed)
                        .request(RequestInfo {
                            tool: host.clone(),
                            action: method.to_string(),
                            resource: None,
                            target: url.clone(),
                        })
                        .error(bulwark_audit::event::ErrorInfo {
                            category: "upstream".to_string(),
                            message: e.to_string(),
                        })
                        .duration_us(start.elapsed().as_micros() as u64);
                if let Some(ref si) = audit_session {
                    builder = builder.session(si.clone());
                }
                logger.log(builder.build());
            }

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
