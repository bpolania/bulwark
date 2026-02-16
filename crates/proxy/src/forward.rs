//! Plain HTTP forward proxy — handles non-CONNECT requests where the client
//! sends an absolute URI (e.g. `GET http://example.com/path`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use uuid::Uuid;

use bulwark_audit::event::{
    AuditEvent, Channel, EventOutcome, EventType, RequestInfo, SessionInfo,
};
use bulwark_audit::logger::AuditLogger;
use bulwark_inspect::scanner::ContentScanner;
use bulwark_policy::engine::PolicyEngine;
use bulwark_vault::store::Vault;

use crate::logging::RequestLog;

/// Boxed body type used for proxy responses.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Forward a plain HTTP request to the target server and return the response.
pub async fn forward_request(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
    policy_engine: Option<Arc<PolicyEngine>>,
    vault: Option<Arc<parking_lot::Mutex<Vault>>>,
    audit_logger: Option<AuditLogger>,
    content_scanner: Option<Arc<ContentScanner>>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("unknown").to_string();
    let url = uri.to_string();

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

        let path = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
        let action = format!("{} {}", method, path);
        let mut ctx = RequestContext::new(&host, action);
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
                    "policy denied HTTP request"
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
        match vault_guard.resolve_credential(&host, session) {
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

    // Collect the request body so we can measure its size.
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

    // Inspect request body if scanner is configured.
    if let Some(ref scanner) = content_scanner {
        let result = scanner.scan_bytes(&body_bytes);
        if result.should_block {
            tracing::warn!(
                host = %host,
                findings = result.findings.len(),
                "Content inspection blocked HTTP request"
            );
            return Ok(error_response(
                StatusCode::FORBIDDEN,
                "Request blocked by content inspection",
            ));
        }
    }

    // Build the outbound request, stripping hop-by-hop headers.
    let mut builder = Request::builder().method(parts.method).uri(&uri);
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
    let outbound = match builder.body(
        Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed(),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to build outbound request");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    // Send via a pooled hyper client.
    let client: Client<_, BoxBody> = Client::builder(TokioExecutor::new()).build_http();

    let result = client.request(outbound).await;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Build audit session info if available.
    let audit_session = session.as_ref().map(|s| SessionInfo {
        session_id: s.id.clone(),
        operator: s.operator.clone(),
        team: s.team.clone(),
        project: s.project.clone(),
        environment: s.environment.clone(),
        agent_type: s.agent_type.clone(),
    });

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();

            // Stream the response body back, collecting size info.
            let (resp_parts, resp_body) = resp.into_parts();
            let resp_bytes = match resp_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_e) => Bytes::new(),
            };
            let response_bytes = resp_bytes.len() as u64;

            RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url,
                host: host.clone(),
                status,
                latency_ms,
                request_bytes,
                response_bytes,
                tls: false,
                error: None,
            }
            .emit();

            // Emit audit event.
            if let Some(ref logger) = audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
                        .outcome(EventOutcome::Success)
                        .request(RequestInfo {
                            tool: host,
                            action: method.to_string(),
                            resource: None,
                            target: uri.to_string(),
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
            RequestLog {
                id: request_id,
                timestamp: Utc::now(),
                method: method.to_string(),
                url,
                host: host.clone(),
                status: 502,
                latency_ms,
                request_bytes,
                response_bytes: 0,
                tls: false,
                error: Some(e.to_string()),
            }
            .emit();

            // Emit audit event for failed request.
            if let Some(ref logger) = audit_logger {
                let mut builder =
                    AuditEvent::builder(EventType::RequestProcessed, Channel::HttpProxy)
                        .outcome(EventOutcome::Failed)
                        .request(RequestInfo {
                            tool: host,
                            action: method.to_string(),
                            resource: None,
                            target: uri.to_string(),
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

/// Build a simple error response with a JSON body.
pub fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("valid error response")
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
