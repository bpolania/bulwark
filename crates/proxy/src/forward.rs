//! Plain HTTP forward proxy — handles non-CONNECT requests where the client
//! sends an absolute URI (e.g. `GET http://example.com/path`).

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use uuid::Uuid;

use crate::logging::RequestLog;

/// Boxed body type used for proxy responses.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Forward a plain HTTP request to the target server and return the response.
pub async fn forward_request(
    req: Request<Incoming>,
    _client_addr: SocketAddr,
) -> Result<Response<BoxBody>, hyper::Error> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("unknown").to_string();
    let url = uri.to_string();

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

    // Build the outbound request, stripping hop-by-hop headers.
    let mut builder = Request::builder().method(parts.method).uri(&uri);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name.as_str()) {
                headers.insert(name.clone(), value.clone());
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
                host,
                status,
                latency_ms,
                request_bytes,
                response_bytes,
                tls: false,
                error: None,
            }
            .emit();

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
                host,
                status: 502,
                latency_ms,
                request_bytes,
                response_bytes: 0,
                tls: false,
                error: Some(e.to_string()),
            }
            .emit();

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
