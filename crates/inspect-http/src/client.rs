//! HTTP client for calling external analyzer endpoints.

use reqwest::Client;

use crate::config::HttpAnalyzerConfig;
use crate::protocol::{AnalyzerRequest, AnalyzerResponse};

/// HTTP client for a single analyzer endpoint.
pub struct AnalyzerClient {
    client: Client,
    endpoint: String,
}

impl AnalyzerClient {
    /// Create a new client for the given analyzer configuration.
    pub fn new(config: &HttpAnalyzerConfig) -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            endpoint: config.endpoint.clone(),
        }
    }

    /// Call the analyzer endpoint with the given request.
    pub async fn call(&self, request: &AnalyzerRequest) -> Result<AnalyzerResponse, ClientError> {
        let resp = self
            .client
            .post(&self.endpoint)
            .json(request)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "analyzer returned HTTP {}",
                status
            )));
        }

        let body = resp
            .json::<AnalyzerResponse>()
            .await
            .map_err(|e| ClientError::Parse(e.to_string()))?;

        Ok(body)
    }
}

/// Errors from the analyzer HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(String),
    /// Response parse error.
    #[error("parse error: {0}")]
    Parse(String),
}
