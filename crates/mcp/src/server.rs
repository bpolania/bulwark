//! MCP server — runs the gateway over a stdio transport.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::gateway::McpGateway;
use crate::transport::stdio::StdioTransport;

/// Run the MCP gateway as a server over stdio.
///
/// Blocks until stdin closes (agent disconnects) or shutdown is triggered.
pub async fn run_stdio_server(
    gateway: Arc<McpGateway>,
    shutdown: CancellationToken,
) -> bulwark_common::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut transport = StdioTransport::new(stdin, stdout);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("MCP server shutting down");
                break;
            }
            msg = transport.read_message() => {
                match msg {
                    Ok(Some(message)) => {
                        if let Some(response) = gateway.handle_message(message).await {
                            transport.write_message(&response).await?;
                        }
                    }
                    Ok(None) => {
                        tracing::info!("Agent disconnected (EOF)");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Error reading message");
                    }
                }
            }
        }
    }

    gateway.shutdown().await;
    Ok(())
}
