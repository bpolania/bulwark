//! `bulwark mcp start` — run the MCP governance gateway over stdio.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bulwark_config::{LogFormat, load_config};
use bulwark_mcp::gateway::McpGateway;
use bulwark_mcp::server::run_stdio_server;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// Start the MCP gateway in stdio mode.
///
/// **Critical**: All tracing output goes to stderr.  stdout is exclusively
/// for JSON-RPC messages — a single stray log line on stdout will corrupt
/// the transport and disconnect the agent.
pub fn start(config_path: &Path, log_level: Option<&str>) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;

    let level = log_level
        .map(String::from)
        .unwrap_or_else(|| config.logging.level.clone());

    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Tracing MUST go to stderr — stdout is the MCP transport.
    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_writer(std::io::stderr),
                )
                .init();
        }
    }

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        let gateway = McpGateway::new(config.mcp_gateway)
            .await
            .context("initialising MCP gateway")?;
        let gateway = Arc::new(gateway);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_clone.cancel();
        });

        run_stdio_server(gateway, shutdown)
            .await
            .context("running MCP server")?;

        Ok(())
    })
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
