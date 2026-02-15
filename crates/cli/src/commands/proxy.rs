//! `bulwark proxy start` — load config, set up tracing, run the proxy.

use std::path::Path;

use anyhow::{Context, Result};
use bulwark_config::{LogFormat, load_config};
use bulwark_proxy::server::ProxyServer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// Start the Bulwark proxy server.
pub fn start(
    config_path: &Path,
    log_level: Option<&str>,
    listen_override: Option<&str>,
) -> Result<()> {
    let mut config = load_config(config_path).context("loading configuration")?;

    // Apply CLI overrides.
    if let Some(addr) = listen_override {
        config.proxy.listen_address = addr.to_string();
    }

    // Determine log level: CLI flag > config > default.
    let level = log_level
        .map(String::from)
        .unwrap_or_else(|| config.logging.level.clone());

    // Set up tracing.
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }

    // Build a tokio runtime and run the server.
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async {
        let server = ProxyServer::new(config.proxy)
            .await
            .context("initialising proxy server")?;

        let shutdown_token = server.shutdown_token();

        // Listen for SIGINT / SIGTERM.
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_token.cancel();
        });

        server.run().await.context("running proxy server")?;
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
