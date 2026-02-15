//! TCP listener, per-connection task spawning, and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use bulwark_config::ProxyConfig;

use crate::handler;
use crate::tls::TlsState;

/// The Bulwark forward proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    tls_state: Arc<TlsState>,
    shutdown: CancellationToken,
    start_time: Instant,
}

impl ProxyServer {
    /// Create a new proxy server from the given configuration.
    ///
    /// This initialises the TLS subsystem (loading or generating the CA) but
    /// does **not** start listening.
    pub async fn new(config: ProxyConfig) -> bulwark_common::Result<Self> {
        let tls_state = Arc::new(TlsState::new(&config.tls.ca_dir)?);
        Ok(Self {
            config,
            tls_state,
            shutdown: CancellationToken::new(),
            start_time: Instant::now(),
        })
    }

    /// Return the CA certificate in DER form (useful for tests).
    pub fn ca_cert_der(&self) -> &rustls::pki_types::CertificateDer<'static> {
        self.tls_state.ca_cert_der()
    }

    /// Return a handle that can be used to trigger graceful shutdown.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Start listening and serving connections.
    ///
    /// This method runs until [`ProxyServer::trigger_shutdown`] is called or a
    /// `SIGINT`/`SIGTERM` is received.
    pub async fn run(&self) -> bulwark_common::Result<()> {
        let listener = TcpListener::bind(&self.config.listen_address)
            .await
            .map_err(|e| {
                bulwark_common::BulwarkError::Proxy(format!(
                    "failed to bind {}: {e}",
                    self.config.listen_address
                ))
            })?;

        let local_addr = listener.local_addr()?;
        tracing::info!(
            address = %local_addr,
            version = bulwark_common::VERSION,
            "Bulwark proxy started"
        );

        self.accept_loop(listener).await;

        tracing::info!("Bulwark proxy shut down");
        Ok(())
    }

    /// Like [`run`](Self::run) but binds to the given listener (useful for
    /// tests that pre-bind to port 0).
    pub async fn run_with_listener(&self, listener: TcpListener) -> bulwark_common::Result<()> {
        let local_addr = listener.local_addr()?;
        tracing::info!(
            address = %local_addr,
            version = bulwark_common::VERSION,
            "Bulwark proxy started"
        );

        self.accept_loop(listener).await;

        tracing::info!("Bulwark proxy shut down");
        Ok(())
    }

    /// Request a graceful shutdown.
    pub fn trigger_shutdown(&self) {
        self.shutdown.cancel();
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    async fn accept_loop(&self, listener: TcpListener) {
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            self.spawn_connection(stream, addr);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept error");
                        }
                    }
                }
            }
        }

        // Grace period for in-flight connections.
        tracing::info!("waiting for in-flight connections (5 s grace period)");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    fn spawn_connection(&self, stream: tokio::net::TcpStream, addr: SocketAddr) {
        let tls_state = Arc::clone(&self.tls_state);
        let start_time = self.start_time;

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let tls = Arc::clone(&tls_state);
                async move { handler::handle_request(req, addr, tls, start_time).await }
            });

            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);

            if let Err(e) = conn.await {
                tracing::debug!(error = %e, peer = %addr, "connection error");
            }
        });
    }
}
