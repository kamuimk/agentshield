//! HTTP/HTTPS proxy server.
//!
//! [`ProxyServer`] is configured via a builder pattern and spawns an async
//! accept loop that handles both plain HTTP forwarding and HTTPS CONNECT tunneling.
//! Each connection is processed against the policy engine, DLP scanner, and
//! system allowlist before being forwarded to the upstream server.

pub mod connect;
mod http;
pub mod network;
pub mod owned_listener;
pub mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::info;

use crate::ask::AskBroadcaster;
use crate::dlp::DlpScanner;
use crate::error::Result;
use crate::logging::{DbPool, LogEvent};
use crate::notification::Notifier;
use crate::policy::config::{LoggingConfig, PolicyConfig};
use crate::proxy::tls::CertCache;
use crate::ratelimit::RateLimiter;
use connect::ConnectionContext;

/// The main proxy server, configured via builder methods.
///
/// # Example
///
/// ```rust,ignore
/// let server = ProxyServer::new("127.0.0.1:18080".to_string())
///     .with_policy(policy_config)
///     .with_db(pool);
/// let addr = server.start().await?;
/// ```
pub struct ProxyServer {
    listen_addr: String,
    policy: Option<Arc<RwLock<PolicyConfig>>>,
    db: Option<DbPool>,
    ask_broadcaster: Option<Arc<AskBroadcaster>>,
    sensitive_approval: Option<Arc<AskBroadcaster>>,
    dlp_scanner: Option<Arc<dyn DlpScanner>>,
    system_allowlist: Option<Arc<Vec<String>>>,
    notifier: Option<Arc<dyn Notifier>>,
    event_tx: Option<broadcast::Sender<LogEvent>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    cert_cache: Option<Arc<CertCache>>,
    mitm_enabled: bool,
    logging_config: Option<LoggingConfig>,
    network: network::NetworkConfig,
}

impl ProxyServer {
    /// Create a new proxy server that will listen on the given address.
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            cert_cache: None,
            mitm_enabled: false,
            logging_config: None,
            network: network::NetworkConfig::default(),
        }
    }

    /// Attach a policy configuration for request evaluation.
    ///
    /// Accepts an `Arc<RwLock<PolicyConfig>>` so the policy can be
    /// hot-reloaded while the server is running.
    pub fn with_policy(mut self, policy: Arc<RwLock<PolicyConfig>>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attach a SQLite connection pool for request logging.
    pub fn with_db(mut self, db: DbPool) -> Self {
        self.db = Some(db);
        self
    }

    /// Attach an ASK broadcaster for multi-channel interactive approval.
    pub fn with_ask_broadcaster(mut self, broadcaster: Arc<AskBroadcaster>) -> Self {
        self.ask_broadcaster = Some(broadcaster);
        self
    }

    /// Use a dedicated authenticated responder for sensitive data, never the general
    /// terminal/web ASK channel. Approval applies only to this buffered request.
    pub fn with_sensitive_approval(mut self, broadcaster: Arc<AskBroadcaster>) -> Self {
        self.sensitive_approval = Some(broadcaster);
        self
    }

    /// Attach a DLP scanner for inspecting request bodies.
    pub fn with_dlp(mut self, scanner: Arc<dyn DlpScanner>) -> Self {
        self.dlp_scanner = Some(scanner);
        self
    }

    /// Attach a system allowlist; matching domains bypass policy evaluation.
    pub fn with_system_allowlist(mut self, allowlist: Vec<String>) -> Self {
        if !allowlist.is_empty() {
            self.system_allowlist = Some(Arc::new(allowlist));
        }
        self
    }

    /// Attach a notification backend for deny/DLP event alerts.
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Attach a broadcast channel for real-time log events.
    pub fn with_event_channel(mut self, tx: broadcast::Sender<LogEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Attach a rate limiter for domain-based request throttling.
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Enable MITM TLS interception with the given certificate cache.
    pub fn with_cert_cache(mut self, cache: Arc<CertCache>) -> Self {
        self.cert_cache = Some(cache);
        self.mitm_enabled = true;
        self
    }

    /// Attach audit logging configuration.
    pub fn with_logging_config(mut self, config: LoggingConfig) -> Self {
        self.logging_config = Some(config);
        self
    }

    /// Set destination constraints. Private networks are blocked by default.
    pub fn with_network_policy(mut self, config: network::NetworkConfig) -> Self {
        self.network = config;
        self
    }

    /// Start the proxy server and return the actual bound address plus a
    /// shutdown sender. Sending `true` on the sender stops the accept loop.
    pub async fn start(&self) -> Result<(SocketAddr, tokio::sync::watch::Sender<bool>)> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        self.serve_listener(listener).await
    }

    /// Use a caller-owned listener without releasing and rebinding its address.
    pub async fn start_with_listener(
        &self,
        listener: TcpListener,
    ) -> Result<(SocketAddr, tokio::sync::watch::Sender<bool>)> {
        let expected: SocketAddr = self
            .listen_addr
            .parse()
            .map_err(|_| std::io::Error::other("owned_listener_address_invalid"))?;
        let local_addr = listener.local_addr()?;
        if local_addr != expected && !(expected.port() == 0 && local_addr.ip() == expected.ip()) {
            return Err(std::io::Error::other("owned_listener_address_mismatch").into());
        }
        self.serve_listener(listener).await
    }

    async fn serve_listener(
        &self,
        listener: TcpListener,
    ) -> Result<(SocketAddr, tokio::sync::watch::Sender<bool>)> {
        let local_addr = listener.local_addr()?;
        info!("AgentShield proxy listening on {}", local_addr);

        // Build upstream TLS config once for MITM mode (reused across all connections)
        let upstream_tls_config = if self.mitm_enabled {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?
            .with_root_certificates(root_store)
            .with_no_client_auth();
            Some(Arc::new(config))
        } else {
            None
        };

        let ctx = Arc::new(ConnectionContext {
            policy: self.policy.clone(),
            db: self.db.clone(),
            ask_broadcaster: self.ask_broadcaster.clone(),
            sensitive_approval: self.sensitive_approval.clone(),
            dlp_scanner: self.dlp_scanner.clone(),
            system_allowlist: self.system_allowlist.clone(),
            notifier: self.notifier.clone(),
            event_tx: self.event_tx.clone(),
            rate_limiter: self.rate_limiter.clone(),
            mitm_enabled: self.mitm_enabled,
            cert_cache: self.cert_cache.clone(),
            upstream_tls_config,
            logging_config: self.logging_config.clone(),
            network: self.network.clone(),
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            connect::accept_loop(listener, ctx, shutdown_rx).await;
        });

        Ok((local_addr, shutdown_tx))
    }
}

#[cfg(test)]
mod owned_listener_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn handed_listener_serves_without_rebinding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = ProxyServer::new(address.to_string()).with_policy(Arc::new(RwLock::new(
            PolicyConfig {
                default: crate::policy::config::Action::Deny,
                rules: vec![],
            },
        )));
        let (actual, shutdown) = server.start_with_listener(listener).await.unwrap();
        assert_eq!(actual, address);
        let mut connection = tokio::net::TcpStream::connect(actual).await.unwrap();
        connection.write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = [0; 64];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connection.read(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response[..count].starts_with(b"HTTP/1.1 403"));
        shutdown.send(true).unwrap();
    }

    #[tokio::test]
    async fn handed_listener_cannot_change_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = ProxyServer::new("127.0.0.2:0".into())
            .start_with_listener(listener)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("address_mismatch"));
    }

    #[tokio::test]
    async fn ordinary_hostname_binding_remains_supported() {
        let (address, shutdown) = ProxyServer::new("localhost:0".into())
            .start()
            .await
            .unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        shutdown.send(true).unwrap();
    }
}
