//! HTTP/HTTPS proxy server.
//!
//! [`ProxyServer`] is configured via a builder pattern and spawns an async
//! accept loop that handles both plain HTTP forwarding and HTTPS CONNECT tunneling.
//! Each connection is processed against the policy engine, DLP scanner, and
//! system allowlist before being forwarded to the upstream server.

pub mod connect;
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
    dlp_scanner: Option<Arc<dyn DlpScanner>>,
    system_allowlist: Option<Arc<Vec<String>>>,
    notifier: Option<Arc<dyn Notifier>>,
    event_tx: Option<broadcast::Sender<LogEvent>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    cert_cache: Option<Arc<CertCache>>,
    mitm_enabled: bool,
    logging_config: Option<LoggingConfig>,
}

impl ProxyServer {
    /// Create a new proxy server that will listen on the given address.
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            policy: None,
            db: None,
            ask_broadcaster: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            cert_cache: None,
            mitm_enabled: false,
            logging_config: None,
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

    /// Start the proxy server and return the actual bound address plus a
    /// shutdown sender. Sending `true` on the sender stops the accept loop.
    pub async fn start(&self) -> Result<(SocketAddr, tokio::sync::watch::Sender<bool>)> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
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
            dlp_scanner: self.dlp_scanner.clone(),
            system_allowlist: self.system_allowlist.clone(),
            notifier: self.notifier.clone(),
            event_tx: self.event_tx.clone(),
            rate_limiter: self.rate_limiter.clone(),
            mitm_enabled: self.mitm_enabled,
            cert_cache: self.cert_cache.clone(),
            upstream_tls_config,
            logging_config: self.logging_config.clone(),
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            connect::accept_loop(listener, ctx, shutdown_rx).await;
        });

        Ok((local_addr, shutdown_tx))
    }
}
