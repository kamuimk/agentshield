//! HTTP/HTTPS proxy server.
//!
//! [`ProxyServer`] is configured via a builder pattern and spawns an async
//! accept loop that handles both plain HTTP forwarding and HTTPS CONNECT tunneling.
//! Each connection is processed against the policy engine, DLP scanner, and
//! system allowlist before being forwarded to the upstream server.

pub mod connect;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::ask::AskBroadcaster;
use crate::error::Result;
use crate::logging::DbPool;
use tokio::net::TcpListener;
use tracing::info;

use crate::dlp::DlpScanner;
use crate::notification::Notifier;
use crate::policy::config::PolicyConfig;
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
    policy: Option<Arc<PolicyConfig>>,
    db: Option<DbPool>,
    ask_broadcaster: Option<Arc<AskBroadcaster>>,
    dlp_scanner: Option<Arc<dyn DlpScanner>>,
    system_allowlist: Option<Arc<Vec<String>>>,
    notifier: Option<Arc<dyn Notifier>>,
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
        }
    }

    /// Attach a policy configuration for request evaluation.
    pub fn with_policy(mut self, policy: PolicyConfig) -> Self {
        self.policy = Some(Arc::new(policy));
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

    /// Start the proxy server and return the actual bound address.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("AgentShield proxy listening on {}", local_addr);

        let ctx = Arc::new(ConnectionContext {
            policy: self.policy.clone(),
            db: self.db.clone(),
            ask_broadcaster: self.ask_broadcaster.clone(),
            dlp_scanner: self.dlp_scanner.clone(),
            system_allowlist: self.system_allowlist.clone(),
            notifier: self.notifier.clone(),
        });
        tokio::spawn(async move {
            connect::accept_loop(listener, ctx).await;
        });

        Ok(local_addr)
    }
}
