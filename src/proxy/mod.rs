pub mod connect;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::info;

use crate::policy::config::PolicyConfig;

pub struct ProxyServer {
    listen_addr: String,
    policy: Option<Arc<PolicyConfig>>,
}

impl ProxyServer {
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            policy: None,
        }
    }

    pub fn with_policy(mut self, policy: PolicyConfig) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    /// Start the proxy server and return the actual bound address.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("AgentShield proxy listening on {}", local_addr);

        let policy = self.policy.clone();
        tokio::spawn(async move {
            connect::accept_loop(listener, policy).await;
        });

        Ok(local_addr)
    }
}
