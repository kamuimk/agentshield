pub mod connect;
pub mod tls;

use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::info;

pub struct ProxyServer {
    listen_addr: String,
}

impl ProxyServer {
    pub fn new(listen_addr: String) -> Self {
        Self { listen_addr }
    }

    /// Start the proxy server and return the actual bound address.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("AgentShield proxy listening on {}", local_addr);

        tokio::spawn(async move {
            connect::accept_loop(listener).await;
        });

        Ok(local_addr)
    }
}
