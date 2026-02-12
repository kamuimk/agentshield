pub mod connect;
pub mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::error::Result;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::info;

use crate::cli::prompt::AskRequest;
use crate::policy::config::PolicyConfig;

pub struct ProxyServer {
    listen_addr: String,
    policy: Option<Arc<PolicyConfig>>,
    db: Option<Arc<Mutex<Connection>>>,
    ask_tx: Option<mpsc::Sender<AskRequest>>,
}

impl ProxyServer {
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            policy: None,
            db: None,
            ask_tx: None,
        }
    }

    pub fn with_policy(mut self, policy: PolicyConfig) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    pub fn with_db(mut self, db: Arc<Mutex<Connection>>) -> Self {
        self.db = Some(db);
        self
    }

    pub fn with_ask_channel(mut self, ask_tx: mpsc::Sender<AskRequest>) -> Self {
        self.ask_tx = Some(ask_tx);
        self
    }

    /// Start the proxy server and return the actual bound address.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("AgentShield proxy listening on {}", local_addr);

        let policy = self.policy.clone();
        let db = self.db.clone();
        let ask_tx = self.ask_tx.clone();
        tokio::spawn(async move {
            connect::accept_loop(listener, policy, db, ask_tx).await;
        });

        Ok(local_addr)
    }
}
