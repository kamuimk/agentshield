//! Synthetic integration fixture for browser tests. Never uses service credentials.
use agentshield::{
    logging,
    policy::config::{Action, PolicyConfig},
    web::{self, AppState},
};
use std::sync::{Arc, RwLock};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let origin = std::env::args()
        .nth(1)
        .expect("provide the browser test parent origin");
    let (event_tx, _) = tokio::sync::broadcast::channel(16);
    let pool = logging::open_memory_pool()?;
    logging::log_request(
        &*pool.get()?,
        &logging::RequestLog {
            id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: "GET".into(),
            domain: "<img src=x onerror=\"window.injected=true\">".into(),
            path: "/fixture".into(),
            action: "deny".into(),
            reason: "synthetic event".into(),
            request_body: Some("SYNTHETIC_AUDIT_BODY".into()),
            dlp_findings: None,
        },
    )?;
    let state = Arc::new(AppState {
        db: Some(pool),
        event_tx: event_tx.clone(),
        policy: Some(Arc::new(RwLock::new(PolicyConfig {
            default: Action::Deny,
            rules: vec![],
        }))),
        auth_token: Some("admin-token-0000000000000000000000".into()),
    });
    let (ask_event_tx, _) = tokio::sync::broadcast::channel(16);
    let asks = web::ask::AskState {
        pending: Default::default(),
        ask_event_tx,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    asks.pending.lock().unwrap().insert(
        "fixture-ask".into(),
        web::ask::PendingWebAsk {
            info: agentshield::ask::AskRequestInfo {
                req_id: "fixture-ask".into(),
                approval: None,

                domain: "example.test".into(),
                method: "POST".into(),
                path: "<img src=x onerror=\"window.injected=true\">".into(),
                body: None,
            },
            tx,
        },
    );
    tokio::spawn(async {
        let _ = rx.await;
    });
    let app = web::integration::router(
        state,
        asks,
        web::integration::IntegrationConfig {
            allowed_origins: vec![origin],
            read_token: "reader-token-000000000000000000000".into(),
            control_token: Some("control-token-00000000000000000000".into()),
        },
    )
    .map_err(anyhow::Error::msg)?;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let _ = event_tx.send(logging::LogEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                method: "GET".into(),
                domain: "stream.example.test".into(),
                path: "/stream".into(),
                action: "deny".into(),
                reason: "fixture".into(),
            });
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!("http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
