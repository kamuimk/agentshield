//! Loopback-only synthetic host-transport acceptance fixture. NOT a product entrypoint.
//! It uses the production parser/MITM/DLP/held-request path with a test-only upstream CA.
//! stdio decisions are fixture decisions, never evidence of authenticated human approval.
use agentshield::{
    ask::{AskBroadcaster, AskRequestInfo, AskResponder},
    dlp::patterns::RegexScanner,
    policy::config::{Action, PolicyConfig, Rule},
    proxy::{
        connect::{ConnectionContext, accept_loop},
        network::NetworkConfig,
        tls::CertCache,
    },
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{Mutex, oneshot},
};

type Pending = Arc<Mutex<HashMap<String, (String, oneshot::Sender<bool>)>>>;

static OUTPUT: Mutex<()> = Mutex::const_new(());

async fn emit(value: serde_json::Value) {
    let _output = OUTPUT.lock().await;
    // Each complete frame is written while holding stdout; concurrent prompts cannot interleave.
    let mut stdout = tokio::io::stdout();
    let mut bytes = serde_json::to_vec(&value).expect("fixture JSON");
    bytes.push(b'\n');
    let _ = stdout.write_all(&bytes).await;
    let _ = stdout.flush().await;
}

struct Responder {
    pending: Pending,
}
#[async_trait::async_trait]
impl AskResponder for Responder {
    async fn prompt(&self, request: &AskRequestInfo) -> Option<bool> {
        let metadata = request.approval.as_ref()?;
        // The public engine must not offer paths, headers, payload previews or credentials here.
        assert!(request.body.is_none());
        assert_eq!(request.path, "[withheld]");
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(
            request.req_id.clone(),
            (metadata.request_sha256.clone(), tx),
        );
        emit(json!({"type":"approval", "requestId":request.req_id,
            "requestSha256":metadata.request_sha256, "requestBytes":metadata.request_bytes,
            "categories":metadata.categories}))
        .await;
        let answer = rx.await.ok();
        self.pending.lock().await.remove(&request.req_id);
        answer
    }
    async fn notify_resolved(&self, request_id: &str, allowed: bool) {
        self.pending.lock().await.remove(request_id);
        emit(json!({"type":"resolved", "requestId":request_id, "allowed":allowed})).await;
    }
    fn name(&self) -> &str {
        "synthetic-stdio-only"
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "requestSha256")]
    digest: String,
    allowed: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("AGENTSHIELD_SYNTHETIC_FIXTURE").as_deref() == Ok("1"),
        "synthetic opt-in required"
    );
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(
        (3..=5).contains(&args.len()),
        "usage: inspection_fixture <private-ca-dir> <synthetic-upstream-cert> <loopback-port> [private-authority-json] [private-approval-json]"
    );
    let upstream_port: u16 = args[2]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid port"))?
        .parse()?;
    anyhow::ensure!(upstream_port != 0, "nonzero synthetic port required");
    let ca_dir = PathBuf::from(&args[0]);
    anyhow::ensure!(!ca_dir.exists(), "CA directory must be fresh");
    agentshield::cli::ca::generate_ca(&ca_dir)?;
    let cache = Arc::new(CertCache::load(&ca_dir)?);
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&args[1])?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_slice())) {
        roots.add(cert?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "synthetic root required");
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let mut approval = AskBroadcaster::new(10);
    if args.len() == 5 {
        use agentshield::ask::workos::{WorkosApprovalConfig, WorkosApprovalResponder};
        use std::io::Read;
        let file = std::fs::File::open(&args[4])
            .map_err(|_| anyhow::anyhow!("invalid fixture approval config"))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "invalid fixture approval config"
        );
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        file.take(8193).read_to_end(&mut raw)?;
        anyhow::ensure!(raw.len() <= 8192, "invalid fixture approval config");
        let config: WorkosApprovalConfig = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("invalid fixture approval config"))?;
        approval.add_responder(Arc::new(
            WorkosApprovalResponder::new(config)
                .map_err(|_| anyhow::anyhow!("invalid fixture approval config"))?,
        ));
    } else {
        approval.add_responder(Arc::new(Responder {
            pending: pending.clone(),
        }));
    }
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![Rule {
            name: "synthetic-loopback-only".into(),
            domains: vec!["127.0.0.1".into(), "localhost".into()],
            action: Action::Allow,
            methods: None,
            note: None,
            rate_limit: None,
        }],
    };
    let host_authenticator: Option<
        Arc<dyn agentshield::proxy::host_authentication::HostAuthenticator>,
    > = if args.len() >= 4 && args[3] != "-" {
        use std::io::Read;
        let file = std::fs::File::open(&args[3])
            .map_err(|_| anyhow::anyhow!("invalid fixture authority"))?;
        anyhow::ensure!(file.metadata()?.is_file(), "invalid fixture authority");
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        file.take(8193).read_to_end(&mut raw)?;
        anyhow::ensure!(raw.len() <= 8192, "invalid fixture authority");
        let config = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("invalid fixture authority"))?;
        Some(Arc::new(
            agentshield::proxy::host_authentication::HostAuthenticationClient::new(config)
                .map_err(|_| anyhow::anyhow!("invalid fixture authority"))?,
        ))
    } else {
        None
    };
    let host_authentication_enabled = host_authenticator.is_some();
    let context = Arc::new(ConnectionContext {
        policy: Some(Arc::new(RwLock::new(policy))),
        db: None,
        ask_broadcaster: None,
        host_authenticator,
        sensitive_approval: Some(Arc::new(approval)),
        dlp_scanner: Some(Arc::new(RegexScanner::new())),
        system_allowlist: None,
        notifier: None,
        event_tx: None,
        rate_limiter: None,
        mitm_enabled: true,
        cert_cache: Some(cache),
        upstream_tls_config: Some(Arc::new(tls)),
        logging_config: None,
        network: NetworkConfig {
            block_private_networks: false,
            connect_ports: vec![upstream_port],
        },
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, context, stopped));
    emit(
        json!({"type":"ready", "proxy":format!("http://{address}"), "ca":ca_dir.join("cert.pem"), "hostAuthentication":host_authentication_enabled}),
    )
    .await;
    let mut input = BufReader::new(tokio::io::stdin());
    'input: loop {
        let mut line = Vec::new();
        loop {
            let Ok(byte) = input.read_u8().await else {
                break 'input;
            };
            if byte == b'\n' {
                break;
            }
            line.push(byte);
            if line.len() > 1024 {
                break 'input;
            }
        }
        let Ok(decision) = serde_json::from_slice::<Decision>(&line) else {
            break;
        };
        let mut held = pending.lock().await;
        let matching = held
            .get(&decision.request_id)
            .is_some_and(|(digest, _)| *digest == decision.digest);
        if matching {
            if let Some((_, sender)) = held.remove(&decision.request_id) {
                let _ = sender.send(decision.allowed);
            }
        }
        drop(held);
        emit(json!({"type":"decision", "accepted":matching})).await;
    }
    drop(pending);
    let _ = stop.send(true);
    task.await?;
    Ok(())
}
