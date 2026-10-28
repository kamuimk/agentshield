//! Real local TLS interception and upstream non-delivery, with in-memory trust only.
use agentshield::dlp::patterns::RegexScanner;
use agentshield::policy::config::{Action, PolicyConfig};
use agentshield::proxy::{
    connect::{ConnectionContext, accept_loop},
    network::NetworkConfig,
    tls::CertCache,
};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn request(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
    body: &str,
) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 4096);
        header.push(stream.read_u8().await.unwrap());
    }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let mut tls = connector.connect(name, stream).await.unwrap();
    tls.write_all(format!("POST /submit HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    // Some denial paths close without close_notify; still require the full
    // expected HTTP status/body below, rather than treating TLS EOF as success.
    let _ = tls.read_to_end(&mut response).await;
    response
}

#[tokio::test]
async fn inspected_tls_blocks_duplicate_field_secrets_before_upstream_connect() {
    verify_tls("trusted").await;
}

#[tokio::test]
async fn inspected_tls_rejects_untrusted_upstream_before_body_delivery() {
    verify_tls("untrusted").await;
}

#[tokio::test]
async fn inspected_tls_rejects_wrong_upstream_hostname_before_body_delivery() {
    verify_tls("wrong-hostname").await;
}

async fn verify_tls(case: &'static str) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let directory = tempfile::tempdir().unwrap();
    let ca = directory.path().join("ca");
    agentshield::cli::ca::generate_ca(&ca).unwrap();
    let cache = Arc::new(CertCache::load(&ca).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(ca.join("cert.pem")).unwrap();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
        roots.add(cert.unwrap()).unwrap();
    }
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let upstream_client = if case == "untrusted" {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        )
    } else {
        client.clone()
    };
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let endpoint = match target {
        std::net::SocketAddr::V4(v) => v,
        _ => unreachable!(),
    };
    let ctx = ConnectionContext {
        policy: Some(Arc::new(RwLock::new(PolicyConfig {
            default: Action::Allow,
            rules: vec![],
        }))),
        db: None,
        ask_broadcaster: None,
        sensitive_approval: None,
        host_authenticator: None,
        dlp_scanner: Some(Arc::new(RegexScanner::new())),
        system_allowlist: None,
        notifier: None,
        event_tx: None,
        rate_limiter: None,
        mitm_enabled: true,
        cert_cache: Some(cache.clone()),
        upstream_tls_config: Some(upstream_client),
        logging_config: None,
        network: NetworkConfig {
            connect_ports: vec![target.port()],
            loopback_endpoint: Some(endpoint),
            ..Default::default()
        },
    };
    let (stop, rx) = tokio::sync::watch::channel(false);
    let accept = tokio::spawn(accept_loop(listener, Arc::new(ctx), rx));
    let hidden = r#"{"value":"sk\u002dabcdefghijklmnopqrstuvwxyz1234567890","value":"harmless"}"#;
    for body in [hidden.to_string(), STANDARD.encode(hidden)] {
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            request(proxy, target, client.clone(), &body),
        )
        .await
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert!(!String::from_utf8_lossy(&response).contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), upstream.accept())
                .await
                .is_err()
        );
    }
    let server_config = cache
        .get_or_create(if case == "wrong-hostname" {
            "wrong.example.test"
        } else {
            "127.0.0.1"
        })
        .unwrap();
    let receiver = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut tls = match tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
        {
            Ok(tls) => tls,
            Err(_) => {
                assert_ne!(case, "trusted");
                return Vec::new();
            }
        };
        let mut raw = Vec::new();
        while !raw.ends_with(b"ordinary harmless prose") {
            let mut part = [0; 1024];
            match tls.read(&mut part).await {
                Ok(n) if n > 0 => raw.extend_from_slice(&part[..n]),
                _ => {
                    assert_ne!(case, "trusted");
                    return raw;
                }
            }
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
        raw
    });
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        request(proxy, target, client, "ordinary harmless prose"),
    )
    .await
    .unwrap();
    if case == "trusted" {
        assert!(response.starts_with(b"HTTP/1.1 200") && response.ends_with(b"OK"));
    } else {
        assert!(response.starts_with(b"HTTP/1.1 502"));
    }
    let received = tokio::time::timeout(Duration::from_secs(3), receiver)
        .await
        .unwrap()
        .unwrap();
    if case == "trusted" {
        assert!(received.ends_with(b"ordinary harmless prose"));
    } else {
        assert!(
            received.is_empty(),
            "invalid certificate must prevent all HTTP bytes"
        );
    }
    stop.send(true).unwrap();
    accept.await.unwrap();
}
