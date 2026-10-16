//! Attack regressions use only loopback fixtures and never contact external services.
use agentshield::{
    dlp::patterns::RegexScanner,
    policy::config::{Action, PolicyConfig, Rule},
    proxy::{ProxyServer, network::NetworkConfig},
};
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn allow() -> PolicyConfig {
    PolicyConfig {
        default: Action::Allow,
        rules: vec![],
    }
}
fn local_network() -> NetworkConfig {
    NetworkConfig {
        block_private_networks: false,
        ..Default::default()
    }
}

async fn raw(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn fragmented_secret_body_is_blocked_before_upstream_connection() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_network_policy(local_network())
        .with_dlp(Arc::new(RegexScanner::new()))
        .start()
        .await
        .unwrap();
    let body = b"sk-abcdefghijklmnopqrstuvwxyz1234567890";
    let headers = format!(
        "POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(headers.as_bytes()).await.unwrap();
    client.write_all(&body[..3]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.write_all(&body[3..]).await.unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(
        tokio::time::timeout(Duration::from_millis(25), upstream.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn chunk_split_secret_is_blocked_and_binary_clean_body_is_exact() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_network_policy(local_network())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_dlp(Arc::new(RegexScanner::new()))
        .start()
        .await
        .unwrap();
    let request = format!(
        "POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsk-\r\n24\r\nabcdefghijklmnopqrstuvwxyz1234567890\r\n0\r\n\r\n"
    );
    assert!(
        raw(proxy, request.as_bytes())
            .await
            .starts_with("HTTP/1.1 403")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), upstream.accept())
            .await
            .is_err()
    );
    let received = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            bytes.extend_from_slice(&buf[..n]);
            if bytes.ends_with(&[0xff, 0x00, 0x80]) {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        bytes
    });
    let mut request = format!("POST http://{target}/upload HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: secret\r\nContent-Length: 3\r\n\r\n").into_bytes();
    request.extend_from_slice(&[0xff, 0x00, 0x80]);
    assert!(raw(proxy, &request).await.starts_with("HTTP/1.1 200"));
    let bytes = received.await.unwrap();
    assert!(bytes.starts_with(b"POST /upload HTTP/1.1\r\n"));
    assert!(bytes.ends_with(&[0xff, 0x00, 0x80]));
    assert!(!String::from_utf8_lossy(&bytes).contains("Proxy-Authorization"));
    assert!(!String::from_utf8_lossy(&bytes).contains("proxy-authorization"));
}

#[tokio::test]
async fn destination_mismatch_oversize_and_compression_never_reach_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_network_policy(local_network())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_dlp(Arc::new(RegexScanner::new()))
        .start()
        .await
        .unwrap();
    for (headers, status) in [
        ("Host: other.example\r\nContent-Length: 0", 400),
        ("Host: localhost\r\nContent-Length: 999999999", 413),
        ("Content-Encoding: gzip\r\nContent-Length: 1", 415),
    ] {
        let request = if status == 415 {
            format!("POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\n{headers}\r\n\r\nx")
        } else {
            format!("POST http://{target}/ HTTP/1.1\r\n{headers}\r\n\r\n")
        };
        assert!(
            raw(proxy, request.as_bytes())
                .await
                .starts_with(&format!("HTTP/1.1 {status}"))
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(25), upstream.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn default_private_network_and_connect_port_guards_override_allowlist() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_system_allowlist(vec!["*".into()])
        .start()
        .await
        .unwrap();
    assert!(
        raw(
            proxy,
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()
        )
        .await
        .starts_with("HTTP/1.1 403")
    );
    assert!(
        raw(
            proxy,
            b"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"
        )
        .await
        .starts_with("HTTP/1.1 403")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), upstream.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn decrypted_method_and_authority_are_checked_before_upstream() {
    let dir = tempfile::tempdir().unwrap();
    agentshield::cli::ca::generate_ca(dir.path()).unwrap();
    let cache = Arc::new(agentshield::proxy::tls::CertCache::load(dir.path()).unwrap());
    let policy = PolicyConfig {
        default: Action::Deny,
        rules: vec![Rule {
            name: "read-only".into(),
            domains: vec!["example.com".into()],
            methods: Some(vec!["GET".into()]),
            action: Action::Allow,
            note: None,
            rate_limit: None,
        }],
    };
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_policy(Arc::new(RwLock::new(policy)))
        .with_cert_cache(cache)
        .start()
        .await
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(dir.path().join("cert.pem")).unwrap();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    for (request, expected) in [
        (
            b"POST /write HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n".as_slice(),
            403,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n".as_slice(),
            400,
        ),
    ] {
        let mut tcp = TcpStream::connect(proxy).await.unwrap();
        tcp.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(tcp.read_u8().await.unwrap());
        }
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        tls.write_all(request).await.unwrap();
        let mut response = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&response[..n]).starts_with(&format!("HTTP/1.1 {expected}"))
        );
    }
}

struct SensitiveFixture {
    decision: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl agentshield::ask::AskResponder for SensitiveFixture {
    async fn prompt(&self, req: &agentshield::ask::AskRequestInfo) -> Option<bool> {
        use sha2::{Digest, Sha256};
        let approval = req.approval.as_ref().expect("typed sensitive metadata");
        assert!(req.body.is_none());
        assert_eq!(req.path, "[withheld]");
        assert!(
            approval
                .categories
                .iter()
                .any(|name| name == "openai-api-key")
        );
        assert_eq!(approval.request_sha256.len(), 64);
        assert_ne!(
            approval.request_sha256,
            format!("{:x}", Sha256::digest(b""))
        );
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(self.decision)
    }
    async fn notify_resolved(&self, _: &str, _: bool) {}
    fn name(&self) -> &str {
        "synthetic-authenticated-slack"
    }
}

#[tokio::test]
async fn sensitive_request_is_held_until_approval_and_approval_is_not_reused() {
    use agentshield::ask::AskBroadcaster;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut approvals = AskBroadcaster::new(1);
    approvals.add_responder(Arc::new(SensitiveFixture {
        decision: true,
        calls: calls.clone(),
    }));
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_network_policy(local_network())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_dlp(Arc::new(RegexScanner::new()))
        .with_sensitive_approval(Arc::new(approvals))
        .start()
        .await
        .unwrap();
    let body = "sk-abcdefghijklmnopqrstuvwxyz1234567890";
    let request = format!(
        "POST http://{target}/?account=synthetic HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let receive = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = upstream.accept().await.unwrap();
            assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
            let mut received = vec![0; 4096];
            let n = socket.read(&mut received).await.unwrap();
            assert!(String::from_utf8_lossy(&received[..n]).ends_with(body));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        calls.load(std::sync::atomic::Ordering::SeqCst)
    });
    assert!(
        raw(proxy, request.as_bytes())
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        raw(proxy, request.as_bytes())
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert_eq!(receive.await.unwrap(), 2);
}

#[tokio::test]
async fn sensitive_approval_missing_denies_and_headers_are_inspected() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (proxy, _stop) = ProxyServer::new("127.0.0.1:0".into())
        .with_network_policy(local_network())
        .with_policy(Arc::new(RwLock::new(allow())))
        .with_dlp(Arc::new(RegexScanner::new()))
        .with_sensitive_approval(Arc::new(agentshield::ask::AskBroadcaster::new(1)))
        .start()
        .await
        .unwrap();
    let request = format!(
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890\r\n\r\n"
    );
    assert!(
        raw(proxy, request.as_bytes())
            .await
            .starts_with("HTTP/1.1 403")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), upstream.accept())
            .await
            .is_err()
    );
}
