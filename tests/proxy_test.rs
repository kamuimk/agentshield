use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use agentshield::dlp::DlpScanner;
use agentshield::dlp::patterns::RegexScanner;
use agentshield::notification::{NotificationEvent, Notifier};
use agentshield::policy::config::{Action, AppConfig, PolicyConfig, Rule};
use agentshield::proxy::ProxyServer;

/// Test-only mock notifier that collects events.
struct TestNotifier {
    events: Arc<Mutex<Vec<NotificationEvent>>>,
}

impl TestNotifier {
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<NotificationEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let n = Arc::new(Self {
            events: events.clone(),
        });
        (n, events)
    }
}

#[async_trait::async_trait]
impl Notifier for TestNotifier {
    async fn notify(&self, event: &NotificationEvent) -> agentshield::error::Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
    fn name(&self) -> &str {
        "test"
    }
}

/// Helper: connect to the proxy and send a raw HTTP request
async fn send_raw_request(proxy_addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

fn deny_all_policy() -> PolicyConfig {
    PolicyConfig {
        default: Action::Deny,
        rules: vec![],
    }
}

fn allow_example_policy() -> PolicyConfig {
    PolicyConfig {
        default: Action::Deny,
        rules: vec![Rule {
            name: "allow-example".to_string(),
            domains: vec!["example.com".to_string()],
            methods: None,
            action: Action::Allow,
            note: None,
        }],
    }
}

#[tokio::test]
async fn proxy_starts_and_accepts_connections() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(local_addr).await;
    assert!(stream.is_ok());
}

#[tokio::test]
async fn proxy_responds_to_connect_request() {
    let server = ProxyServer::new("127.0.0.1:0".to_string());
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Expected 200 response, got: {}",
        response
    );
}

#[tokio::test]
async fn proxy_handles_http_request() {
    let server = ProxyServer::new("127.0.0.1:0".to_string());
    let addr = server.start().await.unwrap();

    let request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response = send_raw_request(addr, request).await;

    assert!(
        response.contains("HTTP/1."),
        "Expected HTTP response, got: {}",
        response
    );
}

// --- Policy integration tests ---

#[tokio::test]
async fn policy_deny_all_blocks_connect() {
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(deny_all_policy());
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("403"),
        "Expected 403 Forbidden, got: {}",
        response
    );
    assert!(
        response.contains("X-AgentShield-Reason"),
        "Expected X-AgentShield-Reason header, got: {}",
        response
    );
}

#[tokio::test]
async fn policy_deny_all_blocks_http() {
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(deny_all_policy());
    let addr = server.start().await.unwrap();

    let request = "GET http://evil.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n";
    let response = send_raw_request(addr, request).await;

    assert!(
        response.contains("403"),
        "Expected 403 Forbidden, got: {}",
        response
    );
}

#[tokio::test]
async fn policy_allows_whitelisted_domain_connect() {
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(allow_example_policy());
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    // Should get 200 (tunnel established) since example.com is allowed
    assert!(response.contains("200"), "Expected 200, got: {}", response);
}

#[tokio::test]
async fn policy_blocks_non_whitelisted_domain() {
    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(allow_example_policy());
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("403"),
        "Expected 403 for non-whitelisted domain, got: {}",
        response
    );
}

#[tokio::test]
async fn openclaw_policy_allows_anthropic() {
    let template = include_str!("../templates/openclaw-default.toml");
    let config: AppConfig = toml::from_str(template).unwrap();

    let server = ProxyServer::new("127.0.0.1:0".to_string()).with_policy(config.policy.clone());
    let addr = server.start().await.unwrap();

    // api.anthropic.com should be allowed
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req =
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Expected anthropic to be allowed, got: {}",
        response
    );
}

// --- System allowlist integration tests ---

#[tokio::test]
async fn system_allowlist_bypasses_deny_all_connect() {
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(deny_all_policy())
        .with_system_allowlist(vec!["example.com".to_string()]);
    let addr = server.start().await.unwrap();

    // example.com is in allowlist → should get 200 despite deny-all
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "Allowlisted domain should bypass deny-all, got: {}",
        response
    );
}

#[tokio::test]
async fn system_allowlist_does_not_affect_unlisted_domain() {
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(deny_all_policy())
        .with_system_allowlist(vec!["api.telegram.org".to_string()]);
    let addr = server.start().await.unwrap();

    // evil.com is NOT in allowlist → should still be denied
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("403"),
        "Unlisted domain should still be denied, got: {}",
        response
    );
}

// --- DLP integration tests ---

#[tokio::test]
async fn dlp_blocks_http_request_with_critical_finding() {
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_dlp(scanner);
    let addr = server.start().await.unwrap();

    // HTTP POST with OpenAI API key in body (Critical severity)
    let request = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\n\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
    let response = send_raw_request(addr, request).await;
    assert!(
        response.contains("403"),
        "DLP should block critical finding, got: {}",
        response
    );
}

#[tokio::test]
async fn dlp_allows_clean_http_request() {
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_dlp(scanner);
    let addr = server.start().await.unwrap();

    // Clean HTTP request — no sensitive data
    let request = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, world!";
    let response = send_raw_request(addr, request).await;
    assert!(
        !response.contains("403"),
        "Clean request should not be blocked by DLP, got: {}",
        response
    );
}

#[tokio::test]
async fn dlp_does_not_scan_connect_tunnels() {
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_dlp(scanner);
    let addr = server.start().await.unwrap();

    // CONNECT request — DLP should be skipped (encrypted tunnel)
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("200"),
        "CONNECT should not be affected by DLP, got: {}",
        response
    );
}

// --- System allowlist + DLP bypass integration tests ---

#[tokio::test]
async fn system_allowlist_bypasses_dlp_for_http() {
    // System allowlist domain should bypass BOTH policy AND DLP
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(deny_all_policy())
        .with_dlp(scanner)
        .with_system_allowlist(vec!["example.com".to_string()]);
    let addr = server.start().await.unwrap();

    // HTTP POST with API key in body to allowlisted domain → should pass (not 403)
    let request = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\n\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
    let response = send_raw_request(addr, request).await;
    assert!(
        !response.contains("403"),
        "System allowlist domain should bypass DLP, got: {}",
        response
    );
}

#[tokio::test]
async fn non_allowlist_domain_still_blocked_by_dlp() {
    // Non-allowlist domain should still be subject to DLP scanning
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_dlp(scanner)
        .with_system_allowlist(vec!["api.telegram.org".to_string()]);
    let addr = server.start().await.unwrap();

    // HTTP POST with API key to NON-allowlisted domain → should be blocked by DLP
    let request = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\n\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
    let response = send_raw_request(addr, request).await;
    assert!(
        response.contains("403"),
        "Non-allowlist domain should still be blocked by DLP, got: {}",
        response
    );
}

// --- Notification integration tests ---

#[tokio::test]
async fn notification_fires_on_deny() {
    let (notifier, events) = TestNotifier::new();
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(deny_all_policy())
        .with_notifier(notifier);
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await.unwrap();
    drop(stream);

    // Give fire-and-forget task time to complete
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let collected = events.lock().unwrap();
    assert!(
        collected.len() >= 1,
        "Expected at least 1 notification event, got {}",
        collected.len()
    );
    assert!(
        matches!(&collected[0], NotificationEvent::RequestDenied { domain, .. } if domain == "evil.com"),
        "Expected RequestDenied for evil.com"
    );
}

#[tokio::test]
async fn notification_fires_on_dlp_critical() {
    let (notifier, events) = TestNotifier::new();
    let scanner: Arc<dyn DlpScanner> = Arc::new(RegexScanner::new());
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_dlp(scanner)
        .with_notifier(notifier);
    let addr = server.start().await.unwrap();

    let request = "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\n\r\nAuthorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
    send_raw_request(addr, request).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let collected = events.lock().unwrap();
    assert!(
        collected.len() >= 1,
        "Expected DLP notification event, got {}",
        collected.len()
    );
    assert!(
        matches!(&collected[0], NotificationEvent::DlpFinding { .. }),
        "Expected DlpFinding event"
    );
}

#[tokio::test]
async fn notification_does_not_fire_on_allow() {
    let (notifier, events) = TestNotifier::new();
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(allow_example_policy())
        .with_notifier(notifier);
    let addr = server.start().await.unwrap();

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await.unwrap();
    drop(stream);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let collected = events.lock().unwrap();
    assert!(
        collected.is_empty(),
        "Expected no notification on allow, got {} events",
        collected.len()
    );
}

#[tokio::test]
async fn notification_failure_does_not_crash_proxy() {
    /// A notifier that always fails.
    struct FailNotifier;

    #[async_trait::async_trait]
    impl Notifier for FailNotifier {
        async fn notify(&self, _event: &NotificationEvent) -> agentshield::error::Result<()> {
            Err(agentshield::error::AgentShieldError::Notification(
                "test failure".to_string(),
            ))
        }
        fn name(&self) -> &str {
            "fail"
        }
    }

    let notifier: Arc<dyn Notifier> = Arc::new(FailNotifier);
    let server = ProxyServer::new("127.0.0.1:0".to_string())
        .with_policy(deny_all_policy())
        .with_notifier(notifier);
    let addr = server.start().await.unwrap();

    // Proxy should still work even if notification fails
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("403"),
        "Proxy should still respond despite notification failure, got: {}",
        response
    );
}
