//! Connection handling for the proxy server.
//!
//! This module implements the core request processing pipeline:
//!
//! 1. **Accept** incoming TCP connections ([`accept_loop`])
//! 2. **Parse** the first line to distinguish `CONNECT` (HTTPS) from plain HTTP
//! 3. **Validate** the target domain against injection attacks
//! 4. **Check system allowlist** — bypass policy for pre-approved domains
//! 5. **Evaluate policy** — allow, deny, or prompt the user (ASK)
//! 6. **DLP scan** — inspect request bodies for secrets/PII (HTTP only)
//! 7. **Forward** the request to the upstream server
//! 8. **Log** the decision to SQLite and optionally send notifications

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::cli::prompt::AskRequest;
use crate::dlp::{DlpScanner, Severity};
use crate::logging;
use crate::logging::DbPool;
use crate::notification::{NotificationEvent, Notifier};
use crate::policy::config::{Action, PolicyConfig};
use crate::policy::evaluator::{self, RequestInfo};
use std::sync::Arc;

/// Shared context for all connection handlers, consolidating the various
/// optional components that each handler needs access to.
///
/// Created once in [`ProxyServer::start()`](super::ProxyServer::start) and
/// shared via `Arc` across all spawned connection tasks.
#[derive(Clone)]
pub struct ConnectionContext {
    /// Policy configuration for request evaluation.
    pub policy: Option<Arc<PolicyConfig>>,
    /// SQLite connection pool for request logging.
    pub db: Option<DbPool>,
    /// Channel for sending ASK prompts to the CLI handler.
    pub ask_tx: Option<mpsc::Sender<AskRequest>>,
    /// DLP scanner for inspecting HTTP request bodies.
    pub dlp_scanner: Option<Arc<dyn DlpScanner>>,
    /// Domains that bypass policy and DLP evaluation.
    pub system_allowlist: Option<Arc<Vec<String>>>,
    /// Notification backend for deny/DLP alerts.
    pub notifier: Option<Arc<dyn Notifier>>,
}

/// Main accept loop: accept incoming connections and handle them.
pub async fn accept_loop(listener: TcpListener, ctx: Arc<ConnectionContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &ctx).await {
                        error!("Error handling connection from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Log a request to the database if a DB pool is available.
fn log_to_db(
    ctx: &ConnectionContext,
    method: &str,
    domain: &str,
    path: &str,
    action: &str,
    reason: &str,
) {
    if let Some(ref pool) = ctx.db {
        match pool.get() {
            Ok(conn) => {
                let log = logging::RequestLog {
                    id: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    method: method.to_string(),
                    domain: domain.to_string(),
                    path: path.to_string(),
                    action: action.to_string(),
                    reason: reason.to_string(),
                };
                if let Err(e) = logging::log_request(&conn, &log) {
                    warn!("Failed to log request to DB: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to get DB connection from pool: {}", e);
            }
        }
    }
}

/// Fire-and-forget notification: spawn a task that won't block the proxy.
fn notify_event(ctx: &ConnectionContext, event: NotificationEvent) {
    if let Some(ref n) = ctx.notifier {
        let n = n.clone();
        tokio::spawn(async move {
            if let Err(e) = n.notify(&event).await {
                warn!("notification failed: {}", e);
            }
        });
    }
}

/// Handle a single client connection by reading the first request line and
/// dispatching to [`handle_connect`] (HTTPS) or [`handle_http_request`] (HTTP).
async fn handle_connection(
    mut client: TcpStream,
    ctx: &ConnectionContext,
) -> crate::error::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        handle_connect(&mut client, first_line, ctx).await
    } else {
        handle_http_request(&mut client, &buf[..n], ctx).await
    }
}

/// Send an ASK request through the channel and wait for the response.
/// Returns true if allowed, false if denied. Defaults to deny on timeout or error.
async fn ask_and_wait(
    ctx: &ConnectionContext,
    domain: &str,
    method: &str,
    path: &str,
    body: Option<String>,
) -> bool {
    if let Some(ref tx) = ctx.ask_tx {
        let (req, rx) =
            AskRequest::new(domain.to_string(), method.to_string(), path.to_string(), body);
        if tx.send(req).await.is_ok() {
            // Wait up to 30 seconds for a response
            match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                Ok(Ok(allowed)) => return allowed,
                Ok(Err(_)) => warn!("ASK response channel closed for {}", domain),
                Err(_) => warn!("ASK timeout (30s) for {} - defaulting to deny", domain),
            }
        }
    }
    // No channel or error: default to deny (fail-closed)
    false
}

/// Handle CONNECT method for HTTPS tunneling.
///
/// Establishes a TCP tunnel between the client and the target server after
/// validating the domain, checking the system allowlist, and evaluating policy.
/// For CONNECT requests, DLP scanning is not possible since the payload is encrypted.
async fn handle_connect(
    client: &mut TcpStream,
    first_line: &str,
    ctx: &ConnectionContext,
) -> crate::error::Result<()> {
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let target = parts[1]; // e.g. "example.com:443"
    let domain = target.split(':').next().unwrap_or(target);

    // Validate domain to prevent header injection
    if !validate_domain(domain) {
        warn!("Invalid domain in CONNECT: {}", domain);
        log_to_db(ctx, "CONNECT", domain, "/", "deny", "invalid domain");
        let response = "HTTP/1.1 400 Bad Request\r\nX-AgentShield-Reason: invalid domain\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // System allowlist bypass: skip policy evaluation for internal services
    let allowlist_slice = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    if is_system_allowed(domain, allowlist_slice) {
        info!("SYSTEM-ALLOW CONNECT to {} (allowlist)", target);
        log_to_db(
            ctx,
            "CONNECT",
            domain,
            "/",
            "system-allow",
            "system allowlist",
        );
    }
    // Policy evaluation for CONNECT (domain-level only)
    else if let Some(ref policy) = ctx.policy {
        let req_info = RequestInfo {
            domain: domain.to_string(),
            method: "CONNECT".to_string(),
            path: "/".to_string(),
        };
        let result = evaluator::evaluate(&req_info, policy);
        match result.action {
            Action::Deny => {
                warn!("BLOCKED CONNECT to {} - {}", target, result.reason);
                log_to_db(ctx, "CONNECT", domain, "/", "deny", &result.reason);
                notify_event(
                    ctx,
                    NotificationEvent::RequestDenied {
                        domain: domain.to_string(),
                        method: "CONNECT".to_string(),
                        path: "/".to_string(),
                        reason: result.reason.clone(),
                    },
                );
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK CONNECT to {} - {}", target, result.reason);
                notify_event(
                    ctx,
                    NotificationEvent::AskPending {
                        domain: domain.to_string(),
                        method: "CONNECT".to_string(),
                        path: "/".to_string(),
                    },
                );
                let allowed = ask_and_wait(ctx, domain, "CONNECT", "/", None).await;
                if allowed {
                    log_to_db(ctx, "CONNECT", domain, "/", "allow", "approved via ASK");
                } else {
                    log_to_db(ctx, "CONNECT", domain, "/", "deny", "denied via ASK");
                    notify_event(
                        ctx,
                        NotificationEvent::RequestDenied {
                            domain: domain.to_string(),
                            method: "CONNECT".to_string(),
                            path: "/".to_string(),
                            reason: "denied via ASK".to_string(),
                        },
                    );
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                        "denied via ASK prompt"
                    );
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
            Action::Allow => {
                info!("ALLOWED CONNECT to {} - {}", target, result.reason);
                log_to_db(ctx, "CONNECT", domain, "/", "allow", &result.reason);
            }
        }
    }

    info!("CONNECT tunnel to {}", target);

    match TcpStream::connect(target).await {
        Ok(mut remote) => {
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            client.write_all(response.as_bytes()).await?;

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut remote_read, mut remote_write) = tokio::io::split(&mut remote);

            let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
            let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

            tokio::select! {
                r = client_to_remote => {
                    if let Err(e) = r { warn!("client->remote error: {}", e); }
                }
                r = remote_to_client => {
                    if let Err(e) = r { warn!("remote->client error: {}", e); }
                }
            }
        }
        Err(e) => {
            warn!("Failed to connect to {}: {}", target, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

/// Handle plain HTTP requests by forwarding to the target server.
///
/// Unlike CONNECT tunneling, plain HTTP requests expose the full request body,
/// enabling DLP scanning for secrets and PII before forwarding. Critical DLP
/// findings block the request; non-critical findings are logged as warnings.
async fn handle_http_request(
    client: &mut TcpStream,
    raw_request: &[u8],
    ctx: &ConnectionContext,
) -> crate::error::Result<()> {
    let request_str = String::from_utf8_lossy(raw_request);
    let first_line = request_str.lines().next().unwrap_or("");

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];
    let (host, port) = parse_host_port(uri)?;
    let path = parse_path(uri);

    // Validate domain to prevent header injection
    if !validate_domain(&host) {
        warn!("Invalid domain in HTTP request: {}", host);
        log_to_db(ctx, method, &host, &path, "deny", "invalid domain");
        let response = "HTTP/1.1 400 Bad Request\r\nX-AgentShield-Reason: invalid domain\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // System allowlist bypass: skip policy evaluation AND DLP scanning for internal services.
    //
    // SECURITY NOTE: Domains on the system allowlist bypass both policy and DLP checks.
    // Only add trusted internal services (e.g., notification endpoints). Adding external
    // domains here disables all outbound protection for that destination.
    let allowlist_slice = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    let system_allowed = is_system_allowed(&host, allowlist_slice);
    if system_allowed {
        info!(
            "SYSTEM-ALLOW {} {} (allowlist, policy+dlp bypass)",
            method, uri
        );
        log_to_db(
            ctx,
            method,
            &host,
            &path,
            "system-allow",
            "system allowlist (policy+dlp bypass)",
        );
    }
    // Policy evaluation for HTTP
    else if let Some(ref policy) = ctx.policy {
        let req_info = RequestInfo {
            domain: host.clone(),
            method: method.to_string(),
            path: path.clone(),
        };
        let result = evaluator::evaluate(&req_info, policy);
        match result.action {
            Action::Deny => {
                warn!("BLOCKED {} {} - {}", method, uri, result.reason);
                log_to_db(ctx, method, &host, &path, "deny", &result.reason);
                notify_event(
                    ctx,
                    NotificationEvent::RequestDenied {
                        domain: host.clone(),
                        method: method.to_string(),
                        path: path.clone(),
                        reason: result.reason.clone(),
                    },
                );
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK {} {} - {}", method, uri, result.reason);
                notify_event(
                    ctx,
                    NotificationEvent::AskPending {
                        domain: host.clone(),
                        method: method.to_string(),
                        path: path.clone(),
                    },
                );
                let body_str = extract_body(raw_request)
                    .and_then(|b| String::from_utf8(b.to_vec()).ok());
                let allowed = ask_and_wait(ctx, &host, method, &path, body_str).await;
                if allowed {
                    log_to_db(ctx, method, &host, &path, "allow", "approved via ASK");
                } else {
                    log_to_db(ctx, method, &host, &path, "deny", "denied via ASK");
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                        "denied via ASK prompt"
                    );
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
            Action::Allow => {
                info!("ALLOWED {} {} - {}", method, uri, result.reason);
                log_to_db(ctx, method, &host, &path, "allow", &result.reason);
            }
        }
    }

    // DLP scan: check request body for sensitive data before forwarding.
    // System-allowed domains bypass DLP (they already bypass policy above).
    if !system_allowed {
        if let Some(ref scanner) = ctx.dlp_scanner {
            if let Some(body) = extract_body(raw_request) {
                let findings = scanner.scan(body);
                let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
                if has_critical {
                    for f in &findings {
                        warn!(
                            "DLP {} finding in {} {}: pattern={}, match={}",
                            format!("{:?}", f.severity),
                            method,
                            uri,
                            f.pattern_name,
                            f.matched_text
                        );
                    }
                    log_to_db(ctx, method, &host, &path, "deny", "DLP: critical finding");
                    // Notify about first critical finding
                    if let Some(f) = findings.iter().find(|f| f.severity == Severity::Critical) {
                        notify_event(
                            ctx,
                            NotificationEvent::DlpFinding {
                                domain: host.clone(),
                                method: method.to_string(),
                                pattern_name: f.pattern_name.clone(),
                                severity: format!("{:?}", f.severity),
                            },
                        );
                    }
                    let response = "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: DLP: sensitive data detected\r\n\r\n";
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
                // Non-critical findings: log warning but allow request through
                for f in &findings {
                    warn!(
                        "DLP {:?} finding in {} {}: pattern={}, match={}",
                        f.severity, method, uri, f.pattern_name, f.matched_text
                    );
                }
            }
        }
    } // end if !system_allowed (DLP bypass)

    info!("HTTP {} to {}", method, uri);
    let target = format!("{}:{}", host, port);

    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            // Inject Connection: close header so remote server closes after response
            let request_str = String::from_utf8_lossy(raw_request);
            let modified = if !request_str.to_lowercase().contains("connection:") {
                request_str.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
            } else {
                request_str.to_string()
            };
            remote.write_all(modified.as_bytes()).await?;
            // Stream the full response back to client with timeout
            let copy_result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::io::copy(&mut remote, client),
            )
            .await;
            match copy_result {
                Ok(Ok(bytes)) => {
                    info!("Streamed {} bytes from {}", bytes, target);
                }
                Ok(Err(e)) => {
                    warn!("Error streaming response from {}: {}", target, e);
                }
                Err(_) => {
                    warn!("Timeout streaming response from {}", target);
                }
            }
        }
        Err(e) => {
            warn!("Failed to connect to {}: {}", target, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

/// Extract the body from a raw HTTP request (everything after `\r\n\r\n`).
fn extract_body(raw_request: &[u8]) -> Option<&[u8]> {
    raw_request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|pos| {
            let start = pos + 4;
            (start < raw_request.len()).then(|| &raw_request[start..])
        })
}

/// Check if a domain is in the system allowlist (bypass policy evaluation).
fn is_system_allowed(domain: &str, allowlist: Option<&[String]>) -> bool {
    allowlist.is_some_and(|list| list.iter().any(|d| domain_matches(d, domain)))
}

/// Check if a domain matches a pattern.
///
/// Supports exact match, `"*"` (matches everything),
/// and `"*.example.com"` (matches subdomains and the base domain itself).
fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let dot_suffix = &pattern[1..]; // ".example.com"
        return domain.ends_with(dot_suffix) || domain == suffix;
    }
    domain == pattern
}

/// Validate that a domain name contains only safe characters.
fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Parse host and port from an absolute URI like "http://example.com:8080/path"
fn parse_host_port(uri: &str) -> crate::error::Result<(String, u16)> {
    let is_https = uri.starts_with("https://");
    let default_port: u16 = if is_https { 443 } else { 80 };

    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else {
        uri
    };

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().unwrap_or(default_port);
        Ok((host.to_string(), port))
    } else {
        Ok((host_port.to_string(), default_port))
    }
}

/// Parse the path from an absolute URI
fn parse_path(uri: &str) -> String {
    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else {
        uri
    };

    if let Some(pos) = without_scheme.find('/') {
        without_scheme[pos..].to_string()
    } else {
        "/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_scheme() {
        let (host, port) = parse_host_port("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_with_explicit_port() {
        let (host, port) = parse_host_port("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_https() {
        let (host, port) = parse_host_port("https://api.anthropic.com/v1/messages").unwrap();
        assert_eq!(host, "api.anthropic.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_path() {
        assert_eq!(parse_path("http://example.com/foo/bar"), "/foo/bar");
        assert_eq!(parse_path("http://example.com"), "/");
        assert_eq!(
            parse_path("https://api.github.com/repos/user/repo"),
            "/repos/user/repo"
        );
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com"));
        assert!(validate_domain("api.anthropic.com"));
        assert!(validate_domain("my-service.example.com"));
        assert!(validate_domain("localhost"));
        assert!(validate_domain("192.168.1.1"));
    }

    #[test]
    fn extract_body_from_raw_request() {
        let raw = b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{\"key\": \"value\"}";
        let body = extract_body(raw).unwrap();
        assert_eq!(body, b"{\"key\": \"value\"}");
    }

    #[test]
    fn no_body_in_get_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let body = extract_body(raw);
        assert!(body.is_none());
    }

    #[test]
    fn system_allowlist_match() {
        let list = vec!["api.telegram.org".to_string(), "internal.svc".to_string()];
        assert!(is_system_allowed("api.telegram.org", Some(&list)));
        assert!(is_system_allowed("internal.svc", Some(&list)));
    }

    #[test]
    fn system_allowlist_no_match() {
        let list = vec!["api.telegram.org".to_string()];
        assert!(!is_system_allowed("evil.com", Some(&list)));
    }

    #[test]
    fn system_allowlist_none() {
        assert!(!is_system_allowed("api.telegram.org", None));
    }

    #[test]
    fn system_allowlist_wildcard_subdomain() {
        let list = vec!["*.github.com".to_string()];
        assert!(is_system_allowed("api.github.com", Some(&list)));
        assert!(is_system_allowed("github.com", Some(&list)));
        assert!(is_system_allowed("deep.api.github.com", Some(&list)));
        assert!(!is_system_allowed("evil-github.com", Some(&list)));
    }

    #[test]
    fn system_allowlist_wildcard_all() {
        let list = vec!["*".to_string()];
        assert!(is_system_allowed("anything.com", Some(&list)));
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(!validate_domain(""));
        assert!(!validate_domain("evil.com/../../etc/passwd"));
        assert!(!validate_domain("evil@attacker.com"));
        assert!(!validate_domain("evil.com:443\r\nInjected: header"));
        assert!(!validate_domain("domain with spaces"));
        assert!(!validate_domain("evil.com\0null"));
    }
}
