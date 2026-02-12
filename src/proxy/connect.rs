use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::logging;
use crate::policy::config::{Action, PolicyConfig};
use crate::policy::evaluator::{self, RequestInfo};

/// Main accept loop: accept incoming connections and handle them.
pub async fn accept_loop(
    listener: TcpListener,
    policy: Option<Arc<PolicyConfig>>,
    db: Option<Arc<Mutex<Connection>>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);
                let policy = policy.clone();
                let db = db.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, policy.as_deref(), db.as_ref()).await
                    {
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

/// Log a request to the database if a DB connection is available.
fn log_to_db(
    db: Option<&Arc<Mutex<Connection>>>,
    method: &str,
    domain: &str,
    path: &str,
    action: &str,
    reason: &str,
) {
    if let Some(db) = db {
        if let Ok(conn) = db.lock() {
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
    }
}

/// Handle a single client connection.
async fn handle_connection(
    mut client: TcpStream,
    policy: Option<&PolicyConfig>,
    db: Option<&Arc<Mutex<Connection>>>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        handle_connect(&mut client, first_line, policy, db).await
    } else {
        handle_http_request(&mut client, &buf[..n], policy, db).await
    }
}

/// Handle CONNECT method for HTTPS tunneling.
async fn handle_connect(
    client: &mut TcpStream,
    first_line: &str,
    policy: Option<&PolicyConfig>,
    db: Option<&Arc<Mutex<Connection>>>,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let target = parts[1]; // e.g. "example.com:443"
    let domain = target.split(':').next().unwrap_or(target);

    // Policy evaluation for CONNECT (domain-level only)
    if let Some(policy) = policy {
        let req_info = RequestInfo {
            domain: domain.to_string(),
            method: "CONNECT".to_string(),
            path: "/".to_string(),
        };
        let result = evaluator::evaluate(&req_info, policy);
        match result.action {
            Action::Deny => {
                warn!("BLOCKED CONNECT to {} - {}", target, result.reason);
                log_to_db(db, "CONNECT", domain, "/", "deny", &result.reason);
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK CONNECT to {} - {}", target, result.reason);
                log_to_db(db, "CONNECT", domain, "/", "ask", &result.reason);
            }
            Action::Allow => {
                info!("ALLOWED CONNECT to {} - {}", target, result.reason);
                log_to_db(db, "CONNECT", domain, "/", "allow", &result.reason);
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
async fn handle_http_request(
    client: &mut TcpStream,
    raw_request: &[u8],
    policy: Option<&PolicyConfig>,
    db: Option<&Arc<Mutex<Connection>>>,
) -> anyhow::Result<()> {
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

    // Policy evaluation for HTTP
    if let Some(policy) = policy {
        let req_info = RequestInfo {
            domain: host.clone(),
            method: method.to_string(),
            path: path.clone(),
        };
        let result = evaluator::evaluate(&req_info, policy);
        match result.action {
            Action::Deny => {
                warn!("BLOCKED {} {} - {}", method, uri, result.reason);
                log_to_db(db, method, &host, &path, "deny", &result.reason);
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK {} {} - {}", method, uri, result.reason);
                log_to_db(db, method, &host, &path, "ask", &result.reason);
            }
            Action::Allow => {
                info!("ALLOWED {} {} - {}", method, uri, result.reason);
                log_to_db(db, method, &host, &path, "allow", &result.reason);
            }
        }
    }

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

/// Parse host and port from an absolute URI like "http://example.com:8080/path"
fn parse_host_port(uri: &str) -> anyhow::Result<(String, u16)> {
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
}
