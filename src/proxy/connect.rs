use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

/// Main accept loop: accept incoming connections and handle them.
pub async fn accept_loop(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
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

/// Handle a single client connection. Reads the first line to determine
/// if it's a CONNECT request (HTTPS tunnel) or a regular HTTP request.
async fn handle_connection(mut client: TcpStream) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        handle_connect(&mut client, first_line).await
    } else {
        handle_http_request(&mut client, &buf[..n]).await
    }
}

/// Handle CONNECT method for HTTPS tunneling.
/// Establishes a TCP tunnel between client and remote server.
async fn handle_connect(client: &mut TcpStream, first_line: &str) -> anyhow::Result<()> {
    // Parse "CONNECT host:port HTTP/1.1"
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let target = parts[1]; // e.g. "example.com:443"
    info!("CONNECT tunnel to {}", target);

    // Try to connect to the remote server
    match TcpStream::connect(target).await {
        Ok(mut remote) => {
            // Send 200 to client indicating tunnel is established
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            client.write_all(response.as_bytes()).await?;

            // Bidirectional copy between client and remote
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
async fn handle_http_request(client: &mut TcpStream, raw_request: &[u8]) -> anyhow::Result<()> {
    let request_str = String::from_utf8_lossy(raw_request);
    let first_line = request_str.lines().next().unwrap_or("");

    // Parse "GET http://example.com/path HTTP/1.1"
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let uri = parts[1];
    info!("HTTP request to {}", uri);

    // Parse the host and port from the absolute URI
    let (host, port) = parse_host_port(uri)?;
    let target = format!("{}:{}", host, port);

    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            // Forward the raw request
            remote.write_all(raw_request).await?;

            // Read and forward the response
            let mut response_buf = vec![0u8; 65536];
            let n = remote.read(&mut response_buf).await?;
            if n > 0 {
                client.write_all(&response_buf[..n]).await?;
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
    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else {
        uri
    };

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().unwrap_or(80);
        Ok((host.to_string(), port))
    } else {
        Ok((host_port.to_string(), 80))
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
        assert_eq!(port, 80);
    }
}
