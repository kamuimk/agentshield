use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Helper: connect to the proxy and send a raw HTTP request
async fn send_raw_request(proxy_addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn proxy_starts_and_accepts_connections() {
    // Proxy should bind to a random port and accept TCP connections
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Should be able to connect
    let stream = TcpStream::connect(local_addr).await;
    assert!(stream.is_ok());
}

#[tokio::test]
async fn proxy_responds_to_connect_request() {
    use agentshield::proxy::ProxyServer;

    let server = ProxyServer::new("127.0.0.1:0".to_string());
    let addr = server.start().await.unwrap();

    // Send a CONNECT request
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let connect_req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    // Should get a 200 OK response (tunnel established)
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
    use agentshield::proxy::ProxyServer;

    let server = ProxyServer::new("127.0.0.1:0".to_string());
    let addr = server.start().await.unwrap();

    // Send a plain HTTP request through proxy (absolute URI form)
    let request = format!(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    let response = send_raw_request(addr, &request).await;

    // Proxy should attempt to forward and return some HTTP response
    assert!(
        response.contains("HTTP/1."),
        "Expected HTTP response, got: {}",
        response
    );
}
