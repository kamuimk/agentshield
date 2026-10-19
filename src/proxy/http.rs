//! Bounded HTTP/1 request framing shared by plaintext and intercepted TLS.

use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) const MAX_BODY: usize = 10 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_WIRE: usize = MAX_BODY + MAX_HEADERS;

/// A client-visible error with a fixed, non-sensitive reason.
#[derive(Debug)]
pub(super) struct Rejection {
    pub status: u16,
    pub reason: &'static str,
}

fn bad(reason: &'static str) -> Rejection {
    Rejection {
        status: 400,
        reason,
    }
}

async fn more<R: AsyncRead + Unpin>(reader: &mut R, data: &mut Vec<u8>) -> Result<(), Rejection> {
    if data.len() >= MAX_WIRE {
        return Err(Rejection {
            status: 413,
            reason: "request exceeds inspection limit",
        });
    }
    let mut buf = [0u8; 8192];
    let size = buf.len().min(MAX_WIRE - data.len());
    let n = reader
        .read(&mut buf[..size])
        .await
        .map_err(|_| bad("request read failed"))?;
    if n == 0 {
        return Err(bad("incomplete request"));
    }
    data.extend_from_slice(&buf[..n]);
    Ok(())
}

/// Read exactly one request and normalize its framing before inspection/forwarding.
pub(super) async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, Rejection> {
    tokio::time::timeout(std::time::Duration::from_secs(30), read_inner(reader))
        .await
        .map_err(|_| Rejection {
            status: 408,
            reason: "request read timeout",
        })?
}

async fn read_inner<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, Rejection> {
    let mut data = Vec::with_capacity(8192);
    let header_end = loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 > MAX_HEADERS {
                return Err(bad("headers exceed inspection limit"));
            }
            break end + 4;
        }
        if data.len() >= MAX_HEADERS {
            return Err(bad("headers exceed inspection limit"));
        }
        more(reader, &mut data).await?;
    };
    // httparse tolerates bare LF. Require canonical CRLF to avoid parser disagreements.
    if data[..header_end]
        .windows(2)
        .any(|w| (w[1] == b'\n' && w[0] != b'\r') || (w[0] == b'\r' && w[1] != b'\n'))
    {
        return Err(bad("invalid header line ending"));
    }
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    if request
        .parse(&data[..header_end])
        .map_err(|_| bad("invalid HTTP headers"))?
        != httparse::Status::Complete(header_end)
    {
        return Err(bad("invalid HTTP headers"));
    }
    let method = request
        .method
        .ok_or_else(|| bad("missing method"))?
        .to_string();
    let target = request
        .path
        .ok_or_else(|| bad("missing target"))?
        .to_string();
    if request.version != Some(1) || method.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(bad("only canonical HTTP/1.1 requests are supported"));
    }
    let fields: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|h| {
            let value = std::str::from_utf8(h.value).map_err(|_| bad("invalid header value"))?;
            if value.bytes().any(|b| b < 32 && b != b'\t') || value.contains('\x7f') {
                return Err(bad("invalid header value"));
            }
            Ok((h.name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect::<Result<_, _>>()?;
    let values = |name: &str| {
        fields
            .iter()
            .filter(move |(key, _)| key == name)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    if values("host").len() != 1 {
        return Err(bad("exactly one Host is required"));
    }
    let lengths = values("content-length");
    let transfers = values("transfer-encoding");
    if lengths.len() > 1 || transfers.len() > 1 || (!lengths.is_empty() && !transfers.is_empty()) {
        return Err(bad("ambiguous request framing"));
    }
    if !values("upgrade").is_empty()
        || !values("expect").is_empty()
        || !values("trailer").is_empty()
    {
        return Err(bad("upgrade, expect and trailers are unsupported"));
    }
    let connection_fields: Vec<String> = values("connection")
        .iter()
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    if connection_fields
        .iter()
        .any(|v| !matches!(v.as_str(), "close" | "keep-alive"))
    {
        return Err(bad("unsupported Connection option"));
    }
    let body = if let Some(encoding) = transfers.first() {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(bad("unsupported transfer encoding"));
        }
        read_chunks(reader, &mut data, header_end).await?
    } else {
        let length = if let Some(value) = lengths.first() {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("invalid content length"));
            }
            value
                .parse::<usize>()
                .map_err(|_| bad("invalid content length"))?
        } else {
            0
        };
        if length > MAX_BODY {
            return Err(Rejection {
                status: 413,
                reason: "body exceeds inspection limit",
            });
        }
        while data.len() < header_end + length {
            more(reader, &mut data).await?;
        }
        if data.len() != header_end + length {
            return Err(bad("unexpected bytes after request"));
        }
        data[header_end..].to_vec()
    };
    if method == "CONNECT" && !body.is_empty() {
        return Err(bad("CONNECT body is unsupported"));
    }
    let mut normalized = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    for (key, value) in fields {
        if matches!(
            key.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "keep-alive"
                | "te"
        ) {
            continue;
        }
        normalized.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    normalized.extend_from_slice(
        format!(
            "Connection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    normalized.extend_from_slice(&body);
    Ok(normalized)
}

async fn read_chunks<R: AsyncRead + Unpin>(
    reader: &mut R,
    data: &mut Vec<u8>,
    mut pos: usize,
) -> Result<Vec<u8>, Rejection> {
    let mut decoded = Vec::new();
    loop {
        let end = loop {
            if let Some(n) = data[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + n;
            }
            if data.len() - pos > 1024 {
                return Err(bad("chunk line too long"));
            }
            more(reader, data).await?;
        };
        if end - pos > 1024 {
            return Err(bad("chunk line too long"));
        }
        let line = std::str::from_utf8(&data[pos..end]).map_err(|_| bad("invalid chunk size"))?;
        let size = line.split(';').next().unwrap_or("");
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("invalid chunk size"));
        }
        let length = usize::from_str_radix(size, 16).map_err(|_| bad("invalid chunk size"))?;
        if length > MAX_BODY - decoded.len() {
            return Err(Rejection {
                status: 413,
                reason: "body exceeds inspection limit",
            });
        }
        pos = end + 2;
        while data.len() < pos + length + 2 {
            more(reader, data).await?;
        }
        if &data[pos + length..pos + length + 2] != b"\r\n" {
            return Err(bad("invalid chunk boundary or trailers"));
        }
        decoded.extend_from_slice(&data[pos..pos + length]);
        pos += length + 2;
        if length == 0 {
            if pos != data.len() {
                return Err(bad("unexpected bytes after chunks"));
            }
            return Ok(decoded);
        }
    }
}

pub(super) fn host_header(raw: &[u8]) -> Result<&str, Rejection> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("missing headers"))?;
    std::str::from_utf8(&raw[..end])
        .map_err(|_| bad("invalid headers"))?
        .split("\r\n")
        .skip(1)
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim())
        })
        .ok_or_else(|| bad("missing Host"))
}

pub(super) fn authority(value: &str, default_port: u16) -> Result<(String, u16), Rejection> {
    if value.contains('@') || value.contains('#') {
        return Err(bad("invalid authority"));
    }
    let authority: hyper::http::uri::Authority =
        value.parse().map_err(|_| bad("invalid authority"))?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    let ip_host = host.trim_start_matches('[').trim_end_matches(']');
    let valid_dns = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid_dns && ip_host.parse::<std::net::IpAddr>().is_err() {
        return Err(bad("invalid host"));
    }
    let port = match authority.port() {
        Some(port) => port.as_u16(),
        None if value == authority.host() => default_port,
        None => return Err(bad("invalid port")),
    };
    if port == 0 {
        return Err(bad("invalid port"));
    }
    Ok((host, port))
}

/// Bind the requested URI and Host to one canonical destination.
pub(super) fn destination(
    target: &str,
    host: &str,
    tunnel: Option<(&str, u16)>,
) -> Result<(String, u16), Rejection> {
    if target.contains('#') {
        return Err(bad("URI fragments are unsupported"));
    }
    let uri: hyper::Uri = target.parse().map_err(|_| bad("invalid URI"))?;
    let expected = if let Some((domain, port)) = tunnel {
        let authority = authority(host, 443)?;
        if authority != (domain.to_string(), port) {
            return Err(bad("Host differs from CONNECT target"));
        }
        if let Some(scheme) = uri.scheme_str() {
            if scheme != "https"
                || uri
                    .authority()
                    .map(|v| self::authority(v.as_str(), 443))
                    .transpose()?
                    .as_ref()
                    != Some(&authority)
            {
                return Err(bad("URI differs from CONNECT target"));
            }
        } else if !target.starts_with('/') || target.starts_with("//") {
            return Err(bad("invalid origin target"));
        }
        authority
    } else {
        if uri.scheme_str() != Some("http") {
            return Err(bad("plaintext proxy requires absolute HTTP URI"));
        }
        let authority = authority(
            uri.authority()
                .ok_or_else(|| bad("missing authority"))?
                .as_str(),
            80,
        )?;
        if authority != self::authority(host, 80)? {
            return Err(bad("Host differs from URI"));
        }
        authority
    };
    Ok(expected)
}

/// Forward origin-form, never an absolute URI that could be interpreted as another proxy hop.
pub(super) fn origin_form(raw: &[u8]) -> Vec<u8> {
    let end = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("validated request");
    let line = std::str::from_utf8(&raw[..end]).expect("validated request");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap();
    let uri: hyper::Uri = parts.next().unwrap().parse().expect("validated URI");
    let path = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    let mut wire = format!("{method} {path} HTTP/1.1").into_bytes();
    wire.extend_from_slice(&raw[end..]);
    wire
}

pub(super) fn encoded_body(raw: &[u8]) -> bool {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    String::from_utf8_lossy(&raw[..end])
        .split("\r\n")
        .any(|line| {
            line.split_once(':').is_some_and(|(key, value)| {
                key.eq_ignore_ascii_case("content-encoding")
                    && !value.trim().eq_ignore_ascii_case("identity")
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn parse(parts: &[&[u8]]) -> Result<Vec<u8>, Rejection> {
        let (mut writer, mut reader) = tokio::io::duplex(256 * 1024);
        for part in parts {
            writer.write_all(part).await.unwrap();
        }
        writer.shutdown().await.unwrap();
        read_request(&mut reader).await
    }

    #[tokio::test]
    async fn reads_entire_fragmented_body_and_preserves_binary() {
        let result = parse(&[
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
            &[0xff, 0x00, 0x80, 0x42],
        ]).await.unwrap();
        assert!(result.ends_with(&[0xff, 0x00, 0x80, 0x42]));
    }

    #[tokio::test]
    async fn rejects_ambiguous_or_incomplete_framing() {
        for headers in [
            "Content-Length: 1\r\nContent-Length: 1",
            "Content-Length: abc",
            "Content-Length: -1",
            "Content-Length: 1, 1",
            "Content-Length: 5\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: gzip, chunked",
            "Host: other.example",
            "Upgrade: websocket",
            "Connection: content-length",
            "Expect: 100-continue",
        ] {
            let raw = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n\r\nx"
            );
            assert!(
                parse(&[raw.as_bytes()]).await.is_err(),
                "accepted {headers}"
            );
        }
        assert!(parse(&[b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8\r\n\r\nx"]).await.is_err());
    }

    #[tokio::test]
    async fn decodes_chunks_instead_of_scanning_chunk_boundaries() {
        let result = parse(&[b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsec\r\n3\r\nret\r\n0\r\n\r\n"]).await.unwrap();
        assert!(result.ends_with(b"secret"));
        assert!(!String::from_utf8_lossy(&result).contains("Transfer-Encoding"));
        assert!(String::from_utf8_lossy(&result).contains("Content-Length: 6"));
    }

    #[tokio::test]
    async fn rejects_chunk_smuggling_truncation_trailers_and_pipelining() {
        for body in [
            "3\r\nabcXX0\r\n\r\n",
            "3\r\na",
            "0\r\nSecret: value\r\n\r\n",
            "0\r\n\r\nGET /evil HTTP/1.1\r\n\r\n",
        ] {
            let raw = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
            );
            assert!(parse(&[raw.as_bytes()]).await.is_err(), "accepted {body:?}");
        }
    }

    #[tokio::test]
    async fn body_limit_rejects_before_waiting_for_body() {
        let raw = format!(
            "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(&[raw.as_bytes()]).await.unwrap_err().status, 413);
    }

    #[test]
    fn validates_destination_and_tunnel_authority() {
        assert_eq!(
            destination("http://EXAMPLE.com./x", "example.com:80", None).unwrap(),
            ("example.com".into(), 80)
        );
        for target in [
            "http://user@example.com/",
            "https://example.com/",
            "http://example.com:bad/",
            "http://example.com/#fragment",
            "/relative",
        ] {
            assert!(
                destination(target, "example.com", None).is_err(),
                "accepted {target}"
            );
        }
        assert!(destination("/x", "other.com", Some(("example.com", 443))).is_err());
        assert!(
            destination(
                "https://other.com/x",
                "example.com",
                Some(("example.com", 443))
            )
            .is_err()
        );
        assert!(destination("/x", "example.com:8443", Some(("example.com", 443))).is_err());
    }
}
