//! One-shot host intent for a known issuer's authentication header, never a request allow.
//! Body/other credential findings and destination policy remain independent gates.
use crate::{
    ask::workos::WorkosApprovalConfig,
    dlp::{DlpFinding, DlpScanner},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HEADER: &str = "x-agentshield-host-authentication";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostAuthenticationRequest {
    pub v: u8,
    pub intent_id: String,
    pub request_sha256: String,
    pub destination_sha256: String,
    pub method: String,
    pub target_sha256: String,
    pub body_sha256: String,
    pub authorization_sha256: String,
}

#[async_trait::async_trait]
pub trait HostAuthenticator: Send + Sync {
    async fn authenticate(&self, request: &HostAuthenticationRequest) -> bool;
}

pub struct HostAuthenticationClient {
    client: crate::ask::metadata_bridge::MetadataBridgeClient,
}
impl HostAuthenticationClient {
    pub fn new(config: WorkosApprovalConfig) -> Result<Self, &'static str> {
        Ok(Self {
            client: crate::ask::metadata_bridge::MetadataBridgeClient::new(
                config,
                std::time::Duration::from_secs(2),
            )?,
        })
    }
}
#[async_trait::async_trait]
impl HostAuthenticator for HostAuthenticationClient {
    async fn authenticate(&self, request: &HostAuthenticationRequest) -> bool {
        let Some(value) = self.client.post("/authenticate", request, 1024).await else {
            return false;
        };
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Reply {
            intent_id: String,
            request_sha256: String,
            authenticated: bool,
        }
        let Ok(reply) = serde_json::from_value::<Reply>(value) else {
            return false;
        };
        reply.authenticated
            && reply.intent_id == request.intent_id
            && reply.request_sha256 == request.request_sha256
    }
}

pub struct Intent {
    pub request: HostAuthenticationRequest,
    auth_line: std::ops::Range<usize>,
    control_line: std::ops::Range<usize>,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Only canonical, already-framed HTTP requests may enter this function.
/// No nonce means normal inspection. Malformed/duplicate control/auth headers deny.
pub fn intent(
    raw: &[u8],
    domain: &str,
    port: u16,
    method: &str,
    target: &str,
) -> Result<Option<Intent>, &'static str> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid host authentication")?;
    let headers =
        std::str::from_utf8(&raw[..end + 2]).map_err(|_| "invalid host authentication")?;
    let mut offset = 0;
    let mut controls = Vec::new();
    let mut authorizations = Vec::new();
    for line in headers.split_inclusive("\r\n") {
        if let Some((name, value)) = line.trim_end_matches("\r\n").split_once(':') {
            let span = offset..offset + line.len();
            if name.eq_ignore_ascii_case(HEADER) {
                controls.push((value.trim(), span.clone()));
            }
            if name.eq_ignore_ascii_case("authorization") {
                authorizations.push((value.trim(), span));
            }
        }
        offset += line.len();
    }
    if controls.is_empty() {
        return Ok(None);
    }
    if controls.len() != 1 || authorizations.len() != 1 {
        return Err("invalid host authentication");
    }
    let (nonce, control_line) = controls.pop().unwrap();
    if uuid::Uuid::parse_str(nonce)
        .ok()
        .is_none_or(|id| id.to_string() != nonce)
    {
        return Err("invalid host authentication");
    }
    let (authorization, auth_line) = authorizations.pop().unwrap();
    if !authorization.starts_with("Bearer ") || authorization.len() > 8192 {
        return Err("invalid host authentication");
    }
    // JSON tuple avoids ambiguities in IPv6 and default-port rendering. No URL or token leaves the engine.
    let destination =
        serde_json::to_vec(&("https", domain.to_ascii_lowercase(), port)).expect("fixed tuple");
    Ok(Some(Intent {
        request: HostAuthenticationRequest {
            v: 1,
            intent_id: nonce.into(),
            request_sha256: digest(raw),
            destination_sha256: digest(&destination),
            method: method.into(),
            target_sha256: digest(target.as_bytes()),
            body_sha256: digest(&raw[end + 4..]),
            authorization_sha256: digest(authorization.as_bytes()),
        },
        auth_line,
        control_line,
    }))
}

impl Intent {
    /// Retain every non-authorization finding, including provider keys in the authenticated header.
    /// Rescan the rest for authorization text, including encoded body views. Never disable a category globally.
    pub fn findings(&self, scanner: &dyn DlpScanner, raw: &[u8]) -> Vec<DlpFinding> {
        let mut findings = scanner.scan(raw);
        findings.retain(|f| f.pattern_name != "authorization");
        for part in [&raw[..self.auth_line.start], &raw[self.auth_line.end..]] {
            findings.extend(
                scanner
                    .scan(part)
                    .into_iter()
                    .filter(|f| f.pattern_name == "authorization"),
            );
        }
        findings
    }
    /// The local one-shot capability must never be disclosed to the destination.
    pub fn forward_bytes(&self, raw: &[u8]) -> Vec<u8> {
        [
            &raw[..self.control_line.start],
            &raw[self.control_line.end..],
        ]
        .concat()
    }
}

pub fn has_control_header(raw: &[u8]) -> bool {
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    std::str::from_utf8(&raw[..end]).is_ok_and(|headers| {
        headers.split("\r\n").skip(1).any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case(HEADER))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::patterns::RegexScanner;
    fn request(body: &str, auth: &str, control: &str) -> Vec<u8> {
        format!("POST /v1/responses HTTP/1.1\r\nHost: issuer.example\r\nAuthorization: Bearer {auth}\r\n{HEADER}: {control}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
    }
    #[test]
    fn metadata_contains_only_hashes_and_forwards_without_the_local_capability() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let raw = request(
            "private prompt text",
            "synthetic-high-entropy-session-value",
            &nonce,
        );
        let found = intent(&raw, "issuer.example", 443, "POST", "/v1/responses")
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_string(&found.request).unwrap();
        for secret in [
            "private prompt",
            "synthetic-high",
            "issuer.example",
            "/v1/responses",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(found.request.request_sha256, digest(&raw));
        assert_eq!(
            found.request.destination_sha256,
            digest(br#"["https","issuer.example",443]"#)
        );
        assert_eq!(found.request.body_sha256, digest(b"private prompt text"));
        let forwarded = found.forward_bytes(&raw);
        assert!(!has_control_header(&forwarded));
        assert!(forwarded.ends_with(b"private prompt text"));
        assert!(
            String::from_utf8_lossy(&forwarded).contains("Authorization: Bearer synthetic-high")
        );
    }
    #[test]
    fn a_known_auth_header_never_hides_other_credentials_or_encoded_authorization() {
        let scanner = RegexScanner::new();
        let nonce = uuid::Uuid::new_v4().to_string();
        let clean = request("ordinary prompt", "synthetic-session-value", &nonce);
        let ticket = intent(&clean, "issuer.example", 443, "POST", "/v1/responses")
            .unwrap()
            .unwrap();
        assert!(ticket.findings(&scanner, &clean).is_empty());
        for body in [
            "sk-proj-abcdefghijklmnopqrstuvw1234567890",
            "\r\nAuthorization: Bearer foreign-private-value",
            "QXV0aG9yaXphdGlvbjogQmVhcmVyIGZvcmVpZ24tcHJpdmF0ZS12YWx1ZQ==",
        ] {
            let raw = request(body, "synthetic-session-value", &nonce);
            let ticket = intent(&raw, "issuer.example", 443, "POST", "/v1/responses")
                .unwrap()
                .unwrap();
            assert!(
                !ticket.findings(&scanner, &raw).is_empty(),
                "body findings lost"
            );
        }
        let raw = request(
            "ordinary",
            "sk-proj-abcdefghijklmnopqrstuvw1234567890",
            &nonce,
        );
        let ticket = intent(&raw, "issuer.example", 443, "POST", "/v1/responses")
            .unwrap()
            .unwrap();
        assert!(
            ticket
                .findings(&scanner, &raw)
                .iter()
                .any(|f| f.pattern_name == "openai-api-key")
        );
    }
    #[test]
    fn duplicate_or_malformed_control_and_auth_headers_never_select_an_intent() {
        let nonce = uuid::Uuid::new_v4().to_string();
        for control in [
            "not-a-ticket".into(),
            format!("{nonce}\r\n{HEADER}: {nonce}"),
        ] {
            assert!(
                intent(
                    &request("body", "session-value", &control),
                    "issuer.example",
                    443,
                    "POST",
                    "/v1/responses"
                )
                .is_err()
            );
        }
        let raw = request(
            "body",
            "session-value\r\nAuthorization: Bearer other-value",
            &nonce,
        );
        assert!(intent(&raw, "issuer.example", 443, "POST", "/v1/responses").is_err());
        assert!(intent(b"malformed", "issuer.example", 443, "POST", "/").is_err());
    }

    #[tokio::test]
    async fn callback_is_local_authenticated_bounded_and_bound_to_the_exact_request() {
        use axum::{
            Json, Router,
            http::{HeaderMap, StatusCode},
            routing::post,
        };
        for mode in [
            "valid",
            "digest",
            "intent",
            "extra",
            "too-large",
            "redirect",
            "unsigned",
            "wrong-path",
            "wrong-challenge",
            "tampered-body",
        ] {
            let router = Router::new().route("/authenticate", post(move |headers: HeaderMap, raw: axum::body::Bytes| async move {
                let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let challenge = headers[crate::ask::metadata_bridge::CHALLENGE].to_str().unwrap();
                assert_eq!(headers["authorization"], format!("AgentShield-Metadata {}", crate::ask::metadata_bridge::request_tag(&"k".repeat(40), "/authenticate", challenge, &raw)));
                assert!(!headers["authorization"].to_str().unwrap().contains(&"k".repeat(40)));
                assert!(value.get("body").is_none() && value.get("authorization").is_none());
                let mut response = serde_json::json!({"intentId": value["intentId"], "requestSha256":value["requestSha256"], "authenticated":true});
                if mode == "digest" { response["requestSha256"] = serde_json::json!("a".repeat(64)); }
                if mode == "intent" { response["intentId"] = serde_json::json!(uuid::Uuid::new_v4().to_string()); }
                if mode == "extra" { response["untrusted"] = serde_json::json!(true); }
                if mode == "too-large" { response["untrusted"] = serde_json::json!("x".repeat(1025)); }
                let bytes = serde_json::to_vec(&response).unwrap();
                let proof = if mode == "unsigned" { String::new() } else { crate::ask::metadata_bridge::response_tag(&"k".repeat(40), if mode == "wrong-path" { "/approve" } else { "/authenticate" }, if mode == "wrong-challenge" { "replayed-challenge" } else { challenge }, &raw, &bytes) };
                if mode == "tampered-body" { response["authenticated"] = serde_json::json!(false); }
                (if mode == "redirect" { StatusCode::TEMPORARY_REDIRECT } else { StatusCode::OK }, [(crate::ask::metadata_bridge::PROOF, proof)], Json(response))
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/approve", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let client = HostAuthenticationClient::new(WorkosApprovalConfig {
                endpoint,
                token: "k".repeat(40),
            })
            .unwrap();
            let raw = request(
                "ordinary",
                "synthetic-session-value",
                &uuid::Uuid::new_v4().to_string(),
            );
            let request = intent(&raw, "issuer.example", 443, "POST", "/v1/responses")
                .unwrap()
                .unwrap()
                .request;
            assert_eq!(client.authenticate(&request).await, mode == "valid");
            server.abort();
        }
    }
}
