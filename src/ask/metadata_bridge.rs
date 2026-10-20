//! Authenticated metadata-only loopback transport. The shared key is never sent.
//! Fresh request challenges authenticate replies even if a local port is rebound.
use super::workos::WorkosApprovalConfig;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) const CHALLENGE: &str = "x-agentshield-challenge";
pub(crate) const PROOF: &str = "x-agentshield-proof";
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn tag(key: &str, transcript: String) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC key");
    mac.update(transcript.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(crate) fn request_tag(key: &str, path: &str, challenge: &str, body: &[u8]) -> String {
    tag(
        key,
        format!(
            "agentshield.metadata.request.v1\n{path}\n{challenge}\n{}",
            digest(body)
        ),
    )
}
pub(crate) fn response_tag(
    key: &str,
    path: &str,
    challenge: &str,
    request: &[u8],
    response: &[u8],
) -> String {
    tag(
        key,
        format!(
            "agentshield.metadata.response.v1\n{path}\n{challenge}\n{}\n{}",
            digest(request),
            digest(response)
        ),
    )
}

pub(crate) struct MetadataBridgeClient {
    config: WorkosApprovalConfig,
    client: reqwest::Client,
}
impl MetadataBridgeClient {
    pub(crate) fn new(
        config: WorkosApprovalConfig,
        timeout: std::time::Duration,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| "metadata bridge unavailable")?;
        Ok(Self { config, client })
    }
    pub(crate) async fn post(
        &self,
        path: &str,
        value: &impl serde::Serialize,
        limit: usize,
    ) -> Option<serde_json::Value> {
        if !matches!(path, "/approve" | "/authenticate") {
            return None;
        }
        let mut endpoint = reqwest::Url::parse(&self.config.endpoint).ok()?;
        endpoint.set_path(path);
        let body = serde_json::to_vec(value).ok()?;
        if body.len() > 8192 {
            return None;
        }
        let challenge = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let proof = request_tag(&self.config.token, path, &challenge, &body);
        let mut response = self
            .client
            .post(endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("AgentShield-Metadata {proof}"),
            )
            .header(CHALLENGE, &challenge)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .body(body.clone())
            .send()
            .await
            .ok()?;
        if response.status() != reqwest::StatusCode::OK
            || response.content_length().is_some_and(|n| n > limit as u64)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
            || response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v != "identity")
        {
            return None;
        }
        let supplied = response.headers().get(PROOF)?.to_str().ok()?.to_owned();
        let mut raw = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if raw.len() + chunk.len() > limit {
                return None;
            }
            raw.extend_from_slice(&chunk);
        }
        let expected = response_tag(&self.config.token, path, &challenge, &body, &raw);
        if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
            return None;
        }
        serde_json::from_slice(&raw).ok()
    }
}
