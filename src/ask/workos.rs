//! Metadata-only bridge to the existing WorkOS authenticated device channel.
use super::{AskRequestInfo, AskResponder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkosApprovalConfig {
    pub endpoint: String,
    pub token: String,
}
impl std::fmt::Debug for WorkosApprovalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkosApprovalConfig")
            .field("endpoint", &self.endpoint)
            .field("token", &"[REDACTED]")
            .finish()
    }
}
impl WorkosApprovalConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        let url =
            reqwest::Url::parse(&self.endpoint).map_err(|_| "invalid WorkOS approval endpoint")?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.port().is_none()
            || url.path() != "/approve"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(32..=256).contains(&self.token.len())
            || !self
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(
                "WorkOS approvals require an exact loopback endpoint and strong credential",
            );
        }
        Ok(())
    }
}
pub struct WorkosApprovalResponder {
    config: WorkosApprovalConfig,
    client: reqwest::Client,
}
impl WorkosApprovalResponder {
    pub fn new(config: WorkosApprovalConfig) -> Result<Self, &'static str> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(115))
            .build()
            .map_err(|_| "approval client unavailable")?;
        Ok(Self { config, client })
    }
}
#[async_trait::async_trait]
impl AskResponder for WorkosApprovalResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        let metadata = req.approval.as_ref()?;
        let mut response = self.client.post(&self.config.endpoint).bearer_auth(&self.config.token)
            .json(&serde_json::json!({"requestId":req.req_id,"requestSha256":metadata.request_sha256,
                "destination":req.domain,"method":req.method,"requestBytes":metadata.request_bytes,"categories":metadata.categories}))
            .send().await.ok()?;
        if !response.status().is_success() || response.content_length().is_some_and(|n| n > 4096) {
            return Some(false);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len() + chunk.len() > 4096 {
                return Some(false);
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        Some(
            value["requestId"].as_str() == Some(req.req_id.as_str())
                && value["requestSha256"].as_str() == Some(metadata.request_sha256.as_str())
                && value["approved"].as_bool() == Some(true),
        )
    }
    async fn notify_resolved(&self, _: &str, _: bool) {}
    fn name(&self) -> &str {
        "workos-slack-dm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ask::SensitiveApprovalMetadata;

    #[test]
    fn bridge_rejects_remote_redirect_and_weak_credentials() {
        for endpoint in [
            "https://example.test/approve",
            "http://127.0.0.1:18081/approve?token=secret",
            "http://user@127.0.0.1:18081/approve",
        ] {
            assert!(
                WorkosApprovalConfig {
                    endpoint: endpoint.into(),
                    token: "x".repeat(40)
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            WorkosApprovalConfig {
                endpoint: "http://127.0.0.1:18081/approve".into(),
                token: "weak".into()
            }
            .validate()
            .is_err()
        );
    }

    #[tokio::test]
    async fn metadata_only_and_digest_bound() {
        use axum::{Json, Router, routing::post};
        for wrong_digest in [false, true] {
            let app = Router::new().route("/approve", post(move |headers: axum::http::HeaderMap, Json(value): Json<serde_json::Value>| async move {
                assert_eq!(headers["authorization"], format!("Bearer {}", "t".repeat(40)));
                assert!(value.get("body").is_none()); assert!(value.get("path").is_none());
                assert!(!value.to_string().contains("SYNTHETIC_SECRET_VALUE"));
                Json(serde_json::json!({"requestId":value["requestId"], "requestSha256": if wrong_digest { serde_json::json!("b".repeat(64)) } else { value["requestSha256"].clone() }, "approved":true}))
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/approve", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let responder = WorkosApprovalResponder::new(WorkosApprovalConfig {
                endpoint,
                token: "t".repeat(40),
            })
            .unwrap();
            let request = AskRequestInfo {
                req_id: uuid::Uuid::new_v4().to_string(),
                domain: "example.test".into(),
                method: "POST".into(),
                path: "/?secret=SYNTHETIC_SECRET_VALUE".into(),
                body: Some("SYNTHETIC_SECRET_VALUE".into()),
                approval: Some(SensitiveApprovalMetadata {
                    request_sha256: "a".repeat(64),
                    request_bytes: 123,
                    categories: vec!["openai-api-key".into()],
                }),
            };
            assert_eq!(responder.prompt(&request).await, Some(!wrong_digest));
            server.abort();
        }
    }
}
