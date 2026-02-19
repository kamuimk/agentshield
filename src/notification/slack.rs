use serde_json::{Value, json};

use crate::error::{AgentShieldError, Result};
use crate::notification::{NotificationEvent, Notifier, format_message};

/// Sends notifications to a Slack channel via Incoming Webhook.
pub struct SlackNotifier {
    webhook_url: String,
    /// Reusable HTTP client for connection pooling.
    client: reqwest::Client,
}

impl SlackNotifier {
    /// Create a new Slack notifier targeting the given Incoming Webhook URL.
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Notifier for SlackNotifier {
    async fn notify(&self, event: &NotificationEvent) -> Result<()> {
        let payload = format_slack_blocks(event);

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AgentShieldError::Notification(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(AgentShieldError::Notification(format!(
                "Slack Webhook error {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "slack"
    }
}

/// Build a Slack Block Kit payload for the given notification event.
///
/// Uses `format_message()` as the plain-text fallback in the top-level `text` field
/// and constructs a `blocks` array with rich Slack mrkdwn formatting.
pub fn format_slack_blocks(event: &NotificationEvent) -> Value {
    let fallback = format_message(event);
    let mrkdwn = match event {
        NotificationEvent::RequestDenied {
            domain,
            method,
            path,
            reason,
        } => {
            format!(
                ":no_entry: *Request Denied*\n`{} {}{}` → BLOCKED\nReason: {}",
                method, domain, path, reason
            )
        }
        NotificationEvent::DlpFinding {
            domain,
            method,
            pattern_name,
            severity,
        } => {
            format!(
                ":mag: *DLP Finding* ({})\n`{} {}`\nPattern: {}",
                severity, method, domain, pattern_name
            )
        }
        NotificationEvent::ProxyStarted { listen_addr } => {
            format!(
                ":white_check_mark: *AgentShield Started*\nListening on `{}`",
                listen_addr
            )
        }
        NotificationEvent::ProxyShutdown => ":stop_button: *AgentShield Shutdown*".to_string(),
        NotificationEvent::AskPending {
            domain,
            method,
            path,
        } => {
            format!(
                ":warning: *ASK Pending*\n`{} {}{}`\nWaiting for approval",
                method, domain, path
            )
        }
        NotificationEvent::RateLimited {
            domain,
            method,
            limit,
            window_secs,
        } => {
            format!(
                ":stopwatch: *Rate Limited*\n`{} {}`\nLimit: {} requests / {}s",
                method, domain, limit, window_secs
            )
        }
    };

    json!({
        "text": fallback,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": mrkdwn
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_slack_blocks_deny() {
        let event = NotificationEvent::RequestDenied {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            reason: "policy deny".to_string(),
        };
        let payload = format_slack_blocks(&event);

        // Check fallback text
        assert!(payload["text"].as_str().unwrap().contains("Request Denied"));

        // Check blocks
        let blocks = payload["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 1);
        let mrkdwn = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":no_entry:"));
        assert!(mrkdwn.contains("Request Denied"));
        assert!(mrkdwn.contains("api.openai.com"));
        assert!(mrkdwn.contains("policy deny"));
    }

    #[test]
    fn format_slack_blocks_dlp() {
        let event = NotificationEvent::DlpFinding {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            pattern_name: "openai_api_key".to_string(),
            severity: "high".to_string(),
        };
        let payload = format_slack_blocks(&event);

        let mrkdwn = payload["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":mag:"));
        assert!(mrkdwn.contains("DLP Finding"));
        assert!(mrkdwn.contains("openai_api_key"));
        assert!(mrkdwn.contains("high"));
    }

    #[test]
    fn format_slack_blocks_start() {
        let event = NotificationEvent::ProxyStarted {
            listen_addr: "127.0.0.1:8080".to_string(),
        };
        let payload = format_slack_blocks(&event);

        let mrkdwn = payload["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":white_check_mark:"));
        assert!(mrkdwn.contains("127.0.0.1:8080"));
    }

    #[test]
    fn format_slack_blocks_shutdown() {
        let event = NotificationEvent::ProxyShutdown;
        let payload = format_slack_blocks(&event);

        let mrkdwn = payload["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":stop_button:"));
        assert!(mrkdwn.contains("Shutdown"));
    }

    #[test]
    fn format_slack_blocks_ask() {
        let event = NotificationEvent::AskPending {
            domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
        };
        let payload = format_slack_blocks(&event);

        let mrkdwn = payload["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":warning:"));
        assert!(mrkdwn.contains("ASK Pending"));
        assert!(mrkdwn.contains("api.anthropic.com"));
    }

    #[test]
    fn format_slack_blocks_rate_limited() {
        let event = NotificationEvent::RateLimited {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            limit: 10,
            window_secs: 60,
        };
        let payload = format_slack_blocks(&event);

        let mrkdwn = payload["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(mrkdwn.contains(":stopwatch:"));
        assert!(mrkdwn.contains("Rate Limited"));
        assert!(mrkdwn.contains("10 requests / 60s"));
    }

    #[test]
    fn slack_notifier_name() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/services/T/B/xxx".to_string());
        assert_eq!(notifier.name(), "slack");
    }
}
