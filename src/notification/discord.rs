use serde_json::{Value, json};

use crate::error::{AgentShieldError, Result};
use crate::notification::{NotificationEvent, Notifier, format_message};

/// Sends notifications to a Discord channel via Incoming Webhook.
pub struct DiscordNotifier {
    webhook_url: String,
    /// Reusable HTTP client for connection pooling.
    client: reqwest::Client,
}

impl DiscordNotifier {
    /// Create a new Discord notifier targeting the given Webhook URL.
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Notifier for DiscordNotifier {
    async fn notify(&self, event: &NotificationEvent) -> Result<()> {
        let payload = format_discord_embed(event);

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
                "Discord Webhook error {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "discord"
    }
}

/// Discord embed color constants.
const COLOR_RED: u32 = 0xED4245;
const COLOR_ORANGE: u32 = 0xFEE75C;
const COLOR_GREEN: u32 = 0x57F287;
const COLOR_GRAY: u32 = 0x99AAB5;
const COLOR_BLUE: u32 = 0x5865F2;

/// Build a Discord webhook payload with an embed for the given notification event.
///
/// Uses `format_message()` as the `content` fallback and constructs an embed
/// with title, description, color, and fields.
pub fn format_discord_embed(event: &NotificationEvent) -> Value {
    let fallback = format_message(event);

    let (title, description, color) = match event {
        NotificationEvent::RequestDenied {
            domain,
            method,
            path,
            reason,
        } => (
            "Request Denied".to_string(),
            format!(
                "`{} {}{}` → BLOCKED\nReason: {}",
                method, domain, path, reason
            ),
            COLOR_RED,
        ),
        NotificationEvent::DlpFinding {
            domain,
            method,
            pattern_name,
            severity,
        } => (
            format!("DLP Finding ({})", severity),
            format!("`{} {}`\nPattern: {}", method, domain, pattern_name),
            COLOR_ORANGE,
        ),
        NotificationEvent::ProxyStarted { listen_addr } => (
            "AgentShield Started".to_string(),
            format!("Listening on `{}`", listen_addr),
            COLOR_GREEN,
        ),
        NotificationEvent::ProxyShutdown => (
            "AgentShield Shutdown".to_string(),
            "Proxy server has stopped.".to_string(),
            COLOR_GRAY,
        ),
        NotificationEvent::AskPending {
            domain,
            method,
            path,
        } => (
            "ASK Pending".to_string(),
            format!("`{} {}{}`\nWaiting for approval", method, domain, path),
            COLOR_BLUE,
        ),
        NotificationEvent::RateLimited {
            domain,
            method,
            limit,
            window_secs,
        } => (
            "Rate Limited".to_string(),
            format!(
                "`{} {}`\nLimit: {} requests / {}s",
                method, domain, limit, window_secs
            ),
            COLOR_ORANGE,
        ),
    };

    json!({
        "content": fallback,
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_discord_embed_deny() {
        let event = NotificationEvent::RequestDenied {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            reason: "policy deny".to_string(),
        };
        let payload = format_discord_embed(&event);

        assert!(
            payload["content"]
                .as_str()
                .unwrap()
                .contains("Request Denied")
        );
        let embed = &payload["embeds"][0];
        assert_eq!(embed["title"].as_str().unwrap(), "Request Denied");
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("api.openai.com")
        );
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("policy deny")
        );
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_RED as u64);
    }

    #[test]
    fn format_discord_embed_dlp() {
        let event = NotificationEvent::DlpFinding {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            pattern_name: "openai_api_key".to_string(),
            severity: "high".to_string(),
        };
        let payload = format_discord_embed(&event);

        let embed = &payload["embeds"][0];
        assert!(embed["title"].as_str().unwrap().contains("DLP Finding"));
        assert!(embed["title"].as_str().unwrap().contains("high"));
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("openai_api_key")
        );
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_ORANGE as u64);
    }

    #[test]
    fn format_discord_embed_start() {
        let event = NotificationEvent::ProxyStarted {
            listen_addr: "127.0.0.1:8080".to_string(),
        };
        let payload = format_discord_embed(&event);

        let embed = &payload["embeds"][0];
        assert_eq!(embed["title"].as_str().unwrap(), "AgentShield Started");
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("127.0.0.1:8080")
        );
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_GREEN as u64);
    }

    #[test]
    fn format_discord_embed_shutdown() {
        let event = NotificationEvent::ProxyShutdown;
        let payload = format_discord_embed(&event);

        let embed = &payload["embeds"][0];
        assert_eq!(embed["title"].as_str().unwrap(), "AgentShield Shutdown");
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_GRAY as u64);
    }

    #[test]
    fn format_discord_embed_ask() {
        let event = NotificationEvent::AskPending {
            domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
        };
        let payload = format_discord_embed(&event);

        let embed = &payload["embeds"][0];
        assert_eq!(embed["title"].as_str().unwrap(), "ASK Pending");
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("api.anthropic.com")
        );
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_BLUE as u64);
    }

    #[test]
    fn format_discord_embed_rate_limited() {
        let event = NotificationEvent::RateLimited {
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            limit: 10,
            window_secs: 60,
        };
        let payload = format_discord_embed(&event);

        let embed = &payload["embeds"][0];
        assert_eq!(embed["title"].as_str().unwrap(), "Rate Limited");
        assert!(
            embed["description"]
                .as_str()
                .unwrap()
                .contains("10 requests / 60s")
        );
        assert_eq!(embed["color"].as_u64().unwrap(), COLOR_ORANGE as u64);
    }

    #[test]
    fn discord_notifier_name() {
        let notifier = DiscordNotifier::new("https://discord.com/api/webhooks/123/abc".to_string());
        assert_eq!(notifier.name(), "discord");
    }
}
