use crate::error::{AgentShieldError, Result};
use crate::notification::{NotificationEvent, Notifier, format_message};

/// Sends notifications to a Telegram chat via the Bot API.
pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Notifier for TelegramNotifier {
    async fn notify(&self, event: &NotificationEvent) -> Result<()> {
        let text = format_message(event);
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }))
            .send()
            .await
            .map_err(|e| AgentShieldError::Notification(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(AgentShieldError::Notification(format!(
                "Telegram API error {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "telegram"
    }
}
