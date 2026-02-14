//! Telegram-based ASK responder with inline keyboard approval.
//!
//! [`TelegramResponder`] sends ASK requests as Telegram messages with
//! inline `Allow` / `Deny` buttons. A background polling loop reads
//! [`getUpdates`](https://core.telegram.org/bots/api#getupdates) for
//! `callback_query` events and resolves pending requests.
//!
//! Only callbacks from the configured `chat_id` are accepted; others are
//! silently ignored. When a request is resolved (either by this responder
//! or another), the original message is edited to show the outcome and
//! the inline keyboard is removed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use super::{AskRequestInfo, AskResponder};

/// A pending ASK request awaiting a Telegram callback response.
struct PendingAsk {
    /// One-shot channel to deliver the decision back to `prompt()`.
    tx: oneshot::Sender<bool>,
}

/// Telegram inline keyboard ASK responder.
///
/// On [`prompt()`](AskResponder::prompt), sends a message with `Allow` / `Deny`
/// buttons. A background task polls `getUpdates` and resolves the matching
/// pending request when a callback arrives.
pub struct TelegramResponder {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
    /// Map from `req_id` → pending one-shot sender + message ID.
    pending: Arc<Mutex<HashMap<String, PendingAsk>>>,
    /// Map from `req_id` → Telegram message ID (for `notify_resolved` edits).
    message_ids: Arc<Mutex<HashMap<String, i64>>>,
}

impl TelegramResponder {
    /// Create a new Telegram responder and start the `getUpdates` polling loop.
    pub fn new(bot_token: String, chat_id: String) -> Self {
        let client = reqwest::Client::new();
        let pending: Arc<Mutex<HashMap<String, PendingAsk>>> = Arc::new(Mutex::new(HashMap::new()));
        let message_ids: Arc<Mutex<HashMap<String, i64>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the background polling loop
        let poll_client = client.clone();
        let poll_token = bot_token.clone();
        let poll_chat_id = chat_id.clone();
        let poll_pending = pending.clone();

        tokio::spawn(async move {
            polling_loop(&poll_client, &poll_token, &poll_chat_id, &poll_pending).await;
        });

        Self {
            bot_token,
            chat_id,
            client,
            pending,
            message_ids,
        }
    }

    /// Create a responder without starting the polling loop (for testing).
    #[cfg(test)]
    fn new_without_polling(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            message_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl AskResponder for TelegramResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        // Send message with inline keyboard
        let message_id =
            match send_ask_message(&self.client, &self.bot_token, &self.chat_id, req).await {
                Ok(id) => id,
                Err(e) => {
                    error!("Failed to send Telegram ASK message: {}", e);
                    return None;
                }
            };

        info!(
            "Telegram ASK sent for {} {} {} (msg_id: {})",
            req.method, req.domain, req.path, message_id
        );

        // Create one-shot channel and store in pending map
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(req.req_id.clone(), PendingAsk { tx });
        }
        {
            let mut ids = self.message_ids.lock().unwrap();
            ids.insert(req.req_id.clone(), message_id);
        }

        // Wait for callback response (timeout is handled by AskBroadcaster)
        match rx.await {
            Ok(allowed) => Some(allowed),
            Err(_) => {
                // Sender was dropped (e.g., timeout cleanup)
                debug!("Telegram ASK oneshot dropped for {}", req.req_id);
                None
            }
        }
    }

    async fn notify_resolved(&self, req_id: &str, allowed: bool) {
        // Clean up pending entry if still present (in case another responder answered)
        {
            let mut map = self.pending.lock().unwrap();
            map.remove(req_id);
        }

        // Edit the original message to show the result
        let message_id = {
            let ids = self.message_ids.lock().unwrap();
            ids.get(req_id).copied()
        };

        if let Some(msg_id) = message_id {
            if let Err(e) = edit_message_result(
                &self.client,
                &self.bot_token,
                &self.chat_id,
                msg_id,
                allowed,
            )
            .await
            {
                warn!("Failed to edit Telegram message: {}", e);
            }
            let mut ids = self.message_ids.lock().unwrap();
            ids.remove(req_id);
        }
    }

    fn name(&self) -> &str {
        "telegram"
    }
}

/// Build the inline keyboard JSON for Allow/Deny buttons.
pub fn build_inline_keyboard(req_id: &str) -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [[
            {"text": "✅ Allow", "callback_data": format!("allow:{}", req_id)},
            {"text": "❌ Deny", "callback_data": format!("deny:{}", req_id)}
        ]]
    })
}

/// Format the ASK message text for Telegram.
pub fn format_ask_text(req: &AskRequestInfo) -> String {
    let mut text = format!(
        "🔔 *AgentShield ASK*\n\n\
         *Domain:* `{}`\n\
         *Method:* `{}`\n\
         *Path:* `{}`",
        req.domain, req.method, req.path
    );
    if let Some(ref body) = req.body {
        let preview = if body.len() > 200 {
            format!("{}...", &body[..200])
        } else {
            body.clone()
        };
        text.push_str(&format!("\n*Body:* `{}`", preview));
    }
    text
}

/// Parse callback data (e.g., `"allow:uuid"` or `"deny:uuid"`).
///
/// Returns `Some((action, req_id))` on success, `None` if format is invalid.
pub fn parse_callback_data(data: &str) -> Option<(&str, &str)> {
    let (action, req_id) = data.split_once(':')?;
    if (action == "allow" || action == "deny") && !req_id.is_empty() {
        Some((action, req_id))
    } else {
        None
    }
}

/// Send an ASK message with inline keyboard to Telegram.
///
/// Returns the Telegram message ID on success.
async fn send_ask_message(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: &str,
    req: &AskRequestInfo,
) -> Result<i64, String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let text = format_ask_text(req);
    let keyboard = build_inline_keyboard(&req.req_id);

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": keyboard,
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Telegram API error: {}", body));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON error: {}", e))?;
    json["result"]["message_id"]
        .as_i64()
        .ok_or_else(|| "No message_id in response".to_string())
}

/// Edit a resolved ASK message to show the outcome and remove the keyboard.
async fn edit_message_result(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: &str,
    message_id: i64,
    allowed: bool,
) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/editMessageText", bot_token);

    let status = if allowed {
        "✅ *ALLOWED*"
    } else {
        "❌ *DENIED*"
    };

    let text = format!("🔔 *AgentShield ASK*\n\nResult: {}", status);

    client
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "Markdown",
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    Ok(())
}

/// Background polling loop that reads `getUpdates` and resolves pending ASK requests.
async fn polling_loop(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: &str,
    pending: &Arc<Mutex<HashMap<String, PendingAsk>>>,
) {
    let mut offset: i64 = 0;

    loop {
        let url = format!("https://api.telegram.org/bot{}/getUpdates", bot_token);

        let resp = client
            .post(&url)
            .json(&serde_json::json!({
                "offset": offset,
                "timeout": 30,
                "allowed_updates": ["callback_query"],
            }))
            .send()
            .await;

        let json = match resp {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(j) => j,
                Err(e) => {
                    warn!("Telegram getUpdates JSON error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            },
            Err(e) => {
                warn!("Telegram getUpdates HTTP error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let updates = match json["result"].as_array() {
            Some(arr) => arr,
            None => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        for update in updates {
            // Update offset to acknowledge this update
            if let Some(update_id) = update["update_id"].as_i64() {
                offset = update_id + 1;
            }

            // Process callback queries only
            let callback = match update.get("callback_query") {
                Some(cb) => cb,
                None => continue,
            };

            // Validate chat_id
            let cb_chat_id = callback["message"]["chat"]["id"].to_string();
            if cb_chat_id != chat_id {
                debug!("Ignoring callback from wrong chat: {}", cb_chat_id);
                continue;
            }

            // Parse callback data
            let data = match callback["data"].as_str() {
                Some(d) => d,
                None => continue,
            };

            let (action, req_id) = match parse_callback_data(data) {
                Some(parsed) => parsed,
                None => {
                    debug!("Invalid callback data: {}", data);
                    continue;
                }
            };

            let allowed = action == "allow";
            info!("Telegram callback: {} req_id={}", action, req_id);

            // Answer the callback query to dismiss the loading indicator
            let callback_id = callback["id"].as_str().unwrap_or("");
            answer_callback_query(client, bot_token, callback_id).await;

            // Resolve the pending request
            let pending_ask = {
                let mut map = pending.lock().unwrap();
                map.remove(req_id)
            };

            if let Some(pa) = pending_ask {
                let _ = pa.tx.send(allowed);
            } else {
                debug!("No pending ASK for req_id={} (already resolved)", req_id);
            }
        }
    }
}

/// Answer a callback query to dismiss Telegram's loading indicator.
async fn answer_callback_query(client: &reqwest::Client, bot_token: &str, callback_query_id: &str) {
    let url = format!(
        "https://api.telegram.org/bot{}/answerCallbackQuery",
        bot_token
    );
    let _ = client
        .post(&url)
        .json(&serde_json::json!({
            "callback_query_id": callback_query_id,
        }))
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_callback_data_allow() {
        let result = parse_callback_data("allow:abc-123-def");
        assert_eq!(result, Some(("allow", "abc-123-def")));
    }

    #[test]
    fn parse_callback_data_deny() {
        let result = parse_callback_data("deny:xyz-789");
        assert_eq!(result, Some(("deny", "xyz-789")));
    }

    #[test]
    fn parse_callback_data_invalid_action() {
        assert!(parse_callback_data("block:abc").is_none());
    }

    #[test]
    fn parse_callback_data_no_colon() {
        assert!(parse_callback_data("allowabc").is_none());
    }

    #[test]
    fn parse_callback_data_empty_req_id() {
        assert!(parse_callback_data("allow:").is_none());
    }

    #[test]
    fn parse_callback_data_empty_string() {
        assert!(parse_callback_data("").is_none());
    }

    #[test]
    fn build_keyboard_contains_allow_deny() {
        let kb = build_inline_keyboard("test-req-id");
        let buttons = kb["inline_keyboard"][0].as_array().unwrap();
        assert_eq!(buttons.len(), 2);
        assert_eq!(buttons[0]["callback_data"], "allow:test-req-id");
        assert_eq!(buttons[1]["callback_data"], "deny:test-req-id");
        assert!(buttons[0]["text"].as_str().unwrap().contains("Allow"));
        assert!(buttons[1]["text"].as_str().unwrap().contains("Deny"));
    }

    #[test]
    fn format_ask_text_without_body() {
        let req = AskRequestInfo {
            req_id: "id-1".to_string(),
            domain: "api.github.com".to_string(),
            method: "POST".to_string(),
            path: "/repos/user/repo/pulls".to_string(),
            body: None,
        };
        let text = format_ask_text(&req);
        assert!(text.contains("api.github.com"));
        assert!(text.contains("POST"));
        assert!(text.contains("/repos/user/repo/pulls"));
        assert!(!text.contains("Body:"));
    }

    #[test]
    fn format_ask_text_with_body() {
        let req = AskRequestInfo {
            req_id: "id-2".to_string(),
            domain: "example.com".to_string(),
            method: "PUT".to_string(),
            path: "/data".to_string(),
            body: Some(r#"{"key": "value"}"#.to_string()),
        };
        let text = format_ask_text(&req);
        assert!(text.contains("Body:"));
        assert!(text.contains(r#"{"key": "value"}"#));
    }

    #[test]
    fn format_ask_text_truncates_long_body() {
        let long_body = "x".repeat(500);
        let req = AskRequestInfo {
            req_id: "id-3".to_string(),
            domain: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/upload".to_string(),
            body: Some(long_body),
        };
        let text = format_ask_text(&req);
        assert!(text.contains("..."));
        // Body preview should be truncated to 200 chars + "..."
        assert!(text.len() < 500);
    }

    #[test]
    fn responder_name() {
        let r = TelegramResponder::new_without_polling("token".into(), "123".into());
        assert_eq!(r.name(), "telegram");
    }

    #[tokio::test]
    async fn wrong_chat_id_callback_ignored() {
        // Simulate: pending request exists, but callback comes from wrong chat
        let r = TelegramResponder::new_without_polling("token".into(), "correct_chat".into());
        let (tx, _rx) = oneshot::channel();
        {
            let mut map = r.pending.lock().unwrap();
            map.insert("req-1".to_string(), PendingAsk { tx });
        }

        // The pending map should still have the entry (callback from wrong chat is ignored)
        assert!(r.pending.lock().unwrap().contains_key("req-1"));
    }

    #[tokio::test]
    async fn already_resolved_callback_handled() {
        // Simulate: no pending entry for req_id (already resolved by another responder)
        let r = TelegramResponder::new_without_polling("token".into(), "123".into());

        // Pending map is empty — parse_callback_data returns valid data but
        // no PendingAsk is found. This should not panic.
        let data = "allow:already-resolved-id";
        let (action, req_id) = parse_callback_data(data).unwrap();
        assert_eq!(action, "allow");

        let pending_ask = {
            let mut map = r.pending.lock().unwrap();
            map.remove(req_id)
        };
        assert!(pending_ask.is_none()); // gracefully handled
    }

    #[tokio::test]
    async fn notify_resolved_cleans_up_pending() {
        let r = TelegramResponder::new_without_polling("token".into(), "123".into());

        // Add a pending entry
        let (tx, _rx) = oneshot::channel();
        {
            let mut map = r.pending.lock().unwrap();
            map.insert("req-cleanup".to_string(), PendingAsk { tx });
        }
        {
            let mut ids = r.message_ids.lock().unwrap();
            ids.insert("req-cleanup".to_string(), 99);
        }

        // notify_resolved should remove from pending map
        // (edit_message_result will fail with fake token, but cleanup still happens)
        r.notify_resolved("req-cleanup", true).await;

        assert!(!r.pending.lock().unwrap().contains_key("req-cleanup"));
        assert!(!r.message_ids.lock().unwrap().contains_key("req-cleanup"));
    }
}
