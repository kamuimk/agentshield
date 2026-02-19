//! Slack Socket Mode ASK responder with interactive button approval.
//!
//! [`SlackAskResponder`] sends ASK requests as Slack messages with Block Kit
//! `Allow` / `Deny` buttons. A background WebSocket loop connects to Slack's
//! Socket Mode API and receives interaction payloads when users click buttons.
//!
//! The responder uses two Slack tokens:
//! - `bot_token` (xoxb-...): for sending messages via `chat.postMessage`
//! - `app_token` (xapp-...): for establishing the Socket Mode WebSocket connection

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use super::{AskRequestInfo, AskResponder};

/// A pending ASK request awaiting a Slack interaction response.
pub(crate) struct PendingAsk {
    /// One-shot channel to deliver the decision back to `prompt()`.
    tx: oneshot::Sender<bool>,
}

/// Slack interactive ASK responder using Socket Mode.
pub struct SlackAskResponder {
    bot_token: String,
    channel: String,
    client: reqwest::Client,
    /// Map from `req_id` → pending one-shot sender.
    pending: Arc<Mutex<HashMap<String, PendingAsk>>>,
    /// Map from `req_id` → Slack message timestamp (for `notify_resolved` edits).
    message_ts: Arc<Mutex<HashMap<String, String>>>,
}

impl SlackAskResponder {
    /// Create a new Slack ASK responder and start the Socket Mode WebSocket loop.
    pub fn new(bot_token: String, app_token: String, channel: String) -> Self {
        let client = reqwest::Client::new();
        let pending: Arc<Mutex<HashMap<String, PendingAsk>>> = Arc::new(Mutex::new(HashMap::new()));
        let message_ts: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the background Socket Mode WebSocket loop
        let ws_client = client.clone();
        let ws_app_token = app_token;
        let ws_pending = pending.clone();

        tokio::spawn(async move {
            socket_mode_loop(&ws_client, &ws_app_token, &ws_pending).await;
        });

        Self {
            bot_token,
            channel,
            client,
            pending,
            message_ts,
        }
    }

    /// Create a responder without starting the WebSocket loop (for testing).
    #[cfg(test)]
    pub fn new_without_ws(bot_token: String, channel: String) -> Self {
        Self {
            bot_token,
            channel,
            client: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            message_ts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a reference to the pending map (for testing).
    #[cfg(test)]
    pub(crate) fn pending(&self) -> &Arc<Mutex<HashMap<String, PendingAsk>>> {
        &self.pending
    }

    /// Get a reference to the message_ts map (for testing).
    #[cfg(test)]
    pub(crate) fn message_ts_map(&self) -> &Arc<Mutex<HashMap<String, String>>> {
        &self.message_ts
    }
}

#[async_trait::async_trait]
impl AskResponder for SlackAskResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        // Send message with buttons via Slack Web API
        let ts = match send_ask_message(&self.client, &self.bot_token, &self.channel, req).await {
            Ok(ts) => ts,
            Err(e) => {
                error!("Failed to send Slack ASK message: {}", e);
                return None;
            }
        };

        info!(
            "Slack ASK sent for {} {} {} (ts: {})",
            req.method, req.domain, req.path, ts
        );

        // Create one-shot channel and store in pending map
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(req.req_id.clone(), PendingAsk { tx });
        }
        {
            let mut ts_map = self.message_ts.lock().unwrap();
            ts_map.insert(req.req_id.clone(), ts);
        }

        // Wait for interaction response (timeout is handled by AskBroadcaster)
        match rx.await {
            Ok(allowed) => Some(allowed),
            Err(_) => {
                debug!("Slack ASK oneshot dropped for {}", req.req_id);
                None
            }
        }
    }

    async fn notify_resolved(&self, req_id: &str, allowed: bool) {
        // Clean up pending entry
        {
            let mut map = self.pending.lock().unwrap();
            map.remove(req_id);
        }

        // Update the original message to show the result
        let ts = {
            let ts_map = self.message_ts.lock().unwrap();
            ts_map.get(req_id).cloned()
        };

        if let Some(msg_ts) = ts {
            if let Err(e) = update_message_result(
                &self.client,
                &self.bot_token,
                &self.channel,
                &msg_ts,
                allowed,
            )
            .await
            {
                warn!("Failed to update Slack message: {}", e);
            }
            let mut ts_map = self.message_ts.lock().unwrap();
            ts_map.remove(req_id);
        }
    }

    fn name(&self) -> &str {
        "slack"
    }
}

/// Build Block Kit blocks for an ASK message with Allow/Deny buttons.
pub fn build_ask_blocks(req: &AskRequestInfo) -> serde_json::Value {
    let mut text = format!(
        ":bell: *AgentShield ASK*\n\n\
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

    serde_json::json!([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Allow"},
                    "style": "primary",
                    "action_id": "ask_allow",
                    "value": req.req_id
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "ask_deny",
                    "value": req.req_id
                }
            ]
        }
    ])
}

/// Format the fallback text for the ASK message.
pub fn format_ask_text(req: &AskRequestInfo) -> String {
    format!(
        "AgentShield ASK: {} {} {}",
        req.method, req.domain, req.path
    )
}

/// Send an ASK message with interactive buttons to a Slack channel.
///
/// Returns the message timestamp (`ts`) on success.
async fn send_ask_message(
    client: &reqwest::Client,
    bot_token: &str,
    channel: &str,
    req: &AskRequestInfo,
) -> Result<String, String> {
    let url = "https://slack.com/api/chat.postMessage";
    let text = format_ask_text(req);
    let blocks = build_ask_blocks(req);

    let resp = client
        .post(url)
        .bearer_auth(bot_token)
        .json(&serde_json::json!({
            "channel": channel,
            "text": text,
            "blocks": blocks,
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON error: {}", e))?;

    if json["ok"].as_bool() != Some(true) {
        let error = json["error"].as_str().unwrap_or("unknown");
        return Err(format!("Slack API error: {}", error));
    }

    json["ts"]
        .as_str()
        .or_else(|| json["message"]["ts"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No ts in response".to_string())
}

/// Update a Slack message to show the resolution result (removes buttons).
async fn update_message_result(
    client: &reqwest::Client,
    bot_token: &str,
    channel: &str,
    ts: &str,
    allowed: bool,
) -> Result<(), String> {
    let url = "https://slack.com/api/chat.update";
    let result_text = if allowed {
        ":white_check_mark: *Allowed* by responder"
    } else {
        ":no_entry: *Denied* by responder"
    };

    let resp = client
        .post(url)
        .bearer_auth(bot_token)
        .json(&serde_json::json!({
            "channel": channel,
            "ts": ts,
            "text": result_text,
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": result_text}
            }],
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON error: {}", e))?;

    if json["ok"].as_bool() != Some(true) {
        let error = json["error"].as_str().unwrap_or("unknown");
        return Err(format!("Slack API error: {}", error));
    }

    Ok(())
}

/// Open a Socket Mode WebSocket connection.
///
/// Calls `apps.connections.open` with the app-level token to get a WebSocket URL.
async fn open_socket_mode_connection(
    client: &reqwest::Client,
    app_token: &str,
) -> Result<String, String> {
    let url = "https://slack.com/api/apps.connections.open";
    let resp = client
        .post(url)
        .bearer_auth(app_token)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON error: {}", e))?;

    if json["ok"].as_bool() != Some(true) {
        let error = json["error"].as_str().unwrap_or("unknown");
        return Err(format!("Slack connections.open error: {}", error));
    }

    json["url"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No url in connections.open response".to_string())
}

/// Parse a Slack interaction payload from a Socket Mode envelope.
///
/// Returns `Some((action_id, req_id))` if this is a valid ASK button click.
pub fn parse_interaction_payload(payload: &serde_json::Value) -> Option<(String, String)> {
    let actions = payload.get("payload")?.get("actions")?.as_array()?;

    let action = actions.first()?;
    let action_id = action.get("action_id")?.as_str()?;
    let value = action.get("value")?.as_str()?;

    if action_id == "ask_allow" || action_id == "ask_deny" {
        Some((action_id.to_string(), value.to_string()))
    } else {
        None
    }
}

/// Background Socket Mode WebSocket loop.
///
/// Connects to Slack via Socket Mode, receives interaction events,
/// and resolves pending ASK requests. Auto-reconnects on disconnect.
async fn socket_mode_loop(
    client: &reqwest::Client,
    app_token: &str,
    pending: &Arc<Mutex<HashMap<String, PendingAsk>>>,
) {
    loop {
        // Get WebSocket URL
        let ws_url = match open_socket_mode_connection(client, app_token).await {
            Ok(url) => url,
            Err(e) => {
                error!("Failed to open Slack Socket Mode connection: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("Slack Socket Mode connected");

        // Connect WebSocket
        let ws_result = tokio_tungstenite::connect_async(&ws_url).await;
        let (mut ws, _) = match ws_result {
            Ok(pair) => pair,
            Err(e) => {
                error!("Slack WebSocket connection error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Read messages from WebSocket
        while let Some(msg) = ws.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    warn!("Slack WebSocket read error: {}", e);
                    break; // Reconnect
                }
            };

            let text = match msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => t,
                tokio_tungstenite::tungstenite::Message::Ping(_) => continue,
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    info!("Slack WebSocket closed, reconnecting...");
                    break;
                }
                _ => continue,
            };

            let envelope: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Slack WebSocket non-JSON message: {}", e);
                    continue;
                }
            };

            // Acknowledge the envelope immediately
            if let Some(envelope_id) = envelope.get("envelope_id").and_then(|v| v.as_str()) {
                let ack = serde_json::json!({"envelope_id": envelope_id});
                if let Err(e) = ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        ack.to_string().into(),
                    ))
                    .await
                {
                    warn!("Failed to ack Slack envelope: {}", e);
                }
            }

            // Check if this is an interactive_message type
            let event_type = envelope.get("type").and_then(|v| v.as_str());
            if event_type != Some("interactive") {
                debug!(
                    "Slack Socket Mode event type: {:?}",
                    event_type.unwrap_or("unknown")
                );
                continue;
            }

            // Parse the interaction
            if let Some((action_id, req_id)) = parse_interaction_payload(&envelope) {
                let allowed = action_id == "ask_allow";
                info!("Slack interaction: {} req_id={}", action_id, req_id);

                let pending_ask = {
                    let mut map = pending.lock().unwrap();
                    map.remove(&req_id)
                };

                if let Some(pa) = pending_ask {
                    let _ = pa.tx.send(allowed);
                } else {
                    debug!("No pending ASK for req_id={} (already resolved)", req_id);
                }
            }
        }

        // Reconnect delay
        warn!("Slack Socket Mode disconnected, reconnecting in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ask_blocks_contains_buttons() {
        let req = AskRequestInfo {
            req_id: "test-123".to_string(),
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            body: None,
        };
        let blocks = build_ask_blocks(&req);
        let arr = blocks.as_array().unwrap();
        assert_eq!(arr.len(), 2); // section + actions

        // Check section text
        let section = &arr[0];
        assert_eq!(section["type"], "section");
        let text = section["text"]["text"].as_str().unwrap();
        assert!(text.contains("api.openai.com"));
        assert!(text.contains("POST"));

        // Check action buttons
        let actions = &arr[1];
        assert_eq!(actions["type"], "actions");
        let elements = actions["elements"].as_array().unwrap();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0]["action_id"], "ask_allow");
        assert_eq!(elements[0]["value"], "test-123");
        assert_eq!(elements[1]["action_id"], "ask_deny");
        assert_eq!(elements[1]["value"], "test-123");
    }

    #[test]
    fn build_ask_blocks_with_body() {
        let req = AskRequestInfo {
            req_id: "test-456".to_string(),
            domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            body: Some("hello world".to_string()),
        };
        let blocks = build_ask_blocks(&req);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(text.contains("hello world"));
    }

    #[test]
    fn build_ask_blocks_truncates_long_body() {
        let req = AskRequestInfo {
            req_id: "test-789".to_string(),
            domain: "api.example.com".to_string(),
            method: "POST".to_string(),
            path: "/data".to_string(),
            body: Some("x".repeat(300)),
        };
        let blocks = build_ask_blocks(&req);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(text.contains("..."));
        // Should not contain the full 300 chars
        assert!(text.len() < 400);
    }

    #[test]
    fn format_ask_text_basic() {
        let req = AskRequestInfo {
            req_id: "r1".to_string(),
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            body: None,
        };
        let text = format_ask_text(&req);
        assert!(text.contains("POST"));
        assert!(text.contains("api.openai.com"));
        assert!(text.contains("/v1/chat"));
    }

    #[test]
    fn parse_interaction_payload_allow() {
        let payload = serde_json::json!({
            "type": "interactive",
            "payload": {
                "type": "block_actions",
                "actions": [
                    {
                        "action_id": "ask_allow",
                        "value": "req-abc-123"
                    }
                ]
            }
        });
        let result = parse_interaction_payload(&payload);
        assert_eq!(
            result,
            Some(("ask_allow".to_string(), "req-abc-123".to_string()))
        );
    }

    #[test]
    fn parse_interaction_payload_deny() {
        let payload = serde_json::json!({
            "type": "interactive",
            "payload": {
                "type": "block_actions",
                "actions": [
                    {
                        "action_id": "ask_deny",
                        "value": "req-xyz-789"
                    }
                ]
            }
        });
        let result = parse_interaction_payload(&payload);
        assert_eq!(
            result,
            Some(("ask_deny".to_string(), "req-xyz-789".to_string()))
        );
    }

    #[test]
    fn parse_interaction_payload_unknown_action() {
        let payload = serde_json::json!({
            "type": "interactive",
            "payload": {
                "type": "block_actions",
                "actions": [
                    {
                        "action_id": "some_other_action",
                        "value": "req-123"
                    }
                ]
            }
        });
        assert_eq!(parse_interaction_payload(&payload), None);
    }

    #[test]
    fn parse_interaction_payload_missing_payload() {
        let payload = serde_json::json!({"type": "hello"});
        assert_eq!(parse_interaction_payload(&payload), None);
    }

    #[test]
    fn responder_name() {
        let r = SlackAskResponder::new_without_ws("xoxb-test".to_string(), "#test".to_string());
        assert_eq!(r.name(), "slack");
    }

    #[tokio::test]
    async fn notify_resolved_cleans_up_pending() {
        let r = SlackAskResponder::new_without_ws("xoxb-test".to_string(), "#test".to_string());

        // Insert a pending entry
        let (tx, _rx) = oneshot::channel();
        {
            let mut map = r.pending().lock().unwrap();
            map.insert("req-1".to_string(), PendingAsk { tx });
        }
        {
            let mut ts = r.message_ts_map().lock().unwrap();
            ts.insert("req-1".to_string(), "1234.5678".to_string());
        }

        // notify_resolved should clean up (message update will fail since no real API, but that's OK)
        r.notify_resolved("req-1", true).await;

        assert!(r.pending().lock().unwrap().is_empty());
        // message_ts also cleaned up (update_message_result fails but ts is removed after attempt)
    }
}
