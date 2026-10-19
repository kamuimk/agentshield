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
    channel: String,
    message_ts: String,
    expires: std::time::Instant,
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
    pub fn new(
        bot_token: String,
        app_token: String,
        channel: String,
        approver_user: String,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("HTTP client");
        let pending: Arc<Mutex<HashMap<String, PendingAsk>>> = Arc::new(Mutex::new(HashMap::new()));
        let message_ts: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the background Socket Mode WebSocket loop
        let ws_client = client.clone();
        let ws_app_token = app_token;
        let ws_pending = pending.clone();

        tokio::spawn(async move {
            socket_mode_loop(&ws_client, &ws_app_token, &ws_pending, &approver_user).await;
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
            req.method, req.domain, "[path omitted]", ts
        );

        // Create one-shot channel and store in pending map
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(
                req.req_id.clone(),
                PendingAsk {
                    tx,
                    channel: self.channel.clone(),
                    message_ts: ts.clone(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(120),
                },
            );
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
    use sha2::{Digest, Sha256};
    // Never send URL paths, queries, account values, or payload previews to Slack.
    // A digest distinguishes held requests without disclosing their contents.
    let mut digest = Sha256::new();
    for field in [&req.domain, &req.method, &req.path] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    if let Some(body) = &req.body {
        digest.update(body.as_bytes());
    }
    let mut text = format!(
        "AgentShield: approve this request once?\nDestination: {}\nMethod: {}\nRequest digest: {:x}\nPayload and URL path omitted. Expires within 120 seconds.",
        req.domain,
        req.method,
        digest.finalize()
    );

    if let Some(metadata) = &req.approval {
        text.push_str(&format!(
            "\nSensitive categories: {}\nHeld request bytes: {}\nHeld request SHA256: {}",
            metadata.categories.join(", "),
            metadata.request_bytes,
            metadata.request_sha256
        ));
    }

    serde_json::json!([
        {
            "type": "section",
            "text": {
                "type": "plain_text",
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
        "AgentShield ASK: {} {} (payload and path omitted)",
        req.method, req.domain
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

fn authorized_interaction(
    envelope: &serde_json::Value,
    approver: &str,
    pending: &PendingAsk,
) -> bool {
    let payload = &envelope["payload"];
    !approver.is_empty()
        && pending.channel.starts_with('D')
        && std::time::Instant::now() < pending.expires
        && payload["user"]["id"].as_str() == Some(approver)
        && payload["channel"]["id"].as_str() == Some(pending.channel.as_str())
        && payload["container"]["message_ts"].as_str() == Some(pending.message_ts.as_str())
        && payload["type"].as_str() == Some("block_actions")
        && payload["actions"]
            .as_array()
            .is_some_and(|actions| actions.len() == 1)
}

/// Background Socket Mode WebSocket loop.
///
/// Connects to Slack via Socket Mode, receives interaction events,
/// and resolves pending ASK requests. Auto-reconnects on disconnect.
async fn socket_mode_loop(
    client: &reqwest::Client,
    app_token: &str,
    pending: &Arc<Mutex<HashMap<String, PendingAsk>>>,
    approver_user: &str,
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
                    let valid = map.get(&req_id).is_some_and(|entry| {
                        authorized_interaction(&envelope, approver_user, entry)
                    });
                    if valid { map.remove(&req_id) } else { None }
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
    fn interactions_are_owner_message_and_expiry_bound() {
        let (tx, _) = oneshot::channel();
        let mut pending = PendingAsk {
            tx,
            channel: "DTEST".into(),
            message_ts: "1.2".into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(60),
        };
        let valid = serde_json::json!({"payload":{"type":"block_actions","user":{"id":"UOWNER"},"channel":{"id":"DTEST"},"container":{"message_ts":"1.2"},"actions":[{"action_id":"ask_allow","value":"request"}]}});
        assert!(authorized_interaction(&valid, "UOWNER", &pending));
        assert!(!authorized_interaction(&valid, "UOTHER", &pending));
        let mut wrong = valid.clone();
        wrong["payload"]["channel"]["id"] = "DOTHER".into();
        assert!(!authorized_interaction(&wrong, "UOWNER", &pending));
        wrong = valid.clone();
        wrong["payload"]["container"]["message_ts"] = "other".into();
        assert!(!authorized_interaction(&wrong, "UOWNER", &pending));
        pending.expires = std::time::Instant::now();
        assert!(!authorized_interaction(&valid, "UOWNER", &pending));
    }

    #[test]
    fn build_ask_blocks_contains_buttons() {
        let req = AskRequestInfo {
            req_id: "test-123".to_string(),
            approval: None,

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
            approval: None,

            domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            body: Some("hello world".to_string()),
        };
        let blocks = build_ask_blocks(&req);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(!text.contains("hello world"));
        assert!(text.contains("Request digest"));
    }

    #[test]
    fn build_ask_blocks_truncates_long_body() {
        let req = AskRequestInfo {
            req_id: "test-789".to_string(),
            approval: None,

            domain: "api.example.com".to_string(),
            method: "POST".to_string(),
            path: "/data".to_string(),
            body: Some("x".repeat(300)),
        };
        let blocks = build_ask_blocks(&req);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(!text.contains(&"x".repeat(200)));
        // Should not contain the full 300 chars
        assert!(text.len() < 400);
    }

    #[test]
    fn format_ask_text_basic() {
        let req = AskRequestInfo {
            req_id: "r1".to_string(),
            approval: None,

            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            body: None,
        };
        let text = format_ask_text(&req);
        assert!(text.contains("POST"));
        assert!(text.contains("api.openai.com"));
        assert!(!text.contains("/v1/chat"));
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
            map.insert(
                "req-1".to_string(),
                PendingAsk {
                    tx,
                    channel: "DTEST".into(),
                    message_ts: "1234.5678".into(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(120),
                },
            );
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
