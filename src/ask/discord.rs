//! Discord Gateway ASK responder with interactive button approval.
//!
//! [`DiscordAskResponder`] sends ASK requests as Discord messages with
//! `Allow` / `Deny` buttons (message components). A background WebSocket
//! loop connects to Discord's Gateway API and receives interaction events
//! when users click buttons.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use super::{AskRequestInfo, AskResponder};

/// A pending ASK request awaiting a Discord interaction response.
pub(crate) struct PendingAsk {
    /// One-shot channel to deliver the decision back to `prompt()`.
    tx: oneshot::Sender<bool>,
}

/// Discord interactive ASK responder using Gateway WebSocket.
pub struct DiscordAskResponder {
    bot_token: String,
    channel_id: String,
    client: reqwest::Client,
    /// Map from `req_id` → pending one-shot sender.
    pending: Arc<Mutex<HashMap<String, PendingAsk>>>,
    /// Map from `req_id` → Discord message ID (for `notify_resolved` edits).
    message_ids: Arc<Mutex<HashMap<String, String>>>,
}

impl DiscordAskResponder {
    /// Create a new Discord ASK responder and start the Gateway WebSocket loop.
    pub fn new(bot_token: String, channel_id: String) -> Self {
        let client = reqwest::Client::new();
        let pending: Arc<Mutex<HashMap<String, PendingAsk>>> = Arc::new(Mutex::new(HashMap::new()));
        let message_ids: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn the background Gateway WebSocket loop
        let ws_token = bot_token.clone();
        let ws_pending = pending.clone();
        let ws_client = client.clone();

        tokio::spawn(async move {
            gateway_loop(&ws_client, &ws_token, &ws_pending).await;
        });

        Self {
            bot_token,
            channel_id,
            client,
            pending,
            message_ids,
        }
    }

    /// Create a responder without starting the WebSocket loop (for testing).
    #[cfg(test)]
    pub fn new_without_ws(bot_token: String, channel_id: String) -> Self {
        Self {
            bot_token,
            channel_id,
            client: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            message_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a reference to the pending map (for testing).
    #[cfg(test)]
    pub(crate) fn pending(&self) -> &Arc<Mutex<HashMap<String, PendingAsk>>> {
        &self.pending
    }

    /// Get a reference to the message_ids map (for testing).
    #[cfg(test)]
    pub(crate) fn message_ids_map(&self) -> &Arc<Mutex<HashMap<String, String>>> {
        &self.message_ids
    }
}

#[async_trait::async_trait]
impl AskResponder for DiscordAskResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        // Send message with buttons via Discord REST API
        let msg_id =
            match send_ask_message(&self.client, &self.bot_token, &self.channel_id, req).await {
                Ok(id) => id,
                Err(e) => {
                    error!("Failed to send Discord ASK message: {}", e);
                    return None;
                }
            };

        info!(
            "Discord ASK sent for {} {} {} (msg_id: {})",
            req.method, req.domain, req.path, msg_id
        );

        // Create one-shot channel and store in pending map
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(req.req_id.clone(), PendingAsk { tx });
        }
        {
            let mut id_map = self.message_ids.lock().unwrap();
            id_map.insert(req.req_id.clone(), msg_id);
        }

        // Wait for interaction response (timeout is handled by AskBroadcaster)
        match rx.await {
            Ok(allowed) => Some(allowed),
            Err(_) => {
                debug!("Discord ASK oneshot dropped for {}", req.req_id);
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
        let msg_id = {
            let id_map = self.message_ids.lock().unwrap();
            id_map.get(req_id).cloned()
        };

        if let Some(mid) = msg_id {
            if let Err(e) = update_message_result(
                &self.client,
                &self.bot_token,
                &self.channel_id,
                &mid,
                allowed,
            )
            .await
            {
                warn!("Failed to update Discord message: {}", e);
            }
            let mut id_map = self.message_ids.lock().unwrap();
            id_map.remove(req_id);
        }
    }

    fn name(&self) -> &str {
        "discord"
    }
}

/// Build Discord message components (buttons) for an ASK message.
pub fn build_ask_components(req: &AskRequestInfo) -> serde_json::Value {
    serde_json::json!([
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 3,
                    "label": "Allow",
                    "custom_id": format!("ask_allow:{}", req.req_id)
                },
                {
                    "type": 2,
                    "style": 4,
                    "label": "Deny",
                    "custom_id": format!("ask_deny:{}", req.req_id)
                }
            ]
        }
    ])
}

/// Build Discord embed for an ASK message.
pub fn build_ask_embed(req: &AskRequestInfo) -> serde_json::Value {
    let mut description = format!(
        "**Domain:** `{}`\n**Method:** `{}`\n**Path:** `{}`",
        req.domain, req.method, req.path
    );
    if let Some(ref body) = req.body {
        let preview = if body.len() > 200 {
            format!("{}...", &body[..200])
        } else {
            body.clone()
        };
        description.push_str(&format!("\n**Body:** `{}`", preview));
    }

    serde_json::json!({
        "title": "AgentShield ASK",
        "description": description,
        "color": 5793266
    })
}

/// Format the fallback content text for the ASK message.
pub fn format_ask_content(req: &AskRequestInfo) -> String {
    format!(
        "AgentShield ASK: {} {} {}",
        req.method, req.domain, req.path
    )
}

/// Send an ASK message with interactive buttons to a Discord channel.
///
/// Returns the message ID on success.
async fn send_ask_message(
    client: &reqwest::Client,
    bot_token: &str,
    channel_id: &str,
    req: &AskRequestInfo,
) -> Result<String, String> {
    let url = format!(
        "https://discord.com/api/v10/channels/{}/messages",
        channel_id
    );
    let content = format_ask_content(req);
    let embeds = vec![build_ask_embed(req)];
    let components = build_ask_components(req);

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bot {}", bot_token))
        .json(&serde_json::json!({
            "content": content,
            "embeds": embeds,
            "components": components,
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
        return Err(format!("Discord API error {}: {}", status, body));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON error: {}", e))?;

    json["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No id in response".to_string())
}

/// Update a Discord message to show the resolution result (removes buttons).
async fn update_message_result(
    client: &reqwest::Client,
    bot_token: &str,
    channel_id: &str,
    message_id: &str,
    allowed: bool,
) -> Result<(), String> {
    let url = format!(
        "https://discord.com/api/v10/channels/{}/messages/{}",
        channel_id, message_id
    );
    let (title, color) = if allowed {
        ("Allowed", 0x57F287u32) // green
    } else {
        ("Denied", 0xED4245u32) // red
    };

    let resp = client
        .patch(&url)
        .header("Authorization", format!("Bot {}", bot_token))
        .json(&serde_json::json!({
            "embeds": [{
                "title": title,
                "description": format!("Request has been **{}** by responder.", title.to_lowercase()),
                "color": color
            }],
            "components": []
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
        return Err(format!("Discord API error {}: {}", status, body));
    }

    Ok(())
}

/// Acknowledge a Discord interaction (required within 3 seconds).
async fn ack_interaction(
    client: &reqwest::Client,
    interaction_id: &str,
    interaction_token: &str,
) -> Result<(), String> {
    let url = format!(
        "https://discord.com/api/v10/interactions/{}/{}/callback",
        interaction_id, interaction_token
    );

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "type": 6
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
        return Err(format!(
            "Discord interaction ACK error {}: {}",
            status, body
        ));
    }

    Ok(())
}

/// Parse a Discord interaction event from a Gateway dispatch.
///
/// Returns `Some((action, req_id, interaction_id, interaction_token))`
/// if this is a valid ASK button click.
pub fn parse_interaction_event(
    event: &serde_json::Value,
) -> Option<(String, String, String, String)> {
    // Gateway dispatch: { "t": "INTERACTION_CREATE", "d": { ... } }
    let d = event.get("d")?;

    // Check it's a message component interaction (type 3)
    let interaction_type = d.get("type")?.as_u64()?;
    if interaction_type != 3 {
        return None;
    }

    let data = d.get("data")?;
    let custom_id = data.get("custom_id")?.as_str()?;
    let interaction_id = d.get("id")?.as_str()?;
    let interaction_token = d.get("token")?.as_str()?;

    // custom_id format: "ask_allow:req_id" or "ask_deny:req_id"
    let (action, req_id) = custom_id.split_once(':')?;

    if action == "ask_allow" || action == "ask_deny" {
        Some((
            action.to_string(),
            req_id.to_string(),
            interaction_id.to_string(),
            interaction_token.to_string(),
        ))
    } else {
        None
    }
}

/// Fetch the Discord Gateway URL dynamically via the Bot API.
///
/// Falls back to the well-known URL if the API call fails.
async fn get_gateway_url(client: &reqwest::Client, bot_token: &str) -> String {
    let fallback = "wss://gateway.discord.gg/?v=10&encoding=json".to_string();

    let resp = client
        .get("https://discord.com/api/v10/gateway/bot")
        .header("Authorization", format!("Bot {}", bot_token))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                if let Some(url) = json["url"].as_str() {
                    return format!("{}/?v=10&encoding=json", url);
                }
            }
            warn!("Discord Gateway API response missing url, using fallback");
            fallback
        }
        Ok(r) => {
            warn!(
                "Discord Gateway API returned {}, using fallback URL",
                r.status()
            );
            fallback
        }
        Err(e) => {
            warn!(
                "Discord Gateway API request failed: {}, using fallback URL",
                e
            );
            fallback
        }
    }
}

/// Background Discord Gateway WebSocket loop.
///
/// Connects to Discord's Gateway, identifies with bot token, receives
/// INTERACTION_CREATE events, and resolves pending ASK requests.
/// Uses `tokio::select!` with a heartbeat timer to keep the connection alive.
/// Auto-reconnects on disconnect.
async fn gateway_loop(
    client: &reqwest::Client,
    bot_token: &str,
    pending: &Arc<Mutex<HashMap<String, PendingAsk>>>,
) {
    loop {
        let gateway_url = get_gateway_url(client, bot_token).await;

        // Connect WebSocket
        let ws_result = tokio_tungstenite::connect_async(&gateway_url).await;
        let (ws, _) = match ws_result {
            Ok(pair) => pair,
            Err(e) => {
                error!("Discord Gateway connection error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("Discord Gateway connected");

        let (mut write, mut read) = ws.split();
        let mut heartbeat_interval_ms: u64 = 41250; // default
        let mut sequence: Option<u64> = None;
        let mut identified = false;
        let mut heartbeat_timer =
            tokio::time::interval(std::time::Duration::from_millis(heartbeat_interval_ms));
        // Don't send heartbeat immediately on first tick
        heartbeat_timer.reset();

        loop {
            tokio::select! {
                msg = read.next() => {
                    let msg = match msg {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            warn!("Discord Gateway read error: {}", e);
                            break;
                        }
                        None => break,
                    };

                    let text = match msg {
                        tokio_tungstenite::tungstenite::Message::Text(t) => t,
                        tokio_tungstenite::tungstenite::Message::Ping(_) => continue,
                        tokio_tungstenite::tungstenite::Message::Close(_) => {
                            info!("Discord Gateway closed, reconnecting...");
                            break;
                        }
                        _ => continue,
                    };

                    let event: serde_json::Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("Discord Gateway non-JSON message: {}", e);
                            continue;
                        }
                    };

                    let op = event.get("op").and_then(|v| v.as_u64()).unwrap_or(0);

                    // Track sequence number
                    if let Some(s) = event.get("s").and_then(|v| v.as_u64()) {
                        sequence = Some(s);
                    }

                    match op {
                        // Opcode 10: Hello — extract heartbeat interval and identify
                        10 => {
                            if let Some(interval) = event
                                .get("d")
                                .and_then(|d| d.get("heartbeat_interval"))
                                .and_then(|v| v.as_u64())
                            {
                                heartbeat_interval_ms = interval;
                                heartbeat_timer = tokio::time::interval(
                                    std::time::Duration::from_millis(heartbeat_interval_ms),
                                );
                                // First tick fires immediately (initial heartbeat)
                            }

                            // Send Identify (opcode 2)
                            if !identified {
                                let identify = serde_json::json!({
                                    "op": 2,
                                    "d": {
                                        "token": bot_token,
                                        "intents": 0,
                                        "properties": {
                                            "os": "linux",
                                            "browser": "agentshield",
                                            "device": "agentshield"
                                        }
                                    }
                                });
                                if let Err(e) = write
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        identify.to_string().into(),
                                    ))
                                    .await
                                {
                                    error!("Failed to send Discord Identify: {}", e);
                                    break;
                                }
                                identified = true;
                            }
                        }

                        // Opcode 11: Heartbeat ACK
                        11 => {
                            debug!("Discord Gateway heartbeat ACK");
                        }

                        // Opcode 1: Server-requested heartbeat
                        1 => {
                            let hb = serde_json::json!({"op": 1, "d": sequence});
                            if let Err(e) = write
                                .send(tokio_tungstenite::tungstenite::Message::Text(
                                    hb.to_string().into(),
                                ))
                                .await
                            {
                                warn!("Failed to send Discord heartbeat: {}", e);
                                break;
                            }
                        }

                        // Opcode 0: Dispatch
                        0 => {
                            let event_type = event.get("t").and_then(|v| v.as_str());

                            if event_type == Some("INTERACTION_CREATE") {
                                if let Some((action, req_id, interaction_id, interaction_token)) =
                                    parse_interaction_event(&event)
                                {
                                    if let Err(e) =
                                        ack_interaction(client, &interaction_id, &interaction_token).await
                                    {
                                        warn!("Failed to ACK Discord interaction: {}", e);
                                    }

                                    let allowed = action == "ask_allow";
                                    info!("Discord interaction: {} req_id={}", action, req_id);

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
                            } else {
                                debug!("Discord dispatch: {:?}", event_type.unwrap_or("unknown"));
                            }
                        }

                        _ => {
                            debug!("Discord Gateway opcode: {}", op);
                        }
                    }
                }

                // Periodic heartbeat (opcode 1) at the interval from Hello
                _ = heartbeat_timer.tick() => {
                    let hb = serde_json::json!({"op": 1, "d": sequence});
                    if let Err(e) = write
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            hb.to_string().into(),
                        ))
                        .await
                    {
                        warn!("Heartbeat send error: {}", e);
                        break;
                    }
                    debug!("Discord Gateway heartbeat sent (seq: {:?})", sequence);
                }
            }
        }

        // Reconnect delay
        warn!("Discord Gateway disconnected, reconnecting in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ask_components_contains_buttons() {
        let req = AskRequestInfo {
            req_id: "test-123".to_string(),
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            body: None,
        };
        let components = build_ask_components(&req);
        let arr = components.as_array().unwrap();
        assert_eq!(arr.len(), 1); // action row

        let row = &arr[0];
        assert_eq!(row["type"], 1); // ACTION_ROW
        let buttons = row["components"].as_array().unwrap();
        assert_eq!(buttons.len(), 2);

        assert_eq!(buttons[0]["type"], 2); // BUTTON
        assert_eq!(buttons[0]["style"], 3); // SUCCESS
        assert_eq!(buttons[0]["label"], "Allow");
        assert_eq!(buttons[0]["custom_id"], "ask_allow:test-123");

        assert_eq!(buttons[1]["type"], 2); // BUTTON
        assert_eq!(buttons[1]["style"], 4); // DANGER
        assert_eq!(buttons[1]["label"], "Deny");
        assert_eq!(buttons[1]["custom_id"], "ask_deny:test-123");
    }

    #[test]
    fn build_ask_embed_basic() {
        let req = AskRequestInfo {
            req_id: "test-456".to_string(),
            domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            body: None,
        };
        let embed = build_ask_embed(&req);
        assert_eq!(embed["title"], "AgentShield ASK");
        let desc = embed["description"].as_str().unwrap();
        assert!(desc.contains("api.anthropic.com"));
        assert!(desc.contains("POST"));
        assert!(desc.contains("/v1/messages"));
    }

    #[test]
    fn build_ask_embed_with_body() {
        let req = AskRequestInfo {
            req_id: "test-789".to_string(),
            domain: "api.example.com".to_string(),
            method: "POST".to_string(),
            path: "/data".to_string(),
            body: Some("hello world".to_string()),
        };
        let embed = build_ask_embed(&req);
        let desc = embed["description"].as_str().unwrap();
        assert!(desc.contains("hello world"));
    }

    #[test]
    fn build_ask_embed_truncates_long_body() {
        let req = AskRequestInfo {
            req_id: "test-abc".to_string(),
            domain: "api.example.com".to_string(),
            method: "POST".to_string(),
            path: "/data".to_string(),
            body: Some("x".repeat(300)),
        };
        let embed = build_ask_embed(&req);
        let desc = embed["description"].as_str().unwrap();
        assert!(desc.contains("..."));
        assert!(desc.len() < 400);
    }

    #[test]
    fn format_ask_content_basic() {
        let req = AskRequestInfo {
            req_id: "r1".to_string(),
            domain: "api.openai.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            body: None,
        };
        let text = format_ask_content(&req);
        assert!(text.contains("POST"));
        assert!(text.contains("api.openai.com"));
        assert!(text.contains("/v1/chat"));
    }

    #[test]
    fn parse_interaction_event_allow() {
        let event = serde_json::json!({
            "op": 0,
            "t": "INTERACTION_CREATE",
            "s": 42,
            "d": {
                "type": 3,
                "id": "interaction-123",
                "token": "inter-token-abc",
                "data": {
                    "custom_id": "ask_allow:req-abc-123"
                }
            }
        });
        let result = parse_interaction_event(&event);
        assert!(result.is_some());
        let (action, req_id, inter_id, inter_token) = result.unwrap();
        assert_eq!(action, "ask_allow");
        assert_eq!(req_id, "req-abc-123");
        assert_eq!(inter_id, "interaction-123");
        assert_eq!(inter_token, "inter-token-abc");
    }

    #[test]
    fn parse_interaction_event_deny() {
        let event = serde_json::json!({
            "op": 0,
            "t": "INTERACTION_CREATE",
            "s": 43,
            "d": {
                "type": 3,
                "id": "interaction-456",
                "token": "inter-token-def",
                "data": {
                    "custom_id": "ask_deny:req-xyz-789"
                }
            }
        });
        let result = parse_interaction_event(&event);
        assert!(result.is_some());
        let (action, req_id, _, _) = result.unwrap();
        assert_eq!(action, "ask_deny");
        assert_eq!(req_id, "req-xyz-789");
    }

    #[test]
    fn parse_interaction_event_wrong_type() {
        let event = serde_json::json!({
            "op": 0,
            "t": "INTERACTION_CREATE",
            "d": {
                "type": 1,
                "id": "123",
                "token": "abc",
                "data": {
                    "custom_id": "ask_allow:req-1"
                }
            }
        });
        assert!(parse_interaction_event(&event).is_none());
    }

    #[test]
    fn parse_interaction_event_unknown_action() {
        let event = serde_json::json!({
            "op": 0,
            "t": "INTERACTION_CREATE",
            "d": {
                "type": 3,
                "id": "123",
                "token": "abc",
                "data": {
                    "custom_id": "other_action:req-1"
                }
            }
        });
        assert!(parse_interaction_event(&event).is_none());
    }

    #[test]
    fn parse_interaction_event_missing_d() {
        let event = serde_json::json!({"op": 0, "t": "INTERACTION_CREATE"});
        assert!(parse_interaction_event(&event).is_none());
    }

    #[test]
    fn responder_name() {
        let r = DiscordAskResponder::new_without_ws("bot-token".to_string(), "123456".to_string());
        assert_eq!(r.name(), "discord");
    }

    #[tokio::test]
    async fn notify_resolved_cleans_up_pending() {
        let r = DiscordAskResponder::new_without_ws("bot-token".to_string(), "123456".to_string());

        // Insert a pending entry
        let (tx, _rx) = oneshot::channel();
        {
            let mut map = r.pending().lock().unwrap();
            map.insert("req-1".to_string(), PendingAsk { tx });
        }
        {
            let mut ids = r.message_ids_map().lock().unwrap();
            ids.insert("req-1".to_string(), "msg-123".to_string());
        }

        // notify_resolved should clean up
        r.notify_resolved("req-1", true).await;

        assert!(r.pending().lock().unwrap().is_empty());
    }
}
