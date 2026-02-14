//! Web dashboard ASK responder and API endpoints.
//!
//! [`WebDashboardResponder`] implements [`AskResponder`] by storing pending
//! ASK requests in a shared map and exposing them via REST endpoints.
//! The web dashboard polls `GET /api/ask/pending` or subscribes to the
//! `GET /api/ask/stream` SSE endpoint for real-time updates.
//!
//! Endpoints:
//!
//! - `GET  /api/ask/pending`       — list pending ASK requests
//! - `GET  /api/ask/stream`        — SSE stream of ASK events
//! - `POST /api/ask/:id/allow`     — approve a pending request
//! - `POST /api/ask/:id/deny`      — deny a pending request

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use tokio::sync::{broadcast, oneshot};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::ask::{AskRequestInfo, AskResponder};

/// A pending ASK request stored for the web dashboard.
pub struct PendingWebAsk {
    /// Request metadata for display.
    pub info: AskRequestInfo,
    /// One-shot channel to deliver the decision back to the proxy.
    pub tx: oneshot::Sender<bool>,
}

/// Thread-safe map of pending ASK requests keyed by `req_id`.
pub type PendingAsks = Arc<Mutex<HashMap<String, PendingWebAsk>>>;

/// SSE events broadcast to web dashboard subscribers.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum AskSseEvent {
    /// A new ASK request is pending.
    #[serde(rename = "new_ask")]
    NewAsk {
        req_id: String,
        domain: String,
        method: String,
        path: String,
        body: Option<String>,
    },
    /// A pending ASK request has been resolved.
    #[serde(rename = "resolved")]
    Resolved {
        req_id: String,
        allowed: bool,
    },
}

/// Web dashboard ASK responder.
///
/// Stores pending ASK requests in a shared map and broadcasts events via SSE.
/// REST endpoints allow the dashboard to approve or deny requests.
pub struct WebDashboardResponder {
    pending: PendingAsks,
    ask_event_tx: broadcast::Sender<AskSseEvent>,
}

impl WebDashboardResponder {
    /// Create a new web dashboard responder with shared state.
    pub fn new(
        pending: PendingAsks,
        ask_event_tx: broadcast::Sender<AskSseEvent>,
    ) -> Self {
        Self {
            pending,
            ask_event_tx,
        }
    }
}

#[async_trait::async_trait]
impl AskResponder for WebDashboardResponder {
    async fn prompt(&self, req: &AskRequestInfo) -> Option<bool> {
        let (tx, rx) = oneshot::channel();

        // Store the pending request
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(
                req.req_id.clone(),
                PendingWebAsk {
                    info: req.clone(),
                    tx,
                },
            );
        }

        // Broadcast the new ASK event to SSE subscribers
        let _ = self.ask_event_tx.send(AskSseEvent::NewAsk {
            req_id: req.req_id.clone(),
            domain: req.domain.clone(),
            method: req.method.clone(),
            path: req.path.clone(),
            body: req.body.clone(),
        });

        tracing::info!(
            "Web ASK pending: {} {} {} (req_id: {})",
            req.method,
            req.domain,
            req.path,
            req.req_id
        );

        // Wait for the web dashboard to respond
        match rx.await {
            Ok(allowed) => Some(allowed),
            Err(_) => {
                // Sender was dropped (e.g., timeout or cleanup)
                tracing::debug!("Web ASK oneshot dropped for {}", req.req_id);
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

        // Broadcast resolution to SSE subscribers
        let _ = self.ask_event_tx.send(AskSseEvent::Resolved {
            req_id: req_id.to_string(),
            allowed,
        });
    }

    fn name(&self) -> &str {
        "web-dashboard"
    }
}

// ─── API Response Types ─────────────────────────────────────────────────────

/// A pending ASK request returned by the API.
#[derive(Debug, Serialize)]
pub struct PendingAskResponse {
    pub req_id: String,
    pub domain: String,
    pub method: String,
    pub path: String,
    pub body: Option<String>,
}

// ─── Router ─────────────────────────────────────────────────────────────────

/// Shared state for ASK endpoints.
#[derive(Clone)]
pub struct AskState {
    pub pending: PendingAsks,
    pub ask_event_tx: broadcast::Sender<AskSseEvent>,
}

/// Build the ASK sub-router with all ASK-related endpoints.
pub fn ask_router(state: AskState) -> Router {
    Router::new()
        .route("/api/ask/pending", get(get_pending))
        .route("/api/ask/stream", get(get_ask_stream))
        .route("/api/ask/{id}/allow", post(post_allow))
        .route("/api/ask/{id}/deny", post(post_deny))
        .with_state(state)
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// `GET /api/ask/pending` — list all pending ASK requests.
async fn get_pending(State(state): State<AskState>) -> Json<Vec<PendingAskResponse>> {
    let map = state.pending.lock().unwrap();
    let pending: Vec<PendingAskResponse> = map
        .values()
        .map(|pa| PendingAskResponse {
            req_id: pa.info.req_id.clone(),
            domain: pa.info.domain.clone(),
            method: pa.info.method.clone(),
            path: pa.info.path.clone(),
            body: pa.info.body.clone(),
        })
        .collect();
    Json(pending)
}

/// `GET /api/ask/stream` — SSE stream of ASK events.
async fn get_ask_stream(
    State(state): State<AskState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.ask_event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().data(data)))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// `POST /api/ask/:id/allow` — approve a pending ASK request.
async fn post_allow(
    State(state): State<AskState>,
    Path(req_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    resolve_ask(&state, &req_id, true)
}

/// `POST /api/ask/:id/deny` — deny a pending ASK request.
async fn post_deny(
    State(state): State<AskState>,
    Path(req_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    resolve_ask(&state, &req_id, false)
}

/// Resolve a pending ASK request by sending the decision via oneshot.
fn resolve_ask(state: &AskState, req_id: &str, allowed: bool) -> (StatusCode, Json<serde_json::Value>) {
    let pending_ask = {
        let mut map = state.pending.lock().unwrap();
        map.remove(req_id)
    };

    match pending_ask {
        Some(pa) => {
            let _ = pa.tx.send(allowed);
            let action = if allowed { "allowed" } else { "denied" };
            tracing::info!("Web ASK {}: req_id={}", action, req_id);

            // Broadcast resolution
            let _ = state.ask_event_tx.send(AskSseEvent::Resolved {
                req_id: req_id.to_string(),
                allowed,
            });

            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "ok", "action": action})),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no pending ASK with this id"})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    fn test_ask_state() -> AskState {
        let (tx, _rx) = broadcast::channel(16);
        AskState {
            pending: Arc::new(Mutex::new(HashMap::new())),
            ask_event_tx: tx,
        }
    }

    async fn json_response(app: Router, method: &str, uri: &str) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.into_service().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn get_pending_empty() {
        let state = test_ask_state();
        let app = ask_router(state);
        let (status, json) = json_response(app, "GET", "/api/ask/pending").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_pending_with_entries() {
        let state = test_ask_state();
        let (tx, _rx) = oneshot::channel();
        {
            let mut map = state.pending.lock().unwrap();
            map.insert(
                "req-1".to_string(),
                PendingWebAsk {
                    info: AskRequestInfo {
                        req_id: "req-1".to_string(),
                        domain: "example.com".to_string(),
                        method: "GET".to_string(),
                        path: "/api".to_string(),
                        body: None,
                    },
                    tx,
                },
            );
        }

        let app = ask_router(state);
        let (status, json) = json_response(app, "GET", "/api/ask/pending").await;
        assert_eq!(status, StatusCode::OK);
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["req_id"], "req-1");
        assert_eq!(arr[0]["domain"], "example.com");
    }

    #[tokio::test]
    async fn post_allow_resolves_pending() {
        let state = test_ask_state();
        let (tx, rx) = oneshot::channel();
        {
            let mut map = state.pending.lock().unwrap();
            map.insert(
                "req-allow".to_string(),
                PendingWebAsk {
                    info: AskRequestInfo {
                        req_id: "req-allow".to_string(),
                        domain: "test.com".to_string(),
                        method: "POST".to_string(),
                        path: "/data".to_string(),
                        body: None,
                    },
                    tx,
                },
            );
        }

        let app = ask_router(state.clone());
        let (status, json) = json_response(app, "POST", "/api/ask/req-allow/allow").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["action"], "allowed");

        // oneshot should have received true
        assert_eq!(rx.await.unwrap(), true);
        // pending map should be empty
        assert!(state.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn post_deny_resolves_pending() {
        let state = test_ask_state();
        let (tx, rx) = oneshot::channel();
        {
            let mut map = state.pending.lock().unwrap();
            map.insert(
                "req-deny".to_string(),
                PendingWebAsk {
                    info: AskRequestInfo {
                        req_id: "req-deny".to_string(),
                        domain: "test.com".to_string(),
                        method: "DELETE".to_string(),
                        path: "/resource".to_string(),
                        body: None,
                    },
                    tx,
                },
            );
        }

        let app = ask_router(state.clone());
        let (status, json) = json_response(app, "POST", "/api/ask/req-deny/deny").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["action"], "denied");

        assert_eq!(rx.await.unwrap(), false);
    }

    #[tokio::test]
    async fn post_allow_not_found() {
        let state = test_ask_state();
        let app = ask_router(state);
        let (status, json) = json_response(app, "POST", "/api/ask/nonexistent/allow").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().unwrap().contains("no pending"));
    }

    #[tokio::test]
    async fn post_deny_not_found() {
        let state = test_ask_state();
        let app = ask_router(state);
        let (status, _json) = json_response(app, "POST", "/api/ask/nonexistent/deny").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn prompt_stores_in_pending_map() {
        let (tx, _rx) = broadcast::channel(16);
        let pending: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
        let responder = WebDashboardResponder::new(pending.clone(), tx);

        let req = AskRequestInfo {
            req_id: "test-prompt".to_string(),
            domain: "prompt.com".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            body: None,
        };

        // Spawn prompt in background (it will wait on oneshot)
        let handle = tokio::spawn({
            let req = req.clone();
            async move { responder.prompt(&req).await }
        });

        // Give it a moment to store the pending
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify it's in the pending map
        {
            let map = pending.lock().unwrap();
            assert!(map.contains_key("test-prompt"));
            assert_eq!(map["test-prompt"].info.domain, "prompt.com");
        }

        // Resolve it by removing and sending
        {
            let mut map = pending.lock().unwrap();
            let pa = map.remove("test-prompt").unwrap();
            let _ = pa.tx.send(true);
        }

        let result = handle.await.unwrap();
        assert_eq!(result, Some(true));
    }

    #[tokio::test]
    async fn notify_resolved_removes_from_pending() {
        let (tx, _rx) = broadcast::channel(16);
        let pending: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
        let responder = WebDashboardResponder::new(pending.clone(), tx.clone());

        // Add a pending entry
        let (ask_tx, _ask_rx) = oneshot::channel();
        {
            let mut map = pending.lock().unwrap();
            map.insert(
                "cleanup-test".to_string(),
                PendingWebAsk {
                    info: AskRequestInfo {
                        req_id: "cleanup-test".to_string(),
                        domain: "cleanup.com".to_string(),
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        body: None,
                    },
                    tx: ask_tx,
                },
            );
        }

        responder.notify_resolved("cleanup-test", true).await;
        assert!(!pending.lock().unwrap().contains_key("cleanup-test"));
    }

    #[tokio::test]
    async fn notify_resolved_broadcasts_sse_event() {
        let (tx, mut rx) = broadcast::channel(16);
        let pending: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
        let responder = WebDashboardResponder::new(pending, tx);

        responder.notify_resolved("sse-test", false).await;

        let event = rx.try_recv().unwrap();
        match event {
            AskSseEvent::Resolved { req_id, allowed } => {
                assert_eq!(req_id, "sse-test");
                assert!(!allowed);
            }
            _ => panic!("expected Resolved event"),
        }
    }

    #[test]
    fn responder_name() {
        let (tx, _rx) = broadcast::channel(16);
        let pending: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
        let responder = WebDashboardResponder::new(pending, tx);
        assert_eq!(responder.name(), "web-dashboard");
    }

    #[tokio::test]
    async fn prompt_broadcasts_new_ask_sse_event() {
        let (tx, mut rx) = broadcast::channel(16);
        let pending: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
        let responder = WebDashboardResponder::new(pending.clone(), tx);

        let req = AskRequestInfo {
            req_id: "sse-new".to_string(),
            domain: "sse.com".to_string(),
            method: "POST".to_string(),
            path: "/hook".to_string(),
            body: Some("payload".to_string()),
        };

        // Spawn prompt
        tokio::spawn({
            let req = req.clone();
            async move { responder.prompt(&req).await }
        });

        // Should receive a NewAsk SSE event
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            rx.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        match event {
            AskSseEvent::NewAsk { req_id, domain, method, path, body } => {
                assert_eq!(req_id, "sse-new");
                assert_eq!(domain, "sse.com");
                assert_eq!(method, "POST");
                assert_eq!(path, "/hook");
                assert_eq!(body, Some("payload".to_string()));
            }
            _ => panic!("expected NewAsk event"),
        }

        // Clean up by resolving the pending ask
        {
            let mut map = pending.lock().unwrap();
            if let Some(pa) = map.remove("sse-new") {
                let _ = pa.tx.send(false);
            }
        }
    }
}
