//! Web dashboard backend for AgentShield.
//!
//! Provides a JSON API and SSE log stream for the web dashboard.
//! The server binds to `127.0.0.1:18081` by default and exposes:
//!
//! - `GET  /api/logs`        — recent request log entries
//! - `GET  /api/logs/stream` — real-time SSE log event stream
//! - `GET  /api/status`      — aggregated request statistics
//! - `GET  /api/policy`      — current policy configuration
//! - `PUT  /api/policy`      — replace policy configuration

pub mod ask;

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::logging::{self, DbPool, LogEvent, RequestStats};
use crate::policy::config::PolicyConfig;

/// Shared application state for all web handlers.
#[derive(Clone)]
pub struct AppState {
    /// SQLite connection pool for reading logs.
    pub db: Option<DbPool>,
    /// Broadcast sender for subscribing to real-time log events.
    pub event_tx: broadcast::Sender<LogEvent>,
    /// Shared policy configuration (hot-reloadable).
    pub policy: Option<Arc<RwLock<PolicyConfig>>>,
}

/// Build the axum router with all API endpoints and embedded dashboard.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/logs", get(get_logs))
        .route("/api/logs/stream", get(get_logs_stream))
        .route("/api/status", get(get_status))
        .route("/api/policy", get(get_policy).put(put_policy))
        .with_state(state)
}

/// Build the full router including ASK endpoints.
pub fn full_router(state: Arc<AppState>, ask_state: ask::AskState) -> Router {
    let api_router = router(state);
    let ask_router = ask::ask_router(ask_state);
    api_router.merge(ask_router)
}

/// Embedded dashboard HTML (compiled into the binary).
const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

/// `GET /` — serve the embedded SPA dashboard.
async fn dashboard_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(DASHBOARD_HTML)
}

/// Start the web server on the given address.
pub async fn start(listen_addr: &str, state: Arc<AppState>) -> crate::error::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("Web dashboard listening on {}", listen_addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::AgentShieldError::Proxy(e.to_string()))?;
    Ok(())
}

// ─── Query Parameters ───────────────────────────────────────────────────────

/// Query parameters for `GET /api/logs`.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Maximum number of log entries to return (default: 50).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

// ─── Response Types ─────────────────────────────────────────────────────────

/// A single log entry returned by the API.
#[derive(Debug, Serialize)]
pub struct LogEntryResponse {
    pub id: Option<i64>,
    pub timestamp: String,
    pub method: String,
    pub domain: String,
    pub path: String,
    pub action: String,
    pub reason: String,
}

/// Aggregated status response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub total: usize,
    pub allowed: usize,
    pub denied: usize,
    pub asked: usize,
    pub system_allowed: usize,
}

impl From<RequestStats> for StatusResponse {
    fn from(s: RequestStats) -> Self {
        Self {
            total: s.total,
            allowed: s.allowed,
            denied: s.denied,
            asked: s.asked,
            system_allowed: s.system_allowed,
        }
    }
}

// ─── Handlers ───────────────────────────────────────────────────────────────

/// `GET /api/logs` — return recent log entries as JSON.
async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsQuery>,
) -> impl IntoResponse {
    let Some(ref pool) = state.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "no database"})),
        )
            .into_response();
    };

    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    match logging::query_recent(&conn, params.limit) {
        Ok(logs) => {
            let entries: Vec<LogEntryResponse> = logs
                .into_iter()
                .map(|l| LogEntryResponse {
                    id: l.id,
                    timestamp: l.timestamp,
                    method: l.method,
                    domain: l.domain,
                    path: l.path,
                    action: l.action,
                    reason: l.reason,
                })
                .collect();
            Json(entries).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/logs/stream` — SSE stream of real-time log events.
async fn get_logs_stream(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::json!({
                "timestamp": event.timestamp,
                "method": event.method,
                "domain": event.domain,
                "path": event.path,
                "action": event.action,
                "reason": event.reason,
            });
            Some(Ok(Event::default().data(data.to_string())))
        }
        Err(_) => None, // lagged receiver — skip
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// `GET /api/status` — aggregated request statistics.
async fn get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref pool) = state.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "no database"})),
        )
            .into_response();
    };

    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    match logging::query_stats(&conn) {
        Ok(stats) => Json(StatusResponse::from(stats)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/policy` — current policy configuration as JSON.
async fn get_policy(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref policy_lock) = state.policy else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "no policy loaded"})),
        )
            .into_response();
    };

    let policy = policy_lock.read().unwrap();
    Json(serde_json::to_value(&*policy).unwrap()).into_response()
}

/// `PUT /api/policy` — replace the policy configuration.
async fn put_policy(
    State(state): State<Arc<AppState>>,
    Json(new_policy): Json<PolicyConfig>,
) -> impl IntoResponse {
    let Some(ref policy_lock) = state.policy else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "no policy loaded"})),
        )
            .into_response();
    };

    let mut policy = policy_lock.write().unwrap();
    let rule_count = new_policy.rules.len();
    *policy = new_policy;
    tracing::info!("Policy updated via API ({} rules)", rule_count);

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "rules": rule_count})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging;
    use crate::policy::config::{Action, Rule};
    use axum::body::Body;
    use axum::http::Request;

    fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let pool = logging::open_pool(&db_path).unwrap();
        let (tx, _rx) = broadcast::channel(16);
        let policy = PolicyConfig {
            default: Action::Deny,
            rules: vec![Rule {
                name: "test".to_string(),
                domains: vec!["example.com".to_string()],
                methods: None,
                action: Action::Allow,
                note: None,
            }],
        };

        (
            Arc::new(AppState {
                db: Some(pool),
                event_tx: tx,
                policy: Some(Arc::new(RwLock::new(policy))),
            }),
            dir,
        )
    }

    /// Send a GET request to the router and parse the JSON response body.
    async fn response_json(app: Router, uri: &str) -> serde_json::Value {
        use tower::ServiceExt as _;
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.into_service().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn get_logs_returns_empty_array() {
        let (state, _dir) = test_state();
        let app = router(state);
        let json = response_json(app, "/api/logs").await;
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_logs_returns_entries() {
        let (state, _dir) = test_state();
        // Insert a log entry
        let conn = state.db.as_ref().unwrap().get().unwrap();
        logging::log_request(
            &conn,
            &logging::RequestLog {
                id: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                method: "GET".to_string(),
                domain: "test.com".to_string(),
                path: "/api".to_string(),
                action: "allow".to_string(),
                reason: "test".to_string(),
            },
        )
        .unwrap();

        let app = router(state);
        let json = response_json(app, "/api/logs").await;
        let logs = json.as_array().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["domain"], "test.com");
        assert_eq!(logs[0]["action"], "allow");
    }

    #[tokio::test]
    async fn get_logs_respects_limit() {
        let (state, _dir) = test_state();
        let conn = state.db.as_ref().unwrap().get().unwrap();
        for i in 0..10 {
            logging::log_request(
                &conn,
                &logging::RequestLog {
                    id: None,
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    method: "GET".to_string(),
                    domain: format!("host{}.com", i),
                    path: "/".to_string(),
                    action: "allow".to_string(),
                    reason: "test".to_string(),
                },
            )
            .unwrap();
        }

        let app = router(state);
        let json = response_json(app, "/api/logs?limit=3").await;
        assert_eq!(json.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn get_status_returns_stats() {
        let (state, _dir) = test_state();
        let conn = state.db.as_ref().unwrap().get().unwrap();
        logging::log_request(
            &conn,
            &logging::RequestLog {
                id: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                method: "GET".to_string(),
                domain: "a.com".to_string(),
                path: "/".to_string(),
                action: "allow".to_string(),
                reason: "test".to_string(),
            },
        )
        .unwrap();
        logging::log_request(
            &conn,
            &logging::RequestLog {
                id: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                method: "POST".to_string(),
                domain: "b.com".to_string(),
                path: "/".to_string(),
                action: "deny".to_string(),
                reason: "blocked".to_string(),
            },
        )
        .unwrap();

        let app = router(state);
        let json = response_json(app, "/api/status").await;
        assert_eq!(json["total"], 2);
        assert_eq!(json["allowed"], 1);
        assert_eq!(json["denied"], 1);
    }

    #[tokio::test]
    async fn get_policy_returns_config() {
        let (state, _dir) = test_state();
        let app = router(state);
        let json = response_json(app, "/api/policy").await;
        assert_eq!(json["default"], "deny");
        assert_eq!(json["rules"][0]["domains"][0], "example.com");
    }

    #[tokio::test]
    async fn put_policy_updates_config() {
        let (state, _dir) = test_state();
        let app = router(state.clone());

        let new_policy = serde_json::json!({
            "default": "allow",
            "rules": [
                {
                    "name": "new-rule",
                    "domains": ["new.com"],
                    "action": "deny"
                }
            ]
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/policy")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&new_policy).unwrap()))
            .unwrap();

        let resp = {
            use tower::ServiceExt as _;
            app.into_service().oneshot(req).await.unwrap()
        };
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify policy was updated
        let policy = state.policy.as_ref().unwrap().read().unwrap();
        assert_eq!(policy.default, Action::Allow);
        assert_eq!(policy.rules[0].name, "new-rule");
    }

    #[tokio::test]
    async fn get_status_empty_db() {
        let (state, _dir) = test_state();
        let app = router(state);
        let json = response_json(app, "/api/status").await;
        assert_eq!(json["total"], 0);
    }

    #[tokio::test]
    async fn get_logs_no_db_returns_503() {
        let (tx, _rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            db: None,
            event_tx: tx,
            policy: None,
        });
        let app = router(state);

        let req = Request::builder()
            .uri("/api/logs")
            .body(Body::empty())
            .unwrap();
        let resp = {
            use tower::ServiceExt as _;
            app.into_service().oneshot(req).await.unwrap()
        };
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn get_policy_no_policy_returns_503() {
        let (tx, _rx) = broadcast::channel(16);
        let state = Arc::new(AppState {
            db: None,
            event_tx: tx,
            policy: None,
        });
        let app = router(state);

        let req = Request::builder()
            .uri("/api/policy")
            .body(Body::empty())
            .unwrap();
        let resp = {
            use tower::ServiceExt as _;
            app.into_service().oneshot(req).await.unwrap()
        };
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn dashboard_returns_html() {
        let (state, _dir) = test_state();
        let app = router(state);

        use tower::ServiceExt as _;
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app.into_service().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("AgentShield Dashboard"));
        assert!(html.contains("tailwindcss"));
    }
}
