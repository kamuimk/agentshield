use agentshield::{
    logging,
    policy::config::{Action, PolicyConfig},
    web::{self, AppState, integration::IntegrationConfig},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

const ADMIN: &str = "admin-token-0000000000000000000000";
const READER: &str = "reader-token-000000000000000000000";
const CONTROL: &str = "control-token-00000000000000000000";

fn config() -> IntegrationConfig {
    IntegrationConfig {
        allowed_origins: vec!["https://workos.example".into()],
        read_token: READER.into(),
        control_token: Some(CONTROL.into()),
    }
}

fn app() -> axum::Router {
    app_with_read_only(false)
}

fn app_with_read_only(read_only: bool) -> axum::Router {
    let (event_tx, _) = tokio::sync::broadcast::channel(8);
    let state = Arc::new(AppState {
        db: Some(logging::open_memory_pool().unwrap()),
        event_tx,
        policy: Some(Arc::new(RwLock::new(PolicyConfig {
            default: Action::Deny,
            rules: vec![],
        }))),
        auth_token: Some(ADMIN.into()),
    });
    let (ask_event_tx, _) = tokio::sync::broadcast::channel(8);
    let asks = web::ask::AskState {
        pending: Default::default(),
        ask_event_tx,
    };
    if read_only {
        web::integration::read_only_router(state, asks, config()).unwrap()
    } else {
        web::integration::router(state, asks, config()).unwrap()
    }
}

#[tokio::test]
async fn immutable_integration_keeps_observation_but_removes_all_control_credentials() {
    for token in [ADMIN, CONTROL, READER] {
        let app = app_with_read_only(true);
        let request = |method: &str, path: &str, body: Body| {
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(body)
                .unwrap()
        };
        let result = app
            .clone()
            .oneshot(request(
                "PUT",
                "/api/policy",
                Body::from(r#"{"default":"allow","rules":[]}"#),
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        for (method, path) in [("POST", "/api/ask/id/allow"), ("GET", "/api/ask/pending")] {
            assert_eq!(
                app.clone()
                    .oneshot(request(method, path, Body::empty()))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        for path in ["/api/policy", "/api/integration"] {
            let result = app
                .clone()
                .oneshot(request("GET", path, Body::empty()))
                .await
                .unwrap();
            assert_eq!(result.status(), StatusCode::OK);
            let raw = axum::body::to_bytes(result.into_body(), 8192)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            if path == "/api/policy" {
                assert_eq!(value["default"], "deny");
            } else {
                assert_eq!(value["capabilities"], serde_json::json!(["observe"]));
            }
        }
    }
}

async fn send(method: &str, path: &str, token: Option<&str>) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    app()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn reader_can_observe_but_cannot_mutate_or_read_ask_payloads() {
    for path in [
        "/api/status",
        "/api/logs",
        "/api/policy",
        "/api/stats/timeline",
        "/api/integration",
    ] {
        assert_eq!(
            send("GET", path, Some(READER)).await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
    for (method, path) in [
        ("PUT", "/api/policy"),
        ("POST", "/api/ask/id/allow"),
        ("POST", "/api/ask/id/deny"),
        ("GET", "/api/ask/pending"),
        ("GET", "/api/ask/stream"),
    ] {
        assert_eq!(
            send(method, path, Some(READER)).await.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
}

#[tokio::test]
async fn integration_requires_header_credentials_and_reports_capabilities() {
    for token in [None, Some("invalid")] {
        assert_eq!(
            send("GET", "/api/integration", token).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        send("GET", &format!("/api/integration?token={READER}"), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = send("GET", "/api/integration", Some(READER)).await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest["protocol"], "agentshield.dashboard.v1");
    assert_eq!(manifest["capabilities"], serde_json::json!(["observe"]));
    assert!(!String::from_utf8_lossy(&bytes).contains(READER));
}

#[tokio::test]
async fn embed_has_explicit_frame_ancestors_but_standalone_cannot_be_framed() {
    let response = send("GET", "/embed", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-security-policy"],
        "frame-ancestors https://workos.example"
    );
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let response = send("GET", "/", None).await;
    assert_eq!(
        response.headers()["content-security-policy"],
        "frame-ancestors 'none'"
    );
}

#[test]
fn rejects_unsafe_config_without_leaking_credentials() {
    assert!(config().validate("0.0.0.0:18081", Some(ADMIN)).is_err());
    assert!(config().validate("127.0.0.1:18081", None).is_err());
    for origin in [
        "*",
        "null",
        "https://workos.example/path",
        "https://workos.example/",
        "https://workos.example#x",
        "http://remote.example",
        "https://user@workos.example",
        "https://workos.example; frame-ancestors *",
    ] {
        let mut config = config();
        config.allowed_origins = vec![origin.into()];
        assert!(
            config.validate("127.0.0.1:18081", Some(ADMIN)).is_err(),
            "{origin}"
        );
    }
    let mut same = config();
    same.read_token = ADMIN.into();
    assert!(same.validate("127.0.0.1:18081", Some(ADMIN)).is_err());
    assert!(!format!("{:?}", config()).contains(READER));
}
