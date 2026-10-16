//! Authenticated dashboard embedding contract for WorkOS and other trusted hosts.

use super::{AppState, ask::AskState};
use axum::{
    Extension, Router,
    body::Body,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Explicit embedding trust and independent bearer credentials.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationConfig {
    /// Exact parent origins; wildcards and paths are rejected.
    pub allowed_origins: Vec<String>,
    /// Credential limited to request metadata, statistics and policy reads.
    pub read_token: String,
    /// Optional credential that also permits policy updates and ASK decisions.
    #[serde(default)]
    pub control_token: Option<String>,
}

impl std::fmt::Debug for IntegrationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationConfig")
            .field("allowed_origins", &self.allowed_origins)
            .field("read_token", &"***")
            .field("control_token", &self.control_token.as_ref().map(|_| "***"))
            .finish()
    }
}

impl IntegrationConfig {
    /// Validate before opening any listeners. Errors never include token values.
    pub fn validate(&self, listen: &str, admin: Option<&str>) -> Result<(), &'static str> {
        if !listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| address.ip().is_loopback())
        {
            return Err("dashboard integration requires a loopback listen address");
        }
        let valid_token = |value: &str| {
            value.len() >= 32
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        let Some(admin) = admin.filter(|value| valid_token(value)) else {
            return Err("dashboard integration requires a strong administrator token");
        };
        if !valid_token(&self.read_token) || super::token_matches(admin, &self.read_token) {
            return Err("integration read token must be strong and distinct");
        }
        if let Some(control) = &self.control_token {
            if !valid_token(control)
                || super::token_matches(admin, control)
                || super::token_matches(&self.read_token, control)
            {
                return Err("integration control token must be strong and distinct");
            }
        }
        if self.allowed_origins.is_empty()
            || self
                .allowed_origins
                .iter()
                .any(|value| !valid_origin(value))
        {
            return Err("integration requires exact trusted HTTPS or local application origins");
        }
        Ok(())
    }
}

fn valid_origin(value: &str) -> bool {
    if value == "tauri://localhost" {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host == "tauri.localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    (url.scheme() == "https" || (url.scheme() == "http" && local))
        && url.username().is_empty()
        && url.password().is_none()
        && url.origin().ascii_serialization() == value
}

/// Request-local authorization context. Embedding does not grant remote service authority.
#[derive(Clone, Copy)]
pub(super) struct Access {
    pub control: bool,
    pub embedded: bool,
}

/// Build the authenticated integration router; the legacy standalone router is unchanged.
pub fn router(
    state: Arc<AppState>,
    asks: AskState,
    config: IntegrationConfig,
) -> Result<Router, &'static str> {
    // Binding is validated against the actual configured listen address by startup too.
    config.validate("127.0.0.1:0", state.auth_token.as_deref())?;
    let admin = state.auth_token.clone().unwrap();
    let protected = super::api_router(state)
        .merge(super::ask::ask_router(asks))
        .route("/api/integration", get(manifest))
        .layer(axum::middleware::from_fn({
            let config = config.clone();
            move |request, next| authenticate(admin.clone(), config.clone(), request, next)
        }));
    let ancestors = format!("frame-ancestors {}", config.allowed_origins.join(" "));
    let embed_config =
        serde_json::to_string(&serde_json::json!({ "origins": config.allowed_origins }))
            .unwrap()
            .replace('<', "\\u003c");
    let html = super::DASHBOARD_HTML.replacen(
        "<script>",
        &format!("<script>window.AGENTSHIELD_EMBED={embed_config};</script><script>"),
        1,
    );
    let public = Router::new()
        .route("/", get(super::dashboard_handler))
        .route(
            "/embed",
            get(move || {
                let html = html.clone();
                let ancestors = ancestors.clone();
                async move {
                    (
                        [(header::CONTENT_SECURITY_POLICY, ancestors)],
                        axum::response::Html(html),
                    )
                        .into_response()
                }
            }),
        );
    Ok(public
        .merge(protected)
        .layer(axum::middleware::from_fn(response_headers)))
}

async fn authenticate(
    admin: String,
    config: IntegrationConfig,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(provided) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let access = if super::token_matches(provided, &admin) {
        Access {
            control: true,
            embedded: false,
        }
    } else if super::token_matches(provided, &config.read_token) {
        Access {
            control: false,
            embedded: true,
        }
    } else if config
        .control_token
        .as_ref()
        .is_some_and(|token| super::token_matches(provided, token))
    {
        Access {
            control: true,
            embedded: true,
        }
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Exact route allowlist: future API endpoints do not silently become available.
    let path = req.uri().path();
    let observe = req.method() == Method::GET
        && matches!(
            path,
            "/api/integration"
                | "/api/status"
                | "/api/logs"
                | "/api/logs/stream"
                | "/api/stats/timeline"
                | "/api/policy"
        );
    let ask = req.method() == Method::GET && matches!(path, "/api/ask/pending" | "/api/ask/stream");
    let resolve = req.method() == Method::POST
        && path.strip_prefix("/api/ask/").is_some_and(|rest| {
            let parts: Vec<_> = rest.split('/').collect();
            parts.len() == 2 && !parts[0].is_empty() && matches!(parts[1], "allow" | "deny")
        });
    let control = ask || resolve || (req.method() == Method::PUT && path == "/api/policy");
    if !observe && !(access.control && control) {
        return StatusCode::FORBIDDEN.into_response();
    }
    req.extensions_mut().insert(access);
    next.run(req).await
}

async fn manifest(Extension(access): Extension<Access>) -> impl IntoResponse {
    let capabilities = if access.control {
        vec!["observe", "policy:write", "ask:resolve"]
    } else {
        vec!["observe"]
    };
    axum::Json(serde_json::json!({
        "protocol": "agentshield.dashboard.v1", "version": env!("CARGO_PKG_VERSION"),
        "dashboard": "/embed", "capabilities": capabilities,
        "protection": { "mode": "proxy", "system_egress_enforced": false },
        "streams": { "logs": "/api/logs/stream", "ask": "/api/ask/stream" }
    }))
}

async fn response_headers(req: Request, next: Next) -> Response<Body> {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert("frame-ancestors 'none'".parse().unwrap());
    response
}
