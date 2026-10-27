//! Connection handling for the proxy server.
//!
//! This module implements the core request processing pipeline:
//!
//! 1. **Accept** incoming TCP connections ([`accept_loop`])
//! 2. **Parse** the first line to distinguish `CONNECT` (HTTPS) from plain HTTP
//! 3. **Validate** the target domain against injection attacks
//! 4. **Check system allowlist** — bypass policy for pre-approved domains
//! 5. **Evaluate policy** — allow, deny, or prompt the user (ASK)
//! 6. **DLP scan** — inspect request bodies for secrets/PII (HTTP only)
//! 7. **Forward** the request to the upstream server
//! 8. **Log** the decision to SQLite and optionally send notifications

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use tokio::sync::broadcast;

use crate::ask::AskBroadcaster;
use crate::dlp::{DlpScanner, Severity};
use crate::logging;
use crate::logging::{DbPool, LogEvent};
use crate::notification::{NotificationEvent, Notifier};
use crate::policy::config::{Action, LoggingConfig, PolicyConfig};
use crate::policy::evaluator::{self, RequestInfo, domain_matches};
use crate::proxy::tls::CertCache;
use crate::ratelimit::RateLimiter;
use std::sync::{Arc, RwLock};

/// Shared context for all connection handlers, consolidating the various
/// optional components that each handler needs access to.
///
/// Created once in [`ProxyServer::start()`](super::ProxyServer::start) and
/// shared via `Arc` across all spawned connection tasks.
#[derive(Clone)]
pub struct ConnectionContext {
    /// Policy configuration for request evaluation (hot-reloadable via `RwLock`).
    pub policy: Option<Arc<RwLock<PolicyConfig>>>,
    /// SQLite connection pool for request logging.
    pub db: Option<DbPool>,
    /// Broadcaster for ASK prompts to all registered responders.
    pub ask_broadcaster: Option<Arc<AskBroadcaster>>,
    /// Dedicated Slack-only approval for sensitive request bytes.
    pub sensitive_approval: Option<Arc<AskBroadcaster>>,
    pub host_authenticator: Option<Arc<dyn super::host_authentication::HostAuthenticator>>,
    /// DLP scanner for inspecting HTTP request bodies.
    pub dlp_scanner: Option<Arc<dyn DlpScanner>>,
    /// Domains that bypass policy and DLP evaluation.
    pub system_allowlist: Option<Arc<Vec<String>>>,
    /// Notification backend for deny/DLP alerts.
    pub notifier: Option<Arc<dyn Notifier>>,
    /// Broadcast channel for real-time log events (web dashboard SSE, etc.).
    pub event_tx: Option<broadcast::Sender<LogEvent>>,
    /// Rate limiter for domain-based request throttling.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Whether MITM TLS interception is enabled.
    pub mitm_enabled: bool,
    /// Certificate cache for MITM TLS interception.
    pub cert_cache: Option<Arc<CertCache>>,
    /// Shared TLS client config for upstream MITM connections (cached once).
    pub upstream_tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Audit logging configuration.
    pub logging_config: Option<LoggingConfig>,
    /// Destination constraints, enforced even for system allowlist entries.
    pub network: super::network::NetworkConfig,
}

/// Main accept loop: accept incoming connections and handle them.
///
/// Listens for incoming connections until a shutdown signal is received.
/// When `shutdown_rx` fires, stops accepting new connections. Existing
/// connections continue until they complete naturally (draining is handled
/// by the caller via the returned `JoinHandle`).
pub async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<ConnectionContext>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    accept_loop_with_proof(listener, ctx, shutdown_rx, None).await;
}

pub(super) async fn accept_loop_with_proof(
    listener: TcpListener,
    ctx: Arc<ConnectionContext>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    proof: Option<Arc<super::listener_proof::ListenerProof>>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        info!("New connection from {}", peer_addr);
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
                        let ctx = ctx.clone();
                        let proof = proof.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if handle_connection(stream, &ctx, proof.as_deref()).await.is_err() {
                                error!("Error handling connection from (request details withheld)");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Accept loop shutting down (no new connections)");
                    break;
                }
            }
        }
    }
}

/// Log a request to the database if a DB pool is available.
fn log_to_db(
    ctx: &ConnectionContext,
    method: &str,
    domain: &str,
    path: &str,
    action: &str,
    reason: &str,
) {
    log_to_db_with_audit(ctx, method, domain, path, action, reason, None, None);
}

#[allow(clippy::too_many_arguments)]
fn log_to_db_with_audit(
    ctx: &ConnectionContext,
    method: &str,
    domain: &str,
    path: &str,
    action: &str,
    reason: &str,
    request_body: Option<&str>,
    dlp_findings: Option<&str>,
) {
    let domain = if ctx
        .dlp_scanner
        .as_ref()
        .is_some_and(|scanner| !scanner.scan(domain.as_bytes()).is_empty())
    {
        "redacted.invalid"
    } else {
        domain
    };
    let path = path.split('?').next().unwrap_or("/");
    let path = if ctx
        .dlp_scanner
        .as_ref()
        .is_some_and(|scanner| !scanner.scan(path.as_bytes()).is_empty())
    {
        "[PATH REDACTED]"
    } else {
        path
    };
    let reason = if ctx
        .dlp_scanner
        .as_ref()
        .is_some_and(|scanner| !scanner.scan(reason.as_bytes()).is_empty())
    {
        "[REASON REDACTED]"
    } else {
        reason
    };
    let timestamp = chrono::Utc::now().to_rfc3339();

    if let Some(ref pool) = ctx.db {
        match pool.get() {
            Ok(conn) => {
                let log = logging::RequestLog {
                    id: None,
                    timestamp: timestamp.clone(),
                    method: method.to_string(),
                    domain: domain.to_string(),
                    path: path.to_string(),
                    action: action.to_string(),
                    reason: reason.to_string(),
                    request_body: request_body.map(|s| s.to_string()),
                    dlp_findings: dlp_findings.map(|s| s.to_string()),
                };
                if let Err(e) = logging::log_request(&conn, &log) {
                    warn!("Failed to log request to DB: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to get DB connection from pool: {}", e);
            }
        }
    }

    // Broadcast log event for real-time subscribers (SSE, etc.)
    if let Some(ref tx) = ctx.event_tx {
        let _ = tx.send(LogEvent {
            timestamp,
            method: method.to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            action: action.to_string(),
            reason: reason.to_string(),
        });
    }
}

/// Check whether the given action should be audit-logged based on LoggingConfig.
fn should_audit(config: Option<&LoggingConfig>, action: &str) -> bool {
    let Some(cfg) = config else { return false };
    if !cfg.audit {
        return false;
    }
    // Empty audit_actions = audit all actions
    if cfg.audit_actions.is_empty() {
        return true;
    }
    cfg.audit_actions.iter().any(|a| a == action)
}

/// Format DLP findings as a JSON string for storage.
fn format_dlp_findings(findings: &[crate::dlp::DlpFinding]) -> String {
    let entries: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "pattern": f.pattern_name,
                "severity": format!("{:?}", f.severity),
                "matched": f.matched_text,
            })
        })
        .collect();
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

/// Log with optional audit body capture. Checks should_audit and truncates body.
#[allow(clippy::too_many_arguments)]
fn log_to_db_audited(
    ctx: &ConnectionContext,
    method: &str,
    domain: &str,
    path: &str,
    action: &str,
    reason: &str,
    body: Option<&[u8]>,
    dlp_findings: Option<&str>,
) {
    if should_audit(ctx.logging_config.as_ref(), action) {
        let max_size = ctx
            .logging_config
            .as_ref()
            .map(|c| c.audit_max_body_size)
            .unwrap_or(65536);
        let redact_dlp = ctx
            .logging_config
            .as_ref()
            .map(|c| c.audit_redact_dlp)
            .unwrap_or(true);
        // Redact body when DLP findings are present and redaction is enabled
        let sensitive_approval_body = ctx.sensitive_approval.is_some()
            && body.is_some_and(|bytes| {
                ctx.dlp_scanner
                    .as_ref()
                    .is_some_and(|scanner| !scanner.scan(bytes).is_empty())
            });
        let truncated_body = if (redact_dlp && dlp_findings.is_some()) || sensitive_approval_body {
            Some("[BODY REDACTED: DLP sensitive data detected]".to_string())
        } else {
            body.and_then(|b| {
                let slice = &b[..b.len().min(max_size)];
                String::from_utf8(slice.to_vec()).ok()
            })
        };
        log_to_db_with_audit(
            ctx,
            method,
            domain,
            path,
            action,
            reason,
            truncated_body.as_deref(),
            dlp_findings,
        );
    } else {
        log_to_db(ctx, method, domain, path, action, reason);
    }
}

/// Fire-and-forget notification: spawn a task that won't block the proxy.
fn notify_event(ctx: &ConnectionContext, mut event: NotificationEvent) {
    // Remote notifications must never copy request paths or query credentials.
    match &mut event {
        NotificationEvent::RequestDenied { path, reason, .. } => {
            *path = "[path withheld]".into();
            *reason = "[policy details withheld]".into();
        }
        NotificationEvent::AskPending { path, .. } => {
            *path = "[path withheld]".into();
        }
        _ => {}
    }
    let destination = match &mut event {
        NotificationEvent::RequestDenied { domain, .. }
        | NotificationEvent::AskPending { domain, .. }
        | NotificationEvent::DlpFinding { domain, .. }
        | NotificationEvent::RateLimited { domain, .. } => Some(domain),
        _ => None,
    };
    if let Some(domain) = destination {
        if ctx
            .dlp_scanner
            .as_ref()
            .is_some_and(|scanner| !scanner.scan(domain.as_bytes()).is_empty())
        {
            *domain = "redacted.invalid".into();
        }
    }
    if let Some(ref n) = ctx.notifier {
        let n = n.clone();
        tokio::spawn(async move {
            if let Err(e) = n.notify(&event).await {
                warn!("notification failed: {}", e);
            }
        });
    }
}

/// Handle a single client connection by reading the first request line and
/// dispatching to [`handle_connect`] (HTTPS) or [`handle_http_request`] (HTTP).
async fn handle_connection(
    mut client: TcpStream,
    ctx: &ConnectionContext,
    proof: Option<&super::listener_proof::ListenerProof>,
) -> crate::error::Result<()> {
    let request = match super::http::read_request(&mut client).await {
        Ok(request) => request,
        Err(rejection) => {
            reject_request(&mut client, ctx, rejection.status, rejection.reason).await?;
            return Ok(());
        }
    };
    if let Some(proof) = proof {
        if let Some(response) = proof.response(&request, client.local_addr()?) {
            client.write_all(&response).await?;
            return Ok(());
        }
    }
    // Only parse the validated header line; bodies may be arbitrary binary.
    let line_end = request.windows(2).position(|w| w == b"\r\n").unwrap();
    let first_line = std::str::from_utf8(&request[..line_end]).unwrap();
    if first_line.starts_with("CONNECT ") {
        if super::host_authentication::has_control_header(&request) {
            reject_request(
                &mut client,
                ctx,
                403,
                "host authentication belongs inside inspected TLS",
            )
            .await?;
            return Ok(());
        }

        let target = first_line.split_whitespace().nth(1).unwrap_or("");
        let authority = super::http::authority(target, 443);
        let host =
            super::http::host_header(&request).and_then(|host| super::http::authority(host, 443));
        if authority.is_err()
            || authority.as_ref().ok() != host.as_ref().ok()
            || !target.contains(':')
        {
            reject_request(&mut client, ctx, 400, "invalid CONNECT authority").await?;
            return Ok(());
        }
        handle_connect(&mut client, first_line, ctx).await
    } else {
        handle_http_request(&mut client, &request, ctx).await
    }
}

/// Broadcast an ASK request to all registered responders and wait for the first response.
/// Returns true if allowed, false if denied. Defaults to deny if no broadcaster is configured.
async fn ask_and_wait(
    ctx: &ConnectionContext,
    domain: &str,
    method: &str,
    _path: &str,
    _body: Option<String>,
) -> bool {
    if let Some(ref broadcaster) = ctx.ask_broadcaster {
        return broadcaster
            .ask(
                domain.to_string(),
                method.to_string(),
                "[path withheld]".to_string(),
                None,
            )
            .await;
    }
    // No broadcaster: default to deny (fail-closed)
    false
}

/// Keep the exact request buffer in this handler until the one-shot decision.
/// Only category names, length and a digest leave the device for approval.
async fn approve_sensitive(
    ctx: &ConnectionContext,
    domain: &str,
    method: &str,
    request: &[u8],
    findings: &[crate::dlp::DlpFinding],
) -> bool {
    let Some(broadcaster) = &ctx.sensitive_approval else {
        return false;
    };
    // Do not leak a credential embedded in a destination hostname to an approval
    // service. A hostname containing a sensitive value cannot be released here.
    if ctx
        .dlp_scanner
        .as_ref()
        .is_some_and(|scanner| !scanner.scan(domain.as_bytes()).is_empty())
    {
        return false;
    }
    if ctx.policy.as_ref().is_some_and(|policy| {
        evaluator::evaluate(
            &RequestInfo {
                domain: domain.into(),
                method: method.into(),
                path: "/".into(),
            },
            &policy.read().unwrap(),
        )
        .action
            == Action::Deny
    }) {
        return false;
    }
    let mut categories: Vec<String> = findings.iter().map(|f| f.pattern_name.clone()).collect();
    categories.sort_unstable();
    categories.dedup();
    broadcaster
        .ask_sensitive(domain.into(), method.into(), request, categories)
        .await
}

async fn reject_request<W: tokio::io::AsyncWrite + Unpin>(
    client: &mut W,
    ctx: &ConnectionContext,
    status: u16,
    reason: &str,
) -> crate::error::Result<()> {
    log_to_db(ctx, "REJECT", "", "/", "deny", reason);
    let phrase = match status {
        403 => "Forbidden",
        408 => "Request Timeout",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Bad Request",
    };
    // Only fixed internal reasons reach this helper; never reflect request bytes.
    client.write_all(format!("HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\nX-AgentShield-Reason: {reason}\r\n\r\n").as_bytes()).await?;
    Ok(())
}

async fn write_bounded<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> std::io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), writer.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream write timeout"))?
}

async fn relay<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<u64> {
    let mut buffer = [0u8; 8192];
    let mut total = 0;
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            reader.read(&mut buffer),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay idle timeout"))??;
        if n == 0 {
            return Ok(total);
        }
        write_bounded(writer, &buffer[..n]).await?;
        total += n as u64;
    }
}

async fn authorize_mitm<W: tokio::io::AsyncWrite + Unpin>(
    client: &mut W,
    ctx: &ConnectionContext,
    domain: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> crate::error::Result<bool> {
    let decision = ctx.policy.as_ref().map(|lock| {
        evaluator::evaluate(
            &RequestInfo {
                domain: domain.into(),
                method: method.into(),
                path: path.into(),
            },
            &lock.read().unwrap(),
        )
    });
    let Some(decision) = decision else {
        return Ok(true);
    };
    let allowed = match decision.action {
        Action::Deny => false,
        Action::Ask => {
            notify_event(
                ctx,
                NotificationEvent::AskPending {
                    domain: domain.into(),
                    method: method.into(),
                    path: path.into(),
                },
            );
            ask_and_wait(
                ctx,
                domain,
                method,
                path,
                body.map(|b| String::from_utf8_lossy(&b[..b.len().min(4096)]).into_owned()),
            )
            .await
        }
        Action::Allow => true,
    };
    if !allowed {
        log_to_db(ctx, method, domain, path, "deny", &decision.reason);
        notify_event(
            ctx,
            NotificationEvent::RequestDenied {
                domain: domain.into(),
                method: method.into(),
                path: path.into(),
                reason: decision.reason,
            },
        );
        reject_request(client, ctx, 403, "decrypted request denied by policy").await?;
        return Ok(false);
    }
    if let (Some(limit), Some(limiter)) = (&decision.rate_limit, &ctx.rate_limiter) {
        if !limiter.check_and_record(domain, limit.max_requests, limit.window_secs) {
            log_to_db(
                ctx,
                method,
                domain,
                path,
                "rate-limited",
                "decrypted request rate limited",
            );
            notify_event(
                ctx,
                NotificationEvent::RateLimited {
                    domain: domain.into(),
                    method: method.into(),
                    limit: limit.max_requests,
                    window_secs: limit.window_secs,
                },
            );
            reject_request(client, ctx, 429, "decrypted request rate limited").await?;
            return Ok(false);
        }
    }
    Ok(true)
}

/// Handle CONNECT method for HTTPS tunneling.
///
/// Establishes a TCP tunnel between the client and the target server after
/// validating the domain, checking the system allowlist, and evaluating policy.
/// For CONNECT requests, DLP scanning is not possible since the payload is encrypted.
async fn handle_connect(
    client: &mut TcpStream,
    first_line: &str,
    ctx: &ConnectionContext,
) -> crate::error::Result<()> {
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let (domain, port) = super::http::authority(parts[1], 443)
        .map_err(|_| crate::error::AgentShieldError::Proxy("invalid CONNECT authority".into()))?;
    let target_owned = format!("{domain}:{port}");
    let target = target_owned.as_str();
    let domain = domain.as_str();
    if !ctx.network.connect_ports.contains(&port) {
        reject_request(client, ctx, 403, "CONNECT port denied").await?;
        return Ok(());
    }

    // In MITM mode, CONNECT is only a transport preflight. Apply method rules
    // to the actual decrypted request, rather than authorizing the tunnel once.
    let system_allowed =
        is_system_allowed(domain, ctx.system_allowlist.as_deref().map(Vec::as_slice))
            && !ctx.network.is_loopback_relay(domain, port);
    if ctx.mitm_enabled && !system_allowed {
        let possible = ctx.policy.as_ref().is_none_or(|lock| {
            let policy = lock.read().unwrap();
            let mut possible = policy.default != Action::Deny;
            for rule in &policy.rules {
                if !rule
                    .domains
                    .iter()
                    .any(|pattern| domain_matches(pattern, domain))
                {
                    continue;
                }
                if rule.methods.is_none() {
                    return possible || rule.action != Action::Deny;
                }
                possible |= rule.action != Action::Deny;
            }
            possible
        });
        if !possible {
            reject_request(client, ctx, 403, "CONNECT destination denied").await?;
            return Ok(());
        }
        let Some(cache) = ctx.cert_cache.as_ref() else {
            reject_request(client, ctx, 503, "TLS inspection unavailable").await?;
            return Ok(());
        };
        return handle_connect_mitm(client, domain, target, ctx, cache).await;
    }

    // System allowlist bypass: skip policy evaluation for internal services
    if system_allowed {
        info!("SYSTEM-ALLOW CONNECT to (request details withheld)");
        log_to_db(
            ctx,
            "CONNECT",
            domain,
            "/",
            "system-allow",
            "system allowlist",
        );
    }
    // Policy evaluation for CONNECT (domain-level only)
    else if let Some(ref policy_lock) = ctx.policy {
        let req_info = RequestInfo {
            domain: domain.to_string(),
            method: "CONNECT".to_string(),
            path: "/".to_string(),
        };
        let result = {
            let policy = policy_lock.read().unwrap();
            evaluator::evaluate(&req_info, &policy)
        };
        match result.action {
            Action::Deny => {
                warn!("BLOCKED CONNECT to (request details withheld)");
                log_to_db(ctx, "CONNECT", domain, "/", "deny", &result.reason);
                notify_event(
                    ctx,
                    NotificationEvent::RequestDenied {
                        domain: domain.to_string(),
                        method: "CONNECT".to_string(),
                        path: "/".to_string(),
                        reason: result.reason.clone(),
                    },
                );
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK CONNECT to (request details withheld)");
                notify_event(
                    ctx,
                    NotificationEvent::AskPending {
                        domain: domain.to_string(),
                        method: "CONNECT".to_string(),
                        path: "/".to_string(),
                    },
                );
                let allowed = ask_and_wait(ctx, domain, "CONNECT", "/", None).await;
                if allowed {
                    log_to_db(ctx, "CONNECT", domain, "/", "allow", "approved via ASK");
                } else {
                    log_to_db(ctx, "CONNECT", domain, "/", "deny", "denied via ASK");
                    notify_event(
                        ctx,
                        NotificationEvent::RequestDenied {
                            domain: domain.to_string(),
                            method: "CONNECT".to_string(),
                            path: "/".to_string(),
                            reason: "denied via ASK".to_string(),
                        },
                    );
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                        "denied via ASK prompt"
                    );
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
            Action::Allow => {
                // Rate limit check
                if let Some(ref rl_config) = result.rate_limit {
                    if let Some(ref limiter) = ctx.rate_limiter {
                        if !limiter.check_and_record(
                            domain,
                            rl_config.max_requests,
                            rl_config.window_secs,
                        ) {
                            let reason = format!(
                                "Rate limit exceeded ({}/ {}s for {})",
                                rl_config.max_requests, rl_config.window_secs, domain
                            );
                            warn!("RATE-LIMITED CONNECT to (request details withheld)");
                            log_to_db(ctx, "CONNECT", domain, "/", "rate-limited", &reason);
                            notify_event(
                                ctx,
                                NotificationEvent::RateLimited {
                                    domain: domain.to_string(),
                                    method: "CONNECT".to_string(),
                                    limit: rl_config.max_requests,
                                    window_secs: rl_config.window_secs,
                                },
                            );
                            let response = format!(
                                "HTTP/1.1 429 Too Many Requests\r\nX-AgentShield-Reason: {}\r\n\r\n",
                                reason
                            );
                            client.write_all(response.as_bytes()).await?;
                            return Ok(());
                        }
                    }
                }
                info!("ALLOWED CONNECT to (request details withheld)");
                log_to_db(ctx, "CONNECT", domain, "/", "allow", &result.reason);
            }
        }
    }

    info!("CONNECT tunnel to (request details withheld)");

    match super::network::connect(target, &ctx.network).await {
        Ok(mut remote) => {
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            client.write_all(response.as_bytes()).await?;

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut remote_read, mut remote_write) = tokio::io::split(&mut remote);

            let client_to_remote = async {
                let count = relay(&mut client_read, &mut remote_write).await?;
                remote_write.shutdown().await?;
                Ok::<u64, std::io::Error>(count)
            };
            let remote_to_client = relay(&mut remote_read, &mut client_write);
            tokio::pin!(client_to_remote, remote_to_client);

            tokio::select! {
                r = &mut client_to_remote => {
                    if let Err(e) = r { warn!("client->remote error: {}", e); }
                    else { let _ = remote_to_client.await; }
                }
                r = &mut remote_to_client => {
                    if let Err(e) = r { warn!("remote->client error: {}", e); }
                }
            }
        }
        Err(super::network::ConnectError::Denied) => {
            reject_request(client, ctx, 403, "destination address denied").await?;
        }
        Err(_) => {
            warn!("Failed to connect to (request details withheld)");
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

/// Handle plain HTTP requests by forwarding to the target server.
///
/// Unlike CONNECT tunneling, plain HTTP requests expose the full request body,
/// enabling DLP scanning for secrets and PII before forwarding. Critical DLP
/// findings block the request; non-critical findings are logged as warnings.
async fn handle_http_request(
    client: &mut TcpStream,
    raw_request: &[u8],
    ctx: &ConnectionContext,
) -> crate::error::Result<()> {
    if super::host_authentication::has_control_header(raw_request) {
        reject_request(
            client,
            ctx,
            403,
            "host authentication requires TLS inspection",
        )
        .await?;
        return Ok(());
    }
    let request_str = String::from_utf8_lossy(raw_request);
    let first_line = request_str.lines().next().unwrap_or("");

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];
    let (host, port) = match super::http::host_header(raw_request)
        .and_then(|host| super::http::destination(uri, host, None))
    {
        Ok(destination) => destination,
        Err(error) => {
            reject_request(client, ctx, error.status, error.reason).await?;
            return Ok(());
        }
    };
    let path = parse_path(uri);

    // Extract body early for audit logging
    let request_body = extract_body(raw_request);

    // Validate domain to prevent header injection
    if !validate_domain(&host) {
        warn!("Invalid domain in HTTP request: (request details withheld)");
        log_to_db_audited(
            ctx,
            method,
            &host,
            &path,
            "deny",
            "invalid domain",
            None,
            None,
        );
        let response = "HTTP/1.1 400 Bad Request\r\nX-AgentShield-Reason: invalid domain\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // The pinned local relay is an address exception only. It cannot inherit
    // legacy system-allowlist policy, DLP or TLS-inspection bypasses.
    // Other system allowlist traffic keeps its explicitly configured behavior.
    let allowlist_slice = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    let system_allowed =
        is_system_allowed(&host, allowlist_slice) && !ctx.network.is_loopback_relay(&host, port);
    // DLP scan: check request body for sensitive data before forwarding.
    // System-allowed domains bypass DLP (they already bypass policy above).
    if !system_allowed || ctx.sensitive_approval.is_some() {
        if let Some(ref scanner) = ctx.dlp_scanner {
            if super::http::encoded_body(raw_request) {
                reject_request(client, ctx, 415, "encoded body cannot be inspected").await?;
                return Ok(());
            }
            {
                let findings = scanner.scan(raw_request);
                let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
                let needs_approval = ctx.sensitive_approval.is_some() && !findings.is_empty();
                let approved = if has_critical || needs_approval {
                    approve_sensitive(ctx, &host, method, raw_request, &findings).await
                } else {
                    false
                };
                if (has_critical || needs_approval) && !approved {
                    for f in &findings {
                        warn!(severity = ?f.severity, pattern = %f.pattern_name, "DLP finding (request details withheld)");
                    }
                    let dlp_str = format_dlp_findings(&findings);
                    log_to_db_audited(
                        ctx,
                        method,
                        &host,
                        &path,
                        "deny",
                        "DLP: critical finding",
                        request_body,
                        Some(&dlp_str),
                    );
                    // Notify about first critical finding
                    if let Some(f) = findings.iter().find(|f| f.severity == Severity::Critical) {
                        notify_event(
                            ctx,
                            NotificationEvent::DlpFinding {
                                domain: host.clone(),
                                method: method.to_string(),
                                pattern_name: f.pattern_name.clone(),
                                severity: format!("{:?}", f.severity),
                            },
                        );
                    }
                    let response = "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: DLP: sensitive data detected\r\n\r\n";
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
                if approved {
                    log_to_db(
                        ctx,
                        method,
                        &host,
                        &path,
                        "sensitive-approved",
                        "one-shot Slack approval for exact request",
                    );
                }
                // Non-critical findings: log warning but allow request through
                for f in &findings {
                    warn!(severity = ?f.severity, pattern = %f.pattern_name, "DLP finding (request details withheld)");
                }
            }
        }
    } // end if !system_allowed (DLP bypass)

    if system_allowed {
        info!("SYSTEM-ALLOW (request details withheld)");
        log_to_db_audited(
            ctx,
            method,
            &host,
            &path,
            "system-allow",
            "system allowlist (policy+dlp bypass)",
            request_body,
            None,
        );
    }
    // Policy evaluation for HTTP
    else if let Some(ref policy_lock) = ctx.policy {
        let req_info = RequestInfo {
            domain: host.clone(),
            method: method.to_string(),
            path: path.clone(),
        };
        let result = {
            let policy = policy_lock.read().unwrap();
            evaluator::evaluate(&req_info, &policy)
        };
        match result.action {
            Action::Deny => {
                warn!("BLOCKED (request details withheld)");
                log_to_db_audited(
                    ctx,
                    method,
                    &host,
                    &path,
                    "deny",
                    &result.reason,
                    request_body,
                    None,
                );
                notify_event(
                    ctx,
                    NotificationEvent::RequestDenied {
                        domain: host.clone(),
                        method: method.to_string(),
                        path: path.clone(),
                        reason: result.reason.clone(),
                    },
                );
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                    result.reason
                );
                client.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            Action::Ask => {
                info!("ASK (request details withheld)");
                notify_event(
                    ctx,
                    NotificationEvent::AskPending {
                        domain: host.clone(),
                        method: method.to_string(),
                        path: path.clone(),
                    },
                );
                // Truncate body to 4KB for display purposes to avoid large allocations
                const MAX_BODY_CAPTURE: usize = 4096;
                let body_str = extract_body(raw_request).and_then(|b| {
                    let slice = &b[..b.len().min(MAX_BODY_CAPTURE)];
                    String::from_utf8(slice.to_vec()).ok()
                });
                let allowed = ask_and_wait(ctx, &host, method, &path, body_str).await;
                if allowed {
                    log_to_db_audited(
                        ctx,
                        method,
                        &host,
                        &path,
                        "allow",
                        "approved via ASK",
                        request_body,
                        None,
                    );
                } else {
                    log_to_db_audited(
                        ctx,
                        method,
                        &host,
                        &path,
                        "deny",
                        "denied via ASK",
                        request_body,
                        None,
                    );
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: {}\r\n\r\n",
                        "denied via ASK prompt"
                    );
                    client.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
            Action::Allow => {
                // Rate limit check
                if let Some(ref rl_config) = result.rate_limit {
                    if let Some(ref limiter) = ctx.rate_limiter {
                        if !limiter.check_and_record(
                            &host,
                            rl_config.max_requests,
                            rl_config.window_secs,
                        ) {
                            let reason = format!(
                                "Rate limit exceeded ({}/{}s for {})",
                                rl_config.max_requests, rl_config.window_secs, host
                            );
                            warn!("RATE-LIMITED (request details withheld)");
                            log_to_db_audited(
                                ctx,
                                method,
                                &host,
                                &path,
                                "rate-limited",
                                &reason,
                                request_body,
                                None,
                            );
                            notify_event(
                                ctx,
                                NotificationEvent::RateLimited {
                                    domain: host.clone(),
                                    method: method.to_string(),
                                    limit: rl_config.max_requests,
                                    window_secs: rl_config.window_secs,
                                },
                            );
                            let response = format!(
                                "HTTP/1.1 429 Too Many Requests\r\nX-AgentShield-Reason: {}\r\n\r\n",
                                reason
                            );
                            client.write_all(response.as_bytes()).await?;
                            return Ok(());
                        }
                    }
                }
                info!("ALLOWED (request details withheld)");
                log_to_db_audited(
                    ctx,
                    method,
                    &host,
                    &path,
                    "allow",
                    &result.reason,
                    request_body,
                    None,
                );
            }
        }
    }

    info!("HTTP (request details withheld)");
    let target = format!("{}:{}", host, port);

    match super::network::connect(&target, &ctx.network).await {
        Ok(mut remote) => {
            let wire_request = super::http::origin_form(raw_request);
            write_bounded(&mut remote, &wire_request).await?;
            // Stream the full response back to client with timeout
            let copy_result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                relay(&mut remote, client),
            )
            .await;
            match copy_result {
                Ok(Ok(bytes)) => {
                    info!(bytes, "Response streamed (request details withheld)");
                }
                Ok(Err(_)) => {
                    warn!("Error streaming response from (request details withheld)");
                }
                Err(_) => {
                    warn!("Timeout streaming response from (request details withheld)");
                }
            }
        }
        Err(super::network::ConnectError::Denied) => {
            reject_request(client, ctx, 403, "destination address denied").await?;
        }
        Err(_) => {
            warn!("Failed to connect to (request details withheld)");
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

/// Extract the body from a raw HTTP request (everything after `\r\n\r\n`).
fn extract_body(raw_request: &[u8]) -> Option<&[u8]> {
    raw_request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|pos| {
            let start = pos + 4;
            (start < raw_request.len()).then(|| &raw_request[start..])
        })
}

/// Handle CONNECT in MITM mode: decrypt TLS, inspect payload with DLP, re-encrypt.
///
/// Flow:
/// 1. Send "200 Connection Established" to client
/// 2. TLS-accept client connection using a cert signed by our CA for `domain`
/// 3. Read decrypted HTTP request from client
/// 4. DLP scan request body (block if critical)
/// 5. TLS-connect to real upstream server
/// 6. Forward request and relay response back through the client TLS connection
async fn handle_connect_mitm(
    client: &mut TcpStream,
    domain: &str,
    target: &str,
    ctx: &ConnectionContext,
    cert_cache: &CertCache,
) -> crate::error::Result<()> {
    // Step 1: Tell the client the tunnel is established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Step 2: TLS-accept the client using our CA-signed cert for this domain
    let server_config = match cert_cache.get_or_create(domain) {
        Ok(cfg) => cfg,
        Err(_) => {
            error!("Failed to generate cert for (request details withheld)");
            return Ok(());
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let mut client_tls =
        match tokio::time::timeout(std::time::Duration::from_secs(15), acceptor.accept(client))
            .await
        {
            Err(_) => return Ok(()),
            Ok(result) => match result {
                Ok(stream) => stream,
                Err(_) => {
                    warn!("TLS handshake with client failed for (request details withheld)");
                    return Ok(());
                }
            },
        };

    // Use the same complete, bounded framing for decrypted and plaintext HTTP.
    let request_buf = match super::http::read_request(&mut client_tls).await {
        Ok(request) => request,
        Err(rejection) => {
            reject_request(&mut client_tls, ctx, rejection.status, rejection.reason).await?;
            return Ok(());
        }
    };
    let raw_request = &request_buf[..];

    // Parse method and path from decrypted request
    let request_str = String::from_utf8_lossy(raw_request);
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("UNKNOWN");
    let path = parts.get(1).copied().unwrap_or("/");

    let (_, port) = super::http::authority(target, 443).expect("validated CONNECT target");
    if let Err(error) = super::http::host_header(raw_request)
        .and_then(|host| super::http::destination(path, host, Some((domain, port))))
    {
        reject_request(&mut client_tls, ctx, error.status, error.reason).await?;
        return Ok(());
    }
    let path_owned = if path.starts_with('/') {
        path.to_string()
    } else {
        parse_path(path)
    };
    let path = path_owned.as_str();
    if ctx.dlp_scanner.is_some() && super::http::encoded_body(raw_request) {
        reject_request(
            &mut client_tls,
            ctx,
            415,
            "encoded body cannot be inspected",
        )
        .await?;
        return Ok(());
    }

    let host_intent =
        match super::host_authentication::intent(raw_request, domain, port, method, path) {
            Ok(value) => value,
            Err(reason) => {
                reject_request(&mut client_tls, ctx, 403, reason).await?;
                return Ok(());
            }
        };
    if let Some(intent) = &host_intent {
        let allowed = if let Some(authenticator) = &ctx.host_authenticator {
            authenticator.authenticate(&intent.request).await
        } else {
            false
        };
        if !allowed {
            reject_request(&mut client_tls, ctx, 403, "host authentication unavailable").await?;
            return Ok(());
        }
    }

    // Extract body for audit logging
    let mitm_body = extract_body(raw_request);

    // Step 4: DLP scan
    if let Some(ref scanner) = ctx.dlp_scanner {
        {
            let findings = if let Some(intent) = &host_intent {
                intent.findings(scanner.as_ref(), raw_request)
            } else {
                scanner.scan(raw_request)
            };
            let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
            let needs_approval = ctx.sensitive_approval.is_some() && !findings.is_empty();
            let approved = if has_critical || needs_approval {
                approve_sensitive(ctx, domain, method, raw_request, &findings).await
            } else {
                false
            };
            if (has_critical || needs_approval) && !approved {
                for f in &findings {
                    warn!(severity = ?f.severity, pattern = %f.pattern_name, "DLP finding (request details withheld)");
                }
                let dlp_str = format_dlp_findings(&findings);
                log_to_db_audited(
                    ctx,
                    method,
                    domain,
                    path,
                    "deny",
                    "DLP: critical finding (MITM)",
                    mitm_body,
                    Some(&dlp_str),
                );
                if let Some(f) = findings.iter().find(|f| f.severity == Severity::Critical) {
                    notify_event(
                        ctx,
                        NotificationEvent::DlpFinding {
                            domain: domain.to_string(),
                            method: method.to_string(),
                            pattern_name: f.pattern_name.clone(),
                            severity: format!("{:?}", f.severity),
                        },
                    );
                }
                let response = "HTTP/1.1 403 Forbidden\r\nX-AgentShield-Reason: DLP: sensitive data detected (MITM)\r\n\r\n";
                let _ = client_tls.write_all(response.as_bytes()).await;
                let _ = client_tls.shutdown().await;
                return Ok(());
            }
            if approved {
                log_to_db(
                    ctx,
                    method,
                    domain,
                    path,
                    "sensitive-approved",
                    "one-shot Slack approval for exact request",
                );
            }
            // Non-critical findings: log but allow
            for f in &findings {
                warn!(severity = ?f.severity, pattern = %f.pattern_name, "DLP finding (request details withheld)");
            }
        }
    }

    if !authorize_mitm(
        &mut client_tls,
        ctx,
        domain,
        method,
        path,
        extract_body(raw_request),
    )
    .await?
    {
        return Ok(());
    }

    // Step 5: TLS-connect to the real upstream server (reuse cached ClientConfig)
    let tls_config = ctx
        .upstream_tls_config
        .as_ref()
        .expect("upstream_tls_config must be set in MITM mode")
        .clone();
    let connector = tokio_rustls::TlsConnector::from(tls_config);

    let remote_tcp = match super::network::connect(target, &ctx.network).await {
        Ok(s) => s,
        Err(super::network::ConnectError::Denied) => {
            reject_request(&mut client_tls, ctx, 403, "destination address denied").await?;
            return Ok(());
        }
        Err(_) => {
            warn!("Failed to connect to upstream (request details withheld)");
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_tls.write_all(response.as_bytes()).await;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }
    };

    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string()).map_err(|e| {
        crate::error::AgentShieldError::Proxy(format!("Invalid server name: {}", e))
    })?;

    let mut remote_tls = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(server_name, remote_tcp),
    )
    .await
    {
        Err(_) => return Ok(()),
        Ok(result) => match result {
            Ok(s) => s,
            Err(_) => {
                warn!("TLS handshake with upstream (request details withheld)");
                let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
                let _ = client_tls.write_all(response.as_bytes()).await;
                let _ = client_tls.shutdown().await;
                return Ok(());
            }
        },
    };

    // Step 6: Forward decrypted request to upstream
    let forward = host_intent
        .as_ref()
        .map(|intent| intent.forward_bytes(raw_request));
    let forwarded = forward.as_deref().unwrap_or(raw_request);
    if write_bounded(&mut remote_tls, &super::http::origin_form(forwarded))
        .await
        .is_err()
    {
        warn!("Failed to forward request to (request details withheld)");
        let _ = client_tls.shutdown().await;
        return Ok(());
    }

    // Step 7: Stream upstream response back to client
    let (mut remote_read, _remote_write) = tokio::io::split(remote_tls);
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let _ = relay(&mut remote_read, &mut client_write).await;

    // Drain any remaining client data (keep-alive cleanup)
    let _ = client_read.read(&mut [0u8; 0]).await;

    info!("MITM (request details withheld)");
    log_to_db_audited(
        ctx,
        method,
        domain,
        path,
        "allow",
        "MITM inspected (DLP clean)",
        mitm_body,
        None,
    );

    let _ = client_write.shutdown().await;

    Ok(())
}

/// Check if a domain is in the system allowlist (bypass policy evaluation).
fn is_system_allowed(domain: &str, allowlist: Option<&[String]>) -> bool {
    allowlist.is_some_and(|list| list.iter().any(|d| domain_matches(d, domain)))
}

/// Validate that a domain name contains only safe characters.
fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Parse the path from an absolute URI
fn parse_path(uri: &str) -> String {
    uri.parse::<hyper::Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|path| path.as_str().to_string()))
        .unwrap_or_else(|| "/".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aws_hostname_credentials_never_reach_approval_metadata() {
        use crate::ask::{AskRequestInfo, AskResponder};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Approver(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl AskResponder for Approver {
            async fn prompt(&self, _request: &AskRequestInfo) -> Option<bool> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Some(true)
            }
            async fn notify_resolved(&self, _id: &str, _allowed: bool) {}
            fn name(&self) -> &str {
                "synthetic-approval-fixture"
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let mut approvals = AskBroadcaster::new(1);
        approvals.add_responder(Arc::new(Approver(calls.clone())));
        let scanner = Arc::new(crate::dlp::patterns::RegexScanner::new());
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            host_authenticator: None,
            sensitive_approval: Some(Arc::new(approvals)),
            dlp_scanner: Some(scanner.clone()),
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };
        let request = b"password=synthetic-hostname-fixture";
        let findings = scanner.scan(request);
        assert!(!findings.is_empty());
        for key in ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"] {
            let host = format!("{key}.example.test");
            let (canonical, _) = super::super::http::authority(&host, 443).unwrap();
            assert_eq!(canonical, host.to_ascii_lowercase());
            assert!(
                !approve_sensitive(&ctx, &canonical, "POST", request, &findings).await,
                "hostname credentials must never be released through approval"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "hostname credential reached the approval service"
            );
        }
        assert!(approve_sensitive(&ctx, "example.test", "POST", request, &findings).await);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "ordinary approval positive control failed"
        );
    }

    #[tokio::test]
    async fn denied_query_credentials_never_enter_diagnostic_output() {
        use tracing::instrument::WithSubscriber;
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Capture(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: Some(Arc::new(crate::dlp::patterns::RegexScanner::new())),
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        handle_http_request(&mut server,
            b"GET http://example.test/private-path?password=fixture-sensitive-value HTTP/1.1\r\nHost: example.test\r\n\r\n", &ctx)
            .with_subscriber(subscriber).await.unwrap();
        let mut response = [0; 1024];
        let size = client.read(&mut response).await.unwrap();
        assert!(response[..size].starts_with(b"HTTP/1.1 403"));
        let text = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(
            text.contains("DLP finding"),
            "diagnostic event should remain useful"
        );
        for value in [
            "fixture-sensitive-value",
            "private-path",
            "example.test",
            "password=",
        ] {
            assert!(!text.contains(value), "diagnostic leaked request data");
        }
    }

    #[test]
    fn test_parse_path() {
        assert_eq!(parse_path("http://example.com/foo/bar"), "/foo/bar");
        assert_eq!(parse_path("http://example.com"), "/");
        assert_eq!(
            parse_path("https://api.github.com/repos/user/repo"),
            "/repos/user/repo"
        );
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com"));
        assert!(validate_domain("api.anthropic.com"));
        assert!(validate_domain("my-service.example.com"));
        assert!(validate_domain("localhost"));
        assert!(validate_domain("192.168.1.1"));
    }

    #[test]
    fn extract_body_from_raw_request() {
        let raw = b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{\"key\": \"value\"}";
        let body = extract_body(raw).unwrap();
        assert_eq!(body, b"{\"key\": \"value\"}");
    }

    #[test]
    fn no_body_in_get_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let body = extract_body(raw);
        assert!(body.is_none());
    }

    #[test]
    fn system_allowlist_match() {
        let list = vec!["api.telegram.org".to_string(), "internal.svc".to_string()];
        assert!(is_system_allowed("api.telegram.org", Some(&list)));
        assert!(is_system_allowed("internal.svc", Some(&list)));
    }

    #[test]
    fn system_allowlist_no_match() {
        let list = vec!["api.telegram.org".to_string()];
        assert!(!is_system_allowed("evil.com", Some(&list)));
    }

    #[test]
    fn system_allowlist_none() {
        assert!(!is_system_allowed("api.telegram.org", None));
    }

    #[test]
    fn system_allowlist_wildcard_subdomain() {
        let list = vec!["*.github.com".to_string()];
        assert!(is_system_allowed("api.github.com", Some(&list)));
        assert!(is_system_allowed("github.com", Some(&list)));
        assert!(is_system_allowed("deep.api.github.com", Some(&list)));
        assert!(!is_system_allowed("evil-github.com", Some(&list)));
    }

    #[test]
    fn system_allowlist_wildcard_all() {
        let list = vec!["*".to_string()];
        assert!(is_system_allowed("anything.com", Some(&list)));
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(!validate_domain(""));
        assert!(!validate_domain("evil.com/../../etc/passwd"));
        assert!(!validate_domain("evil@attacker.com"));
        assert!(!validate_domain("evil.com:443\r\nInjected: header"));
        assert!(!validate_domain("domain with spaces"));
        assert!(!validate_domain("evil.com\0null"));
    }

    #[test]
    fn log_to_db_broadcasts_event() {
        let (tx, mut rx) = broadcast::channel::<LogEvent>(16);
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db(&ctx, "GET", "example.com", "/api", "allow", "test rule");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.method, "GET");
        assert_eq!(event.domain, "example.com");
        assert_eq!(event.path, "/api");
        assert_eq!(event.action, "allow");
        assert_eq!(event.reason, "test rule");
        assert!(!event.timestamp.is_empty());
    }

    #[test]
    fn log_to_db_no_event_tx_does_not_panic() {
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };

        // Should not panic when event_tx is None
        log_to_db(&ctx, "POST", "api.test.com", "/v1", "deny", "blocked");
    }

    #[test]
    fn log_to_db_no_receivers_does_not_panic() {
        let (tx, _) = broadcast::channel::<LogEvent>(16);
        // Drop the receiver — send should silently fail
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };

        // Should not panic even with no active receivers
        log_to_db(&ctx, "DELETE", "api.test.com", "/v1", "deny", "no receiver");
    }

    #[test]
    fn log_to_db_multiple_subscribers_receive_event() {
        let (tx, mut rx1) = broadcast::channel::<LogEvent>(16);
        let mut rx2 = tx.subscribe();
        let ctx = ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db(&ctx, "PUT", "multi.com", "/data", "allow", "multi test");

        let e1 = rx1.try_recv().unwrap();
        let e2 = rx2.try_recv().unwrap();
        assert_eq!(e1.domain, "multi.com");
        assert_eq!(e2.domain, "multi.com");
        assert_eq!(e1.action, "allow");
        assert_eq!(e2.action, "allow");
    }

    #[test]
    fn log_event_clone_and_debug() {
        let event = LogEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            method: "GET".to_string(),
            domain: "test.com".to_string(),
            path: "/".to_string(),
            action: "allow".to_string(),
            reason: "ok".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(cloned.domain, "test.com");
        // Debug trait works
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("test.com"));
    }

    #[test]
    fn should_audit_disabled_by_default() {
        assert!(!should_audit(None, "allow"));
    }

    #[test]
    fn should_audit_disabled_when_false() {
        let config = LoggingConfig {
            audit: false,
            ..Default::default()
        };
        assert!(!should_audit(Some(&config), "allow"));
    }

    #[test]
    fn should_audit_enabled_all_actions() {
        let config = LoggingConfig {
            audit: true,
            audit_max_body_size: 65536,
            audit_actions: vec![],
            ..Default::default()
        };
        assert!(should_audit(Some(&config), "allow"));
        assert!(should_audit(Some(&config), "deny"));
        assert!(should_audit(Some(&config), "system-allow"));
    }

    #[test]
    fn should_audit_filtered_actions() {
        let config = LoggingConfig {
            audit: true,
            audit_max_body_size: 65536,
            audit_actions: vec!["deny".to_string(), "allow".to_string()],
            ..Default::default()
        };
        assert!(should_audit(Some(&config), "deny"));
        assert!(should_audit(Some(&config), "allow"));
        assert!(!should_audit(Some(&config), "system-allow"));
        assert!(!should_audit(Some(&config), "rate-limited"));
    }

    #[test]
    fn format_dlp_findings_empty() {
        let findings: Vec<crate::dlp::DlpFinding> = vec![];
        assert_eq!(format_dlp_findings(&findings), "[]");
    }

    #[test]
    fn format_dlp_findings_single() {
        let findings = vec![crate::dlp::DlpFinding {
            pattern_name: "test-pattern".to_string(),
            severity: crate::dlp::Severity::Critical,
            matched_text: "sk-secret".to_string(),
        }];
        let result = format_dlp_findings(&findings);
        assert!(result.contains("test-pattern"));
        assert!(result.contains("Critical"));
        assert!(result.contains("sk-secret"));
    }

    #[test]
    fn log_to_db_audited_stores_body_when_audit_enabled() {
        let pool = crate::logging::open_memory_pool().unwrap();
        let config = LoggingConfig {
            audit: true,
            audit_max_body_size: 65536,
            audit_actions: vec![],
            ..Default::default()
        };
        let ctx = ConnectionContext {
            policy: None,
            db: Some(pool.clone()),
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db_audited(
            &ctx,
            "POST",
            "api.example.com",
            "/v1/chat",
            "allow",
            "test rule",
            Some(b"hello world"),
            None,
        );

        let conn = pool.get().unwrap();
        let logs = crate::logging::query_recent(&conn, 1).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_body.as_deref(), Some("hello world"));
        assert!(logs[0].dlp_findings.is_none());
    }

    #[test]
    fn log_to_db_audited_skips_body_when_audit_disabled() {
        let pool = crate::logging::open_memory_pool().unwrap();
        let ctx = ConnectionContext {
            policy: None,
            db: Some(pool.clone()),
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db_audited(
            &ctx,
            "POST",
            "api.example.com",
            "/v1/chat",
            "allow",
            "test rule",
            Some(b"hello world"),
            None,
        );

        let conn = pool.get().unwrap();
        let logs = crate::logging::query_recent(&conn, 1).unwrap();
        assert_eq!(logs.len(), 1);
        // Body should NOT be stored when audit is disabled
        assert!(logs[0].request_body.is_none());
    }

    #[test]
    fn log_to_db_audited_truncates_body() {
        let pool = crate::logging::open_memory_pool().unwrap();
        let config = LoggingConfig {
            audit: true,
            audit_max_body_size: 10, // Only 10 bytes
            audit_actions: vec![],
            ..Default::default()
        };
        let ctx = ConnectionContext {
            policy: None,
            db: Some(pool.clone()),
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db_audited(
            &ctx,
            "POST",
            "api.example.com",
            "/v1/chat",
            "allow",
            "test",
            Some(b"this is a very long body that should be truncated"),
            None,
        );

        let conn = pool.get().unwrap();
        let logs = crate::logging::query_recent(&conn, 1).unwrap();
        assert_eq!(logs.len(), 1);
        let body = logs[0].request_body.as_deref().unwrap();
        assert_eq!(body.len(), 10);
        assert_eq!(body, "this is a ");
    }

    #[test]
    fn log_to_db_audited_stores_dlp_findings() {
        let pool = crate::logging::open_memory_pool().unwrap();
        let config = LoggingConfig {
            audit: true,
            audit_max_body_size: 65536,
            audit_actions: vec![],
            ..Default::default()
        };
        let ctx = ConnectionContext {
            policy: None,
            db: Some(pool.clone()),
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db_audited(
            &ctx,
            "POST",
            "api.example.com",
            "/v1/chat",
            "deny",
            "DLP: critical",
            Some(b"sk-secret123"),
            Some(r#"[{"pattern":"openai","severity":"Critical","matched":"sk-secret123"}]"#),
        );

        let conn = pool.get().unwrap();
        let logs = crate::logging::query_recent(&conn, 1).unwrap();
        assert_eq!(logs.len(), 1);
        assert!(logs[0].dlp_findings.as_deref().unwrap().contains("openai"));
        // Body should be redacted when audit_redact_dlp is true (default)
        assert_eq!(
            logs[0].request_body.as_deref(),
            Some("[BODY REDACTED: DLP sensitive data detected]")
        );
    }

    #[test]
    fn log_to_db_audited_no_redact_when_disabled() {
        let pool = crate::logging::open_memory_pool().unwrap();
        let config = LoggingConfig {
            audit: true,
            audit_redact_dlp: false,
            ..Default::default()
        };
        let ctx = ConnectionContext {
            policy: None,
            db: Some(pool.clone()),
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
            network: super::super::network::NetworkConfig::default(),
        };

        log_to_db_audited(
            &ctx,
            "POST",
            "api.example.com",
            "/v1/chat",
            "deny",
            "DLP: critical",
            Some(b"sk-secret123"),
            Some(r#"[{"pattern":"openai"}]"#),
        );

        let conn = pool.get().unwrap();
        let logs = crate::logging::query_recent(&conn, 1).unwrap();
        assert_eq!(logs.len(), 1);
        // Body should NOT be redacted when audit_redact_dlp is false
        assert_eq!(logs[0].request_body.as_deref(), Some("sk-secret123"));
    }

    #[test]
    fn format_dlp_findings_escapes_special_chars() {
        let findings = vec![crate::dlp::DlpFinding {
            pattern_name: "test".to_string(),
            severity: crate::dlp::Severity::Critical,
            matched_text: r#"has "quotes" and \backslash"#.to_string(),
        }];
        let result = format_dlp_findings(&findings);
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed[0]["matched"], r#"has "quotes" and \backslash"#);
    }

    #[tokio::test]
    async fn accept_loop_stops_on_shutdown_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = Arc::new(ConnectionContext {
            policy: None,
            db: None,
            ask_broadcaster: None,
            sensitive_approval: None,
            host_authenticator: None,
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
            network: super::super::network::NetworkConfig::default(),
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let accept_handle = tokio::spawn(async move {
            accept_loop(listener, ctx, shutdown_rx).await;
        });

        // Verify the proxy is accepting connections
        let _conn = TcpStream::connect(addr).await.unwrap();

        // Send shutdown signal
        shutdown_tx.send(true).unwrap();

        // accept_loop should terminate
        tokio::time::timeout(std::time::Duration::from_secs(3), accept_handle)
            .await
            .expect("accept_loop should stop within 3s")
            .expect("accept_loop task should not panic");
    }
}
