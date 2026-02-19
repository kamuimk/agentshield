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
}

/// Main accept loop: accept incoming connections and handle them.
pub async fn accept_loop(listener: TcpListener, ctx: Arc<ConnectionContext>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &ctx).await {
                        error!("Error handling connection from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
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
        let truncated_body = if redact_dlp && dlp_findings.is_some() {
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
fn notify_event(ctx: &ConnectionContext, event: NotificationEvent) {
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
) -> crate::error::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        handle_connect(&mut client, first_line, ctx).await
    } else {
        handle_http_request(&mut client, &buf[..n], ctx).await
    }
}

/// Broadcast an ASK request to all registered responders and wait for the first response.
/// Returns true if allowed, false if denied. Defaults to deny if no broadcaster is configured.
async fn ask_and_wait(
    ctx: &ConnectionContext,
    domain: &str,
    method: &str,
    path: &str,
    body: Option<String>,
) -> bool {
    if let Some(ref broadcaster) = ctx.ask_broadcaster {
        return broadcaster
            .ask(
                domain.to_string(),
                method.to_string(),
                path.to_string(),
                body,
            )
            .await;
    }
    // No broadcaster: default to deny (fail-closed)
    false
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

    let target = parts[1]; // e.g. "example.com:443"
    let domain = target.split(':').next().unwrap_or(target);

    // Validate domain to prevent header injection
    if !validate_domain(domain) {
        warn!("Invalid domain in CONNECT: {}", domain);
        log_to_db(ctx, "CONNECT", domain, "/", "deny", "invalid domain");
        let response = "HTTP/1.1 400 Bad Request\r\nX-AgentShield-Reason: invalid domain\r\n\r\n";
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // System allowlist bypass: skip policy evaluation for internal services
    let allowlist_slice = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    if is_system_allowed(domain, allowlist_slice) {
        info!("SYSTEM-ALLOW CONNECT to {} (allowlist)", target);
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
                warn!("BLOCKED CONNECT to {} - {}", target, result.reason);
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
                info!("ASK CONNECT to {} - {}", target, result.reason);
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
                            warn!("RATE-LIMITED CONNECT to {} - {}", target, reason);
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
                info!("ALLOWED CONNECT to {} - {}", target, result.reason);
                log_to_db(ctx, "CONNECT", domain, "/", "allow", &result.reason);
            }
        }
    }

    // MITM mode: decrypt TLS, inspect, re-encrypt
    // System-allowlisted domains bypass MITM (use plain tunnel)
    let allowlist_slice_for_mitm = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    let system_allowed = is_system_allowed(domain, allowlist_slice_for_mitm);
    if ctx.mitm_enabled && !system_allowed {
        if let Some(ref cert_cache) = ctx.cert_cache {
            info!("MITM CONNECT to {}", target);
            return handle_connect_mitm(client, domain, target, ctx, cert_cache).await;
        }
    }

    info!("CONNECT tunnel to {}", target);

    match TcpStream::connect(target).await {
        Ok(mut remote) => {
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            client.write_all(response.as_bytes()).await?;

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut remote_read, mut remote_write) = tokio::io::split(&mut remote);

            let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
            let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

            tokio::select! {
                r = client_to_remote => {
                    if let Err(e) = r { warn!("client->remote error: {}", e); }
                }
                r = remote_to_client => {
                    if let Err(e) = r { warn!("remote->client error: {}", e); }
                }
            }
        }
        Err(e) => {
            warn!("Failed to connect to {}: {}", target, e);
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
    let (host, port) = parse_host_port(uri)?;
    let path = parse_path(uri);

    // Extract body early for audit logging
    let request_body = extract_body(raw_request);

    // Validate domain to prevent header injection
    if !validate_domain(&host) {
        warn!("Invalid domain in HTTP request: {}", host);
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

    // System allowlist bypass: skip policy evaluation AND DLP scanning for internal services.
    //
    // SECURITY NOTE: Domains on the system allowlist bypass both policy and DLP checks.
    // Only add trusted internal services (e.g., notification endpoints). Adding external
    // domains here disables all outbound protection for that destination.
    let allowlist_slice = ctx.system_allowlist.as_ref().map(|v| v.as_slice());
    let system_allowed = is_system_allowed(&host, allowlist_slice);
    if system_allowed {
        info!(
            "SYSTEM-ALLOW {} {} (allowlist, policy+dlp bypass)",
            method, uri
        );
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
                warn!("BLOCKED {} {} - {}", method, uri, result.reason);
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
                info!("ASK {} {} - {}", method, uri, result.reason);
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
                            warn!("RATE-LIMITED {} {} - {}", method, uri, reason);
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
                info!("ALLOWED {} {} - {}", method, uri, result.reason);
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

    // DLP scan: check request body for sensitive data before forwarding.
    // System-allowed domains bypass DLP (they already bypass policy above).
    if !system_allowed {
        if let Some(ref scanner) = ctx.dlp_scanner {
            if let Some(body) = extract_body(raw_request) {
                let findings = scanner.scan(body);
                let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
                if has_critical {
                    for f in &findings {
                        warn!(
                            "DLP {} finding in {} {}: pattern={}, match={}",
                            format!("{:?}", f.severity),
                            method,
                            uri,
                            f.pattern_name,
                            f.matched_text
                        );
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
                // Non-critical findings: log warning but allow request through
                for f in &findings {
                    warn!(
                        "DLP {:?} finding in {} {}: pattern={}, match={}",
                        f.severity, method, uri, f.pattern_name, f.matched_text
                    );
                }
            }
        }
    } // end if !system_allowed (DLP bypass)

    info!("HTTP {} to {}", method, uri);
    let target = format!("{}:{}", host, port);

    match TcpStream::connect(&target).await {
        Ok(mut remote) => {
            // Inject Connection: close header so remote server closes after response
            let request_str = String::from_utf8_lossy(raw_request);
            let modified = if !request_str.to_lowercase().contains("connection:") {
                request_str.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
            } else {
                request_str.to_string()
            };
            remote.write_all(modified.as_bytes()).await?;
            // Stream the full response back to client with timeout
            let copy_result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::io::copy(&mut remote, client),
            )
            .await;
            match copy_result {
                Ok(Ok(bytes)) => {
                    info!("Streamed {} bytes from {}", bytes, target);
                }
                Ok(Err(e)) => {
                    warn!("Error streaming response from {}: {}", target, e);
                }
                Err(_) => {
                    warn!("Timeout streaming response from {}", target);
                }
            }
        }
        Err(e) => {
            warn!("Failed to connect to {}: {}", target, e);
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
        Err(e) => {
            error!("Failed to generate cert for {}: {}", domain, e);
            return Ok(());
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let mut client_tls = match acceptor.accept(client).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TLS handshake with client failed for {}: {}", domain, e);
            return Ok(());
        }
    };

    // Step 3: Read full decrypted HTTP request from client
    // First read headers, then read remaining body based on Content-Length
    let mut request_buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let mut header_end = None;

    // Read until we find the end of headers (\r\n\r\n)
    loop {
        let n = match client_tls.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                warn!("Failed to read decrypted request for {}: {}", domain, e);
                return Ok(());
            }
        };
        request_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&request_buf) {
            header_end = Some(pos);
            break;
        }
        // Safety limit: 64KB for headers alone
        if request_buf.len() > 65536 {
            break;
        }
    }

    if request_buf.is_empty() {
        return Ok(());
    }

    // If we found headers, read remaining body based on Content-Length or chunked encoding
    if let Some(hdr_end) = header_end {
        let body_start = hdr_end + 4; // after \r\n\r\n
        let header_str = String::from_utf8_lossy(&request_buf[..hdr_end]);
        let expected_body = if let Some(cl) = parse_content_length(&header_str) {
            Some(cl)
        } else if is_chunked(&header_str) {
            // For chunked encoding, read until we see "0\r\n\r\n" terminator
            None
        } else {
            // No body expected
            Some(0)
        };

        match expected_body {
            Some(content_length) if content_length > 0 => {
                let body_so_far = request_buf.len() - body_start;
                let remaining = content_length.saturating_sub(body_so_far);
                // Cap at 10MB to prevent unbounded allocation
                let remaining = remaining.min(10 * 1024 * 1024);
                let mut left = remaining;
                while left > 0 {
                    let to_read = left.min(tmp.len());
                    let n = match client_tls.read(&mut tmp[..to_read]).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    request_buf.extend_from_slice(&tmp[..n]);
                    left -= n;
                }
            }
            None => {
                // Chunked transfer encoding: read until "0\r\n\r\n" terminator or 10MB cap
                let max_body = 10 * 1024 * 1024;
                loop {
                    if request_buf.len() > max_body + body_start {
                        break;
                    }
                    // Check for chunked terminator "0\r\n\r\n" in body portion
                    let body_portion = &request_buf[body_start..];
                    if body_portion.windows(5).any(|w| w == b"0\r\n\r\n") {
                        break;
                    }
                    let n = match client_tls.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    request_buf.extend_from_slice(&tmp[..n]);
                }
                // Decode chunked body and reconstruct request with Content-Length
                let decoded = {
                    let chunked_data = &request_buf[body_start..];
                    decode_chunked_body(chunked_data, max_body)
                };
                if let Ok(decoded) = decoded {
                    // Fix headers: remove Transfer-Encoding, add Content-Length, replace body
                    fix_headers_after_chunked_decode(&mut request_buf, body_start, &decoded);
                }
            }
            _ => {} // No body
        }
    }

    let raw_request = &request_buf[..];

    // Parse method and path from decrypted request
    let request_str = String::from_utf8_lossy(raw_request);
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("UNKNOWN");
    let path = parts.get(1).copied().unwrap_or("/");

    // Extract body for audit logging
    let mitm_body = extract_body(raw_request);

    // Step 4: DLP scan
    if let Some(ref scanner) = ctx.dlp_scanner {
        if let Some(body) = mitm_body {
            let findings = scanner.scan(body);
            let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
            if has_critical {
                for f in &findings {
                    warn!(
                        "MITM DLP {:?} finding in {} https://{}{}: pattern={}, match={}",
                        f.severity, method, domain, path, f.pattern_name, f.matched_text
                    );
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
            // Non-critical findings: log but allow
            for f in &findings {
                warn!(
                    "MITM DLP {:?} finding in {} https://{}{}: pattern={}, match={}",
                    f.severity, method, domain, path, f.pattern_name, f.matched_text
                );
            }
        }
    }

    // Step 5: TLS-connect to the real upstream server (reuse cached ClientConfig)
    let tls_config = ctx
        .upstream_tls_config
        .as_ref()
        .expect("upstream_tls_config must be set in MITM mode")
        .clone();
    let connector = tokio_rustls::TlsConnector::from(tls_config);

    let remote_tcp = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to connect to upstream {}: {}", target, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_tls.write_all(response.as_bytes()).await;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }
    };

    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string()).map_err(|e| {
        crate::error::AgentShieldError::Proxy(format!("Invalid server name: {}", e))
    })?;

    let mut remote_tls = match connector.connect(server_name, remote_tcp).await {
        Ok(s) => s,
        Err(e) => {
            warn!("TLS handshake with upstream {} failed: {}", target, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_tls.write_all(response.as_bytes()).await;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }
    };

    // Step 6: Forward decrypted request to upstream
    if let Err(e) = remote_tls.write_all(raw_request).await {
        warn!("Failed to forward request to {}: {}", target, e);
        let _ = client_tls.shutdown().await;
        return Ok(());
    }

    // Step 7: Stream upstream response back to client
    let (mut remote_read, _remote_write) = tokio::io::split(remote_tls);
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let _ = tokio::io::copy(&mut remote_read, &mut client_write).await;

    // Drain any remaining client data (keep-alive cleanup)
    let _ = client_read.read(&mut [0u8; 0]).await;

    info!("MITM {} https://{}{}", method, domain, path);
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

/// Find the end of HTTP headers (\r\n\r\n) in a buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse Content-Length value from HTTP headers string.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((key, val)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("content-length") {
                return val.trim().parse().ok();
            }
        }
    }
    None
}

/// After decoding chunked body, fix headers: remove Transfer-Encoding and add Content-Length.
fn fix_headers_after_chunked_decode(request_buf: &mut Vec<u8>, body_start: usize, decoded: &[u8]) {
    let header_str = String::from_utf8_lossy(&request_buf[..body_start]).into_owned();
    let fixed_lines: Vec<&str> = header_str
        .split("\r\n")
        .filter(|line| {
            if line.is_empty() {
                return false;
            }
            if let Some((key, _)) = line.split_once(':') {
                if key.trim().eq_ignore_ascii_case("transfer-encoding") {
                    return false;
                }
            }
            true
        })
        .collect();

    request_buf.clear();
    for line in &fixed_lines {
        request_buf.extend_from_slice(line.as_bytes());
        request_buf.extend_from_slice(b"\r\n");
    }
    request_buf.extend_from_slice(format!("Content-Length: {}\r\n", decoded.len()).as_bytes());
    request_buf.extend_from_slice(b"\r\n");
    request_buf.extend_from_slice(decoded);
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

/// Parse host and port from an absolute URI like "http://example.com:8080/path"
fn parse_host_port(uri: &str) -> crate::error::Result<(String, u16)> {
    let is_https = uri.starts_with("https://");
    let default_port: u16 = if is_https { 443 } else { 80 };

    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else {
        uri
    };

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().unwrap_or(default_port);
        Ok((host.to_string(), port))
    } else {
        Ok((host_port.to_string(), default_port))
    }
}

/// Parse the path from an absolute URI
fn parse_path(uri: &str) -> String {
    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else if let Some(rest) = uri.strip_prefix("https://") {
        rest
    } else {
        uri
    };

    if let Some(pos) = without_scheme.find('/') {
        without_scheme[pos..].to_string()
    } else {
        "/".to_string()
    }
}

/// Check if the request uses chunked transfer encoding.
fn is_chunked(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':')
            .map(|(key, val)| {
                key.trim().eq_ignore_ascii_case("transfer-encoding")
                    && val.trim().eq_ignore_ascii_case("chunked")
            })
            .unwrap_or(false)
    })
}

/// Decode a chunked-encoded body from a byte slice.
/// Returns an error if the decoded body exceeds `max_size`.
fn decode_chunked_body(data: &[u8], max_size: usize) -> crate::error::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 0;

    loop {
        // Find end of chunk size line
        let size_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p);

        let size_end = match size_end {
            Some(e) => e,
            None => break,
        };

        // Parse chunk size (hex), ignoring optional chunk extensions after ';'
        let size_str = std::str::from_utf8(&data[pos..size_end]).unwrap_or("0");
        let size_part = size_str.split(';').next().unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_part.trim(), 16).unwrap_or(0);

        if chunk_size == 0 {
            break;
        }

        if result.len() + chunk_size > max_size {
            return Err(crate::error::AgentShieldError::Proxy(format!(
                "Chunked body exceeds max size ({} bytes)",
                max_size
            )));
        }

        let chunk_start = size_end + 2; // skip \r\n after size
        let chunk_end = chunk_start + chunk_size;
        if chunk_end > data.len() {
            break;
        }

        result.extend_from_slice(&data[chunk_start..chunk_end]);
        pos = chunk_end + 2; // skip \r\n after chunk data
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_scheme() {
        let (host, port) = parse_host_port("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_with_explicit_port() {
        let (host, port) = parse_host_port("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_https() {
        let (host, port) = parse_host_port("https://api.anthropic.com/v1/messages").unwrap();
        assert_eq!(host, "api.anthropic.com");
        assert_eq!(port, 443);
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: Some(tx),
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
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
    fn find_header_end_found() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        assert_eq!(find_header_end(buf), Some(33));
    }

    #[test]
    fn find_header_end_not_found() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(find_header_end(buf), None);
    }

    #[test]
    fn parse_content_length_standard() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 42\r\nHost: x";
        assert_eq!(parse_content_length(headers), Some(42));
    }

    #[test]
    fn parse_content_length_lowercase() {
        let headers = "POST / HTTP/1.1\r\ncontent-length: 100\r\nHost: x";
        assert_eq!(parse_content_length(headers), Some(100));
    }

    #[test]
    fn parse_content_length_missing() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com";
        assert_eq!(parse_content_length(headers), None);
    }

    #[test]
    fn is_chunked_true() {
        let headers = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: x";
        assert!(is_chunked(headers));
    }

    #[test]
    fn is_chunked_false() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 42\r\nHost: x";
        assert!(!is_chunked(headers));
    }

    #[test]
    fn is_chunked_case_insensitive() {
        let headers = "POST / HTTP/1.1\r\ntransfer-encoding: Chunked\r\nHost: x";
        assert!(is_chunked(headers));
    }

    #[test]
    fn decode_chunked_body_simple() {
        // "5\r\nhello\r\n0\r\n\r\n"
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let result = decode_chunked_body(input, 1024).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn decode_chunked_body_multiple_chunks() {
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let result = decode_chunked_body(input, 1024).unwrap();
        assert_eq!(result, b"hello world");
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: None,
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
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
            dlp_scanner: None,
            system_allowlist: None,
            notifier: None,
            event_tx: None,
            rate_limiter: None,
            mitm_enabled: false,
            cert_cache: None,
            upstream_tls_config: None,
            logging_config: Some(config),
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
    fn decode_chunked_body_exceeds_limit() {
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let result = decode_chunked_body(input, 3);
        assert!(result.is_err());
    }

    #[test]
    fn decode_chunked_body_with_extension() {
        // RFC 7230: chunk-size can be followed by ";ext=value"
        let input = b"5;ext=val\r\nhello\r\n0\r\n\r\n";
        let result = decode_chunked_body(input, 1024).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn fix_headers_removes_transfer_encoding_adds_content_length() {
        let mut buf =
            b"POST /api HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        let body_start = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let decoded = b"hello world";
        fix_headers_after_chunked_decode(&mut buf, body_start, decoded);

        let result = String::from_utf8_lossy(&buf);
        assert!(!result.contains("Transfer-Encoding"));
        assert!(result.contains("Content-Length: 11"));
        assert!(result.contains("hello world"));
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

    #[test]
    fn is_chunked_mixed_case() {
        let headers = "POST / HTTP/1.1\r\nTRANSFER-ENCODING: CHUNKED\r\nHost: x";
        assert!(is_chunked(headers));
    }

    #[test]
    fn parse_content_length_mixed_case() {
        let headers = "POST / HTTP/1.1\r\nCONTENT-LENGTH: 99\r\nHost: x";
        assert_eq!(parse_content_length(headers), Some(99));
    }
}
