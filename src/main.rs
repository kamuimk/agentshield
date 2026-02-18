//! AgentShield CLI entry point.
//!
//! Parses command-line arguments via [`clap`] and dispatches to the appropriate
//! handler: `start`, `stop`, `status`, `logs`, `policy`, `init`, or `integrate`.

use std::path::Path;
use std::sync::Arc;

use agentshield::ask::AskBroadcaster;
use agentshield::ask::telegram::TelegramResponder;
use agentshield::ask::terminal::TerminalResponder;
use agentshield::cli::ca;
use agentshield::cli::integrate;
use agentshield::cli::{CaAction, Cli, Commands, IntegrateTarget, PolicyAction};
use agentshield::dlp::DlpScanner;
use agentshield::dlp::patterns::RegexScanner;
use agentshield::logging::{self, LogEvent};
use agentshield::notification::FilteredNotifier;
use agentshield::notification::Notifier;
use agentshield::notification::telegram::TelegramNotifier;
use agentshield::policy::config::AppConfig;
use agentshield::policy::reload;
use agentshield::proxy::ProxyServer;
use agentshield::proxy::tls::CertCache;
use agentshield::ratelimit::RateLimiter;
use agentshield::web;
use agentshield::web::ask::{AskState, PendingAsks, WebDashboardResponder};
use clap::Parser;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Return the path to the SQLite log database (`~/.agentshield/agentshield.db`).
fn db_path() -> std::path::PathBuf {
    dirs_path().join("agentshield.db")
}

/// Return (and lazily create) the AgentShield data directory (`~/.agentshield/`).
fn dirs_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = std::path::PathBuf::from(home).join(".agentshield");
    std::fs::create_dir_all(&dir).ok();
    dir
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { daemon: _ } => {
            cmd_start(&cli.config).await?;
        }
        Commands::Stop => {
            cmd_stop()?;
        }
        Commands::Status => {
            cmd_status()?;
        }
        Commands::Logs {
            tail,
            export,
            format,
            show_body,
        } => {
            cmd_logs(tail, export, &format, show_body)?;
        }
        Commands::Policy { action } => match action {
            PolicyAction::Show => cmd_policy_show(&cli.config)?,
            PolicyAction::Add => cmd_policy_add()?,
            PolicyAction::Template { name } => cmd_policy_template(&cli.config, &name)?,
        },
        Commands::Init => {
            cmd_init(&cli.config)?;
        }
        Commands::Integrate { target } => match target {
            IntegrateTarget::Openclaw => integrate::cmd_integrate_openclaw()?,
            IntegrateTarget::ClaudeCode { ca_cert } => {
                integrate::cmd_integrate_claude_code(ca_cert.as_deref())?
            }
            IntegrateTarget::Remove => integrate::cmd_integrate_remove()?,
            IntegrateTarget::RemoveClaudeCode => integrate::cmd_integrate_remove_claude_code()?,
        },
        Commands::Dashboard => {
            cmd_dashboard(&cli.config)?;
        }
        Commands::Ca { action } => {
            use agentshield::cli::ca;
            let ca_dir = ca::ca_dir();
            match action {
                CaAction::Init => ca::cmd_ca_init(&ca_dir)?,
                CaAction::Trust => ca::cmd_ca_trust(&ca_dir)?,
                CaAction::Show => ca::cmd_ca_show(&ca_dir)?,
                CaAction::Export { path } => ca::cmd_ca_export(&ca_dir, &path)?,
            }
        }
    }

    Ok(())
}

/// Start the proxy server with the given configuration.
///
/// This function orchestrates the full startup sequence:
/// 1. Load and validate the TOML configuration
/// 2. Open a SQLite connection pool for request logging
/// 3. Set up an async channel for interactive ASK prompts (stdin/stdout)
/// 4. Optionally enable the system allowlist, DLP scanner, and Telegram notifier
/// 5. Bind the TCP listener and enter the accept loop
/// 6. Block until Ctrl-C is received
async fn cmd_start(config_path: &Path) -> anyhow::Result<()> {
    let config = AppConfig::load_from_path(config_path)?;
    info!("AgentShield starting...");
    info!("Config: {}", config_path.display());
    info!("Listen: {}", config.proxy.listen);
    info!("Default policy: {:?}", config.policy.default);
    info!("Rules loaded: {}", config.policy.rules.len());

    let db = db_path();
    let pool = logging::open_pool(&db)?;

    // Shared policy state for hot-reload
    let policy = Arc::new(RwLock::new(config.policy.clone()));

    // Broadcast channel for real-time log events (SSE, web dashboard)
    let (event_tx, _event_rx) = broadcast::channel::<LogEvent>(1024);

    // ASK broadcaster: broadcasts ASK requests to all registered responders
    let mut broadcaster = AskBroadcaster::new(120);
    let terminal = Arc::new(TerminalResponder::new(config_path.to_path_buf()));
    broadcaster.add_responder(terminal);

    // Pending ASK state (shared between WebDashboardResponder and web server)
    let pending_asks: PendingAsks = Arc::new(Mutex::new(HashMap::new()));
    let (ask_event_tx, _ask_event_rx) = broadcast::channel(256);

    // Add TelegramResponder if interactive mode is enabled
    if let Some(ref notif_config) = config.notification {
        if notif_config.enabled {
            if let Some(ref tg) = notif_config.telegram {
                if tg.interactive {
                    let tg_responder = Arc::new(TelegramResponder::new(
                        tg.bot_token.clone(),
                        tg.chat_id.clone(),
                    ));
                    broadcaster.add_responder(tg_responder);
                    info!("Telegram ASK responder enabled (interactive mode)");
                }
            }
        }
    }

    // Add WebDashboardResponder if web is enabled
    if let Some(ref web_config) = config.web {
        if web_config.enabled {
            let web_responder = Arc::new(WebDashboardResponder::new(
                pending_asks.clone(),
                ask_event_tx.clone(),
            ));
            broadcaster.add_responder(web_responder);
            info!("Web dashboard ASK responder enabled");
        }
    }

    let broadcaster = Arc::new(broadcaster);

    // Create rate limiter if any policy rule has rate_limit configured
    let has_rate_limits = {
        let p = policy.read().unwrap();
        p.rules.iter().any(|r| r.rate_limit.is_some())
    };
    let rate_limiter = if has_rate_limits {
        info!("Rate limiting enabled");
        Some(Arc::new(RateLimiter::new()))
    } else {
        None
    };

    let mut server = ProxyServer::new(config.proxy.listen.clone())
        .with_policy(policy.clone())
        .with_db(pool.clone())
        .with_ask_broadcaster(broadcaster)
        .with_event_channel(event_tx.clone());

    if let Some(limiter) = rate_limiter {
        server = server.with_rate_limiter(limiter);
    }

    // Apply system allowlist if configured
    if let Some(ref system) = config.system {
        if !system.allowlist.is_empty() {
            info!("System allowlist: {:?}", system.allowlist);
            server = server.with_system_allowlist(system.allowlist.clone());
        }
    }

    // Initialize MITM mode if configured
    if config.proxy.mode == agentshield::policy::config::ProxyMode::Mitm {
        let ca_path = config
            .proxy
            .ca_dir
            .as_deref()
            .map(expand_tilde)
            .unwrap_or_else(ca::ca_dir);
        match CertCache::load(&ca_path) {
            Ok(cache) => {
                info!("MITM mode enabled (CA: {})", ca_path.display());
                server = server.with_cert_cache(Arc::new(cache));
            }
            Err(e) => {
                error!(
                    "Failed to load CA for MITM: {}. Falling back to transparent mode.",
                    e
                );
            }
        }
    }

    // Initialize DLP scanner if enabled in config
    if let Some(ref dlp_config) = config.dlp {
        if dlp_config.enabled {
            let scanner: Arc<dyn DlpScanner> = match &dlp_config.patterns {
                Some(patterns) => Arc::new(RegexScanner::with_patterns(patterns)),
                None => Arc::new(RegexScanner::new()),
            };
            info!("DLP scanner enabled");
            server = server.with_dlp(scanner);
        }
    }

    // Apply audit logging config if configured
    if let Some(ref logging_config) = config.logging {
        if logging_config.audit {
            info!(
                "Audit logging enabled (max_body_size: {} bytes)",
                logging_config.audit_max_body_size
            );
            server = server.with_logging_config(logging_config.clone());
        }
    }

    // Initialize notification if configured
    if let Some(ref notif_config) = config.notification {
        if notif_config.enabled {
            if let Some(ref tg) = notif_config.telegram {
                let inner: Arc<dyn Notifier> = Arc::new(TelegramNotifier::new(
                    tg.bot_token.clone(),
                    tg.chat_id.clone(),
                ));
                let notifier: Arc<dyn Notifier> = if tg.events.is_empty() {
                    info!(
                        "Telegram notification enabled (chat_id: {}, events: all)",
                        tg.chat_id
                    );
                    inner
                } else {
                    info!(
                        "Telegram notification enabled (chat_id: {}, events: {:?})",
                        tg.chat_id, tg.events
                    );
                    Arc::new(FilteredNotifier::new(inner, tg.events.clone()))
                };
                server = server.with_notifier(notifier);
            }
        }
    }

    let addr = server.start().await?;
    info!("Proxy running on {}", addr);
    info!(
        "Set HTTPS_PROXY=http://{} to route traffic through AgentShield",
        addr
    );

    // Start web dashboard if enabled
    if let Some(ref web_config) = config.web {
        if web_config.enabled {
            let web_state = Arc::new(web::AppState {
                db: Some(pool),
                event_tx: event_tx.clone(),
                policy: Some(policy.clone()),
                auth_token: web_config.auth_token.clone(),
            });
            let ask_state = AskState {
                pending: pending_asks,
                ask_event_tx,
            };
            let listen = web_config.listen.clone();
            tokio::spawn(async move {
                let app = web::full_router(web_state, ask_state);
                match tokio::net::TcpListener::bind(&listen).await {
                    Ok(listener) => {
                        info!("Web dashboard listening on {}", listen);
                        if let Err(e) = axum::serve(listener, app).await {
                            error!("Web dashboard server error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to bind web dashboard on {}: {}", listen, e);
                    }
                }
            });
        }
    }

    // Policy hot-reload: file watcher + SIGHUP handler
    let _watcher = reload::start_file_watcher(config_path.to_path_buf(), policy.clone())
        .map_err(|e| {
            warn!("Failed to start config file watcher: {}", e);
            e
        })
        .ok();
    reload::start_sighup_handler(config_path.to_path_buf(), policy);

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    Ok(())
}

/// Stop a running AgentShield instance by removing its PID file.
fn cmd_stop() -> anyhow::Result<()> {
    info!("Stopping AgentShield proxy...");
    let pid_path = dirs_path().join("agentshield.pid");
    if pid_path.exists() {
        let pid_str = std::fs::read_to_string(&pid_path)?;
        info!("Stopping process {}", pid_str.trim());
        std::fs::remove_file(&pid_path)?;
    } else {
        println!("No running AgentShield instance found.");
    }
    Ok(())
}

/// Display a summary of logged requests using SQL aggregation.
fn cmd_status() -> anyhow::Result<()> {
    let db = db_path();
    if db.exists() {
        let conn = logging::open_db(&db)?;
        let stats = logging::query_stats(&conn)?;

        println!("AgentShield Status");
        println!("──────────────────");
        println!("Total requests: {}", stats.total);
        println!("  Allowed:        {}", stats.allowed);
        println!("  Denied:         {}", stats.denied);
        println!("  Asked:          {}", stats.asked);
        println!("  System-allowed: {}", stats.system_allowed);
        println!("  Rate-limited:   {}", stats.rate_limited);
    } else {
        println!("AgentShield Status: No log database found.");
        println!("Run 'agentshield start' to begin monitoring.");
    }
    Ok(())
}

/// View recent request logs or export all logs as JSON/CSV.
fn cmd_logs(tail: usize, export: bool, format: &str, show_body: bool) -> anyhow::Result<()> {
    let db = db_path();
    if !db.exists() {
        println!("No log database found. Run 'agentshield start' first.");
        return Ok(());
    }

    let conn = logging::open_db(&db)?;

    if export {
        match format {
            "csv" => {
                let csv = logging::export::export_csv(&conn)?;
                print!("{}", csv);
            }
            _ => {
                let json = logging::export::export_json(&conn)?;
                println!("{}", json);
            }
        }
    } else {
        let logs = logging::query_recent(&conn, tail)?;
        if logs.is_empty() {
            println!("No log entries found.");
        } else {
            println!(
                "{:<20} {:<8} {:<30} {:<30} {:<8} REASON",
                "TIMESTAMP", "METHOD", "DOMAIN", "PATH", "ACTION"
            );
            println!("{}", "─".repeat(120));
            for log in &logs {
                println!(
                    "{:<20} {:<8} {:<30} {:<30} {:<8} {}",
                    log.timestamp, log.method, log.domain, log.path, log.action, log.reason
                );
                if show_body {
                    if let Some(ref body) = log.request_body {
                        println!("  Body: {}", body);
                    }
                    if let Some(ref findings) = log.dlp_findings {
                        println!("  DLP: {}", findings);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Display the current policy configuration (default action and all rules).
fn cmd_policy_show(config_path: &Path) -> anyhow::Result<()> {
    let config = AppConfig::load_from_path(config_path)?;
    println!("Current Policy ({})", config_path.display());
    println!("═══════════════════════════════════════");
    println!("Default action: {:?}", config.policy.default);
    println!("Rules ({}):", config.policy.rules.len());
    for rule in &config.policy.rules {
        let methods = rule
            .methods
            .as_ref()
            .map(|m| m.join(", "))
            .unwrap_or_else(|| "*".to_string());
        println!(
            "  [{}] {} → {:?} (methods: {})",
            rule.name,
            rule.domains.join(", "),
            rule.action,
            methods
        );
    }
    Ok(())
}

/// Placeholder for interactive policy rule addition (not yet implemented).
fn cmd_policy_add() -> anyhow::Result<()> {
    println!("Interactive policy rule addition is not yet implemented.");
    println!("Edit agentshield.toml directly or use 'agentshield policy template'.");
    Ok(())
}

/// Apply a built-in policy template to the config file.
///
/// Available templates: `openclaw-default`, `claude-code-default`, `strict`.
fn cmd_policy_template(config_path: &Path, name: &str) -> anyhow::Result<()> {
    let template_content = match name {
        "openclaw-default" => include_str!("../templates/openclaw-default.toml"),
        "claude-code-default" => include_str!("../templates/claude-code-default.toml"),
        "strict" => include_str!("../templates/strict.toml"),
        _ => {
            println!("Unknown template: {}", name);
            println!("Available templates: openclaw-default, claude-code-default, strict");
            return Ok(());
        }
    };

    std::fs::write(config_path, template_content)?;
    println!("Applied template '{}' to {}", name, config_path.display());
    Ok(())
}

/// Initialize AgentShield: create data directory, database, and default config.
fn cmd_init(config_path: &Path) -> anyhow::Result<()> {
    info!("Initializing AgentShield...");

    // Create data directory
    let data_dir = dirs_path();
    std::fs::create_dir_all(&data_dir)?;
    info!("Created data dir: {}", data_dir.display());

    // Initialize database
    let db = db_path();
    logging::open_db(&db)?;
    info!("Initialized database: {}", db.display());

    // Create default config if not exists
    if !config_path.exists() {
        let default_config = include_str!("../templates/strict.toml");
        std::fs::write(config_path, default_config)?;
        info!("Created config: {}", config_path.display());
    } else {
        info!("Config already exists: {}", config_path.display());
    }

    println!("\nDone! Next steps:");
    println!("  1. Apply a template: agentshield policy template openclaw-default");
    println!("  2. Start the proxy:  agentshield start");
    println!("  3. Set env variable: HTTPS_PROXY=http://127.0.0.1:18080");
    Ok(())
}

/// Open the web dashboard in the default browser.
///
/// Reads the config to determine the web dashboard address, then launches
/// the platform-appropriate browser command (`open` on macOS, `xdg-open`
/// on Linux, `start` on Windows).
fn cmd_dashboard(config_path: &Path) -> anyhow::Result<()> {
    let config = AppConfig::load_from_path(config_path)?;
    match config.web {
        Some(ref web) if web.enabled => {
            let url = format!("http://{}", web.listen);
            println!("Opening dashboard: {}", url);
            open_browser(&url)?;
        }
        _ => {
            println!("Web dashboard is not enabled.");
            println!("Add [web] section with enabled = true to your config.");
        }
    }
    Ok(())
}

/// Expand `~` at the start of a path to the user's home directory.
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    std::path::PathBuf::from(path)
}

/// Open a URL in the platform's default browser.
fn open_browser(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_with_subpath() {
        let result = expand_tilde("~/some/path");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home.join("some/path"));
    }

    #[test]
    fn expand_tilde_alone() {
        let result = expand_tilde("~");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home);
    }

    #[test]
    fn expand_tilde_no_tilde() {
        let result = expand_tilde("/absolute/path");
        assert_eq!(result, std::path::PathBuf::from("/absolute/path"));
    }
}
