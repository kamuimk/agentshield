use std::path::Path;

use agentshield::cli::{Cli, Commands, PolicyAction};
use agentshield::logging;
use agentshield::policy::config::AppConfig;
use agentshield::proxy::ProxyServer;
use clap::Parser;

fn db_path() -> std::path::PathBuf {
    dirs_path().join("agentshield.db")
}

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
        } => {
            cmd_logs(tail, export, &format)?;
        }
        Commands::Policy { action } => match action {
            PolicyAction::Show => cmd_policy_show(&cli.config)?,
            PolicyAction::Add => cmd_policy_add()?,
            PolicyAction::Template { name } => cmd_policy_template(&cli.config, &name)?,
        },
        Commands::Init => {
            cmd_init(&cli.config)?;
        }
    }

    Ok(())
}

async fn cmd_start(config_path: &Path) -> anyhow::Result<()> {
    let config = AppConfig::load_from_path(config_path)?;
    println!("AgentShield starting...");
    println!("Config: {}", config_path.display());
    println!("Listen: {}", config.proxy.listen);
    println!("Default policy: {:?}", config.policy.default);
    println!("Rules loaded: {}", config.policy.rules.len());

    let server = ProxyServer::new(config.proxy.listen.clone());
    let addr = server.start().await?;
    println!("Proxy running on {}", addr);
    println!("Set HTTPS_PROXY=http://{} to route traffic through AgentShield", addr);

    // Keep running until interrupted
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");
    Ok(())
}

fn cmd_stop() -> anyhow::Result<()> {
    println!("Stopping AgentShield proxy...");
    let pid_path = dirs_path().join("agentshield.pid");
    if pid_path.exists() {
        let pid_str = std::fs::read_to_string(&pid_path)?;
        println!("Stopping process {}", pid_str.trim());
        std::fs::remove_file(&pid_path)?;
    } else {
        println!("No running AgentShield instance found.");
    }
    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let db = db_path();
    if db.exists() {
        let conn = logging::open_db(&db)?;
        let total_logs = logging::query_recent(&conn, usize::MAX)?;
        let allowed = total_logs.iter().filter(|l| l.action == "allow").count();
        let denied = total_logs.iter().filter(|l| l.action == "deny").count();
        let asked = total_logs.iter().filter(|l| l.action == "ask").count();

        println!("AgentShield Status");
        println!("──────────────────");
        println!("Total requests: {}", total_logs.len());
        println!("  Allowed: {}", allowed);
        println!("  Denied:  {}", denied);
        println!("  Asked:   {}", asked);
    } else {
        println!("AgentShield Status: No log database found.");
        println!("Run 'agentshield start' to begin monitoring.");
    }
    Ok(())
}

fn cmd_logs(tail: usize, export: bool, format: &str) -> anyhow::Result<()> {
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
                "{:<20} {:<8} {:<30} {:<30} {:<8} {}",
                "TIMESTAMP", "METHOD", "DOMAIN", "PATH", "ACTION", "REASON"
            );
            println!("{}", "─".repeat(120));
            for log in &logs {
                println!(
                    "{:<20} {:<8} {:<30} {:<30} {:<8} {}",
                    log.timestamp, log.method, log.domain, log.path, log.action, log.reason
                );
            }
        }
    }
    Ok(())
}

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

fn cmd_policy_add() -> anyhow::Result<()> {
    println!("Interactive policy rule addition is not yet implemented.");
    println!("Edit agentshield.toml directly or use 'agentshield policy template'.");
    Ok(())
}

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

fn cmd_init(config_path: &Path) -> anyhow::Result<()> {
    println!("Initializing AgentShield...");

    // Create data directory
    let data_dir = dirs_path();
    std::fs::create_dir_all(&data_dir)?;
    println!("  Created data dir: {}", data_dir.display());

    // Initialize database
    let db = db_path();
    logging::open_db(&db)?;
    println!("  Initialized database: {}", db.display());

    // Create default config if not exists
    if !config_path.exists() {
        let default_config = include_str!("../templates/strict.toml");
        std::fs::write(config_path, default_config)?;
        println!("  Created config: {}", config_path.display());
    } else {
        println!("  Config already exists: {}", config_path.display());
    }

    println!("\nDone! Next steps:");
    println!("  1. Apply a template: agentshield policy template openclaw-default");
    println!("  2. Start the proxy:  agentshield start");
    println!("  3. Set env variable: HTTPS_PROXY=http://127.0.0.1:18080");
    Ok(())
}
