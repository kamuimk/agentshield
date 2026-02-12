pub mod integrate;
pub mod prompt;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentshield")]
#[command(about = "AI Agent Egress Firewall - Default-deny egress control for AI agents")]
#[command(version)]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "agentshield.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy server
    Start {
        /// Run as daemon in the background
        #[arg(long)]
        daemon: bool,
    },
    /// Stop the proxy server
    Stop,
    /// Show proxy status
    Status,
    /// View request logs
    Logs {
        /// Show last N entries
        #[arg(long, default_value = "50")]
        tail: usize,
        /// Export logs
        #[arg(long)]
        export: bool,
        /// Export format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Initialize AgentShield configuration
    Init,
    /// Integrate with external applications
    Integrate {
        #[command(subcommand)]
        target: IntegrateTarget,
    },
}

#[derive(Subcommand)]
pub enum IntegrateTarget {
    /// Integrate with OpenClaw (set Telegram proxy)
    Openclaw,
    /// Remove integration from OpenClaw
    Remove,
}

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Show current policy
    Show,
    /// Add a new policy rule (interactive)
    Add,
    /// Apply a policy template
    Template {
        /// Template name (e.g., openclaw-default, claude-code-default, strict)
        name: String,
    },
}
