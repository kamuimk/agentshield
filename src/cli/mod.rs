//! Command-line interface definitions for AgentShield.
//!
//! Uses [`clap`] derive macros to define the CLI structure. The main entry point
//! is [`Cli`], which dispatches to subcommands defined in [`Commands`].
//!
//! Submodules:
//! - [`prompt`] — Interactive approval prompt for ASK actions
//! - [`integrate`] — OpenClaw integration (set/remove Telegram proxy)

pub mod ca;
pub mod integrate;
pub mod prompt;
pub mod quickstart;
pub mod wrap;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Top-level CLI arguments parsed by `clap`.
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

/// Available CLI subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Start the proxy server
    Start {
        /// Run as daemon in the background
        #[arg(long)]
        daemon: bool,
        /// Import a Windows parent-owned listener from a private binary stdin pipe.
        #[arg(long)]
        owned_listener_stdin: bool,
        /// Receive a one-shot listener proof challenge from a local SYSTEM pipe.
        #[arg(long, requires = "owned_listener_stdin")]
        listener_proof_pipe: Option<String>,
        /// Freeze the startup policy; disable reload and dashboard control.
        #[arg(long)]
        immutable_policy: bool,
        /// Bind an immutable exact-byte configuration to a privileged v2 proof.
        #[arg(long, requires_all = ["owned_listener_stdin", "immutable_policy"], conflicts_with = "listener_proof_pipe")]
        managed_proof_pipe: Option<String>,
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
        /// Show request body (audit data)
        #[arg(long)]
        show_body: bool,
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by action (allow, deny, system-allow, rate-limited)
        #[arg(long)]
        action: Option<String>,
        /// Filter by start time (ISO 8601, e.g. 2026-02-19T00:00:00Z)
        #[arg(long)]
        since: Option<String>,
        /// Filter by end time (ISO 8601)
        #[arg(long)]
        until: Option<String>,
        /// Search across domain, path, reason, and body
        #[arg(long)]
        search: Option<String>,
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
    /// Open the web dashboard in a browser
    Dashboard,
    /// Certificate Authority management for MITM mode
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Validate the configuration file
    Validate,
    /// Wrap a command with proxy protection
    Wrap(wrap::WrapArgs),
    /// Interactive setup wizard
    Quickstart,
}

/// CA subcommands for certificate management.
#[derive(Subcommand)]
pub enum CaAction {
    /// Validate or repair the app-local CA without rotating its key or changing system trust
    Prepare,
    /// Generate a new Root CA key pair and self-signed certificate
    Init,
    /// Install the CA certificate into the system trust store
    Trust,
    /// Display CA certificate information
    Show,
    /// Export the CA certificate to a file
    Export {
        /// Destination path for the exported certificate
        path: std::path::PathBuf,
    },
}

/// Targets for the `integrate` subcommand.
#[derive(Subcommand)]
pub enum IntegrateTarget {
    /// Integrate with OpenClaw (set Telegram proxy)
    Openclaw,
    /// Integrate with Claude Code (set HTTP(S)_PROXY in ~/.claude/settings.json)
    ClaudeCode {
        /// Path to CA certificate file (for MITM mode)
        #[arg(long)]
        ca_cert: Option<String>,
    },
    /// Remove integration from OpenClaw
    Remove,
    /// Remove integration from Claude Code
    RemoveClaudeCode,
}

/// Actions for the `policy` subcommand.
#[derive(Subcommand)]
pub enum PolicyAction {
    /// Show current policy
    Show,
    /// Add a new policy rule (interactive)
    Add,
    /// Apply a policy template or list available templates
    Template {
        /// Template name to apply (omit to list available templates)
        name: Option<String>,
        /// List all available templates (built-in + community)
        #[arg(long)]
        list: bool,
    },
}

#[cfg(test)]
mod listener_proof_args_tests {
    use super::*;
    #[test]
    fn managed_proof_requires_owned_immutable_startup_and_excludes_v1() {
        for extra in [
            vec![],
            vec!["--owned-listener-stdin"],
            vec!["--immutable-policy"],
            vec![
                "--owned-listener-stdin",
                "--immutable-policy",
                "--listener-proof-pipe",
                "other",
            ],
        ] {
            let mut args = vec!["agentshield", "start", "--managed-proof-pipe", "fixture"];
            args.extend(extra);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "agentshield",
                "start",
                "--managed-proof-pipe",
                "fixture",
                "--owned-listener-stdin",
                "--immutable-policy"
            ])
            .is_ok()
        );
    }
    #[test]
    fn proof_pipe_cannot_be_enabled_without_owned_socket_import() {
        let pipe = r"\\.\pipe\AgentShield.ListenerProof.v1.00000000000000000000000000000000";
        assert!(
            Cli::try_parse_from(["agentshield", "start", "--listener-proof-pipe", pipe]).is_err()
        );
        let cli = Cli::try_parse_from([
            "agentshield",
            "start",
            "--owned-listener-stdin",
            "--listener-proof-pipe",
            pipe,
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Start {
                owned_listener_stdin: true,
                listener_proof_pipe: Some(_),
                ..
            }
        ));
    }
}
