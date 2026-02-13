//! # AgentShield
//!
//! **Default-deny egress firewall for AI agents.**
//!
//! AgentShield is a local HTTP/HTTPS proxy that intercepts outbound requests from
//! AI agents (e.g., Claude Code, OpenClaw) and enforces configurable security policies.
//!
//! ## Architecture
//!
//! - **[`proxy`]** — TCP proxy server handling HTTP and HTTPS CONNECT tunneling
//! - **[`policy`]** — TOML-based configuration and rule evaluation engine
//! - **[`dlp`]** — Data Loss Prevention scanner detecting secrets and PII in request bodies
//! - **[`logging`]** — SQLite-backed request logging with JSON/CSV export
//! - **[`notification`]** — Async notification system (Telegram) for deny/DLP events
//! - **[`cli`]** — Command-line interface (clap) and interactive approval prompt
//! - **[`error`]** — Unified error types using `thiserror`
//!
//! ## Quick Start
//!
//! ```bash
//! # Initialize configuration and database
//! agentshield init
//!
//! # Apply a policy template
//! agentshield policy template openclaw-default
//!
//! # Start the proxy
//! agentshield start
//!
//! # Route AI agent traffic through the proxy
//! export HTTPS_PROXY=http://127.0.0.1:18080
//! ```

pub mod cli;
pub mod dlp;
pub mod error;
pub mod logging;
pub mod notification;
pub mod policy;
pub mod proxy;
