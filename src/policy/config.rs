//! TOML configuration types for AgentShield.
//!
//! The top-level [`AppConfig`] is deserialized from `agentshield.toml` and contains
//! sections for proxy settings, policy rules, DLP, system allowlist, and notifications.
//!
//! # Example `agentshield.toml`
//!
//! ```toml
//! [proxy]
//! listen = "127.0.0.1:18080"
//! mode = "transparent"
//!
//! [policy]
//! default = "deny"
//!
//! [[policy.rules]]
//! name = "anthropic"
//! domains = ["api.anthropic.com"]
//! action = "allow"
//! ```

use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{AgentShieldError, Result};

/// The action to take when a request matches a policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Permit the request to proceed.
    Allow,
    /// Block the request and return 403 Forbidden.
    Deny,
    /// Prompt the user for an interactive allow/deny decision.
    Ask,
}

/// Proxy server configuration (`[proxy]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Address to listen on (e.g., `"127.0.0.1:18080"`).
    pub listen: String,
    /// Proxy mode (currently only `"transparent"` is supported).
    pub mode: String,
}

/// A single policy rule that matches requests by domain and optional HTTP method.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// Human-readable rule name (e.g., `"anthropic-api"`).
    pub name: String,
    /// Domain patterns to match. Supports `"*"` (wildcard) and `"*.example.com"` (subdomain).
    pub domains: Vec<String>,
    /// Optional HTTP method filter (e.g., `["GET"]`). If `None`, matches all methods.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Action to take when this rule matches.
    pub action: Action,
    /// Optional note for documentation purposes.
    #[serde(default)]
    pub note: Option<String>,
}

/// Policy configuration (`[policy]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    /// Default action when no rule matches.
    pub default: Action,
    /// Ordered list of rules; first match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Data Loss Prevention configuration (`[dlp]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpConfig {
    /// Whether DLP scanning is active.
    pub enabled: bool,
    /// Optional subset of built-in pattern names to use. If `None`, all patterns are active.
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
}

/// System-level configuration (`[system]` section).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SystemConfig {
    /// Domains that bypass policy evaluation entirely (e.g., internal services).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Telegram Bot API configuration (nested under `[notification.telegram]`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelegramConfig {
    /// Bot API token from @BotFather.
    pub bot_token: String,
    /// Target chat or channel ID.
    pub chat_id: String,
    /// Event types to send (reserved for future filtering).
    #[serde(default)]
    pub events: Vec<String>,
}

/// Notification configuration (`[notification]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotificationConfig {
    /// Whether notifications are active.
    #[serde(default)]
    pub enabled: bool,
    /// Optional Telegram backend configuration.
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
}

/// Top-level application configuration deserialized from `agentshield.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// Proxy server settings.
    pub proxy: ProxyConfig,
    /// Policy rules and default action.
    pub policy: PolicyConfig,
    /// Optional DLP scanner configuration.
    #[serde(default)]
    pub dlp: Option<DlpConfig>,
    /// Optional system allowlist configuration.
    #[serde(default)]
    pub system: Option<SystemConfig>,
    /// Optional notification configuration.
    #[serde(default)]
    pub notification: Option<NotificationConfig>,
}

impl AppConfig {
    /// Load and parse the configuration from a TOML file at the given path.
    ///
    /// Before parsing, `${VAR}` and `$VAR` placeholders in the TOML text are
    /// replaced with the corresponding environment variable values. An error is
    /// returned if a referenced variable is not set.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let content = substitute_env_vars(&content)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

/// Replace `${VAR_NAME}` and `$VAR_NAME` placeholders with environment variable values.
///
/// Returns an error containing the variable name if the variable is not set.
fn substitute_env_vars(input: &str) -> Result<String> {
    // Match ${VAR_NAME} (braces form)
    let re_braces = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap();
    // Match $VAR_NAME (no braces, uppercase + underscore only to avoid false positives)
    let re_bare = Regex::new(r"\$([A-Z_][A-Z0-9_]*)").unwrap();

    let mut result = input.to_string();

    // First pass: ${VAR} form
    for cap in re_braces.captures_iter(input) {
        let var_name = &cap[1];
        let value = std::env::var(var_name)
            .map_err(|_| AgentShieldError::ConfigEnvVar(var_name.to_string()))?;
        result = result.replace(&cap[0], &value);
    }

    // Second pass: $VAR form (on already-substituted string, but only matches remaining $VAR)
    let intermediate = result.clone();
    for cap in re_bare.captures_iter(&intermediate) {
        let full_match = &cap[0];
        // Skip if this was part of a ${...} that was already handled (shouldn't happen after replacement)
        let var_name = &cap[1];
        let value = std::env::var(var_name)
            .map_err(|_| AgentShieldError::ConfigEnvVar(var_name.to_string()))?;
        result = result.replace(full_match, &value);
    }

    Ok(result)
}
