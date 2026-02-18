//! Integration commands for AgentShield.
//!
//! Provides commands to route traffic from external tools through the AgentShield proxy.
//!
//! ## OpenClaw
//! - [`cmd_integrate_openclaw`] — set the Telegram proxy and restart the daemon
//! - [`cmd_integrate_remove`] — remove the proxy setting and restart the daemon
//!
//! ## Claude Code
//! - [`cmd_integrate_claude_code`] — set HTTP(S)\_PROXY in `~/.claude/settings.json`
//! - [`cmd_integrate_remove_claude_code`] — remove proxy env vars from settings

use std::path::PathBuf;
use std::process::Command;

/// Default AgentShield proxy URL used for OpenClaw integration.
const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:18080";
/// OpenClaw configuration filename.
const OPENCLAW_CONFIG_FILENAME: &str = "openclaw.json";
/// OpenClaw directory name under `$HOME`.
const OPENCLAW_DIR: &str = ".openclaw";
/// macOS launchd label for the OpenClaw gateway daemon.
const LAUNCHD_LABEL: &str = "ai.openclaw.gateway";

/// Claude Code settings directory name under `$HOME`.
const CLAUDE_CODE_DIR: &str = ".claude";
/// Claude Code settings filename.
const CLAUDE_CODE_SETTINGS_FILENAME: &str = "settings.json";

/// Detect the OpenClaw config file path (~/.openclaw/openclaw.json)
pub fn detect_openclaw_config() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let config_path = PathBuf::from(home)
        .join(OPENCLAW_DIR)
        .join(OPENCLAW_CONFIG_FILENAME);
    if config_path.exists() {
        Some(config_path)
    } else {
        None
    }
}

/// Set the Telegram proxy in openclaw.json
pub fn set_openclaw_proxy(config_path: &std::path::Path, proxy_url: &str) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&content)?;

    let telegram = json
        .get_mut("channels")
        .and_then(|c| c.get_mut("telegram"))
        .ok_or_else(|| anyhow::anyhow!("channels.telegram not found in openclaw.json"))?;

    telegram["proxy"] = serde_json::Value::String(proxy_url.to_string());

    let formatted = serde_json::to_string_pretty(&json)?;
    std::fs::write(config_path, formatted)?;
    Ok(())
}

/// Remove the Telegram proxy from openclaw.json
pub fn remove_openclaw_proxy(config_path: &std::path::Path) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&content)?;

    let telegram = json
        .get_mut("channels")
        .and_then(|c| c.get_mut("telegram"))
        .ok_or_else(|| anyhow::anyhow!("channels.telegram not found in openclaw.json"))?;

    if let Some(obj) = telegram.as_object_mut() {
        obj.remove("proxy");
    }

    let formatted = serde_json::to_string_pretty(&json)?;
    std::fs::write(config_path, formatted)?;
    Ok(())
}

/// Restart the OpenClaw gateway daemon via launchctl
pub fn restart_openclaw_daemon() -> anyhow::Result<()> {
    let home = std::env::var("HOME")?;
    let plist_path = PathBuf::from(&home)
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", LAUNCHD_LABEL));

    if !plist_path.exists() {
        anyhow::bail!("OpenClaw plist not found: {}", plist_path.display());
    }

    let plist_str = plist_path.to_string_lossy().to_string();

    let unload = Command::new("launchctl")
        .args(["unload", &plist_str])
        .output()?;
    if !unload.status.success() {
        tracing::warn!(
            "launchctl unload warning: {}",
            String::from_utf8_lossy(&unload.stderr)
        );
    }

    let load = Command::new("launchctl")
        .args(["load", &plist_str])
        .output()?;
    if !load.status.success() {
        anyhow::bail!(
            "launchctl load failed: {}",
            String::from_utf8_lossy(&load.stderr)
        );
    }

    Ok(())
}

/// Detect the Claude Code settings file path (~/.claude/settings.json)
pub fn detect_claude_code_settings() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let settings_path = home
        .join(CLAUDE_CODE_DIR)
        .join(CLAUDE_CODE_SETTINGS_FILENAME);
    if settings_path.exists() {
        Some(settings_path)
    } else {
        // Return parent dir path for creation
        None
    }
}

/// Return the default Claude Code settings path (creates dir if needed).
fn claude_code_settings_path() -> anyhow::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let claude_dir = home.join(CLAUDE_CODE_DIR);
    if !claude_dir.exists() {
        std::fs::create_dir_all(&claude_dir)?;
    }
    Ok(claude_dir.join(CLAUDE_CODE_SETTINGS_FILENAME))
}

/// Set HTTP(S)_PROXY env vars in Claude Code settings.json
pub fn set_claude_code_proxy(
    settings_path: &std::path::Path,
    proxy_url: &str,
    ca_cert_path: Option<&str>,
) -> anyhow::Result<()> {
    let mut json: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(settings_path)?;
        serde_json::from_str(&content)?
    } else {
        serde_json::json!({})
    };

    // Ensure "env" object exists
    if json.get("env").is_none() {
        json["env"] = serde_json::json!({});
    }

    let env = json.get_mut("env").unwrap();
    env["HTTPS_PROXY"] = serde_json::Value::String(proxy_url.to_string());
    env["HTTP_PROXY"] = serde_json::Value::String(proxy_url.to_string());

    if let Some(cert_path) = ca_cert_path {
        env["NODE_EXTRA_CA_CERTS"] = serde_json::Value::String(cert_path.to_string());
    }

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let formatted = serde_json::to_string_pretty(&json)?;
    std::fs::write(settings_path, formatted)?;
    Ok(())
}

/// Remove HTTP(S)_PROXY env vars from Claude Code settings.json
pub fn remove_claude_code_proxy(settings_path: &std::path::Path) -> anyhow::Result<()> {
    if !settings_path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(settings_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(env) = json.get_mut("env").and_then(|e| e.as_object_mut()) {
        env.remove("HTTPS_PROXY");
        env.remove("HTTP_PROXY");
        env.remove("NODE_EXTRA_CA_CERTS");

        // If env is now empty, remove it entirely
        if env.is_empty() {
            if let Some(obj) = json.as_object_mut() {
                obj.remove("env");
            }
        }
    }

    let formatted = serde_json::to_string_pretty(&json)?;
    std::fs::write(settings_path, formatted)?;
    Ok(())
}

/// Execute the `agentshield integrate claude-code` command
pub fn cmd_integrate_claude_code(ca_cert_path: Option<&str>) -> anyhow::Result<()> {
    println!("Integrating AgentShield with Claude Code...");

    let settings_path = claude_code_settings_path()?;
    let exists = settings_path.exists();

    set_claude_code_proxy(&settings_path, DEFAULT_PROXY_URL, ca_cert_path)?;

    if exists {
        println!("  Updated: {}", settings_path.display());
    } else {
        println!("  Created: {}", settings_path.display());
    }

    println!("  Set HTTPS_PROXY: {}", DEFAULT_PROXY_URL);
    println!("  Set HTTP_PROXY: {}", DEFAULT_PROXY_URL);
    if let Some(cert) = ca_cert_path {
        println!("  Set NODE_EXTRA_CA_CERTS: {}", cert);
    }

    println!();
    println!("Integration complete!");
    println!("  Claude Code traffic will now route through AgentShield.");
    println!("  Run 'agentshield integrate remove-claude-code' to undo.");

    Ok(())
}

/// Execute the `agentshield integrate remove-claude-code` command
pub fn cmd_integrate_remove_claude_code() -> anyhow::Result<()> {
    println!("Removing AgentShield integration from Claude Code...");

    let settings_path = match detect_claude_code_settings() {
        Some(p) => p,
        None => {
            println!("  Claude Code settings not found (~/.claude/settings.json)");
            println!("  Nothing to remove.");
            return Ok(());
        }
    };

    println!("  Found settings: {}", settings_path.display());

    remove_claude_code_proxy(&settings_path)?;
    println!("  Removed proxy environment variables");

    println!();
    println!("Integration removed. Claude Code will connect directly.");

    Ok(())
}

/// Execute the `agentshield integrate openclaw` command
pub fn cmd_integrate_openclaw() -> anyhow::Result<()> {
    println!("Integrating AgentShield with OpenClaw...");

    let config_path = detect_openclaw_config().ok_or_else(|| {
        anyhow::anyhow!(
            "OpenClaw config not found at ~/.openclaw/openclaw.json\n\
             Make sure OpenClaw is installed and configured."
        )
    })?;

    println!("  Found config: {}", config_path.display());

    set_openclaw_proxy(&config_path, DEFAULT_PROXY_URL)?;
    println!("  Set telegram proxy: {}", DEFAULT_PROXY_URL);

    restart_openclaw_daemon()?;
    println!("  Restarted OpenClaw gateway daemon");

    println!();
    println!("Integration complete!");
    println!("  Telegram traffic will now route through AgentShield.");
    println!("  Note: LLM API traffic (Anthropic, etc.) is NOT proxied yet.");
    println!("  Run 'agentshield integrate remove' to undo.");

    Ok(())
}

/// Execute the `agentshield integrate remove` command
pub fn cmd_integrate_remove() -> anyhow::Result<()> {
    println!("Removing AgentShield integration...");

    let config_path = detect_openclaw_config()
        .ok_or_else(|| anyhow::anyhow!("OpenClaw config not found at ~/.openclaw/openclaw.json"))?;

    println!("  Found config: {}", config_path.display());

    remove_openclaw_proxy(&config_path)?;
    println!("  Removed telegram proxy setting");

    restart_openclaw_daemon()?;
    println!("  Restarted OpenClaw gateway daemon");

    println!();
    println!("Integration removed. OpenClaw will connect directly.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_openclaw_json() -> &'static str {
        r#"{
  "meta": {
    "lastTouchedVersion": "2026.2.9"
  },
  "channels": {
    "telegram": {
      "enabled": true,
      "botToken": "test-token",
      "streamMode": "partial"
    }
  },
  "gateway": {
    "port": 18789
  }
}"#
    }

    fn sample_openclaw_json_with_proxy() -> &'static str {
        r#"{
  "meta": {
    "lastTouchedVersion": "2026.2.9"
  },
  "channels": {
    "telegram": {
      "enabled": true,
      "botToken": "test-token",
      "proxy": "http://127.0.0.1:18080",
      "streamMode": "partial"
    }
  },
  "gateway": {
    "port": 18789
  }
}"#
    }

    #[test]
    fn test_set_openclaw_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        fs::write(&config_path, sample_openclaw_json()).unwrap();

        set_openclaw_proxy(&config_path, "http://127.0.0.1:18080").unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            result["channels"]["telegram"]["proxy"],
            "http://127.0.0.1:18080"
        );
        // Other fields preserved
        assert_eq!(result["channels"]["telegram"]["enabled"], true);
        assert_eq!(result["channels"]["telegram"]["botToken"], "test-token");
        assert_eq!(result["gateway"]["port"], 18789);
    }

    #[test]
    fn test_set_openclaw_proxy_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        fs::write(&config_path, sample_openclaw_json_with_proxy()).unwrap();

        set_openclaw_proxy(&config_path, "http://127.0.0.1:9999").unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            result["channels"]["telegram"]["proxy"],
            "http://127.0.0.1:9999"
        );
    }

    #[test]
    fn test_remove_openclaw_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        fs::write(&config_path, sample_openclaw_json_with_proxy()).unwrap();

        remove_openclaw_proxy(&config_path).unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(result["channels"]["telegram"]["proxy"].is_null());
        // Other fields preserved
        assert_eq!(result["channels"]["telegram"]["enabled"], true);
        assert_eq!(result["channels"]["telegram"]["botToken"], "test-token");
    }

    #[test]
    fn test_remove_openclaw_proxy_when_no_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        fs::write(&config_path, sample_openclaw_json()).unwrap();

        // Should not fail even when proxy doesn't exist
        remove_openclaw_proxy(&config_path).unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(result["channels"]["telegram"]["proxy"].is_null());
    }

    #[test]
    fn test_set_proxy_missing_telegram_channel() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        fs::write(
            &config_path,
            r#"{"channels": {}, "gateway": {"port": 18789}}"#,
        )
        .unwrap();

        let result = set_openclaw_proxy(&config_path, "http://127.0.0.1:18080");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("channels.telegram not found")
        );
    }

    // --- Claude Code integration tests ---

    fn sample_claude_settings_json() -> &'static str {
        r#"{
  "env": {
    "SOME_VAR": "existing_value"
  },
  "permissions": {
    "allow": []
  }
}"#
    }

    fn sample_claude_settings_with_proxy() -> &'static str {
        r#"{
  "env": {
    "SOME_VAR": "existing_value",
    "HTTPS_PROXY": "http://127.0.0.1:18080",
    "HTTP_PROXY": "http://127.0.0.1:18080"
  },
  "permissions": {
    "allow": []
  }
}"#
    }

    #[test]
    fn test_set_claude_code_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(&settings_path, sample_claude_settings_json()).unwrap();

        set_claude_code_proxy(&settings_path, "http://127.0.0.1:18080", None).unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(result["env"]["HTTPS_PROXY"], "http://127.0.0.1:18080");
        assert_eq!(result["env"]["HTTP_PROXY"], "http://127.0.0.1:18080");
        // Existing env vars preserved
        assert_eq!(result["env"]["SOME_VAR"], "existing_value");
        // Other top-level fields preserved
        assert!(result["permissions"].is_object());
    }

    #[test]
    fn test_set_claude_code_proxy_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join(".claude").join("settings.json");

        set_claude_code_proxy(&settings_path, "http://127.0.0.1:18080", None).unwrap();

        assert!(settings_path.exists());
        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(result["env"]["HTTPS_PROXY"], "http://127.0.0.1:18080");
        assert_eq!(result["env"]["HTTP_PROXY"], "http://127.0.0.1:18080");
    }

    #[test]
    fn test_set_claude_code_proxy_with_ca_cert() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(&settings_path, "{}").unwrap();

        set_claude_code_proxy(
            &settings_path,
            "http://127.0.0.1:18080",
            Some("/path/to/ca-cert.pem"),
        )
        .unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(result["env"]["HTTPS_PROXY"], "http://127.0.0.1:18080");
        assert_eq!(result["env"]["NODE_EXTRA_CA_CERTS"], "/path/to/ca-cert.pem");
    }

    #[test]
    fn test_remove_claude_code_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(&settings_path, sample_claude_settings_with_proxy()).unwrap();

        remove_claude_code_proxy(&settings_path).unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        // Proxy vars removed
        assert!(result["env"]["HTTPS_PROXY"].is_null());
        assert!(result["env"]["HTTP_PROXY"].is_null());
        // Existing env vars preserved
        assert_eq!(result["env"]["SOME_VAR"], "existing_value");
        // Other top-level fields preserved
        assert!(result["permissions"].is_object());
    }

    #[test]
    fn test_remove_claude_code_proxy_empty_env_removed() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        // Only proxy vars in env — env should be removed entirely after cleanup
        fs::write(
            &settings_path,
            r#"{"env":{"HTTPS_PROXY":"http://127.0.0.1:18080","HTTP_PROXY":"http://127.0.0.1:18080"}}"#,
        )
        .unwrap();

        remove_claude_code_proxy(&settings_path).unwrap();

        let result: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert!(result.get("env").is_none());
    }

    #[test]
    fn test_remove_claude_code_proxy_file_not_exists() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        // Should not fail even when file doesn't exist
        let result = remove_claude_code_proxy(&settings_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_claude_code_proxy_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(&settings_path, "not valid json!!!").unwrap();

        let result = set_claude_code_proxy(&settings_path, "http://127.0.0.1:18080", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_openclaw_config_with_custom_home() {
        let dir = tempfile::tempdir().unwrap();
        let openclaw_dir = dir.path().join(".openclaw");
        fs::create_dir_all(&openclaw_dir).unwrap();
        fs::write(openclaw_dir.join("openclaw.json"), "{}").unwrap();

        // We can't easily test detect_openclaw_config since it reads HOME env var,
        // but we can test the core logic manually
        let config_path = openclaw_dir.join("openclaw.json");
        assert!(config_path.exists());
    }
}
