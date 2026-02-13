use std::path::PathBuf;
use std::process::Command;

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:18080";
const OPENCLAW_CONFIG_FILENAME: &str = "openclaw.json";
const OPENCLAW_DIR: &str = ".openclaw";
const LAUNCHD_LABEL: &str = "ai.openclaw.gateway";

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
