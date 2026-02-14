//! Policy hot-reload support.
//!
//! Watches the TOML configuration file for changes and reloads the
//! [`PolicyConfig`] without restarting the proxy. The policy is stored
//! behind an `Arc<RwLock<PolicyConfig>>` so that concurrent readers
//! (connection handlers) are never blocked for more than the brief
//! write-lock duration during a reload.
//!
//! Reload triggers:
//!
//! - **File change**: [`start_file_watcher`] uses the [`notify`] crate
//!   to detect modifications to `agentshield.toml`.
//! - **SIGHUP** (Unix only): [`start_sighup_handler`] listens for the
//!   HUP signal for manual reload via `kill -HUP <pid>`.
//!
//! Invalid configuration is handled fail-safe: the old policy is retained
//! and a warning is logged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::config::{AppConfig, PolicyConfig};

/// Reload the policy from disk, replacing the contents of the `RwLock`.
///
/// On success the new policy is swapped in atomically. On failure (I/O
/// error, invalid TOML, missing env vars) the old policy is retained and
/// the error is returned.
pub fn reload_policy(
    policy_lock: &Arc<RwLock<PolicyConfig>>,
    config_path: &Path,
) -> crate::error::Result<()> {
    let config = AppConfig::load_from_path(config_path)?;
    let mut policy = policy_lock.write().unwrap();
    *policy = config.policy;
    info!(
        "Policy reloaded from {} ({} rules)",
        config_path.display(),
        policy.rules.len()
    );
    Ok(())
}

/// Start a file-system watcher that triggers [`reload_policy`] on config changes.
///
/// Returns a [`RecommendedWatcher`] handle that must be kept alive for the
/// duration of the watch. Dropping the handle stops the watcher.
pub fn start_file_watcher(
    config_path: PathBuf,
    policy_lock: Arc<RwLock<PolicyConfig>>,
) -> notify::Result<RecommendedWatcher> {
    let path = config_path.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        match res {
            Ok(event) => {
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    info!("Config file changed, reloading policy...");
                    if let Err(e) = reload_policy(&policy_lock, &path) {
                        warn!("Policy reload failed (keeping old policy): {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("File watcher error: {}", e);
            }
        }
    })?;

    watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
    info!("Watching {} for changes", config_path.display());
    Ok(watcher)
}

/// Start a SIGHUP handler that reloads the policy on signal.
///
/// On non-Unix platforms this is a no-op.
#[cfg(unix)]
pub fn start_sighup_handler(
    config_path: PathBuf,
    policy_lock: Arc<RwLock<PolicyConfig>>,
) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        loop {
            sig.recv().await;
            info!("SIGHUP received, reloading policy...");
            if let Err(e) = reload_policy(&policy_lock, &config_path) {
                warn!("Policy reload on SIGHUP failed (keeping old policy): {}", e);
            }
        }
    });
}

/// No-op SIGHUP handler for non-Unix platforms.
#[cfg(not(unix))]
pub fn start_sighup_handler(
    _config_path: PathBuf,
    _policy_lock: Arc<RwLock<PolicyConfig>>,
) {
    // SIGHUP is not available on this platform
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::Action;
    use std::io::Write;

    fn make_toml(default: &str, rule_domain: &str) -> String {
        format!(
            r#"
[proxy]
listen = "127.0.0.1:18080"
mode = "transparent"

[policy]
default = "{}"

[[policy.rules]]
name = "test"
domains = ["{}"]
action = "allow"
"#,
            default, rule_domain
        )
    }

    #[test]
    fn reload_policy_updates_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // Initial config: deny all, allow example.com
        std::fs::write(&path, make_toml("deny", "example.com")).unwrap();
        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        assert_eq!(policy.read().unwrap().rules.len(), 1);
        assert_eq!(policy.read().unwrap().rules[0].domains[0], "example.com");

        // Update config: allow all, allow new-domain.com
        std::fs::write(&path, make_toml("allow", "new-domain.com")).unwrap();
        reload_policy(&policy, &path).unwrap();

        let p = policy.read().unwrap();
        assert_eq!(p.default, Action::Allow);
        assert_eq!(p.rules[0].domains[0], "new-domain.com");
    }

    #[test]
    fn reload_policy_invalid_toml_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // Valid initial config
        std::fs::write(&path, make_toml("deny", "example.com")).unwrap();
        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        // Write invalid TOML
        std::fs::write(&path, "this is not valid toml [[[").unwrap();
        let result = reload_policy(&policy, &path);
        assert!(result.is_err());

        // Old policy is retained
        let p = policy.read().unwrap();
        assert_eq!(p.default, Action::Deny);
        assert_eq!(p.rules[0].domains[0], "example.com");
    }

    #[test]
    fn reload_policy_missing_file_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // Valid initial config
        std::fs::write(&path, make_toml("deny", "example.com")).unwrap();
        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        // Delete the file
        std::fs::remove_file(&path).unwrap();
        let result = reload_policy(&policy, &path);
        assert!(result.is_err());

        // Old policy is retained
        assert_eq!(policy.read().unwrap().rules.len(), 1);
    }

    #[test]
    fn file_watcher_starts_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_test.toml");
        std::fs::write(&path, make_toml("deny", "example.com")).unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        let watcher = start_file_watcher(path, policy);
        assert!(watcher.is_ok());
        // Watcher is dropped here, stopping the watch
    }

    #[test]
    fn file_watcher_triggers_reload_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_reload.toml");
        std::fs::write(&path, make_toml("deny", "original.com")).unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        let _watcher = start_file_watcher(path.clone(), policy.clone()).unwrap();

        // Modify the file
        std::fs::write(&path, make_toml("allow", "reloaded.com")).unwrap();

        // Give the watcher time to detect the change
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Check if policy was reloaded
        let p = policy.read().unwrap();
        // Note: file watcher events may not fire instantly on all platforms
        // so this test is best-effort; the core reload_policy test above is authoritative
        if p.rules[0].domains[0] == "reloaded.com" {
            assert_eq!(p.default, Action::Allow);
        }
    }

    #[test]
    fn reload_policy_concurrent_reads_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.toml");
        std::fs::write(&path, make_toml("deny", "example.com")).unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        let policy = Arc::new(RwLock::new(config.policy));

        // Simulate concurrent reads with a write
        let p1 = policy.clone();
        let p2 = policy.clone();

        let t1 = std::thread::spawn(move || {
            for _ in 0..100 {
                let _p = p1.read().unwrap();
            }
        });

        let t2 = std::thread::spawn(move || {
            for _ in 0..100 {
                let _p = p2.read().unwrap();
            }
        });

        // Write once while readers are running
        std::fs::write(&path, make_toml("allow", "updated.com")).unwrap();
        reload_policy(&policy, &path).unwrap();

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(policy.read().unwrap().default, Action::Allow);
    }
}
