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
//! - **File change**: [`start_file_watcher`] polls one path at bounded intervals
//!   to observe modifications to `agentshield.toml`.
//! - **SIGHUP** (Unix only): [`start_sighup_handler`] listens for the
//!   HUP signal for manual reload via `kill -HUP <pid>`.
//!
//! Invalid configuration is handled fail-safe: the old policy is retained
//! and a warning is logged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};
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

/// Retained, bounded polling of one policy path, including replacement files.
/// Dropping this owner wakes and joins its worker; immutable mode never creates it.
pub struct PolicyWatcher {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for PolicyWatcher {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn file_stamp(path: &Path) -> Option<(SystemTime, Option<SystemTime>, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some((
        metadata.modified().ok()?,
        metadata.created().ok(),
        metadata.len(),
    ))
}

/// Observe metadata changes at the original path every 250ms, not an old inode.
/// High-resolution timestamps detect same-content writes after a dashboard edit.
/// Reload errors retain the current policy; subsequent file changes retry.
pub fn start_file_watcher(
    config_path: PathBuf,
    policy_lock: Arc<RwLock<PolicyConfig>>,
) -> notify::Result<PolicyWatcher> {
    let mut previous = file_stamp(&config_path).ok_or_else(|| {
        notify::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path must be an accessible regular file",
        ))
    })?;
    let (stop, receiver) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("agentshield-policy-watch".into())
        .spawn(move || {
            let mut missing = false;
            loop {
                match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                let current = file_stamp(&config_path);
                if current.is_none() {
                    missing = true;
                    continue;
                }
                let current = current.unwrap();
                if missing || current != previous {
                    missing = false;
                    previous = current;
                    if let Err(error) = reload_policy(&policy_lock, &config_path) {
                        warn!("Policy reload failed (keeping old policy): {}", error);
                    }
                }
            }
        })
        .map_err(notify::Error::io)?;
    Ok(PolicyWatcher {
        stop,
        worker: Some(worker),
    })
}

/// Start a SIGHUP handler that reloads the policy on signal.
///
/// On non-Unix platforms this is a no-op.
#[cfg(unix)]
pub fn start_sighup_handler(config_path: PathBuf, policy_lock: Arc<RwLock<PolicyConfig>>) {
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
pub fn start_sighup_handler(_config_path: PathBuf, _policy_lock: Arc<RwLock<PolicyConfig>>) {
    // SIGHUP is not available on this platform
}

/// Consume SIGHUP without reloading policy or terminating an immutable CLI instance.
#[cfg(unix)]
pub fn start_immutable_sighup_handler() {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        while sig.recv().await.is_some() {
            info!("SIGHUP ignored: startup policy is immutable");
        }
    });
}

/// No-op on platforms without SIGHUP.
#[cfg(not(unix))]
pub fn start_immutable_sighup_handler() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::Action;

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

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            {
                let current = policy.read().unwrap();
                if current.rules[0].domains[0] == "reloaded.com" {
                    assert_eq!(current.default, Action::Allow);
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "policy change not observed"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
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
    #[test]
    fn file_replacement_is_observed_and_drop_stops_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, make_toml("deny", "old.example")).unwrap();
        let policy = Arc::new(RwLock::new(
            AppConfig::load_from_path(&path).unwrap().policy,
        ));
        let watcher = start_file_watcher(path.clone(), policy.clone()).unwrap();
        let replacement = dir.path().join("replacement.toml");
        std::fs::write(&replacement, make_toml("allow", "new.example")).unwrap();
        // A remove/create transition must keep the original path watched,
        // rather than retaining only the replaced file's identity.
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while policy.read().unwrap().default != Action::Allow {
            assert!(
                std::time::Instant::now() < deadline,
                "replacement not observed"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        drop(watcher);
        std::fs::write(&path, make_toml("deny", "after-drop.example")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(350));
        assert_eq!(policy.read().unwrap().default, Action::Allow);
    }
}
