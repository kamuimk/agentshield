//! CA (Certificate Authority) CLI commands for MITM mode.
//!
//! Provides `agentshield ca init|trust|show|export` subcommands
//! to manage the Root CA used for TLS interception.

use std::path::Path;

/// Return the default CA directory path (`~/.agentshield/ca/`).
pub fn ca_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".agentshield")
        .join("ca")
}

/// Placeholder: generate a new Root CA key pair and certificate.
pub fn cmd_ca_init(_ca_dir: &Path) -> anyhow::Result<()> {
    anyhow::bail!("CA init not yet implemented")
}

/// Placeholder: install CA cert into system trust store.
pub fn cmd_ca_trust(_ca_dir: &Path) -> anyhow::Result<()> {
    anyhow::bail!("CA trust not yet implemented")
}

/// Placeholder: display CA certificate info.
pub fn cmd_ca_show(_ca_dir: &Path) -> anyhow::Result<()> {
    anyhow::bail!("CA show not yet implemented")
}

/// Placeholder: export CA certificate to a file.
pub fn cmd_ca_export(_ca_dir: &Path, _dest: &Path) -> anyhow::Result<()> {
    anyhow::bail!("CA export not yet implemented")
}
