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

/// Generate a new Root CA ECDSA P256 key pair and self-signed certificate.
///
/// Files created:
/// - `<ca_dir>/key.pem` — ECDSA private key (PEM)
/// - `<ca_dir>/cert.pem` — Self-signed X.509 certificate (PEM, 10-year validity)
///
/// If files already exist, the caller must handle the overwrite confirmation
/// before calling this function.
pub fn generate_ca(ca_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(ca_dir)?;

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "AgentShield CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "AgentShield");
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let cert = params.self_signed(&key_pair)?;

    let key_path = ca_dir.join("key.pem");
    let cert_path = ca_dir.join("cert.pem");

    std::fs::write(&key_path, key_pair.serialize_pem())?;
    std::fs::write(&cert_path, cert.pem())?;

    Ok(())
}

/// CLI handler for `agentshield ca init`.
///
/// Generates a new Root CA. If files already exist, prints a warning
/// and returns without overwriting (interactive confirmation would
/// require stdin access which is not suitable for all contexts).
pub fn cmd_ca_init(ca_dir: &Path) -> anyhow::Result<()> {
    let key_path = ca_dir.join("key.pem");
    let cert_path = ca_dir.join("cert.pem");

    if key_path.exists() || cert_path.exists() {
        println!(
            "CA already exists at {}. Remove the existing files first to regenerate.",
            ca_dir.display()
        );
        return Ok(());
    }

    generate_ca(ca_dir)?;

    println!("CA generated successfully:");
    println!("  Key:  {}", ca_dir.join("key.pem").display());
    println!("  Cert: {}", ca_dir.join("cert.pem").display());
    println!();
    println!("Next steps:");
    println!("  agentshield ca trust    # Install CA into system trust store");
    println!("  agentshield ca show     # Display certificate info");
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_creates_key_and_cert_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");

        generate_ca(&ca_dir).unwrap();

        let key_path = ca_dir.join("key.pem");
        let cert_path = ca_dir.join("cert.pem");

        assert!(key_path.exists(), "key.pem must exist");
        assert!(cert_path.exists(), "cert.pem must exist");

        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            key_content.contains("BEGIN PRIVATE KEY"),
            "key.pem must contain PEM private key"
        );

        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        assert!(
            cert_content.contains("BEGIN CERTIFICATE"),
            "cert.pem must contain PEM certificate"
        );
    }

    #[test]
    fn generate_ca_cert_is_valid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        generate_ca(&ca_dir).unwrap();

        let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();
        // Verify it can be parsed as a certificate
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>();
        assert!(certs.is_ok(), "cert.pem must be parseable");
        let certs = certs.unwrap();
        assert_eq!(certs.len(), 1, "Should contain exactly one certificate");
    }

    #[test]
    fn generate_ca_key_is_valid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        generate_ca(&ca_dir).unwrap();

        let key_pem = std::fs::read_to_string(ca_dir.join("key.pem")).unwrap();
        let mut reader = std::io::BufReader::new(key_pem.as_bytes());
        let keys = rustls_pemfile::private_key(&mut reader);
        assert!(keys.is_ok(), "key.pem must be parseable");
        assert!(keys.unwrap().is_some(), "Should contain a private key");
    }

    #[test]
    fn cmd_ca_init_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");

        cmd_ca_init(&ca_dir).unwrap();

        assert!(ca_dir.join("key.pem").exists());
        assert!(ca_dir.join("cert.pem").exists());
    }

    #[test]
    fn cmd_ca_init_does_not_overwrite_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");

        // First init
        cmd_ca_init(&ca_dir).unwrap();
        let original_cert = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();

        // Second init should not overwrite
        cmd_ca_init(&ca_dir).unwrap();
        let after_cert = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();

        assert_eq!(original_cert, after_cert, "cert.pem should not be modified");
    }
}
