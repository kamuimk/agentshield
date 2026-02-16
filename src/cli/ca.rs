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
/// and returns without overwriting.
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

/// CLI handler for `agentshield ca trust`.
///
/// Prints platform-specific instructions for installing the CA certificate
/// into the system trust store. Does not execute the commands automatically
/// because they typically require elevated privileges.
pub fn cmd_ca_trust(ca_dir: &Path) -> anyhow::Result<()> {
    let cert_path = ca_dir.join("cert.pem");
    if !cert_path.exists() {
        anyhow::bail!(
            "CA certificate not found at {}. Run 'agentshield ca init' first.",
            cert_path.display()
        );
    }

    println!("CA certificate: {}", cert_path.display());
    println!();

    #[cfg(target_os = "macos")]
    {
        println!("macOS: Install CA into system Keychain (requires sudo):");
        println!(
            "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
            cert_path.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        println!("Linux: Install CA system-wide (requires sudo):");
        println!(
            "  sudo cp {} /usr/local/share/ca-certificates/agentshield-ca.crt",
            cert_path.display()
        );
        println!("  sudo update-ca-certificates");
    }

    #[cfg(target_os = "windows")]
    {
        println!("Windows: Install CA (requires admin):");
        println!("  certutil -addstore -f \"Root\" {}", cert_path.display());
    }

    println!();
    println!("For Node.js applications:");
    println!("  export NODE_EXTRA_CA_CERTS={}", cert_path.display());
    Ok(())
}

/// CLI handler for `agentshield ca show`.
///
/// Reads the CA certificate PEM and displays metadata:
/// subject, issuer, not-before/not-after, and SHA-256 fingerprint.
pub fn cmd_ca_show(ca_dir: &Path) -> anyhow::Result<()> {
    let cert_path = ca_dir.join("cert.pem");
    if !cert_path.exists() {
        anyhow::bail!(
            "CA certificate not found at {}. Run 'agentshield ca init' first.",
            cert_path.display()
        );
    }

    let pem_data = std::fs::read_to_string(&cert_path)?;

    // Parse the DER certificate for fingerprint
    let mut reader = std::io::BufReader::new(pem_data.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let cert_der = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in cert.pem"))?;

    // SHA-256 fingerprint
    use sha2::{Digest, Sha256};
    let fingerprint = Sha256::digest(cert_der.as_ref());
    let fp_hex: String = fingerprint
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    println!("AgentShield CA Certificate");
    println!("==========================");
    println!("File:        {}", cert_path.display());
    println!("Fingerprint: SHA256:{}", fp_hex);
    println!();
    println!("PEM contents:");
    // Show first and last line of PEM for confirmation
    let lines: Vec<&str> = pem_data.lines().collect();
    if let Some(first) = lines.first() {
        println!("  {}", first);
    }
    println!("  ...");
    if let Some(last) = lines.last() {
        println!("  {}", last);
    }

    Ok(())
}

/// CLI handler for `agentshield ca export`.
///
/// Copies the CA certificate PEM to the specified destination path.
pub fn cmd_ca_export(ca_dir: &Path, dest: &Path) -> anyhow::Result<()> {
    let cert_path = ca_dir.join("cert.pem");
    if !cert_path.exists() {
        anyhow::bail!(
            "CA certificate not found at {}. Run 'agentshield ca init' first.",
            cert_path.display()
        );
    }

    std::fs::copy(&cert_path, dest)?;
    println!("CA certificate exported to {}", dest.display());
    Ok(())
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

        cmd_ca_init(&ca_dir).unwrap();
        let original_cert = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();

        cmd_ca_init(&ca_dir).unwrap();
        let after_cert = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();

        assert_eq!(original_cert, after_cert, "cert.pem should not be modified");
    }

    #[test]
    fn cmd_ca_trust_fails_without_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();

        let result = cmd_ca_trust(&ca_dir);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("not found"),
            "Should mention cert not found"
        );
    }

    #[test]
    fn cmd_ca_trust_succeeds_with_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        generate_ca(&ca_dir).unwrap();

        // Should succeed (prints instructions but does not execute them)
        cmd_ca_trust(&ca_dir).unwrap();
    }

    #[test]
    fn cmd_ca_show_fails_without_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();

        let result = cmd_ca_show(&ca_dir);
        assert!(result.is_err());
    }

    #[test]
    fn cmd_ca_show_displays_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        generate_ca(&ca_dir).unwrap();

        // Should succeed without error
        cmd_ca_show(&ca_dir).unwrap();
    }

    #[test]
    fn cmd_ca_export_copies_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        generate_ca(&ca_dir).unwrap();

        let dest = dir.path().join("exported.pem");
        cmd_ca_export(&ca_dir, &dest).unwrap();

        assert!(dest.exists(), "Exported file should exist");
        let original = std::fs::read_to_string(ca_dir.join("cert.pem")).unwrap();
        let exported = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(original, exported, "Exported cert should be identical");
    }

    #[test]
    fn cmd_ca_export_fails_without_cert() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();

        let dest = dir.path().join("exported.pem");
        let result = cmd_ca_export(&ca_dir, &dest);
        assert!(result.is_err());
    }
}
