//! CA (Certificate Authority) CLI commands for MITM mode.
//!
//! Provides `agentshield ca init|trust|show|export` subcommands
//! to manage the Root CA used for TLS interception.

use std::path::Path;

/// Return the default CA directory path (`~/.agentshield/ca/`).
pub fn ca_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::env::var_os("AGENTSHIELD_DATA_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(home).join(".agentshield"))
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
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
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

    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    options
        .open(&key_path)?
        .write_all(key_pair.serialize_pem().as_bytes())?;
    std::fs::write(&cert_path, cert.pem())?;

    Ok(())
}

/// Parse and validate a self-signed, currently valid CA and its matching key.
/// rcgen's importer alone intentionally does not validate any of these properties.
pub(crate) fn validated_ca_params(
    pem: &str,
    key: &rcgen::KeyPair,
) -> anyhow::Result<rcgen::CertificateParams> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(certs.len() == 1, "Expected exactly one CA certificate");
    let (rest, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|_| anyhow::anyhow!("Invalid CA certificate"))?;
    anyhow::ensure!(rest.is_empty(), "Trailing CA data");
    anyhow::ensure!(cert.subject() == cert.issuer(), "CA must be self-issued");
    cert.verify_signature(None)
        .map_err(|_| anyhow::anyhow!("Invalid CA self-signature"))?;
    anyhow::ensure!(cert.validity().is_valid(), "CA is expired or not yet valid");
    anyhow::ensure!(
        cert.public_key().raw == key.public_key_der(),
        "CA key does not match certificate"
    );
    anyhow::ensure!(cert.extensions_map().is_ok(), "Duplicate CA extensions");
    let basic = cert
        .basic_constraints()?
        .ok_or_else(|| anyhow::anyhow!("Missing CA constraints"))?;
    anyhow::ensure!(
        basic.critical && basic.value.ca,
        "Certificate is not a constrained CA"
    );
    if let Some(usage) = cert.key_usage()? {
        anyhow::ensure!(
            usage.critical && usage.value.key_cert_sign(),
            "CA cannot sign certificates"
        );
    }
    anyhow::ensure!(
        cert.extensions()
            .iter()
            .any(|ext| matches!(ext.parsed_extension(),
        x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) if !id.0.is_empty())),
        "Missing or invalid CA key identifier"
    );
    Ok(rcgen::CertificateParams::from_ca_cert_der(&certs[0])?)
}

/// Refuse symlinks in the complete CA path before handling private key material.
fn check_ca_path(path: &Path) -> anyhow::Result<()> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => anyhow::ensure!(!meta.file_type().is_symlink(), "Symlink in CA path"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Prepare only the app-local CA. Never rotate its key or alter system trust.
/// A legacy certificate without KeyUsage is reissued only for the exact known
/// AgentShield shape; constrained/custom CAs are never silently simplified.
pub fn cmd_ca_prepare(ca_dir: &Path) -> anyhow::Result<()> {
    check_ca_path(ca_dir)?;
    let key_path = ca_dir.join("key.pem");
    let cert_path = ca_dir.join("cert.pem");
    check_ca_path(&key_path)?;
    check_ca_path(&cert_path)?;
    match (key_path.try_exists()?, cert_path.try_exists()?) {
        (false, false) => return generate_ca(ca_dir),
        (true, true) => (),
        _ => anyhow::bail!("Incomplete CA; refusing to rotate existing material"),
    }
    anyhow::ensure!(
        key_path.is_file() && cert_path.is_file(),
        "CA files must be regular files"
    );
    let key_pem = std::fs::read_to_string(&key_path)?;
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key = rcgen::KeyPair::from_pem(&key_pem)?;
    let mut params = validated_ca_params(&cert_pem, &key)?;
    if !params.key_usages.is_empty() {
        return Ok(());
    }
    let mut expected_dn = rcgen::DistinguishedName::new();
    expected_dn.push(rcgen::DnType::CommonName, "AgentShield CA");
    expected_dn.push(rcgen::DnType::OrganizationName, "AgentShield");
    anyhow::ensure!(
        params.distinguished_name == expected_dn,
        "Unsupported legacy CA subject"
    );
    anyhow::ensure!(
        matches!(
            params.is_ca,
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        ),
        "Unsupported legacy CA constraints"
    );
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let (_, original) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|_| anyhow::anyhow!("Invalid CA certificate"))?;
    // The old generator emitted only these two extensions. Reissuing anything
    // else risks removing a restriction that rcgen's importer does not retain.
    anyhow::ensure!(
        original.extensions().len() == 2
            && original.extensions().iter().all(|ext| matches!(
                ext.parsed_extension(),
                x509_parser::extensions::ParsedExtension::BasicConstraints(_)
                    | x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(_)
            )),
        "Unsupported legacy CA extensions"
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let updated = params.self_signed(&key)?.pem();
    validated_ca_params(&updated, &key)?;
    // Exclusive sibling staging followed by atomic replacement: an interrupted
    // write leaves the original public certificate intact. The key is untouched.
    let temporary = ca_dir.join(format!(".cert-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        drop(file);
        // Refuse concurrent material replacement rather than overwriting it.
        check_ca_path(&cert_path)?;
        check_ca_path(&key_path)?;
        anyhow::ensure!(
            std::fs::read_to_string(&cert_path)? == cert_pem
                && std::fs::read_to_string(&key_path)? == key_pem,
            "CA changed during preparation"
        );
        std::fs::rename(&temporary, &cert_path)?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
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

    fn legacy_ca(directory: &Path, mutate: impl FnOnce(&mut rcgen::CertificateParams)) {
        std::fs::create_dir_all(directory).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "AgentShield CA");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "AgentShield");
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
        mutate(&mut params);
        std::fs::write(directory.join("key.pem"), key.serialize_pem()).unwrap();
        std::fs::write(
            directory.join("cert.pem"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
    }

    #[test]
    fn prepare_repairs_legacy_ca_preserving_identity_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("ca");
        legacy_ca(&path, |_| {});
        let before_key = std::fs::read(path.join("key.pem")).unwrap();
        let before = std::fs::read_to_string(path.join("cert.pem")).unwrap();
        let old = rcgen::CertificateParams::from_ca_cert_pem(&before).unwrap();
        cmd_ca_prepare(&path).unwrap();
        let after = std::fs::read_to_string(path.join("cert.pem")).unwrap();
        let new = rcgen::CertificateParams::from_ca_cert_pem(&after).unwrap();
        assert_ne!(before, after);
        assert_eq!(before_key, std::fs::read(path.join("key.pem")).unwrap());
        assert_eq!(old.distinguished_name, new.distinguished_name);
        assert_eq!(old.serial_number, new.serial_number);
        assert_eq!(old.not_before, new.not_before);
        assert_eq!(old.not_after, new.not_after);
        let key = rcgen::KeyPair::from_pem(std::str::from_utf8(&before_key).unwrap()).unwrap();
        assert_eq!(
            old.self_signed(&key).unwrap().key_identifier(),
            new.clone().self_signed(&key).unwrap().key_identifier()
        );
        assert!(
            new.key_usages
                .contains(&rcgen::KeyUsagePurpose::KeyCertSign)
        );
        cmd_ca_prepare(&path).unwrap();
        assert_eq!(
            after,
            std::fs::read_to_string(path.join("cert.pem")).unwrap()
        );
    }

    #[test]
    fn prepare_rejects_unsupported_or_invalid_material_without_rewriting() {
        for kind in [
            "subject",
            "constraint",
            "extension",
            "expired",
            "future",
            "not_ca",
            "usage",
            "key",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().canonicalize().unwrap().join("ca");
            legacy_ca(&path, |params| match kind {
                "subject" => params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, "Other CA"),
                "constraint" => {
                    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0))
                }
                "extension" => params
                    .extended_key_usages
                    .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth),
                "expired" => {
                    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1)
                }
                "future" => {
                    params.not_before = time::OffsetDateTime::now_utc() + time::Duration::days(1)
                }
                "not_ca" => params.is_ca = rcgen::IsCa::ExplicitNoCa,
                "usage" => params
                    .key_usages
                    .push(rcgen::KeyUsagePurpose::DigitalSignature),
                _ => (),
            });
            if kind == "key" {
                std::fs::write(
                    path.join("key.pem"),
                    rcgen::KeyPair::generate().unwrap().serialize_pem(),
                )
                .unwrap();
            }
            let before_key = std::fs::read(path.join("key.pem")).unwrap();
            let before_cert = std::fs::read(path.join("cert.pem")).unwrap();
            assert!(cmd_ca_prepare(&path).is_err(), "must reject {kind}");
            assert_eq!(before_key, std::fs::read(path.join("key.pem")).unwrap());
            assert_eq!(before_cert, std::fs::read(path.join("cert.pem")).unwrap());
            assert_eq!(std::fs::read_dir(&path).unwrap().count(), 2);
        }
    }

    #[test]
    fn prepare_creates_fresh_and_refuses_partial_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("ca");
        cmd_ca_prepare(&path).unwrap();
        let original = std::fs::read(path.join("cert.pem")).unwrap();
        cmd_ca_prepare(&path).unwrap();
        assert_eq!(original, std::fs::read(path.join("cert.pem")).unwrap());
        std::fs::remove_file(path.join("key.pem")).unwrap();
        assert!(cmd_ca_prepare(&path).is_err());
        assert_eq!(original, std::fs::read(path.join("cert.pem")).unwrap());
        assert!(!path.join("key.pem").exists());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refuses_symlinked_ca_material() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("real");
        legacy_ca(&target, |_| {});
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert!(cmd_ca_prepare(&alias).is_err());
        std::fs::rename(target.join("cert.pem"), target.join("original.pem")).unwrap();
        std::os::unix::fs::symlink(target.join("original.pem"), target.join("cert.pem")).unwrap();
        assert!(cmd_ca_prepare(&target).is_err());
    }

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
