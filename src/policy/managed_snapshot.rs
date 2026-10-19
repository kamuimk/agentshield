//! Bounded exact-byte startup configuration for privileged host digest binding.

use super::config::AppConfig;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

/// Parsed startup values and the digest of the exact bytes that selected them.
/// Intentionally not Debug/Serialize: configuration can contain credentials.
pub struct ManagedSnapshot {
    /// Configuration selected by the exact snapshot bytes, without variable expansion.
    pub config: AppConfig,
    /// SHA-256 of those same bytes, to compare with the privileged host's expectation.
    pub sha256: [u8; 32],
}

impl ManagedSnapshot {
    /// Read one bounded regular-file snapshot and parse it without environment
    /// expansion. Later file changes cannot change this parsed configuration.
    pub fn load(path: &Path) -> io::Result<Self> {
        let invalid = || io::Error::other("managed_configuration_invalid");
        let file = File::open(path).map_err(|_| invalid())?;
        if !file.metadata().map_err(|_| invalid())?.is_file() {
            return Err(invalid());
        }
        let mut raw = Zeroizing::new(Vec::new());
        file.take(65537)
            .read_to_end(&mut raw)
            .map_err(|_| invalid())?;
        if raw.len() > 65536 {
            return Err(invalid());
        }
        let text = std::str::from_utf8(&raw).map_err(|_| invalid())?;
        let config = toml::from_str(text).map_err(|_| invalid())?;
        let sha256 = Sha256::digest(&raw[..]).into();
        Ok(Self { config, sha256 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::config::Action;
    use sha2::{Digest, Sha256};

    const CONFIG: &[u8] = b"[proxy]\nlisten=\"127.0.0.1:443\"\nca_dir=\"$SNAPSHOT_LITERAL\"\n[policy]\ndefault=\"deny\"\n";

    #[test]
    fn bytes_hashed_are_bytes_parsed_and_environment_placeholders_are_literal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        std::fs::write(&path, CONFIG).unwrap();
        let snapshot = ManagedSnapshot::load(&path).unwrap();
        assert_eq!(snapshot.sha256, <[u8; 32]>::from(Sha256::digest(CONFIG)));
        assert_eq!(
            snapshot.config.proxy.ca_dir.as_deref(),
            Some("$SNAPSHOT_LITERAL")
        );
        std::fs::write(
            &path,
            b"[proxy]\nlisten=\"127.0.0.1:1\"\n[policy]\ndefault=\"allow\"",
        )
        .unwrap();
        assert_eq!(snapshot.config.policy.default, Action::Deny);
        assert_eq!(snapshot.sha256, <[u8; 32]>::from(Sha256::digest(CONFIG)));
    }

    #[test]
    fn malformed_or_oversized_configuration_never_echoes_source_or_secrets() {
        for raw in [
            b"SYNTHETIC_SECRET=\"unterminated".to_vec(),
            vec![b'#'; 65537],
            vec![0xff],
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("config.toml");
            std::fs::write(&path, raw).unwrap();
            let error = match ManagedSnapshot::load(&path) {
                Ok(_) => panic!("accepted invalid snapshot"),
                Err(e) => e,
            };
            assert_eq!(error.to_string(), "managed_configuration_invalid");
        }
    }
}
