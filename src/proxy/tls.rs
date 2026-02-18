//! MITM TLS certificate cache.
//!
//! [`CertCache`] maintains an LRU cache of per-domain `rustls::ServerConfig`
//! objects, each signed by the Root CA loaded from disk. When the proxy
//! intercepts a CONNECT tunnel, it looks up (or generates) the matching
//! domain certificate so that the client sees a valid TLS certificate.

use std::path::Path;
use std::sync::{Arc, Mutex};

/// LRU-based cache of per-domain TLS server configurations.
///
/// On first request for a domain, a new ECDSA P-256 key pair and certificate
/// are generated, signed by the Root CA, and stored. Subsequent requests
/// for the same domain reuse the cached `ServerConfig`.
pub struct CertCache {
    ca_key: rcgen::KeyPair,
    /// Self-signed CA Certificate (reconstructed from params + key for signing child certs).
    ca_cert: rcgen::Certificate,
    /// Original CA certificate DER from disk (included in TLS chain).
    ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    cache: Mutex<lru::LruCache<String, Arc<rustls::ServerConfig>>>,
}

impl CertCache {
    /// Load the Root CA key and certificate from `ca_dir`.
    ///
    /// Expects `key.pem` and `cert.pem` files produced by `agentshield ca init`.
    pub fn load(ca_dir: &Path) -> anyhow::Result<Self> {
        let key_pem = std::fs::read_to_string(ca_dir.join("key.pem"))?;
        let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem"))?;

        // Parse CA private key
        let ca_key = rcgen::KeyPair::from_pem(&key_pem)?;

        // Parse CA certificate DER for the TLS chain
        let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
        let ca_cert_der = certs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No certificate found in cert.pem"))?;

        // NOTE: rcgen does not support loading a Certificate from PEM/DER directly.
        // We reconstruct a CA Certificate by self-signing new params with the same key.
        // The resulting `ca_cert` has a different serial/validity than the disk cert, but
        // since `signed_by()` uses the CA's *key* (not serial) for signing, domain certs
        // are valid. The original `ca_cert_der` from disk is included in the TLS chain
        // so clients can verify against the installed Root CA.
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "AgentShield CA");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "AgentShield");
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let cache = Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(1000).unwrap(),
        ));

        Ok(Self {
            ca_key,
            ca_cert,
            ca_cert_der,
            cache,
        })
    }

    /// Get or create a `ServerConfig` for the given domain.
    ///
    /// If the domain is already cached, the existing config is returned.
    /// Otherwise a new ECDSA P-256 key pair and certificate (with SAN=domain)
    /// are generated, signed by the Root CA, and cached.
    pub fn get_or_create(&self, domain: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(config) = cache.get(domain) {
            return Ok(Arc::clone(config));
        }

        // Generate within the lock to prevent duplicate cert generation for the same domain.
        // Cert generation is fast (~1-2ms) so holding the lock is acceptable.
        let config = self.create_domain_config(domain)?;
        cache.put(domain.to_string(), Arc::clone(&config));
        Ok(config)
    }

    /// Generate a new ECDSA P-256 key pair and certificate for the given domain,
    /// signed by the Root CA, and wrap it in a `rustls::ServerConfig`.
    fn create_domain_config(&self, domain: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let domain_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        let mut domain_params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        domain_params.is_ca = rcgen::IsCa::NoCa;
        domain_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);

        let domain_cert = domain_params.signed_by(&domain_key, &self.ca_cert, &self.ca_key)?;

        let domain_cert_der = rustls::pki_types::CertificateDer::from(domain_cert.der().to_vec());
        let private_key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(domain_key.serialize_der()),
        );

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![domain_cert_der, self.ca_cert_der.clone()], private_key)?;

        Ok(Arc::new(server_config))
    }

    /// Return the current number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Return true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a CA in a temp dir and return the path.
    fn setup_ca() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        crate::cli::ca::generate_ca(&ca_dir).unwrap();
        (dir, ca_dir)
    }

    #[test]
    fn load_ca_from_disk() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir);
        assert!(cache.is_ok(), "Should load CA successfully");
        assert!(cache.unwrap().is_empty());
    }

    #[test]
    fn load_ca_missing_dir_fails() {
        let result = CertCache::load(Path::new("/nonexistent/ca"));
        assert!(result.is_err());
    }

    #[test]
    fn get_or_create_generates_config() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir).unwrap();

        let config = cache.get_or_create("example.com");
        assert!(config.is_ok(), "Should generate domain config");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir).unwrap();

        let c1 = cache.get_or_create("example.com").unwrap();
        let c2 = cache.get_or_create("example.com").unwrap();
        assert!(Arc::ptr_eq(&c1, &c2), "Cache hit should return same Arc");
    }

    #[test]
    fn different_domains_get_separate_configs() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir).unwrap();

        let c1 = cache.get_or_create("a.example.com").unwrap();
        let c2 = cache.get_or_create("b.example.com").unwrap();
        assert!(
            !Arc::ptr_eq(&c1, &c2),
            "Different domains should have different configs"
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir).unwrap();

        // Fill to capacity (1000) + 1 to trigger eviction
        for i in 0..1001 {
            cache
                .get_or_create(&format!("domain-{}.example.com", i))
                .unwrap();
        }
        assert_eq!(cache.len(), 1000, "LRU should evict oldest entry");
    }

    #[test]
    fn generated_cert_is_valid_tls_config() {
        let (_dir, ca_dir) = setup_ca();
        let cache = CertCache::load(&ca_dir).unwrap();

        // ServerConfig construction validates the cert chain is structurally correct
        let config = cache.get_or_create("test.example.com").unwrap();
        // If we get here, rustls accepted the cert chain
        assert_eq!(cache.len(), 1);
        drop(config);
    }
}
