//! TLS certificate provider and resolver

use crate::error::TlsError;
use crate::storage::CertStorage;
use parking_lot::RwLock;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pemfile::{certs, private_key};
use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, warn};

/// TLS certificate resolver with SNI support
pub struct CertResolver {
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("domains", &self.certs.read().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CertResolver {
    /// Create a new certificate resolver
    pub fn new() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            default_cert: RwLock::new(None),
        }
    }

    /// Add a certificate for a domain
    pub fn add_cert(&self, domain: &str, cert: Arc<CertifiedKey>) {
        self.certs.write().insert(domain.to_string(), cert);
        debug!(domain = %domain, "Certificate added to resolver");
    }

    /// Set the default certificate
    pub fn set_default(&self, cert: Arc<CertifiedKey>) {
        *self.default_cert.write() = Some(cert);
        debug!("Default certificate set");
    }

    /// Load certificate from PEM files
    pub fn load_from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, TlsError> {
        let certs = certs(&mut BufReader::new(cert_pem.as_bytes()))
            .collect::<Result<Vec<CertificateDer>, _>>()
            .map_err(|e| TlsError::CertificateError(e.to_string()))?;

        let key = private_key(&mut BufReader::new(key_pem.as_bytes()))
            .map_err(|e| TlsError::CertificateError(e.to_string()))?
            .ok_or_else(|| TlsError::CertificateError("No private key found".to_string()))?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| TlsError::CertificateError(e.to_string()))?;

        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    /// Load certificate from file paths
    pub fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, TlsError> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        Self::load_from_pem(&cert_pem, &key_pem)
    }
}

impl Default for CertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let certs = self.certs.read();

            // Try exact match
            if let Some(cert) = certs.get(sni) {
                debug!(sni = %sni, "Resolved certificate for SNI");
                return Some(cert.clone());
            }

            // Try wildcard match
            if let Some(dot_pos) = sni.find('.') {
                let wildcard = format!("*{}", &sni[dot_pos..]);
                if let Some(cert) = certs.get(&wildcard) {
                    debug!(sni = %sni, wildcard = %wildcard, "Resolved wildcard certificate");
                    return Some(cert.clone());
                }
            }

            warn!(sni = %sni, "No certificate found for SNI");
        }

        // Return default certificate
        self.default_cert.read().clone()
    }
}

/// Load certificates from storage into resolver
pub async fn load_certs_from_storage(
    storage: &CertStorage,
    resolver: &CertResolver,
) -> Result<(), TlsError> {
    let domains = storage.list_domains().await?;

    for domain in domains {
        if let Some(bundle) = storage.load_cert(&domain).await? {
            match CertResolver::load_from_pem(&bundle.certificate_pem, &bundle.private_key_pem) {
                Ok(cert) => {
                    resolver.add_cert(&domain, cert.clone());

                    // Use first cert as default if none set
                    if resolver.default_cert.read().is_none() {
                        resolver.set_default(cert);
                    }
                }
                Err(e) => {
                    warn!(domain = %domain, error = %e, "Failed to load certificate");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed test certificate for testing
    fn generate_test_cert() -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn test_cert_resolver_add_cert() {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert = CertResolver::load_from_pem(&cert_pem, &key_pem).unwrap();

        let resolver = CertResolver::new();
        resolver.add_cert("localhost", cert);

        assert!(resolver.certs.read().contains_key("localhost"));
    }

    #[test]
    fn test_parse_cert_bundle() {
        let (cert_pem, key_pem) = generate_test_cert();
        let result = CertResolver::load_from_pem(&cert_pem, &key_pem);
        assert!(result.is_ok());
    }
}
