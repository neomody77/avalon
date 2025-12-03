//! SNI (Server Name Indication) callback implementation for OpenSSL/BoringSSL
//!
//! This module provides SNI-based certificate selection for Pingora's TLS listeners.

use crate::storage::CertStorage;
use async_trait::async_trait;
use parking_lot::RwLock;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::ext::{ssl_use_certificate, ssl_use_private_key};
use pingora_core::tls::pkey::PKey;
use pingora_core::tls::x509::X509;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Stored certificate and key pair for a domain
#[derive(Clone)]
pub struct CertKeyPair {
    pub cert: X509,
    pub key: PKey<openssl::pkey::Private>,
    pub chain: Vec<X509>,
}

/// SNI-based certificate resolver for OpenSSL
pub struct SniResolver {
    /// Map of domain -> certificate/key pair
    certs: RwLock<HashMap<String, Arc<CertKeyPair>>>,
    /// Default certificate if no SNI match
    default: RwLock<Option<Arc<CertKeyPair>>>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("domains", &self.certs.read().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SniResolver {
    /// Create a new SNI resolver
    pub fn new() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            default: RwLock::new(None),
        }
    }

    /// Add a certificate for a domain
    pub fn add_cert(&self, domain: &str, pair: Arc<CertKeyPair>) {
        let mut certs = self.certs.write();
        certs.insert(domain.to_string(), pair.clone());

        // Set first cert as default if none set
        if self.default.read().is_none() {
            *self.default.write() = Some(pair);
        }

        debug!(domain = %domain, "Added certificate for SNI");
    }

    /// Set the default certificate
    pub fn set_default(&self, pair: Arc<CertKeyPair>) {
        *self.default.write() = Some(pair);
        debug!("Set default certificate");
    }

    /// Get number of loaded certificates
    pub fn domain_count(&self) -> usize {
        self.certs.read().len()
    }

    /// Load certificate from PEM files
    pub fn load_from_files(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Arc<CertKeyPair>, Box<dyn std::error::Error + Send + Sync>> {
        use std::fs;

        let cert_pem = fs::read(cert_path)?;
        let key_pem = fs::read(key_path)?;

        Self::load_from_pem(&cert_pem, &key_pem)
    }

    /// Load certificate from PEM data
    pub fn load_from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Arc<CertKeyPair>, Box<dyn std::error::Error + Send + Sync>> {
        let cert = X509::from_pem(cert_pem)?;
        let key = PKey::private_key_from_pem(key_pem)?;

        // Parse certificate chain (if present)
        let chain = X509::stack_from_pem(cert_pem)?
            .into_iter()
            .skip(1) // Skip the main cert
            .collect();

        Ok(Arc::new(CertKeyPair { cert, key, chain }))
    }

    /// Resolve certificate for a given SNI hostname
    fn resolve(&self, sni: &str) -> Option<Arc<CertKeyPair>> {
        let certs = self.certs.read();

        // Try exact match
        if let Some(pair) = certs.get(sni) {
            debug!(sni = %sni, "Resolved certificate for SNI (exact match)");
            return Some(pair.clone());
        }

        // Try wildcard match (e.g., *.example.com)
        if let Some(dot_pos) = sni.find('.') {
            let wildcard = format!("*{}", &sni[dot_pos..]);
            if let Some(pair) = certs.get(&wildcard) {
                debug!(sni = %sni, wildcard = %wildcard, "Resolved wildcard certificate");
                return Some(pair.clone());
            }
        }

        warn!(sni = %sni, "No certificate found for SNI, using default");
        self.default.read().clone()
    }
}

impl Default for SniResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SniResolver {
    fn clone(&self) -> Self {
        Self {
            certs: RwLock::new(self.certs.read().clone()),
            default: RwLock::new(self.default.read().clone()),
        }
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Get SNI from the SSL connection
        let sni = ssl.servername(openssl::ssl::NameType::HOST_NAME);

        let pair = match sni {
            Some(hostname) => {
                debug!(sni = %hostname, "TLS handshake with SNI");
                self.resolve(hostname)
            }
            None => {
                debug!("TLS handshake without SNI, using default");
                self.default.read().clone()
            }
        };

        if let Some(pair) = pair {
            // Set the certificate
            if let Err(e) = ssl_use_certificate(ssl, &pair.cert) {
                warn!(error = %e, "Failed to set certificate");
                return;
            }

            // Set the private key
            if let Err(e) = ssl_use_private_key(ssl, &pair.key) {
                warn!(error = %e, "Failed to set private key");
                return;
            }

            // Set certificate chain if present
            for chain_cert in &pair.chain {
                if let Err(e) = ssl.add_chain_cert(chain_cert.clone()) {
                    warn!(error = %e, "Failed to add chain certificate");
                }
            }

            debug!("Certificate set successfully");
        } else {
            warn!("No certificate available for TLS handshake");
        }
    }
}

/// Load all domain certificates into the SNI resolver
pub async fn load_all_certs(
    resolver: &SniResolver,
    storage: &CertStorage,
    domains: &[String],
    storage_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for domain in domains {
        // Try loading from ACME storage first
        if let Ok(Some(bundle)) = storage.load_cert(domain).await {
            match SniResolver::load_from_pem(
                bundle.certificate_pem.as_bytes(),
                bundle.private_key_pem.as_bytes(),
            ) {
                Ok(pair) => {
                    resolver.add_cert(domain, pair);
                    info!(domain = %domain, "Loaded certificate from ACME storage");
                    continue;
                }
                Err(e) => {
                    warn!(domain = %domain, error = %e, "Failed to parse ACME certificate");
                }
            }
        }

        // Try loading from file paths
        let cert_paths = [
            // ACME path: storage_path/certs/{domain}.crt
            (
                storage_path.join("certs").join(format!("{}.crt", domain)),
                storage_path.join("certs").join(format!("{}.key", domain)),
            ),
            // Direct path: storage_path/{domain}.crt
            (
                storage_path.join(format!("{}.crt", domain)),
                storage_path.join(format!("{}.key", domain)),
            ),
        ];

        for (cert_path, key_path) in cert_paths {
            if cert_path.exists() && key_path.exists() {
                match SniResolver::load_from_files(&cert_path, &key_path) {
                    Ok(pair) => {
                        resolver.add_cert(domain, pair);
                        info!(domain = %domain, cert = ?cert_path, "Loaded certificate from file");
                        break;
                    }
                    Err(e) => {
                        warn!(domain = %domain, cert = ?cert_path, error = %e, "Failed to load certificate");
                    }
                }
            }
        }
    }

    let count = resolver.domain_count();
    if count == 0 {
        warn!("No certificates loaded for SNI");
    } else {
        info!(count = count, "Loaded certificates for SNI");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_resolver_creation() {
        let resolver = SniResolver::new();
        assert_eq!(resolver.domain_count(), 0);
    }
}
