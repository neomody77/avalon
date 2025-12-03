//! SNI-enabled TLS listener support for Pingora
//!
//! This module provides a custom TLS acceptor that supports SNI (Server Name Indication)
//! for serving multiple certificates based on the requested hostname.

use crate::provider::CertResolver;
use crate::storage::CertStorage;
use anyhow::Result;
use rustls::version;
use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// SNI-enabled TLS settings for Pingora listeners
pub struct SniTlsSettings {
    resolver: Arc<CertResolver>,
    alpn_protocols: Option<Vec<Vec<u8>>>,
}

impl SniTlsSettings {
    /// Create new SNI TLS settings with a certificate resolver
    pub fn new(resolver: Arc<CertResolver>) -> Self {
        Self {
            resolver,
            alpn_protocols: None,
        }
    }

    /// Enable HTTP/2 support
    pub fn enable_h2(&mut self) {
        self.alpn_protocols = Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    /// Build the TLS acceptor with SNI support
    pub fn build(self) -> Result<TlsAcceptor> {
        let mut config = ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(self.resolver);

        if let Some(alpn) = self.alpn_protocols {
            config.alpn_protocols = alpn;
        }

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Get the resolver
    pub fn resolver(&self) -> Arc<CertResolver> {
        self.resolver.clone()
    }
}

/// Load certificates for all domains into the resolver
pub async fn load_all_domain_certs(
    storage: &CertStorage,
    resolver: &CertResolver,
    domains: &[String],
    storage_path: &Path,
) -> Result<()> {
    for domain in domains {
        // Try loading from storage first (ACME certs)
        if let Ok(Some(bundle)) = storage.load_cert(domain).await {
            match CertResolver::load_from_pem(&bundle.certificate_pem, &bundle.private_key_pem) {
                Ok(cert) => {
                    resolver.add_cert(domain, cert.clone());

                    // Set first valid cert as default
                    if !resolver.has_default() {
                        resolver.set_default(cert);
                    }
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
            // ACME storage path: storage_path/certs/{domain}.crt
            (
                storage_path.join("certs").join(format!("{}.crt", domain)),
                storage_path.join("certs").join(format!("{}.key", domain)),
            ),
            // Direct storage path: storage_path/{domain}.crt
            (
                storage_path.join(format!("{}.crt", domain)),
                storage_path.join(format!("{}.key", domain)),
            ),
        ];

        for (cert_path, key_path) in cert_paths {
            if cert_path.exists() && key_path.exists() {
                match CertResolver::load_from_files(&cert_path, &key_path) {
                    Ok(cert) => {
                        resolver.add_cert(domain, cert.clone());

                        if !resolver.has_default() {
                            resolver.set_default(cert);
                        }
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

    // Check if we loaded any certs
    let loaded_count = resolver.domain_count();
    if loaded_count == 0 {
        warn!("No certificates loaded for SNI");
    } else {
        info!(count = loaded_count, "Loaded certificates for SNI");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_tls_settings_creation() {
        let resolver = Arc::new(CertResolver::new());
        let settings = SniTlsSettings::new(resolver);
        assert!(settings.alpn_protocols.is_none());
    }

    #[test]
    fn test_sni_tls_settings_h2() {
        let resolver = Arc::new(CertResolver::new());
        let mut settings = SniTlsSettings::new(resolver);
        settings.enable_h2();
        assert!(settings.alpn_protocols.is_some());
    }
}
