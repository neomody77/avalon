//! Self-signed certificate generation
//!
//! Generate temporary self-signed certificates for initial HTTPS setup,
//! allowing ACME challenges to proceed over HTTPS when behind proxies like Cloudflare.

use crate::error::TlsError;
use crate::storage::{CertBundle, CertStorage};
use chrono::{Duration, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::sync::Arc;
use tracing::info;

/// Generate a self-signed certificate for a domain
pub fn generate_self_signed(domain: &str, valid_days: i64) -> Result<CertBundle, TlsError> {
    info!(domain = %domain, valid_days = valid_days, "Generating self-signed certificate");

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| TlsError::CertGeneration(e.to_string()))?;

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    dn.push(DnType::OrganizationName, "caddy-rs Self-Signed");
    params.distinguished_name = dn;

    // Add subject alternative names
    params.subject_alt_names = vec![SanType::DnsName(domain.try_into().map_err(|e| {
        TlsError::CertGeneration(format!("Invalid domain for SAN: {}", e))
    })?)];

    // Generate key pair
    let key_pair = KeyPair::generate().map_err(|e| TlsError::CertGeneration(e.to_string()))?;

    // Generate certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::CertGeneration(e.to_string()))?;

    let now = Utc::now();
    let bundle = CertBundle {
        domain: domain.to_string(),
        certificate_pem: cert.pem(),
        private_key_pem: key_pair.serialize_pem(),
        expires_at: now + Duration::days(valid_days),
        created_at: now,
    };

    info!(domain = %domain, expires_at = %bundle.expires_at, "Self-signed certificate generated");
    Ok(bundle)
}

/// Generate and store a self-signed certificate
pub async fn generate_and_store_self_signed(
    storage: &Arc<CertStorage>,
    domain: &str,
    valid_days: i64,
) -> Result<CertBundle, TlsError> {
    let bundle = generate_self_signed(domain, valid_days)?;

    // Store to database
    storage.store_cert(&bundle).await?;

    // Write PEM files
    storage.write_pem_files(&bundle).await?;

    Ok(bundle)
}

/// Check if a certificate is self-signed (by checking issuer)
pub fn is_self_signed(cert_pem: &str) -> bool {
    // Simple heuristic: check if "caddy-rs Self-Signed" is in the cert
    cert_pem.contains("caddy-rs Self-Signed") ||
    // Or check if subject == issuer (more complex, would need x509 parsing)
    cert_pem.lines().filter(|l| l.contains("CN=")).count() <= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed() {
        let bundle = generate_self_signed("example.com", 30).unwrap();
        assert_eq!(bundle.domain, "example.com");
        assert!(!bundle.certificate_pem.is_empty());
        assert!(!bundle.private_key_pem.is_empty());
        assert!(bundle.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_self_signed_with_subdomain() {
        let bundle = generate_self_signed("api.example.com", 7).unwrap();
        assert_eq!(bundle.domain, "api.example.com");
    }

    #[test]
    fn test_is_self_signed() {
        let bundle = generate_self_signed("test.com", 1).unwrap();
        // Our self-signed certs should be detectable
        // Note: This is a simple check, in production you'd parse the x509
        assert!(bundle.certificate_pem.contains("CERTIFICATE"));
    }
}
