//! caddy-tls: TLS and ACME management for caddy-rs
//!
//! This crate handles automatic HTTPS certificate provisioning via ACME
//! (Let's Encrypt) and TLS certificate management.

pub mod acme;
pub mod cloudflare;
pub mod error;
pub mod provider;
pub mod renewal;
pub mod self_signed;
pub mod storage;

pub use acme::{AcmeManager, ChallengeTokens};
pub use error::TlsError;
pub use provider::{load_certs_from_storage, CertResolver};
pub use renewal::{RenewalScheduler, shutdown_channel};
pub use storage::{
    CertStorage, DiscoveredCert, auto_select_certificate, discover_certificates,
    find_best_cert_for_domain,
};

// ============================================================================
// ACME Certificate Authority URLs
// ============================================================================

/// Let's Encrypt production CA
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Let's Encrypt staging CA (for testing)
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ZeroSSL production CA
pub const ZEROSSL_PRODUCTION: &str = "https://acme.zerossl.com/v2/DV90";

/// Google Trust Services production CA
pub const GOOGLE_TRUST_SERVICES: &str = "https://dv.acme-v02.api.pki.goog/directory";

/// Buypass production CA
pub const BUYPASS_PRODUCTION: &str = "https://api.buypass.com/acme/directory";

/// Buypass test/staging CA
pub const BUYPASS_STAGING: &str = "https://api.test4.buypass.no/acme/directory";

/// SSL.com production CA
pub const SSLCOM_PRODUCTION: &str = "https://acme.ssl.com/sslcom-dv-rsa";

/// SSL.com ECC production CA
pub const SSLCOM_ECC_PRODUCTION: &str = "https://acme.ssl.com/sslcom-dv-ecc";

/// Resolve ACME CA URL from provider name or direct URL
///
/// Supported provider names (case-insensitive):
/// - `letsencrypt` or `le` - Let's Encrypt production
/// - `letsencrypt-staging` or `le-staging` - Let's Encrypt staging
/// - `zerossl` - ZeroSSL
/// - `google` or `gts` - Google Trust Services
/// - `buypass` - Buypass production
/// - `buypass-staging` - Buypass staging
/// - `sslcom` - SSL.com RSA
/// - `sslcom-ecc` - SSL.com ECC
///
/// If the input is already a URL (starts with `http`), it's returned as-is.
pub fn resolve_acme_ca(provider_or_url: &str) -> String {
    let normalized = provider_or_url.trim().to_lowercase();

    // If it's already a URL, return as-is
    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        return provider_or_url.to_string();
    }

    // Match provider names
    match normalized.as_str() {
        "letsencrypt" | "le" | "letsencrypt-production" | "le-production" => {
            LETS_ENCRYPT_PRODUCTION.to_string()
        }
        "letsencrypt-staging" | "le-staging" | "staging" => {
            LETS_ENCRYPT_STAGING.to_string()
        }
        "zerossl" => ZEROSSL_PRODUCTION.to_string(),
        "google" | "gts" | "google-trust" => GOOGLE_TRUST_SERVICES.to_string(),
        "buypass" | "buypass-production" => BUYPASS_PRODUCTION.to_string(),
        "buypass-staging" | "buypass-test" => BUYPASS_STAGING.to_string(),
        "sslcom" | "ssl.com" | "sslcom-rsa" => SSLCOM_PRODUCTION.to_string(),
        "sslcom-ecc" | "ssl.com-ecc" => SSLCOM_ECC_PRODUCTION.to_string(),
        // Default to Let's Encrypt if unknown
        _ => {
            tracing::warn!(
                provider = %provider_or_url,
                "Unknown ACME provider, defaulting to Let's Encrypt"
            );
            LETS_ENCRYPT_PRODUCTION.to_string()
        }
    }
}

/// Get a human-readable name for an ACME CA URL
pub fn get_acme_ca_name(url: &str) -> &'static str {
    match url {
        LETS_ENCRYPT_PRODUCTION => "Let's Encrypt",
        LETS_ENCRYPT_STAGING => "Let's Encrypt (Staging)",
        ZEROSSL_PRODUCTION => "ZeroSSL",
        GOOGLE_TRUST_SERVICES => "Google Trust Services",
        BUYPASS_PRODUCTION => "Buypass",
        BUYPASS_STAGING => "Buypass (Staging)",
        SSLCOM_PRODUCTION => "SSL.com",
        SSLCOM_ECC_PRODUCTION => "SSL.com (ECC)",
        _ => "Custom CA",
    }
}
