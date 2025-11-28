//! caddy-tls: TLS and ACME management for caddy-rs
//!
//! This crate handles automatic HTTPS certificate provisioning via ACME
//! (Let's Encrypt) and TLS certificate management.

pub mod acme;
pub mod error;
pub mod provider;
pub mod storage;

pub use acme::{AcmeManager, ChallengeTokens};
pub use error::TlsError;
pub use provider::{load_certs_from_storage, CertResolver};
pub use storage::CertStorage;

/// Let's Encrypt production CA
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Let's Encrypt staging CA (for testing)
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
