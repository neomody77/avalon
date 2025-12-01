//! Certificate storage

use crate::error::TlsError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

/// Certificate bundle containing cert and private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBundle {
    pub domain: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl CertBundle {
    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if certificate expires within the given duration
    pub fn expires_within_days(&self, days: i64) -> bool {
        let threshold = Utc::now() + chrono::Duration::days(days);
        self.expires_at <= threshold
    }
}

/// ACME account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    pub email: String,
    pub account_url: String,
    pub private_key_pem: String,
    pub created_at: DateTime<Utc>,
}

/// Certificate storage backend
pub struct CertStorage {
    base_path: PathBuf,
}

impl CertStorage {
    /// Create a new certificate storage
    pub async fn new<P: AsRef<Path>>(base_path: P) -> Result<Self, TlsError> {
        let base_path = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&base_path).await?;
        fs::create_dir_all(base_path.join("certs")).await?;
        fs::create_dir_all(base_path.join("accounts")).await?;

        info!(path = ?base_path, "Certificate storage initialized");
        Ok(Self { base_path })
    }

    /// Store a certificate bundle
    pub async fn store_cert(&self, bundle: &CertBundle) -> Result<(), TlsError> {
        let path = self.cert_path(&bundle.domain);
        let content = serde_json::to_string_pretty(bundle)?;
        fs::write(&path, content).await?;
        debug!(domain = %bundle.domain, path = ?path, "Certificate stored");
        Ok(())
    }

    /// Load a certificate bundle
    pub async fn load_cert(&self, domain: &str) -> Result<Option<CertBundle>, TlsError> {
        let path = self.cert_path(domain);
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).await?;
        let bundle: CertBundle = serde_json::from_str(&content)?;

        if bundle.is_expired() {
            debug!(domain = %domain, "Certificate expired, removing");
            let _ = fs::remove_file(&path).await;
            return Ok(None);
        }

        Ok(Some(bundle))
    }

    /// Delete a certificate
    pub async fn delete_cert(&self, domain: &str) -> Result<(), TlsError> {
        let path = self.cert_path(domain);
        if path.exists() {
            fs::remove_file(&path).await?;
            debug!(domain = %domain, "Certificate deleted");
        }
        Ok(())
    }

    /// List all stored domains
    pub async fn list_domains(&self) -> Result<Vec<String>, TlsError> {
        let certs_dir = self.base_path.join("certs");
        let mut domains = Vec::new();

        let mut entries = fs::read_dir(&certs_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".json") {
                    domains.push(name.trim_end_matches(".json").to_string());
                }
            }
        }

        Ok(domains)
    }

    /// Store ACME account
    pub async fn store_account(&self, account: &AcmeAccount) -> Result<(), TlsError> {
        let path = self.account_path(&account.email);
        let content = serde_json::to_string_pretty(account)?;
        fs::write(&path, content).await?;
        debug!(email = %account.email, "ACME account stored");
        Ok(())
    }

    /// Load ACME account
    pub async fn load_account(&self, email: &str) -> Result<Option<AcmeAccount>, TlsError> {
        let path = self.account_path(email);
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).await?;
        let account: AcmeAccount = serde_json::from_str(&content)?;
        Ok(Some(account))
    }

    /// Get certificate file path
    pub fn cert_path(&self, domain: &str) -> PathBuf {
        self.base_path
            .join("certs")
            .join(format!("{}.json", sanitize_domain(domain)))
    }

    /// Get account file path
    fn account_path(&self, email: &str) -> PathBuf {
        self.base_path
            .join("accounts")
            .join(format!("{}.json", simple_hash(email)))
    }

    /// Get the PEM file paths for a domain
    pub fn get_pem_paths(&self, domain: &str) -> (PathBuf, PathBuf) {
        let sanitized = sanitize_domain(domain);
        let certs_dir = self.base_path.join("certs");
        (
            certs_dir.join(format!("{}.crt", sanitized)),
            certs_dir.join(format!("{}.key", sanitized)),
        )
    }

    /// Write PEM files for a certificate
    pub async fn write_pem_files(&self, bundle: &CertBundle) -> Result<(PathBuf, PathBuf), TlsError> {
        let (cert_path, key_path) = self.get_pem_paths(&bundle.domain);
        fs::write(&cert_path, &bundle.certificate_pem).await?;
        fs::write(&key_path, &bundle.private_key_pem).await?;

        // Set restrictive permissions on private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(&key_path, permissions) {
                tracing::warn!(path = ?key_path, error = %e, "Failed to set key file permissions");
            }
        }

        Ok((cert_path, key_path))
    }
}

/// Sanitize domain name for use as filename
fn sanitize_domain(domain: &str) -> String {
    domain
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

// ============================================================================
// Certificate Discovery
// ============================================================================

/// Discovered certificate with metadata
#[derive(Debug, Clone)]
pub struct DiscoveredCert {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
    /// Domain names in the certificate (CN and SANs)
    pub domains: Vec<String>,
    /// Certificate expiration time
    pub expires_at: DateTime<Utc>,
    /// Certificate not-before time
    pub not_before: DateTime<Utc>,
    /// Is self-signed
    pub is_self_signed: bool,
}

impl DiscoveredCert {
    /// Check if this certificate is valid (not expired and already active)
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now < self.expires_at
    }

    /// Get remaining validity in days
    pub fn remaining_days(&self) -> i64 {
        (self.expires_at - Utc::now()).num_days()
    }
}

/// Discover certificates in a directory and its subdirectories
pub fn discover_certificates<P: AsRef<Path>>(base_path: P) -> Vec<DiscoveredCert> {
    use walkdir::WalkDir;

    let base_path = base_path.as_ref();
    let mut discovered = Vec::new();
    let mut cert_files: Vec<PathBuf> = Vec::new();

    // Find all .crt and .cer files (common certificate extensions)
    // Note: .pem is excluded as it's ambiguous (could be cert or key)
    for entry in WalkDir::new(base_path)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "crt" || ext == "cer" {
                    cert_files.push(path.to_path_buf());
                }
            }
        }
    }

    for cert_path in cert_files {
        match parse_certificate_file(&cert_path) {
            Ok(cert_info) => {
                // Find corresponding key file
                if let Some(key_path) = find_key_file(&cert_path) {
                    info!(
                        cert = ?cert_path,
                        key = ?key_path,
                        domains = ?cert_info.0,
                        expires = %cert_info.1,
                        "Discovered certificate"
                    );
                    discovered.push(DiscoveredCert {
                        cert_path,
                        key_path,
                        domains: cert_info.0,
                        expires_at: cert_info.1,
                        not_before: cert_info.2,
                        is_self_signed: cert_info.3,
                    });
                } else {
                    debug!(cert = ?cert_path, "No matching key file found");
                }
            }
            Err(e) => {
                debug!(cert = ?cert_path, error = %e, "Failed to parse certificate");
            }
        }
    }

    discovered
}

/// Certificate info returned from parsing
type CertInfo = (Vec<String>, DateTime<Utc>, DateTime<Utc>, bool);

/// Parse certificate file and extract domains, expiration, not_before, is_self_signed
fn parse_certificate_file(path: &Path) -> Result<CertInfo, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read cert file: {}", e))?;

    // Parse PEM
    let pem = ::pem::parse(&content)
        .map_err(|e| format!("Failed to parse PEM: {}", e))?;

    // Parse X509
    let (_, cert) = X509Certificate::from_der(pem.contents())
        .map_err(|e| format!("Failed to parse X509: {:?}", e))?;

    // Extract domains
    let mut domains = Vec::new();

    // Get CN from subject
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(cn) = attr.as_str() {
                    domains.push(cn.to_string());
                }
            }
        }
    }

    // Get SANs
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                let dns_str = dns.to_string();
                if !domains.contains(&dns_str) {
                    domains.push(dns_str);
                }
            }
        }
    }

    // Get validity period
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();

    let not_before_chrono = DateTime::from_timestamp(not_before.unix_timestamp(), 0)
        .unwrap_or_else(Utc::now);
    let not_after_chrono = DateTime::from_timestamp(not_after.unix_timestamp(), 0)
        .unwrap_or_else(Utc::now);

    // Check if self-signed (issuer == subject)
    let is_self_signed = cert.issuer() == cert.subject();

    Ok((domains, not_after_chrono, not_before_chrono, is_self_signed))
}

/// Find the corresponding key file for a certificate
fn find_key_file(cert_path: &Path) -> Option<PathBuf> {
    let stem = cert_path.file_stem()?.to_string_lossy();
    let parent = cert_path.parent()?;

    // Try common key file patterns
    let patterns = [
        format!("{}.key", stem),
        format!("{}-key.pem", stem),
        format!("{}.pem.key", stem),
        "privkey.pem".to_string(),
        "private.key".to_string(),
    ];

    for pattern in &patterns {
        let key_path = parent.join(pattern);
        if key_path.exists() {
            // Verify it's actually a private key
            if is_private_key_file(&key_path) {
                return Some(key_path);
            }
        }
    }

    None
}

/// Check if file contains a private key
fn is_private_key_file(path: &Path) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        content.contains("PRIVATE KEY")
    } else {
        false
    }
}

/// Find the best certificate for a domain from discovered certificates
/// Prefers: non-expired > longer validity > non-self-signed
pub fn find_best_cert_for_domain<'a>(domain: &str, certs: &'a [DiscoveredCert]) -> Option<&'a DiscoveredCert> {
    let mut matching: Vec<&DiscoveredCert> = certs
        .iter()
        .filter(|c| {
            c.domains.iter().any(|d| {
                d == domain ||
                // Wildcard matching
                (d.starts_with("*.") && domain.ends_with(&d[1..]))
            })
        })
        .filter(|c| c.is_valid())
        .collect();

    if matching.is_empty() {
        return None;
    }

    // Sort by: non-self-signed first, then by expiration (longer validity first)
    matching.sort_by(|a, b| {
        // Prefer non-self-signed
        match (a.is_self_signed, b.is_self_signed) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            _ => {
                // If same self-signed status, prefer longer validity
                b.expires_at.cmp(&a.expires_at)
            }
        }
    });

    matching.first().copied()
}

/// Auto-discover and select best certificate for a domain
pub fn auto_select_certificate<P: AsRef<Path>>(
    base_path: P,
    domain: &str,
) -> Option<(PathBuf, PathBuf)> {
    let certs = discover_certificates(base_path);

    if certs.is_empty() {
        debug!(domain = %domain, "No certificates discovered");
        return None;
    }

    info!(count = certs.len(), "Discovered certificates");

    if let Some(best) = find_best_cert_for_domain(domain, &certs) {
        info!(
            domain = %domain,
            cert = ?best.cert_path,
            key = ?best.key_path,
            expires_in_days = best.remaining_days(),
            is_self_signed = best.is_self_signed,
            "Selected best certificate"
        );
        Some((best.cert_path.clone(), best.key_path.clone()))
    } else {
        warn!(domain = %domain, "No valid certificate found for domain");
        None
    }
}

/// Simple hash for filenames
fn simple_hash(s: &str) -> String {
    use base64::Engine;
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    base64::engine::general_purpose::STANDARD
        .encode(&result[..8])
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_domain() {
        assert_eq!(sanitize_domain("example.com"), "example.com");
        assert_eq!(sanitize_domain("sub.example.com"), "sub.example.com");
        assert_eq!(sanitize_domain("test/domain"), "test_domain");
    }

    #[test]
    fn test_simple_hash() {
        let hash1 = simple_hash("test@example.com");
        let hash2 = simple_hash("test@example.com");
        let hash3 = simple_hash("other@example.com");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_cert_bundle_serialization() {
        let bundle = CertBundle {
            domain: "example.com".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: CertBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.domain, bundle.domain);
    }

    #[test]
    fn test_cert_expired() {
        let expired = CertBundle {
            domain: "test.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_at: Utc::now() - chrono::Duration::days(1),
            created_at: Utc::now() - chrono::Duration::days(90),
        };

        assert!(expired.is_expired());

        let valid = CertBundle {
            domain: "test.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            created_at: Utc::now(),
        };

        assert!(!valid.is_expired());
    }

    #[test]
    fn test_cert_expiry() {
        let bundle = CertBundle {
            domain: "test.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_at: Utc::now() + chrono::Duration::days(10),
            created_at: Utc::now(),
        };

        assert!(bundle.expires_within_days(30));
        assert!(!bundle.expires_within_days(5));
    }

    #[test]
    fn test_acme_account_serialization() {
        let account = AcmeAccount {
            email: "test@example.com".to_string(),
            account_url: "https://acme.example.com/acct/123".to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&account).unwrap();
        let parsed: AcmeAccount = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.email, account.email);
    }

    #[tokio::test]
    async fn test_storage_init() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        assert!(temp_dir.path().join("certs").exists());
        assert!(temp_dir.path().join("accounts").exists());
        assert!(storage.base_path.exists());
    }

    #[tokio::test]
    async fn test_store_and_load_cert() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let bundle = CertBundle {
            domain: "example.com".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "key".to_string(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            created_at: Utc::now(),
        };

        storage.store_cert(&bundle).await.unwrap();
        let loaded = storage.load_cert("example.com").await.unwrap().unwrap();

        assert_eq!(loaded.domain, bundle.domain);
        assert_eq!(loaded.certificate_pem, bundle.certificate_pem);
    }

    #[tokio::test]
    async fn test_load_nonexistent_cert() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let result = storage.load_cert("nonexistent.com").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_load_expired_cert() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let bundle = CertBundle {
            domain: "expired.com".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "key".to_string(),
            expires_at: Utc::now() - chrono::Duration::days(1),
            created_at: Utc::now() - chrono::Duration::days(90),
        };

        storage.store_cert(&bundle).await.unwrap();
        let result = storage.load_cert("expired.com").await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_cert() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let bundle = CertBundle {
            domain: "delete.com".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "key".to_string(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            created_at: Utc::now(),
        };

        storage.store_cert(&bundle).await.unwrap();
        storage.delete_cert("delete.com").await.unwrap();

        let result = storage.load_cert("delete.com").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_cert() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        // Should not error
        storage.delete_cert("nonexistent.com").await.unwrap();
    }

    #[tokio::test]
    async fn test_list_domains() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        for domain in &["a.com", "b.com", "c.com"] {
            let bundle = CertBundle {
                domain: domain.to_string(),
                certificate_pem: "cert".to_string(),
                private_key_pem: "key".to_string(),
                expires_at: Utc::now() + chrono::Duration::days(90),
                created_at: Utc::now(),
            };
            storage.store_cert(&bundle).await.unwrap();
        }

        let domains = storage.list_domains().await.unwrap();
        assert_eq!(domains.len(), 3);
    }

    #[tokio::test]
    async fn test_list_domains_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let domains = storage.list_domains().await.unwrap();
        assert!(domains.is_empty());
    }

    #[tokio::test]
    async fn test_store_and_load_account() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let account = AcmeAccount {
            email: "test@example.com".to_string(),
            account_url: "https://acme.example.com/acct/123".to_string(),
            private_key_pem: "key".to_string(),
            created_at: Utc::now(),
        };

        storage.store_account(&account).await.unwrap();
        let loaded = storage.load_account("test@example.com").await.unwrap().unwrap();

        assert_eq!(loaded.email, account.email);
        assert_eq!(loaded.account_url, account.account_url);
    }

    #[tokio::test]
    async fn test_load_nonexistent_account() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CertStorage::new(temp_dir.path()).await.unwrap();

        let result = storage.load_account("nonexistent@example.com").await.unwrap();
        assert!(result.is_none());
    }
}
