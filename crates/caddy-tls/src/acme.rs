//! ACME client for automatic certificate provisioning

use crate::error::TlsError;
use crate::storage::{AcmeAccount, CertBundle, CertStorage};
use chrono::Utc;
use dashmap::DashMap;
use instant_acme::{Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Maximum time allowed for a complete ACME certificate acquisition (5 minutes)
const ACME_TOTAL_TIMEOUT_SECS: u64 = 300;

/// Shared storage for ACME HTTP-01 challenge tokens
pub type ChallengeTokens = Arc<DashMap<String, String>>;

/// ACME manager for certificate provisioning
pub struct AcmeManager {
    ca_url: String,
    email: String,
    storage: Arc<CertStorage>,
    challenge_tokens: ChallengeTokens,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub fn new(ca_url: String, email: String, storage: Arc<CertStorage>) -> Self {
        Self {
            ca_url,
            email,
            storage,
            challenge_tokens: Arc::new(DashMap::new()),
        }
    }

    /// Get the challenge tokens map for HTTP-01 challenge handling
    pub fn challenge_tokens(&self) -> ChallengeTokens {
        self.challenge_tokens.clone()
    }

    /// Get or create an ACME account
    pub async fn get_or_create_account(&self) -> Result<Account, TlsError> {
        // For simplicity, always create a new account
        // In production, you'd want to persist and reload credentials
        info!(email = %self.email, ca = %self.ca_url, "Creating ACME account");

        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &self.ca_url,
            None,
        )
        .await
        .map_err(|e| TlsError::Acme(e.to_string()))?;

        // Store account info
        let stored = AcmeAccount {
            email: self.email.clone(),
            account_url: String::new(), // Credentials don't expose URL directly
            private_key_pem: String::new(),
            created_at: Utc::now(),
        };
        let _ = self.storage.store_account(&stored).await;

        Ok(account)
    }

    /// Validate domain name format
    fn validate_domain(domain: &str) -> Result<(), TlsError> {
        // Check for empty domain
        if domain.is_empty() {
            return Err(TlsError::Acme("Domain name cannot be empty".to_string()));
        }

        // Check length (max 253 characters for DNS names)
        if domain.len() > 253 {
            return Err(TlsError::Acme("Domain name too long".to_string()));
        }

        // Check for valid characters and structure
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return Err(TlsError::Acme("Domain must have at least two labels".to_string()));
        }

        for label in &labels {
            // Each label must be 1-63 characters
            if label.is_empty() || label.len() > 63 {
                return Err(TlsError::Acme(format!("Invalid label length in domain: {}", domain)));
            }

            // Labels must start with alphanumeric
            if !label.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false) {
                return Err(TlsError::Acme(format!("Domain label must start with alphanumeric: {}", domain)));
            }

            // Labels can only contain alphanumeric and hyphens
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(TlsError::Acme(format!("Invalid characters in domain: {}", domain)));
            }

            // Labels cannot end with hyphen
            if label.ends_with('-') {
                return Err(TlsError::Acme(format!("Domain label cannot end with hyphen: {}", domain)));
            }
        }

        // TLD cannot be all numeric
        if let Some(tld) = labels.last() {
            if tld.chars().all(|c| c.is_ascii_digit()) {
                return Err(TlsError::Acme(format!("TLD cannot be all numeric: {}", domain)));
            }
        }

        Ok(())
    }

    /// Obtain a certificate for a domain with timeout protection
    pub async fn obtain_certificate(&self, domain: &str) -> Result<CertBundle, TlsError> {
        // Validate domain first
        Self::validate_domain(domain)?;

        // Wrap the entire operation in a timeout
        let timeout_duration = Duration::from_secs(ACME_TOTAL_TIMEOUT_SECS);
        match tokio::time::timeout(timeout_duration, self.obtain_certificate_inner(domain)).await {
            Ok(result) => result,
            Err(_) => Err(TlsError::Acme(format!(
                "ACME certificate acquisition timed out after {} seconds",
                ACME_TOTAL_TIMEOUT_SECS
            ))),
        }
    }

    /// Internal certificate acquisition (without timeout wrapper)
    async fn obtain_certificate_inner(&self, domain: &str) -> Result<CertBundle, TlsError> {
        info!(domain = %domain, "Obtaining certificate via ACME");

        let account = self.get_or_create_account().await?;

        // Create order
        let identifiers = vec![Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder { identifiers: &identifiers })
            .await
            .map_err(|e| TlsError::Acme(e.to_string()))?;

        // Get authorizations
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| TlsError::Acme(e.to_string()))?;

        // Process each authorization
        for auth in authorizations {
            match auth.status {
                AuthorizationStatus::Pending => {
                    // Use HTTP-01 challenge
                    if let Some(challenge) = auth.challenges.iter().find(|c| c.r#type == ChallengeType::Http01) {
                        let key_auth = order.key_authorization(challenge);

                        // Store token for HTTP server to respond
                        debug!(token = %challenge.token, "Setting up HTTP-01 challenge");
                        self.challenge_tokens.insert(
                            challenge.token.clone(),
                            key_auth.as_str().to_string(),
                        );

                        // Tell ACME server we're ready
                        order
                            .set_challenge_ready(&challenge.url)
                            .await
                            .map_err(|e| TlsError::Acme(e.to_string()))?;

                        // Wait for validation
                        self.wait_for_order_ready(&mut order, 10).await?;

                        // Clean up token
                        self.challenge_tokens.remove(&challenge.token);
                    } else {
                        return Err(TlsError::Acme("No supported challenge type found".to_string()));
                    }
                }
                AuthorizationStatus::Valid => {
                    debug!("Authorization already valid");
                }
                status => {
                    return Err(TlsError::Acme(format!(
                        "Unexpected authorization status: {:?}",
                        status
                    )));
                }
            }
        }

        // Generate CSR
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| TlsError::Acme(e.to_string()))?;
        params.distinguished_name = DistinguishedName::new();

        let key_pair = KeyPair::generate()
            .map_err(|e| TlsError::Acme(e.to_string()))?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| TlsError::Acme(e.to_string()))?;

        // Finalize order
        order
            .finalize(csr.der())
            .await
            .map_err(|e| TlsError::Acme(e.to_string()))?;

        // Wait for certificate
        self.wait_for_order_ready(&mut order, 10).await?;

        // Download certificate
        let cert_chain = order
            .certificate()
            .await
            .map_err(|e| TlsError::Acme(e.to_string()))?
            .ok_or_else(|| TlsError::Acme("No certificate returned".to_string()))?;

        let bundle = CertBundle {
            domain: domain.to_string(),
            certificate_pem: cert_chain,
            private_key_pem: key_pair.serialize_pem(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            created_at: Utc::now(),
        };

        // Store certificate
        self.storage.store_cert(&bundle).await?;
        self.storage.write_pem_files(&bundle).await?;

        info!(domain = %domain, "Certificate obtained successfully");
        Ok(bundle)
    }

    /// Wait for order to be ready
    async fn wait_for_order_ready(
        &self,
        order: &mut instant_acme::Order,
        max_attempts: u32,
    ) -> Result<(), TlsError> {
        for i in 0..max_attempts {
            tokio::time::sleep(Duration::from_secs(2)).await;

            order.refresh().await.map_err(|e| TlsError::Acme(e.to_string()))?;

            match order.state().status {
                OrderStatus::Ready | OrderStatus::Valid => {
                    return Ok(());
                }
                OrderStatus::Invalid => {
                    return Err(TlsError::Acme("Order became invalid".to_string()));
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    debug!(attempt = i + 1, "Waiting for order to be ready");
                }
            }
        }

        Err(TlsError::Acme("Order did not become ready in time".to_string()))
    }

    /// Check and renew certificates that are expiring soon
    pub async fn check_renewals(&self, domains: &[String], days_before: i64) -> Result<(), TlsError> {
        for domain in domains {
            if let Some(bundle) = self.storage.load_cert(domain).await? {
                if bundle.expires_within_days(days_before) {
                    info!(domain = %domain, "Certificate expiring soon, renewing");
                    match self.obtain_certificate(domain).await {
                        Ok(_) => info!(domain = %domain, "Certificate renewed"),
                        Err(e) => warn!(domain = %domain, error = %e, "Failed to renew certificate"),
                    }
                }
            }
        }
        Ok(())
    }
}
