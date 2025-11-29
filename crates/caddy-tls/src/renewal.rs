//! Certificate renewal scheduler
//!
//! Periodically checks certificates and renews them before expiration.

use crate::acme::AcmeManager;
use crate::storage::CertStorage;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// Default renewal check interval (12 hours)
const DEFAULT_CHECK_INTERVAL_HOURS: u64 = 12;

/// Default days before expiry to trigger renewal
const DEFAULT_RENEWAL_DAYS: i64 = 30;

/// Certificate renewal scheduler
pub struct RenewalScheduler {
    acme_manager: Arc<AcmeManager>,
    storage: Arc<CertStorage>,
    domains: Vec<String>,
    check_interval: Duration,
    renewal_days: i64,
    shutdown_rx: watch::Receiver<bool>,
}

impl RenewalScheduler {
    /// Create a new renewal scheduler
    pub fn new(
        acme_manager: Arc<AcmeManager>,
        storage: Arc<CertStorage>,
        domains: Vec<String>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            acme_manager,
            storage,
            domains,
            check_interval: Duration::from_secs(DEFAULT_CHECK_INTERVAL_HOURS * 3600),
            renewal_days: DEFAULT_RENEWAL_DAYS,
            shutdown_rx,
        }
    }

    /// Set custom check interval
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Set custom renewal days threshold
    pub fn with_renewal_days(mut self, days: i64) -> Self {
        self.renewal_days = days;
        self
    }

    /// Start the renewal scheduler (runs in background)
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Run the renewal loop
    async fn run(mut self) {
        info!(
            check_interval_hours = self.check_interval.as_secs() / 3600,
            renewal_days = self.renewal_days,
            domains = ?self.domains,
            "Certificate renewal scheduler started"
        );

        loop {
            // Check for shutdown signal
            tokio::select! {
                _ = tokio::time::sleep(self.check_interval) => {
                    self.check_and_renew().await;
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Renewal scheduler shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Check all certificates and renew if needed
    async fn check_and_renew(&self) {
        debug!("Checking certificates for renewal");

        for domain in &self.domains {
            match self.storage.load_cert(domain).await {
                Ok(Some(bundle)) => {
                    if bundle.expires_within_days(self.renewal_days) {
                        let days_left = (bundle.expires_at - chrono::Utc::now()).num_days();
                        info!(
                            domain = %domain,
                            days_left = days_left,
                            "Certificate expiring soon, initiating renewal"
                        );

                        match self.acme_manager.obtain_certificate(domain).await {
                            Ok(_) => {
                                info!(domain = %domain, "Certificate renewed successfully");
                            }
                            Err(e) => {
                                error!(
                                    domain = %domain,
                                    error = %e,
                                    "Failed to renew certificate"
                                );
                            }
                        }
                    } else {
                        let days_left = (bundle.expires_at - chrono::Utc::now()).num_days();
                        debug!(
                            domain = %domain,
                            days_left = days_left,
                            "Certificate still valid"
                        );
                    }
                }
                Ok(None) => {
                    warn!(
                        domain = %domain,
                        "No certificate found, attempting to obtain"
                    );
                    match self.acme_manager.obtain_certificate(domain).await {
                        Ok(_) => info!(domain = %domain, "Certificate obtained"),
                        Err(e) => error!(domain = %domain, error = %e, "Failed to obtain certificate"),
                    }
                }
                Err(e) => {
                    error!(
                        domain = %domain,
                        error = %e,
                        "Failed to load certificate"
                    );
                }
            }
        }
    }
}

/// Create a shutdown channel pair
pub fn shutdown_channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_channel() {
        let (tx, rx) = shutdown_channel();
        assert!(!*rx.borrow());
        tx.send(true).unwrap();
        assert!(*rx.borrow());
    }
}
