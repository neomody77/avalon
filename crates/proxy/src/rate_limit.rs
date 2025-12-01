//! Rate limiting middleware
//!
//! Provides request rate limiting based on client IP address.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Time window duration
    pub window: Duration,
    /// Burst allowance (extra requests above max during burst)
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            burst: 10,
        }
    }
}

impl RateLimitConfig {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            burst: max_requests / 10, // 10% burst by default
        }
    }

    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(max_tokens: u32, window: Duration) -> Self {
        let max = max_tokens as f64;
        Self {
            tokens: max,
            last_update: Instant::now(),
            max_tokens: max,
            refill_rate: max / window.as_secs_f64(),
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    buckets: Arc<DashMap<IpAddr, TokenBucket>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            buckets: Arc::new(DashMap::new()),
            config,
        };

        // Start cleanup task
        limiter.start_cleanup();
        limiter
    }

    /// Check if request from IP should be allowed
    pub fn check(&self, ip: IpAddr) -> bool {
        let max_tokens = self.config.max_requests + self.config.burst;

        let mut entry = self.buckets.entry(ip).or_insert_with(|| {
            TokenBucket::new(max_tokens, self.config.window)
        });

        let allowed = entry.try_consume(1.0);

        if !allowed {
            debug!(ip = %ip, "Rate limit exceeded");
        }

        allowed
    }

    /// Get remaining tokens for an IP
    pub fn remaining(&self, ip: IpAddr) -> u32 {
        if let Some(mut entry) = self.buckets.get_mut(&ip) {
            entry.refill();
            entry.tokens as u32
        } else {
            self.config.max_requests + self.config.burst
        }
    }

    /// Start background cleanup task to remove stale entries
    fn start_cleanup(&self) {
        let buckets = self.buckets.clone();
        let window = self.config.window;

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(window * 2);

                let now = Instant::now();
                let stale_threshold = window * 2;

                buckets.retain(|_, bucket| {
                    now.duration_since(bucket.last_update) < stale_threshold
                });

                debug!(entries = buckets.len(), "Rate limiter cleanup completed");
            }
        });
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            buckets: self.buckets.clone(),
            config: self.config.clone(),
        }
    }
}

/// Rate limit result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request allowed
    Allowed { remaining: u32 },
    /// Request denied due to rate limit
    Denied { retry_after_secs: u64 },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }
}

/// Check rate limit and return detailed result
pub fn check_rate_limit(limiter: &RateLimiter, ip: IpAddr) -> RateLimitResult {
    if limiter.check(ip) {
        RateLimitResult::Allowed {
            remaining: limiter.remaining(ip),
        }
    } else {
        RateLimitResult::Denied {
            retry_after_secs: limiter.config.window.as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let config = RateLimitConfig::new(10, 60);
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_rate_limiter_denies_over_limit() {
        let config = RateLimitConfig::new(5, 60).with_burst(0);
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Use up all tokens
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }

        // Should be denied
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_allows_burst() {
        let config = RateLimitConfig::new(5, 60).with_burst(3);
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow 5 + 3 = 8 requests
        for _ in 0..8 {
            assert!(limiter.check(ip));
        }

        // 9th should be denied
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig::new(2, 60).with_burst(0);
        let limiter = RateLimiter::new(config);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Both IPs should have separate limits
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1)); // ip1 exhausted

        assert!(limiter.check(ip2)); // ip2 still has tokens
        assert!(limiter.check(ip2));
        assert!(!limiter.check(ip2)); // ip2 exhausted
    }

    #[test]
    fn test_check_rate_limit_result() {
        let config = RateLimitConfig::new(2, 60).with_burst(0);
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let result = check_rate_limit(&limiter, ip);
        assert!(result.is_allowed());

        limiter.check(ip);
        limiter.check(ip);

        let result = check_rate_limit(&limiter, ip);
        assert!(!result.is_allowed());
        if let RateLimitResult::Denied { retry_after_secs } = result {
            assert_eq!(retry_after_secs, 60);
        }
    }

    #[test]
    fn test_remaining_tokens() {
        let config = RateLimitConfig::new(10, 60).with_burst(0);
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(limiter.remaining(ip), 10);

        limiter.check(ip);
        assert_eq!(limiter.remaining(ip), 9);

        for _ in 0..5 {
            limiter.check(ip);
        }
        assert_eq!(limiter.remaining(ip), 4);
    }
}
