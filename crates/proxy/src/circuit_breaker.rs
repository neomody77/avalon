//! Circuit breaker pattern implementation for upstream failure protection
//!
//! The circuit breaker prevents cascading failures by temporarily stopping
//! requests to unhealthy upstreams. It has three states:
//!
//! - Closed: Normal operation, requests pass through
//! - Open: Upstream is considered down, requests fail immediately
//! - HalfOpen: After timeout, allows one test request to check recovery

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Circuit is closed, requests pass through normally
    Closed = 0,
    /// Circuit is open, requests are rejected immediately
    Open = 1,
    /// Circuit is half-open, one test request is allowed through
    HalfOpen = 2,
}

impl From<u8> for CircuitState {
    fn from(v: u8) -> Self {
        match v {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit
    pub failure_threshold: u32,
    /// Number of consecutive successes in half-open state to close circuit
    pub success_threshold: u32,
    /// How long to wait before transitioning from Open to HalfOpen
    pub timeout: Duration,
    /// Optional sliding window size for failure counting (0 = count all)
    pub window_size: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
            window_size: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: AtomicU8,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: RwLock<Option<Instant>>,
    opened_at: RwLock<Option<Instant>>,
    name: String,
}

impl CircuitBreaker {
    pub fn new(name: &str, config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: AtomicU8::new(CircuitState::Closed as u8),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: RwLock::new(None),
            opened_at: RwLock::new(None),
            name: name.to_string(),
        }
    }

    /// Get the current circuit state
    pub fn state(&self) -> CircuitState {
        let state = CircuitState::from(self.state.load(Ordering::Relaxed));

        // Check if we should transition from Open to HalfOpen
        if state == CircuitState::Open {
            if let Some(opened) = *self.opened_at.read() {
                if opened.elapsed() >= self.config.timeout {
                    // Transition to half-open
                    self.state.store(CircuitState::HalfOpen as u8, Ordering::Relaxed);
                    info!(name = %self.name, "Circuit breaker transitioning to HalfOpen");
                    return CircuitState::HalfOpen;
                }
            }
        }

        state
    }

    /// Check if a request should be allowed through
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                // In half-open state, we allow requests but track carefully
                true
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(name = %self.name, count, threshold = self.config.success_threshold, "Circuit breaker success in HalfOpen");

                if count >= self.config.success_threshold as u64 {
                    // Close the circuit
                    self.state.store(CircuitState::Closed as u8, Ordering::Relaxed);
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                    *self.opened_at.write() = None;
                    info!(name = %self.name, "Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Open => {
                // Shouldn't happen if allow_request is used properly
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let current_state = self.state();
        let now = Instant::now();

        match current_state {
            CircuitState::Closed => {
                // Check if we should reset the failure count based on window
                if self.config.window_size > Duration::ZERO {
                    if let Some(last) = *self.last_failure_time.read() {
                        if now.duration_since(last) > self.config.window_size {
                            self.failure_count.store(0, Ordering::Relaxed);
                        }
                    }
                }

                *self.last_failure_time.write() = Some(now);
                let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(name = %self.name, count, threshold = self.config.failure_threshold, "Circuit breaker failure recorded");

                if count >= self.config.failure_threshold as u64 {
                    // Open the circuit
                    self.state.store(CircuitState::Open as u8, Ordering::Relaxed);
                    *self.opened_at.write() = Some(now);
                    warn!(name = %self.name, failures = count, "Circuit breaker opened");
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state reopens the circuit
                self.state.store(CircuitState::Open as u8, Ordering::Relaxed);
                self.success_count.store(0, Ordering::Relaxed);
                *self.opened_at.write() = Some(now);
                warn!(name = %self.name, "Circuit breaker reopened after failure in HalfOpen state");
            }
            CircuitState::Open => {
                // Already open, update timestamp
                *self.opened_at.write() = Some(now);
            }
        }
    }

    /// Manually reset the circuit breaker to closed state
    pub fn reset(&self) {
        self.state.store(CircuitState::Closed as u8, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.opened_at.write() = None;
        *self.last_failure_time.write() = None;
        info!(name = %self.name, "Circuit breaker manually reset");
    }

    /// Get statistics about the circuit breaker
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            name: self.name.clone(),
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            time_in_current_state: self.opened_at.read().map(|t| t.elapsed()),
        }
    }
}

/// Statistics for a circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub name: String,
    pub state: CircuitState,
    pub failure_count: u64,
    pub success_count: u64,
    pub time_in_current_state: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure();
        cb.record_failure();
        cb.record_success();

        // Failure count should be reset
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_circuit_closes_after_success_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for transition to half-open
        thread::sleep(Duration::from_millis(20));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_reopens_on_failure_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();

        // Wait for transition to half-open
        thread::sleep(Duration::from_millis(20));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure should reopen
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_manual_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_stats() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test-upstream", config);

        cb.record_failure();
        cb.record_failure();

        let stats = cb.stats();
        assert_eq!(stats.name, "test-upstream");
        assert_eq!(stats.state, CircuitState::Closed);
        assert_eq!(stats.failure_count, 2);
    }

    #[test]
    fn test_window_based_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            window_size: Duration::from_millis(50),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure();
        cb.record_failure();

        // Wait for window to expire
        thread::sleep(Duration::from_millis(60));

        // This failure should reset the count
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Need 3 more failures within window
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
