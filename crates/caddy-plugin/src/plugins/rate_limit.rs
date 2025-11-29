//! Rate Limit Plugin
//!
//! This plugin implements RequestFilterHook to provide rate limiting based on client IP.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestFilterHook, RequestInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;
use std::any::Any;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Rate limit plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitPluginConfig {
    /// Maximum requests allowed in the window
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,
    /// Time window in seconds
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Burst allowance
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// HTTP status code to return when rate limited (default: 429)
    #[serde(default = "default_status_code")]
    pub status_code: u16,
}

fn default_max_requests() -> u32 {
    100
}
fn default_window_secs() -> u64 {
    60
}
fn default_burst() -> u32 {
    10
}
fn default_status_code() -> u16 {
    429
}

impl Default for RateLimitPluginConfig {
    fn default() -> Self {
        Self {
            max_requests: default_max_requests(),
            window_secs: default_window_secs(),
            burst: default_burst(),
            status_code: default_status_code(),
        }
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    max_tokens: f64,
    refill_rate: f64,
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

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
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

    fn remaining(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }
}

/// Rate limiter state
struct RateLimiterState {
    buckets: DashMap<IpAddr, TokenBucket>,
    max_tokens: u32,
    window: Duration,
}

impl RateLimiterState {
    fn new(config: &RateLimitPluginConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            max_tokens: config.max_requests + config.burst,
            window: Duration::from_secs(config.window_secs),
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let mut entry = self
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.max_tokens, self.window));
        entry.try_consume()
    }

    fn remaining(&self, ip: IpAddr) -> u32 {
        if let Some(mut entry) = self.buckets.get_mut(&ip) {
            entry.remaining()
        } else {
            self.max_tokens
        }
    }
}

/// Rate Limit Plugin
pub struct RateLimitPlugin {
    metadata: PluginMetadata,
    config: RateLimitPluginConfig,
    state: Option<Arc<RateLimiterState>>,
    running: bool,
}

impl RateLimitPlugin {
    /// Create a new RateLimitPlugin with default configuration
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("rate_limit", "0.1.0", PluginType::Middleware)
            .with_description("Rate limiting plugin using token bucket algorithm")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: true,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: RateLimitPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    /// Get the hook for the RequestFilterHook implementation
    pub fn get_hook(&self) -> Option<RateLimitHook> {
        self.state.as_ref().map(|s| RateLimitHook {
            state: s.clone(),
            status_code: self.config.status_code,
            retry_after: self.config.window_secs,
        })
    }
}

impl Default for RateLimitPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for RateLimitPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = RateLimitPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(RateLimiterState::new(&self.config)));
        self.running = true;

        info!(
            max_requests = self.config.max_requests,
            window_secs = self.config.window_secs,
            burst = self.config.burst,
            "Rate limit plugin started"
        );

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        info!("Rate limit plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.state.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Hook implementation for rate limiting
pub struct RateLimitHook {
    state: Arc<RateLimiterState>,
    status_code: u16,
    retry_after: u64,
}

#[async_trait]
impl RequestFilterHook for RateLimitHook {
    fn priority(&self) -> HookPriority {
        HookPriority::EARLY // Check rate limit early in the pipeline
    }

    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Get client IP from context or headers
        let client_ip = ctx
            .get::<String>("client_ip")
            .and_then(|s| IpAddr::from_str(&s).ok())
            .or_else(|| {
                request
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|s| s.split(',').next())
                    .and_then(|s| IpAddr::from_str(s.trim()).ok())
            })
            .unwrap_or_else(|| IpAddr::from_str("127.0.0.1").unwrap());

        if self.state.check(client_ip) {
            // Allowed - store remaining in context for headers
            let remaining = self.state.remaining(client_ip);
            ctx.set("rate_limit_remaining", remaining);
            Ok(HookAction::Continue)
        } else {
            // Rate limited
            debug!(ip = %client_ip, "Rate limit exceeded");
            ctx.set("rate_limit_exceeded", true);
            ctx.set("rate_limit_retry_after", self.retry_after);
            ctx.set("rate_limit_status_code", self.status_code);
            Ok(HookAction::ShortCircuit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = RateLimitPlugin::new();
        assert_eq!(plugin.metadata().name, "rate_limit");
        assert_eq!(plugin.metadata().plugin_type, PluginType::Middleware);
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = RateLimitPlugin::new();
        let config = r#"{"max_requests": 50, "window_secs": 30, "burst": 5}"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.max_requests, 50);
        assert_eq!(plugin.config.window_secs, 30);
        assert_eq!(plugin.config.burst, 5);
    }

    #[test]
    fn test_start_stop() {
        let mut plugin = RateLimitPlugin::new();
        plugin.init("").unwrap();
        plugin.start().unwrap();
        assert!(plugin.health_check());
        plugin.stop().unwrap();
        assert!(!plugin.health_check());
    }

    #[test]
    fn test_rate_limiter_state() {
        let config = RateLimitPluginConfig {
            max_requests: 5,
            window_secs: 60,
            burst: 0,
            status_code: 429,
        };
        let state = RateLimiterState::new(&config);
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        // Should allow up to max_requests
        for _ in 0..5 {
            assert!(state.check(ip));
        }

        // Should deny after limit
        assert!(!state.check(ip));
    }

    #[test]
    fn test_different_ips() {
        let config = RateLimitPluginConfig {
            max_requests: 2,
            window_secs: 60,
            burst: 0,
            status_code: 429,
        };
        let state = RateLimiterState::new(&config);
        let ip1 = IpAddr::from_str("127.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.1").unwrap();

        // Both should have separate limits
        assert!(state.check(ip1));
        assert!(state.check(ip1));
        assert!(!state.check(ip1));

        assert!(state.check(ip2));
        assert!(state.check(ip2));
        assert!(!state.check(ip2));
    }
}
