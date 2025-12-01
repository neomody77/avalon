//! Cache Plugin
//!
//! Response caching with TTL and size limits.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestFilterHook, RequestInfo, ResponseFilterHook, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use serde::Deserialize;
use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached response entry
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedResponse {
    pub fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }
}

/// Cache plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CachePluginConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ttl")]
    pub default_ttl: u64,
    #[serde(default = "default_max_entry_size")]
    pub max_entry_size: usize,
    #[serde(default = "default_max_cache_size")]
    pub max_cache_size: usize,
    #[serde(default = "default_cacheable_status")]
    pub cacheable_status: Vec<u16>,
    #[serde(default = "default_cacheable_methods")]
    pub cacheable_methods: Vec<String>,
}

fn default_true() -> bool { true }
fn default_ttl() -> u64 { 300 }
fn default_max_entry_size() -> usize { 10 * 1024 * 1024 }
fn default_max_cache_size() -> usize { 100 * 1024 * 1024 }
fn default_cacheable_status() -> Vec<u16> { vec![200, 301, 302, 304, 307, 308] }
fn default_cacheable_methods() -> Vec<String> { vec!["GET".to_string(), "HEAD".to_string()] }

impl Default for CachePluginConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            default_ttl: default_ttl(),
            max_entry_size: default_max_entry_size(),
            max_cache_size: default_max_cache_size(),
            cacheable_status: default_cacheable_status(),
            cacheable_methods: default_cacheable_methods(),
        }
    }
}

/// Cache state
struct CacheState {
    entries: Arc<DashMap<String, CachedResponse>>,
    config: CachePluginConfig,
    current_size: AtomicUsize,
}

impl CacheState {
    fn new(config: CachePluginConfig) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            config,
            current_size: AtomicUsize::new(0),
        }
    }

    fn make_key(method: &str, host: &str, path: &str, query: Option<&str>) -> String {
        let mut key = format!("{}:{}:{}", method.to_uppercase(), host, path);
        if let Some(q) = query {
            key.push('?');
            key.push_str(q);
        }
        key
    }

    fn get(&self, key: &str) -> Option<CachedResponse> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_valid() {
                return Some(entry.clone());
            }
            drop(entry);
            self.remove(key);
        }
        None
    }

    fn put(&self, key: String, response: CachedResponse) {
        let entry_size = self.estimate_size(&response);
        if entry_size > self.config.max_entry_size {
            return;
        }
        self.maybe_evict(entry_size);
        self.entries.insert(key, response);
        self.current_size.fetch_add(entry_size, Ordering::Relaxed);
    }

    fn remove(&self, key: &str) {
        if let Some((_, entry)) = self.entries.remove(key) {
            let size = self.estimate_size(&entry);
            self.current_size.fetch_sub(size, Ordering::Relaxed);
        }
    }

    fn estimate_size(&self, response: &CachedResponse) -> usize {
        let headers_size: usize = response.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        response.body.len() + headers_size + 100
    }

    fn maybe_evict(&self, needed: usize) {
        let current = self.current_size.load(Ordering::Relaxed);
        if current + needed <= self.config.max_cache_size {
            return;
        }
        // Remove expired entries first
        let expired: Vec<String> = self.entries
            .iter()
            .filter(|e| !e.value().is_valid())
            .map(|e| e.key().clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    fn is_cacheable(&self, method: &str, status: u16, headers: &[(String, String)]) -> bool {
        if !self.config.enabled {
            return false;
        }
        if !self.config.cacheable_methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return false;
        }
        if !self.config.cacheable_status.contains(&status) {
            return false;
        }
        // Check Cache-Control
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cache-control") {
                let lower = value.to_lowercase();
                if lower.contains("no-store") || lower.contains("private") {
                    return false;
                }
            }
        }
        true
    }

    fn parse_ttl(&self, headers: &[(String, String)]) -> Duration {
        let mut s_maxage: Option<u64> = None;
        let mut max_age: Option<u64> = None;

        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cache-control") {
                for directive in value.split(',') {
                    let d = directive.trim().to_lowercase();
                    if d.starts_with("s-maxage=") {
                        if let Ok(secs) = d[9..].parse::<u64>() {
                            s_maxage = Some(secs);
                        }
                    } else if d.starts_with("max-age=") {
                        if let Ok(secs) = d[8..].parse::<u64>() {
                            max_age = Some(secs);
                        }
                    }
                }
            }
        }

        // s-maxage takes priority over max-age
        if let Some(secs) = s_maxage {
            return Duration::from_secs(secs);
        }
        if let Some(secs) = max_age {
            return Duration::from_secs(secs);
        }
        Duration::from_secs(self.config.default_ttl)
    }

    fn stats(&self) -> (usize, usize) {
        (self.entries.len(), self.current_size.load(Ordering::Relaxed))
    }
}

/// Cache Plugin
pub struct CachePlugin {
    metadata: PluginMetadata,
    config: CachePluginConfig,
    state: Option<Arc<CacheState>>,
    running: bool,
}

impl CachePlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("cache", "0.1.0", PluginType::Middleware)
            .with_description("Response caching plugin with TTL and size limits")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: true,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: CachePluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_request_hook(&self) -> Option<CacheRequestHook> {
        self.state.as_ref().map(|s| CacheRequestHook { state: s.clone() })
    }

    pub fn get_response_hook(&self) -> Option<CacheResponseHook> {
        self.state.as_ref().map(|s| CacheResponseHook { state: s.clone() })
    }

    pub fn stats(&self) -> Option<(usize, usize)> {
        self.state.as_ref().map(|s| s.stats())
    }
}

impl Default for CachePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CachePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = CachePluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(CacheState::new(self.config.clone())));
        self.running = true;
        tracing::info!(
            enabled = self.config.enabled,
            default_ttl = self.config.default_ttl,
            max_cache_size = self.config.max_cache_size,
            "Cache plugin started"
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("Cache plugin stopped");
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

/// Cache request hook - checks for cached responses
pub struct CacheRequestHook {
    state: Arc<CacheState>,
}

#[async_trait]
impl RequestFilterHook for CacheRequestHook {
    fn priority(&self) -> HookPriority {
        HookPriority::EARLY
    }

    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let host = request.headers.get("host").map(|s| s.as_str()).unwrap_or("");
        let key = CacheState::make_key(&request.method, host, &request.path, request.query.as_deref());

        if let Some(cached) = self.state.get(&key) {
            ctx.set("cache_hit", true);
            ctx.set("cached_response", cached);
            tracing::debug!(key = %key, "Cache hit");
            return Ok(HookAction::ShortCircuit);
        }

        ctx.set("cache_key", key);
        Ok(HookAction::Continue)
    }
}

/// Cache response hook - stores cacheable responses
pub struct CacheResponseHook {
    state: Arc<CacheState>,
}

#[async_trait]
impl ResponseFilterHook for CacheResponseHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE
    }

    async fn on_response(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Skip if already a cache hit
        if ctx.get::<bool>("cache_hit").unwrap_or(false) {
            return Ok(HookAction::Continue);
        }

        let key = match ctx.get::<String>("cache_key") {
            Some(k) => k,
            None => return Ok(HookAction::Continue),
        };

        let method = ctx.get::<String>("request_method").unwrap_or_else(|| "GET".to_string());
        let headers_vec: Vec<(String, String)> = response.headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        if !self.state.is_cacheable(&method, response.status, &headers_vec) {
            return Ok(HookAction::Continue);
        }

        let ttl = self.state.parse_ttl(&headers_vec);
        let body = ctx.get::<Bytes>("response_body").unwrap_or_default();

        let cached = CachedResponse {
            status: response.status,
            headers: headers_vec,
            body,
            cached_at: Instant::now(),
            ttl,
        };

        self.state.put(key.clone(), cached);
        tracing::debug!(key = %key, ttl = ?ttl, "Cached response");

        Ok(HookAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CachePlugin::new();
        assert_eq!(plugin.metadata().name, "cache");
    }

    #[test]
    fn test_cache_key() {
        let key = CacheState::make_key("GET", "example.com", "/api/users", Some("page=1"));
        assert_eq!(key, "GET:example.com:/api/users?page=1");
    }

    #[test]
    fn test_cache_state() {
        let state = CacheState::new(CachePluginConfig::default());
        let key = "GET:example.com:/test".to_string();

        let response = CachedResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Bytes::from("Hello"),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };

        state.put(key.clone(), response);
        let cached = state.get(&key);
        assert!(cached.is_some());
    }

    #[test]
    fn test_is_cacheable() {
        let state = CacheState::new(CachePluginConfig::default());

        assert!(state.is_cacheable("GET", 200, &[]));
        assert!(!state.is_cacheable("POST", 200, &[]));
        assert!(!state.is_cacheable("GET", 500, &[]));

        let headers = vec![("Cache-Control".to_string(), "no-store".to_string())];
        assert!(!state.is_cacheable("GET", 200, &headers));
    }

    #[test]
    fn test_parse_ttl() {
        let state = CacheState::new(CachePluginConfig::default());

        let headers = vec![("Cache-Control".to_string(), "max-age=600".to_string())];
        assert_eq!(state.parse_ttl(&headers), Duration::from_secs(600));

        let headers = vec![("Cache-Control".to_string(), "max-age=600, s-maxage=1200".to_string())];
        assert_eq!(state.parse_ttl(&headers), Duration::from_secs(1200));
    }
}
