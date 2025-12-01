//! Response caching for reverse proxy

use bytes::Bytes;
use dashmap::DashMap;
use http::StatusCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Cached response entry
#[derive(Clone, Debug)]
pub struct CachedResponse {
    /// HTTP status code
    pub status: StatusCode,
    /// Response headers (excluding hop-by-hop headers)
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Bytes,
    /// When the entry was cached
    pub cached_at: Instant,
    /// Time-to-live
    pub ttl: Duration,
    /// ETag header value if present
    pub etag: Option<String>,
    /// Last-Modified header value if present
    pub last_modified: Option<String>,
}

impl CachedResponse {
    /// Check if the cached response is still valid
    pub fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.cached_at.elapsed())
    }
}

/// Cache key generation
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub vary_headers: Vec<(String, String)>,
}

impl CacheKey {
    pub fn new(method: &str, host: &str, path: &str, query: Option<&str>) -> Self {
        Self {
            method: method.to_uppercase(),
            host: host.to_string(),
            path: path.to_string(),
            query: query.map(|s| s.to_string()),
            vary_headers: Vec::new(),
        }
    }

    /// Add a header value for Vary-based cache keying
    pub fn with_vary_header(mut self, name: &str, value: &str) -> Self {
        self.vary_headers.push((name.to_lowercase(), value.to_string()));
        self
    }

    /// Generate a string key for the cache
    pub fn to_string_key(&self) -> String {
        let mut key = format!("{}:{}:{}", self.method, self.host, self.path);
        if let Some(query) = &self.query {
            key.push('?');
            key.push_str(query);
        }
        for (name, value) in &self.vary_headers {
            key.push_str(&format!("|{}:{}", name, value));
        }
        key
    }
}

/// Cache configuration
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Default TTL for cached responses (seconds)
    pub default_ttl: u64,
    /// Maximum cache entry size in bytes
    pub max_entry_size: usize,
    /// Maximum total cache size in bytes (approximate)
    pub max_cache_size: usize,
    /// Cache only these status codes
    pub cacheable_status: Vec<u16>,
    /// Cache only these methods
    pub cacheable_methods: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl: 300, // 5 minutes
            max_entry_size: 10 * 1024 * 1024, // 10MB
            max_cache_size: 100 * 1024 * 1024, // 100MB
            cacheable_status: vec![200, 301, 302, 304, 307, 308],
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
        }
    }
}

/// In-memory response cache
pub struct ResponseCache {
    entries: Arc<DashMap<String, CachedResponse>>,
    config: CacheConfig,
    current_size: std::sync::atomic::AtomicUsize,
}

impl ResponseCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            config,
            current_size: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get a cached response if valid
    pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        let string_key = key.to_string_key();

        if let Some(entry) = self.entries.get(&string_key) {
            if entry.is_valid() {
                debug!(key = %string_key, remaining_ttl = ?entry.remaining_ttl(), "Cache hit");
                return Some(entry.clone());
            } else {
                // Entry expired, remove it
                drop(entry);
                self.remove(&string_key);
                debug!(key = %string_key, "Cache miss (expired)");
            }
        } else {
            debug!(key = %string_key, "Cache miss");
        }
        None
    }

    /// Store a response in the cache
    pub fn put(&self, key: &CacheKey, response: CachedResponse) {
        let string_key = key.to_string_key();
        let entry_size = self.estimate_size(&response);

        // Check if entry is too large
        if entry_size > self.config.max_entry_size {
            debug!(key = %string_key, size = entry_size, max = self.config.max_entry_size, "Entry too large to cache");
            return;
        }

        // Evict old entries if needed
        self.maybe_evict(entry_size);

        // Store the entry
        self.entries.insert(string_key.clone(), response);
        self.current_size.fetch_add(entry_size, std::sync::atomic::Ordering::Relaxed);
        debug!(key = %string_key, size = entry_size, "Cached response");
    }

    /// Remove an entry from the cache
    pub fn remove(&self, key: &str) {
        if let Some((_, entry)) = self.entries.remove(key) {
            let size = self.estimate_size(&entry);
            self.current_size.fetch_sub(size, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Clear all expired entries
    pub fn cleanup_expired(&self) {
        let expired: Vec<String> = self.entries
            .iter()
            .filter(|e| !e.value().is_valid())
            .map(|e| e.key().clone())
            .collect();

        for key in expired {
            self.remove(&key);
        }
    }

    /// Evict entries if cache is too full
    fn maybe_evict(&self, needed_size: usize) {
        let current = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
        let max = self.config.max_cache_size;

        if current + needed_size <= max {
            return;
        }

        // First, remove expired entries
        self.cleanup_expired();

        let current = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
        if current + needed_size <= max {
            return;
        }

        // Still need space, remove oldest entries (LRU approximation)
        let to_free = (current + needed_size).saturating_sub(max) + (max / 10); // Free 10% extra
        let mut freed = 0usize;

        // Sort by cache time and remove oldest
        let mut entries: Vec<_> = self.entries
            .iter()
            .map(|e| (e.key().clone(), e.value().cached_at))
            .collect();
        entries.sort_by_key(|(_, cached_at)| *cached_at);

        for (key, _) in entries {
            if freed >= to_free {
                break;
            }
            if let Some((_, entry)) = self.entries.remove(&key) {
                freed += self.estimate_size(&entry);
            }
        }

        self.current_size.fetch_sub(freed, std::sync::atomic::Ordering::Relaxed);
        debug!(freed = freed, "Evicted cache entries");
    }

    /// Estimate the size of a cached response
    fn estimate_size(&self, response: &CachedResponse) -> usize {
        let headers_size: usize = response.headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();

        response.body.len() + headers_size + 100 // 100 bytes overhead
    }

    /// Check if a response is cacheable
    pub fn is_cacheable(&self, method: &str, status: u16, headers: &[(String, String)]) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check method
        if !self.config.cacheable_methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return false;
        }

        // Check status code
        if !self.config.cacheable_status.contains(&status) {
            return false;
        }

        // Check Cache-Control header
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cache-control") {
                let directives: Vec<&str> = value.split(',').map(|s| s.trim().to_lowercase()).map(|s| s.leak() as &str).collect();
                if directives.iter().any(|d| *d == "no-store" || *d == "private") {
                    return false;
                }
            }
        }

        true
    }

    /// Parse Cache-Control header to determine TTL
    pub fn parse_ttl(&self, headers: &[(String, String)]) -> Duration {
        let mut max_age: Option<u64> = None;
        let mut s_maxage: Option<u64> = None;

        for (name, value) in headers {
            if name.eq_ignore_ascii_case("cache-control") {
                for directive in value.split(',') {
                    let directive = directive.trim().to_lowercase();
                    if directive.starts_with("s-maxage=") {
                        // s-maxage takes precedence for shared caches
                        if let Ok(secs) = directive[9..].parse::<u64>() {
                            s_maxage = Some(secs);
                        }
                    } else if directive.starts_with("max-age=") {
                        if let Ok(secs) = directive[8..].parse::<u64>() {
                            max_age = Some(secs);
                        }
                    }
                }
            }
        }

        // s-maxage takes precedence over max-age for shared caches
        if let Some(secs) = s_maxage {
            return Duration::from_secs(secs);
        }
        if let Some(secs) = max_age {
            return Duration::from_secs(secs);
        }

        // Fall back to default TTL
        Duration::from_secs(self.config.default_ttl)
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.entries.len(),
            size_bytes: self.current_size.load(std::sync::atomic::Ordering::Relaxed),
            max_size_bytes: self.config.max_cache_size,
        }
    }
}

impl Clone for ResponseCache {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            config: self.config.clone(),
            current_size: std::sync::atomic::AtomicUsize::new(
                self.current_size.load(std::sync::atomic::Ordering::Relaxed)
            ),
        }
    }
}

/// Cache statistics
#[derive(Clone, Debug)]
pub struct CacheStats {
    pub entries: usize,
    pub size_bytes: usize,
    pub max_size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let key = CacheKey::new("GET", "example.com", "/api/users", Some("page=1"));
        assert_eq!(key.to_string_key(), "GET:example.com:/api/users?page=1");
    }

    #[test]
    fn test_cache_key_with_vary() {
        let key = CacheKey::new("GET", "example.com", "/api/users", None)
            .with_vary_header("Accept-Encoding", "gzip");
        assert_eq!(key.to_string_key(), "GET:example.com:/api/users|accept-encoding:gzip");
    }

    #[test]
    fn test_cache_put_get() {
        let cache = ResponseCache::new(CacheConfig::default());
        let key = CacheKey::new("GET", "example.com", "/test", None);

        let response = CachedResponse {
            status: StatusCode::OK,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Bytes::from("Hello, World!"),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
            etag: None,
            last_modified: None,
        };

        cache.put(&key, response.clone());

        let cached = cache.get(&key);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().body, response.body);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = ResponseCache::new(CacheConfig::default());
        let key = CacheKey::new("GET", "example.com", "/test", None);

        let response = CachedResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("test"),
            cached_at: Instant::now() - Duration::from_secs(400), // Already expired
            ttl: Duration::from_secs(300),
            etag: None,
            last_modified: None,
        };

        cache.put(&key, response);

        // Should not return expired entry
        let cached = cache.get(&key);
        assert!(cached.is_none());
    }

    #[test]
    fn test_is_cacheable() {
        let cache = ResponseCache::new(CacheConfig::default());

        // GET 200 should be cacheable
        assert!(cache.is_cacheable("GET", 200, &[]));

        // POST should not be cacheable by default
        assert!(!cache.is_cacheable("POST", 200, &[]));

        // 500 should not be cacheable
        assert!(!cache.is_cacheable("GET", 500, &[]));

        // no-store should prevent caching
        let headers = vec![("Cache-Control".to_string(), "no-store".to_string())];
        assert!(!cache.is_cacheable("GET", 200, &headers));

        // private should prevent caching
        let headers = vec![("Cache-Control".to_string(), "private, max-age=300".to_string())];
        assert!(!cache.is_cacheable("GET", 200, &headers));
    }

    #[test]
    fn test_parse_ttl() {
        let cache = ResponseCache::new(CacheConfig::default());

        // max-age directive
        let headers = vec![("Cache-Control".to_string(), "max-age=600".to_string())];
        assert_eq!(cache.parse_ttl(&headers), Duration::from_secs(600));

        // s-maxage takes precedence
        let headers = vec![("Cache-Control".to_string(), "max-age=600, s-maxage=1200".to_string())];
        assert_eq!(cache.parse_ttl(&headers), Duration::from_secs(1200));

        // Default TTL when no directive
        let headers = vec![];
        assert_eq!(cache.parse_ttl(&headers), Duration::from_secs(300));
    }

    #[test]
    fn test_cache_stats() {
        let cache = ResponseCache::new(CacheConfig::default());
        let key = CacheKey::new("GET", "example.com", "/test", None);

        let response = CachedResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("test"),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
            etag: None,
            last_modified: None,
        };

        cache.put(&key, response);

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert!(stats.size_bytes > 0);
    }

    #[test]
    fn test_cache_entry_too_large() {
        let config = CacheConfig {
            max_entry_size: 10, // Very small
            ..Default::default()
        };
        let cache = ResponseCache::new(config);
        let key = CacheKey::new("GET", "example.com", "/test", None);

        let response = CachedResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("This is a large body that exceeds the limit"),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
            etag: None,
            last_modified: None,
        };

        cache.put(&key, response);

        // Should not be cached
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_cached_response_is_valid() {
        let response = CachedResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("test"),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
            etag: None,
            last_modified: None,
        };

        assert!(response.is_valid());
        assert!(response.remaining_ttl() <= Duration::from_secs(300));
    }
}
