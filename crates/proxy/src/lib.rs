//! avalon-proxy: Reverse proxy implementation for avalon
//!
//! This crate provides the core reverse proxy functionality based on
//! Cloudflare's Pingora framework.

pub mod access_log;
pub mod auth;
pub mod cache;
pub mod circuit_breaker;
pub mod compression;
pub mod ip_filter;
pub mod cors;
pub mod error;
pub mod file_server;
pub mod health;
pub mod metrics;
pub mod proxy;
pub mod rate_limit;
pub mod rewrite;
pub mod rhai_rewrite;
pub mod route;
pub mod script_handler;
pub mod upstream;

#[cfg(feature = "plugins")]
pub mod plugin_integration;

pub use access_log::{AccessLogEntry, AccessLogger, LogFormat};
pub use auth::{AuthResult, CompiledAuth};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerStats, CircuitState};
pub use cache::{CacheConfig, CacheKey, CacheStats, CachedResponse, ResponseCache};
pub use compression::{
    CompressionConfig, CompressionEncoding, ResponseCompressor,
    compress, compress_brotli, compress_gzip, is_already_compressed,
    select_encoding, should_compress_content_type,
};
pub use cors::CompiledCors;
pub use error::*;
pub use ip_filter::{CompiledIpFilter, IpFilterConfig, parse_client_ip};
pub use file_server::FileServer;
pub use health::{HealthCheckConfig, HealthChecker};
pub use metrics::{metrics, wait_for_connections_drain, MetricsRegistry, RequestTimer};
pub use proxy::AvalonProxy;
pub use rate_limit::{RateLimitConfig, RateLimiter, RateLimitResult, check_rate_limit};
pub use rewrite::CompiledRewrite;
pub use rhai_rewrite::{
    RhaiRewriteConfig, RhaiRewriteEngine, RhaiRewriteError, RequestContext, RewriteResult,
};
pub use route::RouteTable;
pub use script_handler::{CompiledScriptHandler, ScriptHandlerError, ScriptRequestContext, ScriptResult};
pub use upstream::UpstreamSelector;

#[cfg(feature = "plugins")]
pub use plugin_integration::{PluginState, HookResult};
