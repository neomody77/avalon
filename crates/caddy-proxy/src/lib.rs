//! caddy-proxy: Reverse proxy implementation for caddy-rs
//!
//! This crate provides the core reverse proxy functionality based on
//! Cloudflare's Pingora framework.

pub mod access_log;
pub mod auth;
pub mod cache;
pub mod compression;
pub mod error;
pub mod file_server;
pub mod health;
pub mod proxy;
pub mod rate_limit;
pub mod rewrite;
pub mod rhai_rewrite;
pub mod route;
pub mod upstream;

#[cfg(feature = "plugins")]
pub mod plugin_integration;

pub use access_log::{AccessLogEntry, AccessLogger, LogFormat};
pub use auth::{AuthResult, CompiledAuth};
pub use cache::{CacheConfig, CacheKey, CacheStats, CachedResponse, ResponseCache};
pub use compression::{
    CompressionConfig, CompressionEncoding, ResponseCompressor,
    compress, compress_brotli, compress_gzip, is_already_compressed,
    select_encoding, should_compress_content_type,
};
pub use error::*;
pub use file_server::FileServer;
pub use health::{HealthCheckConfig, HealthChecker};
pub use proxy::CaddyProxy;
pub use rate_limit::{RateLimitConfig, RateLimiter, RateLimitResult, check_rate_limit};
pub use rewrite::CompiledRewrite;
pub use rhai_rewrite::{
    RhaiRewriteConfig, RhaiRewriteEngine, RhaiRewriteError, RequestContext, RewriteResult,
};
pub use route::RouteTable;
pub use upstream::UpstreamSelector;

#[cfg(feature = "plugins")]
pub use plugin_integration::{PluginState, HookResult};
