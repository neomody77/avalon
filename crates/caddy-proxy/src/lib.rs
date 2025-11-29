//! caddy-proxy: Reverse proxy implementation for caddy-rs
//!
//! This crate provides the core reverse proxy functionality based on
//! Cloudflare's Pingora framework.

pub mod access_log;
pub mod compression;
pub mod error;
pub mod file_server;
pub mod health;
pub mod proxy;
pub mod rate_limit;
pub mod route;
pub mod upstream;

pub use access_log::{AccessLogEntry, AccessLogger, LogFormat};
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
pub use route::RouteTable;
pub use upstream::UpstreamSelector;
