//! caddy-proxy: Reverse proxy implementation for caddy-rs
//!
//! This crate provides the core reverse proxy functionality based on
//! Cloudflare's Pingora framework.

pub mod error;
pub mod file_server;
pub mod health;
pub mod proxy;
pub mod route;
pub mod upstream;

pub use error::*;
pub use file_server::FileServer;
pub use health::{HealthCheckConfig, HealthChecker};
pub use proxy::CaddyProxy;
pub use route::RouteTable;
pub use upstream::UpstreamSelector;
