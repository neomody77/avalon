//! Built-in plugins for avalon
//!
//! These plugins are compiled into the binary when enabled via Cargo features.

pub mod access_log;
pub mod admin;
pub mod auth;
pub mod cache;
pub mod compression;
pub mod file_server;
pub mod headers;
pub mod metrics;
pub mod rate_limit;
pub mod request_id;
pub mod rewrite;

pub use access_log::AccessLogPlugin;
pub use admin::AdminPlugin;
pub use auth::AuthPlugin;
pub use cache::CachePlugin;
pub use compression::CompressionPlugin;
pub use file_server::FileServerPlugin;
pub use headers::HeadersPlugin;
pub use metrics::MetricsPlugin;
pub use rate_limit::RateLimitPlugin;
pub use request_id::RequestIdPlugin;
pub use rewrite::RewritePlugin;

use crate::registry::PluginRegistry;

/// Register all built-in plugins with the registry
pub fn register_builtin_plugins(registry: &PluginRegistry) {
    // Access log plugin
    if let Err(e) = registry.register_factory("access_log", || {
        Box::new(AccessLogPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register access_log plugin");
    }

    // Rate limit plugin
    if let Err(e) = registry.register_factory("rate_limit", || {
        Box::new(RateLimitPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register rate_limit plugin");
    }

    // Auth plugin
    if let Err(e) = registry.register_factory("auth", || {
        Box::new(AuthPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register auth plugin");
    }

    // Rewrite plugin
    if let Err(e) = registry.register_factory("rewrite", || {
        Box::new(RewritePlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register rewrite plugin");
    }

    // Headers plugin
    if let Err(e) = registry.register_factory("headers", || {
        Box::new(HeadersPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register headers plugin");
    }

    // Cache plugin
    if let Err(e) = registry.register_factory("cache", || {
        Box::new(CachePlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register cache plugin");
    }

    // Compression plugin
    if let Err(e) = registry.register_factory("compression", || {
        Box::new(CompressionPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register compression plugin");
    }

    // File server plugin
    if let Err(e) = registry.register_factory("file_server", || {
        Box::new(FileServerPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register file_server plugin");
    }

    // Request ID plugin
    if let Err(e) = registry.register_factory("request_id", || {
        Box::new(RequestIdPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register request_id plugin");
    }

    // Metrics plugin
    if let Err(e) = registry.register_factory("metrics", || {
        Box::new(MetricsPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register metrics plugin");
    }

    // Admin API plugin
    if let Err(e) = registry.register_factory("admin", || {
        Box::new(AdminPlugin::new())
    }) {
        tracing::warn!(error = %e, "Failed to register admin plugin");
    }

    tracing::info!("Registered 11 built-in plugins");
}
