//! Built-in plugins for caddy-rs
//!
//! These plugins are compiled into the binary when enabled via Cargo features.

pub mod access_log;
pub mod auth;
pub mod cache;
pub mod compression;
pub mod file_server;
pub mod headers;
pub mod rate_limit;
pub mod rewrite;

pub use access_log::AccessLogPlugin;
pub use auth::AuthPlugin;
pub use cache::CachePlugin;
pub use compression::CompressionPlugin;
pub use file_server::FileServerPlugin;
pub use headers::HeadersPlugin;
pub use rate_limit::RateLimitPlugin;
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

    tracing::info!("Registered 8 built-in plugins");
}
