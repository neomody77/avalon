//! Core Plugin trait definition

use crate::error::Result;
use std::any::Any;

/// Plugin type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginType {
    /// Middleware plugin (intercepts request/response pipeline)
    Middleware,
    /// Handler plugin (terminal request handler)
    Handler,
    /// Load balancer plugin (custom upstream selection)
    LoadBalancer,
    /// Auth provider plugin
    AuthProvider,
    /// Certificate provider plugin
    CertProvider,
    /// Logger/metrics plugin
    Logger,
    /// Storage plugin
    Storage,
}

/// Plugin capabilities
#[derive(Debug, Clone, Default)]
pub struct PluginCapabilities {
    /// Supports configuration reload without restart
    pub supports_reload: bool,
    /// Exposes metrics
    pub supports_metrics: bool,
    /// Is thread-safe (can be called from multiple threads)
    pub thread_safe: bool,
    /// Requires async initialization
    pub async_init: bool,
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    /// Unique plugin identifier
    pub name: String,
    /// Semantic version
    pub version: String,
    /// Plugin type
    pub plugin_type: PluginType,
    /// API version this plugin was built against
    pub api_version: u32,
    /// Human-readable description
    pub description: String,
    /// Author/maintainer
    pub author: String,
    /// Plugin capabilities
    pub capabilities: PluginCapabilities,
}

impl PluginMetadata {
    /// Create new plugin metadata with required fields
    pub fn new(name: impl Into<String>, version: impl Into<String>, plugin_type: PluginType) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            plugin_type,
            api_version: crate::PLUGIN_API_VERSION,
            description: String::new(),
            author: String::new(),
            capabilities: PluginCapabilities::default(),
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Set capabilities
    pub fn with_capabilities(mut self, caps: PluginCapabilities) -> Self {
        self.capabilities = caps;
        self
    }
}

/// Core Plugin trait that all plugins must implement
pub trait Plugin: Send + Sync {
    /// Return plugin metadata
    fn metadata(&self) -> &PluginMetadata;

    /// Initialize the plugin with configuration (JSON)
    fn init(&mut self, config: &str) -> Result<()>;

    /// Start the plugin (begin processing)
    fn start(&mut self) -> Result<()>;

    /// Stop the plugin gracefully
    fn stop(&mut self) -> Result<()>;

    /// Reload plugin configuration without stopping
    fn reload(&mut self, config: &str) -> Result<()> {
        self.stop()?;
        self.init(config)?;
        self.start()
    }

    /// Health check
    fn health_check(&self) -> bool {
        true
    }

    /// Cast to Any for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Cast to Any mut for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
