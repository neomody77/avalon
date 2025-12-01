//! Plugin registry for managing plugin instances

use crate::error::{PluginError, Result};
use crate::hooks::*;
use crate::plugin::Plugin;
use crate::priority::HookPriority;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Plugin factory function type
pub type PluginFactory = fn() -> Box<dyn Plugin>;

/// Registered hook with priority
struct RegisteredHook<T> {
    name: String,
    hook: T,
}

/// Global plugin registry
pub struct PluginRegistry {
    /// Registered plugin factories (for creating instances)
    factories: RwLock<std::collections::HashMap<String, PluginFactory>>,

    /// Active plugin instances
    instances: RwLock<std::collections::HashMap<String, Arc<RwLock<Box<dyn Plugin>>>>>,

    /// Hook registrations by type and priority
    early_request_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn EarlyRequestHook>>>>>,
    request_filter_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn RequestFilterHook>>>>>,
    route_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn RouteHook>>>>>,
    upstream_select_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn UpstreamSelectHook>>>>>,
    upstream_request_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn UpstreamRequestHook>>>>>,
    response_filter_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn ResponseFilterHook>>>>>,
    response_body_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn ResponseBodyHook>>>>>,
    logging_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn LoggingHook>>>>>,
    connection_failure_hooks: RwLock<BTreeMap<HookPriority, Vec<RegisteredHook<Arc<dyn ConnectionFailureHook>>>>>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        Self {
            factories: RwLock::new(std::collections::HashMap::new()),
            instances: RwLock::new(std::collections::HashMap::new()),
            early_request_hooks: RwLock::new(BTreeMap::new()),
            request_filter_hooks: RwLock::new(BTreeMap::new()),
            route_hooks: RwLock::new(BTreeMap::new()),
            upstream_select_hooks: RwLock::new(BTreeMap::new()),
            upstream_request_hooks: RwLock::new(BTreeMap::new()),
            response_filter_hooks: RwLock::new(BTreeMap::new()),
            response_body_hooks: RwLock::new(BTreeMap::new()),
            logging_hooks: RwLock::new(BTreeMap::new()),
            connection_failure_hooks: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a plugin factory
    pub fn register_factory(&self, name: &str, factory: PluginFactory) -> Result<()> {
        let mut factories = self.factories.write();
        if factories.contains_key(name) {
            return Err(PluginError::AlreadyRegistered(name.to_string()));
        }
        factories.insert(name.to_string(), factory);
        info!(plugin = %name, "Registered plugin factory");
        Ok(())
    }

    /// Create and initialize a plugin instance
    pub fn create_instance(&self, name: &str, config: &str) -> Result<()> {
        let factory = {
            let factories = self.factories.read();
            factories.get(name).copied()
        };

        let factory = factory.ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        let mut plugin = factory();
        let metadata = plugin.metadata().clone();

        // Check API version
        if metadata.api_version != crate::PLUGIN_API_VERSION {
            return Err(PluginError::AbiMismatch {
                expected: crate::PLUGIN_API_VERSION,
                actual: metadata.api_version,
            });
        }

        plugin.init(config)?;
        plugin.start()?;

        let instance = Arc::new(RwLock::new(plugin));
        self.instances.write().insert(name.to_string(), instance);

        info!(
            plugin = %name,
            version = %metadata.version,
            "Created plugin instance"
        );
        Ok(())
    }

    /// Get a plugin instance
    pub fn get_instance(&self, name: &str) -> Option<Arc<RwLock<Box<dyn Plugin>>>> {
        self.instances.read().get(name).cloned()
    }

    /// Stop and remove a plugin instance
    pub fn remove_instance(&self, name: &str) -> Result<()> {
        let instance = self.instances.write().remove(name);
        if let Some(instance) = instance {
            instance.write().stop()?;
            info!(plugin = %name, "Removed plugin instance");
        }
        Ok(())
    }

    /// List all registered plugin names
    pub fn list_factories(&self) -> Vec<String> {
        self.factories.read().keys().cloned().collect()
    }

    /// List all active plugin instances
    pub fn list_instances(&self) -> Vec<String> {
        self.instances.read().keys().cloned().collect()
    }

    /// Check if a factory is registered
    pub fn has_factory(&self, name: &str) -> bool {
        self.factories.read().contains_key(name)
    }

    /// Get the number of active instances
    pub fn instance_count(&self) -> usize {
        self.instances.read().len()
    }

    // ==========================================================================
    // Hook registration methods
    // ==========================================================================

    /// Register an early request hook
    pub fn register_early_request_hook(&self, name: &str, hook: Arc<dyn EarlyRequestHook>) {
        let priority = hook.priority();
        let mut hooks = self.early_request_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered EarlyRequestHook");
    }

    /// Register a request filter hook
    pub fn register_request_filter_hook(&self, name: &str, hook: Arc<dyn RequestFilterHook>) {
        let priority = hook.priority();
        let mut hooks = self.request_filter_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered RequestFilterHook");
    }

    /// Register a route hook
    pub fn register_route_hook(&self, name: &str, hook: Arc<dyn RouteHook>) {
        let priority = hook.priority();
        let mut hooks = self.route_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered RouteHook");
    }

    /// Register an upstream select hook
    pub fn register_upstream_select_hook(&self, name: &str, hook: Arc<dyn UpstreamSelectHook>) {
        let priority = hook.priority();
        let mut hooks = self.upstream_select_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered UpstreamSelectHook");
    }

    /// Register an upstream request hook
    pub fn register_upstream_request_hook(&self, name: &str, hook: Arc<dyn UpstreamRequestHook>) {
        let priority = hook.priority();
        let mut hooks = self.upstream_request_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered UpstreamRequestHook");
    }

    /// Register a response filter hook
    pub fn register_response_filter_hook(&self, name: &str, hook: Arc<dyn ResponseFilterHook>) {
        let priority = hook.priority();
        let mut hooks = self.response_filter_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered ResponseFilterHook");
    }

    /// Register a response body hook
    pub fn register_response_body_hook(&self, name: &str, hook: Arc<dyn ResponseBodyHook>) {
        let priority = hook.priority();
        let mut hooks = self.response_body_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered ResponseBodyHook");
    }

    /// Register a logging hook
    pub fn register_logging_hook(&self, name: &str, hook: Arc<dyn LoggingHook>) {
        let priority = hook.priority();
        let mut hooks = self.logging_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered LoggingHook");
    }

    /// Register a connection failure hook
    pub fn register_connection_failure_hook(&self, name: &str, hook: Arc<dyn ConnectionFailureHook>) {
        let priority = hook.priority();
        let mut hooks = self.connection_failure_hooks.write();
        hooks
            .entry(priority)
            .or_default()
            .push(RegisteredHook {
                name: name.to_string(),
                hook,
            });
        debug!(plugin = %name, ?priority, "Registered ConnectionFailureHook");
    }

    // ==========================================================================
    // Hook retrieval methods (for executor)
    // ==========================================================================

    /// Get all early request hooks in priority order
    pub fn get_early_request_hooks(&self) -> Vec<Arc<dyn EarlyRequestHook>> {
        let hooks = self.early_request_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all request filter hooks in priority order
    pub fn get_request_filter_hooks(&self) -> Vec<Arc<dyn RequestFilterHook>> {
        let hooks = self.request_filter_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all route hooks in priority order
    pub fn get_route_hooks(&self) -> Vec<Arc<dyn RouteHook>> {
        let hooks = self.route_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all upstream select hooks in priority order
    pub fn get_upstream_select_hooks(&self) -> Vec<Arc<dyn UpstreamSelectHook>> {
        let hooks = self.upstream_select_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all upstream request hooks in priority order
    pub fn get_upstream_request_hooks(&self) -> Vec<Arc<dyn UpstreamRequestHook>> {
        let hooks = self.upstream_request_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all response filter hooks in priority order
    pub fn get_response_filter_hooks(&self) -> Vec<Arc<dyn ResponseFilterHook>> {
        let hooks = self.response_filter_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all response body hooks in priority order
    pub fn get_response_body_hooks(&self) -> Vec<Arc<dyn ResponseBodyHook>> {
        let hooks = self.response_body_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all logging hooks in priority order
    pub fn get_logging_hooks(&self) -> Vec<Arc<dyn LoggingHook>> {
        let hooks = self.logging_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Get all connection failure hooks in priority order
    pub fn get_connection_failure_hooks(&self) -> Vec<Arc<dyn ConnectionFailureHook>> {
        let hooks = self.connection_failure_hooks.read();
        hooks
            .values()
            .flat_map(|v| v.iter().map(|h| h.hook.clone()))
            .collect()
    }

    /// Stop all plugin instances
    pub fn stop_all(&self) {
        let instances: Vec<_> = self.instances.read().values().cloned().collect();
        for instance in instances {
            if let Err(e) = instance.write().stop() {
                warn!(error = %e, "Failed to stop plugin");
            }
        }
        self.instances.write().clear();
        info!("Stopped all plugin instances");
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PluginRegistry {
    fn drop(&mut self) {
        self.stop_all();
    }
}
