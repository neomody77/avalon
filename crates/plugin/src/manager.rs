//! Plugin Manager for hot reload and lifecycle management
//!
//! This module provides a high-level plugin management system that handles:
//! - Loading plugins from configuration
//! - Hot reload when configuration changes
//! - Plugin lifecycle management

use crate::error::{PluginError, Result};
use crate::executor::HookExecutor;
use crate::registry::PluginRegistry;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

#[cfg(feature = "dynamic")]
use crate::loader::PluginLoader;

#[cfg(feature = "wasm")]
use crate::wasm::{WasmConfig, WasmPluginManager};

/// Plugin configuration entry (matches avalon-core PluginEntry)
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Plugin name
    pub name: String,
    /// Plugin type: "static", "dynamic", or "wasm"
    pub plugin_type: PluginType,
    /// Path to plugin file (for dynamic/wasm)
    pub path: Option<PathBuf>,
    /// Whether plugin is enabled
    pub enabled: bool,
    /// Plugin-specific configuration (JSON string)
    pub config: String,
}

/// Plugin type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginType {
    Static,
    Dynamic,
    Wasm,
}

impl Default for PluginType {
    fn default() -> Self {
        PluginType::Static
    }
}

/// Reload command sent to the plugin manager
#[derive(Debug)]
pub enum PluginCommand {
    /// Reload all plugins from configuration
    ReloadAll,
    /// Load a specific plugin
    Load(PluginConfig),
    /// Unload a plugin by name
    Unload(String),
    /// Reload a specific plugin
    Reload(String),
    /// Shutdown the plugin manager
    Shutdown,
}

/// Plugin manager state
pub struct PluginManager {
    /// Plugin registry
    registry: Arc<PluginRegistry>,
    /// Hook executor
    executor: HookExecutor,
    /// Dynamic plugin loader (if feature enabled)
    #[cfg(feature = "dynamic")]
    loader: RwLock<PluginLoader>,
    /// WASM plugin manager (if feature enabled)
    #[cfg(feature = "wasm")]
    wasm_manager: RwLock<WasmPluginManager>,
    /// Plugin directory
    plugin_dir: PathBuf,
    /// Running state
    running: AtomicBool,
    /// Command sender for async operations
    command_tx: Option<mpsc::Sender<PluginCommand>>,
    /// Loaded plugin configs
    plugin_configs: RwLock<HashMap<String, PluginConfig>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(plugin_dir: impl Into<PathBuf>) -> Self {
        let registry = Arc::new(PluginRegistry::new());
        let executor = HookExecutor::new(registry.clone());

        #[cfg(feature = "dynamic")]
        let loader = RwLock::new(PluginLoader::new(registry.clone()));

        #[cfg(feature = "wasm")]
        let wasm_manager = RwLock::new(WasmPluginManager::default());

        Self {
            registry,
            executor,
            #[cfg(feature = "dynamic")]
            loader,
            #[cfg(feature = "wasm")]
            wasm_manager,
            plugin_dir: plugin_dir.into(),
            running: AtomicBool::new(false),
            command_tx: None,
            plugin_configs: RwLock::new(HashMap::new()),
        }
    }

    /// Create plugin manager with custom WASM configuration
    #[cfg(feature = "wasm")]
    pub fn with_wasm_config(plugin_dir: impl Into<PathBuf>, wasm_config: WasmConfig) -> Self {
        let registry = Arc::new(PluginRegistry::new());
        let executor = HookExecutor::new(registry.clone());

        #[cfg(feature = "dynamic")]
        let loader = RwLock::new(PluginLoader::new(registry.clone()));

        Self {
            registry,
            executor,
            #[cfg(feature = "dynamic")]
            loader,
            wasm_manager: RwLock::new(WasmPluginManager::new(wasm_config)),
            plugin_dir: plugin_dir.into(),
            running: AtomicBool::new(false),
            command_tx: None,
            plugin_configs: RwLock::new(HashMap::new()),
        }
    }

    /// Get the plugin registry
    pub fn registry(&self) -> Arc<PluginRegistry> {
        self.registry.clone()
    }

    /// Get the hook executor
    pub fn executor(&self) -> &HookExecutor {
        &self.executor
    }

    /// Get the WASM plugin manager (if feature enabled)
    #[cfg(feature = "wasm")]
    pub async fn wasm_manager(&self) -> tokio::sync::RwLockReadGuard<'_, WasmPluginManager> {
        self.wasm_manager.read().await
    }

    /// Get mutable WASM plugin manager (if feature enabled)
    #[cfg(feature = "wasm")]
    pub async fn wasm_manager_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, WasmPluginManager> {
        self.wasm_manager.write().await
    }

    /// Load plugins from configuration
    pub async fn load_plugins(&self, configs: Vec<PluginConfig>) -> Result<()> {
        info!(count = configs.len(), "Loading plugins from configuration");

        let mut plugin_configs = self.plugin_configs.write().await;

        for config in configs {
            if !config.enabled {
                debug!(plugin = %config.name, "Skipping disabled plugin");
                continue;
            }

            match self.load_single_plugin(&config).await {
                Ok(()) => {
                    plugin_configs.insert(config.name.clone(), config);
                }
                Err(e) => {
                    error!(plugin = %config.name, error = %e, "Failed to load plugin");
                }
            }
        }

        Ok(())
    }

    /// Load a single plugin
    async fn load_single_plugin(&self, config: &PluginConfig) -> Result<()> {
        match config.plugin_type {
            PluginType::Static => {
                // Static plugins are already compiled in
                // Just need to create an instance from the registry factory
                if self.registry.has_factory(&config.name) {
                    self.registry.create_instance(&config.name, &config.config)?;
                    info!(plugin = %config.name, "Loaded static plugin");
                } else {
                    warn!(plugin = %config.name, "Static plugin factory not registered");
                }
            }
            PluginType::Dynamic => {
                #[cfg(feature = "dynamic")]
                {
                    if let Some(path) = &config.path {
                        let full_path = if path.is_absolute() {
                            path.clone()
                        } else {
                            self.plugin_dir.join(path)
                        };

                        let mut loader = self.loader.write().await;
                        // Safety: We trust plugins in the configured directory
                        unsafe {
                            loader.load_plugin(&full_path)?;
                        }

                        // Create instance
                        self.registry.create_instance(&config.name, &config.config)?;
                        info!(plugin = %config.name, path = %full_path.display(), "Loaded dynamic plugin");
                    } else {
                        return Err(PluginError::LoadFailed(
                            format!("Dynamic plugin {} has no path specified", config.name)
                        ));
                    }
                }
                #[cfg(not(feature = "dynamic"))]
                {
                    return Err(PluginError::LoadFailed(
                        "Dynamic plugin loading requires 'dynamic' feature".to_string()
                    ));
                }
            }
            PluginType::Wasm => {
                #[cfg(feature = "wasm")]
                {
                    if let Some(path) = &config.path {
                        let full_path = if path.is_absolute() {
                            path.clone()
                        } else {
                            self.plugin_dir.join(path)
                        };

                        let mut wasm_manager = self.wasm_manager.write().await;
                        wasm_manager.load_from_file(&config.name, &full_path)?;
                        info!(plugin = %config.name, path = %full_path.display(), "Loaded WASM plugin");
                    } else {
                        return Err(PluginError::LoadFailed(
                            format!("WASM plugin {} has no path specified", config.name)
                        ));
                    }
                }
                #[cfg(not(feature = "wasm"))]
                {
                    return Err(PluginError::LoadFailed(
                        "WASM plugin loading requires 'wasm' feature".to_string()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Unload a plugin by name
    pub async fn unload_plugin(&self, name: &str) -> Result<()> {
        info!(plugin = %name, "Unloading plugin");

        // Stop the plugin first (synchronous, uses internal RwLock)
        if let Some(plugin) = self.registry.get_instance(name) {
            if let Err(e) = plugin.write().stop() {
                warn!(plugin = %name, error = %e, "Error stopping plugin");
            }
        }

        // Remove from registry
        self.registry.remove_instance(name)?;

        #[cfg(feature = "dynamic")]
        {
            let mut loader = self.loader.write().await;
            if loader.is_loaded(name) {
                loader.unload_plugin(name)?;
            }
        }

        #[cfg(feature = "wasm")]
        {
            let mut wasm_manager = self.wasm_manager.write().await;
            wasm_manager.unload(name);
        }

        // Remove from config
        let mut configs = self.plugin_configs.write().await;
        configs.remove(name);

        info!(plugin = %name, "Plugin unloaded");
        Ok(())
    }

    /// Reload a single plugin
    pub async fn reload_plugin(&self, name: &str) -> Result<()> {
        info!(plugin = %name, "Reloading plugin");

        let config = {
            let configs = self.plugin_configs.read().await;
            configs.get(name).cloned()
        };

        if let Some(config) = config {
            // Unload first
            self.unload_plugin(name).await?;

            // Then reload
            self.load_single_plugin(&config).await?;

            // Re-add to config
            let mut configs = self.plugin_configs.write().await;
            configs.insert(name.to_string(), config);

            info!(plugin = %name, "Plugin reloaded");
        } else {
            warn!(plugin = %name, "Cannot reload: plugin not found in config");
        }

        Ok(())
    }

    /// Reload all plugins
    pub async fn reload_all(&self) -> Result<()> {
        info!("Reloading all plugins");

        let configs: Vec<PluginConfig> = {
            let configs = self.plugin_configs.read().await;
            configs.values().cloned().collect()
        };

        // Unload all
        for config in &configs {
            if let Err(e) = self.unload_plugin(&config.name).await {
                warn!(plugin = %config.name, error = %e, "Error unloading plugin during reload");
            }
        }

        // Load all
        self.load_plugins(configs).await?;

        info!("All plugins reloaded");
        Ok(())
    }

    /// Start all loaded plugins
    pub async fn start_all(&self) -> Result<()> {
        info!("Starting all plugins");

        for name in self.registry.list_instances() {
            if let Some(plugin) = self.registry.get_instance(&name) {
                if let Err(e) = plugin.write().start() {
                    error!(plugin = %name, error = %e, "Failed to start plugin");
                } else {
                    info!(plugin = %name, "Plugin started");
                }
            }
        }

        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop all plugins
    pub async fn stop_all(&self) -> Result<()> {
        info!("Stopping all plugins");

        self.running.store(false, Ordering::SeqCst);

        for name in self.registry.list_instances() {
            if let Some(plugin) = self.registry.get_instance(&name) {
                if let Err(e) = plugin.write().stop() {
                    warn!(plugin = %name, error = %e, "Error stopping plugin");
                } else {
                    info!(plugin = %name, "Plugin stopped");
                }
            }
        }

        Ok(())
    }

    /// Check if manager is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get loaded plugin names
    pub async fn loaded_plugins(&self) -> Vec<String> {
        self.registry.list_instances()
    }

    /// Get plugin count
    pub fn plugin_count(&self) -> usize {
        self.registry.instance_count()
    }

    /// Health check all plugins
    pub async fn health_check(&self) -> HashMap<String, bool> {
        let mut results = HashMap::new();

        for name in self.registry.list_instances() {
            if let Some(plugin) = self.registry.get_instance(&name) {
                let healthy = plugin.read().health_check();
                results.insert(name, healthy);
            }
        }

        results
    }

    /// Create a command channel for async plugin operations
    pub fn create_command_channel(&mut self) -> mpsc::Receiver<PluginCommand> {
        let (tx, rx) = mpsc::channel(32);
        self.command_tx = Some(tx);
        rx
    }

    /// Send a command to the plugin manager
    pub async fn send_command(&self, cmd: PluginCommand) -> Result<()> {
        if let Some(tx) = &self.command_tx {
            tx.send(cmd).await.map_err(|_| {
                PluginError::Other("Failed to send command to plugin manager".to_string())
            })?;
        }
        Ok(())
    }

    /// Process commands in a loop (should be run in a separate task)
    pub async fn process_commands(&self, mut rx: mpsc::Receiver<PluginCommand>) {
        info!("Plugin manager command processor started");

        while let Some(cmd) = rx.recv().await {
            match cmd {
                PluginCommand::ReloadAll => {
                    if let Err(e) = self.reload_all().await {
                        error!(error = %e, "Failed to reload all plugins");
                    }
                }
                PluginCommand::Load(config) => {
                    if let Err(e) = self.load_single_plugin(&config).await {
                        error!(plugin = %config.name, error = %e, "Failed to load plugin");
                    }
                }
                PluginCommand::Unload(name) => {
                    if let Err(e) = self.unload_plugin(&name).await {
                        error!(plugin = %name, error = %e, "Failed to unload plugin");
                    }
                }
                PluginCommand::Reload(name) => {
                    if let Err(e) = self.reload_plugin(&name).await {
                        error!(plugin = %name, error = %e, "Failed to reload plugin");
                    }
                }
                PluginCommand::Shutdown => {
                    info!("Plugin manager shutting down");
                    if let Err(e) = self.stop_all().await {
                        error!(error = %e, "Error during shutdown");
                    }
                    break;
                }
            }
        }

        info!("Plugin manager command processor stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_manager_creation() {
        let manager = PluginManager::new("./plugins");
        assert_eq!(manager.plugin_count(), 0);
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_start_stop() {
        let manager = PluginManager::new("./plugins");
        manager.start_all().await.unwrap();
        assert!(manager.is_running());
        manager.stop_all().await.unwrap();
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_health_check_empty() {
        let manager = PluginManager::new("./plugins");
        let results = manager.health_check().await;
        assert!(results.is_empty());
    }
}
