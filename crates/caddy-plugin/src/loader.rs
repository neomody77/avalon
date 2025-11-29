//! Dynamic plugin loader using libloading
//!
//! This module provides runtime loading of native plugins (.so/.dylib/.dll)

use crate::error::{PluginError, Result};
use crate::plugin::Plugin;
use crate::registry::{PluginFactory, PluginRegistry};
use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Symbol name for the plugin factory function
const PLUGIN_FACTORY_SYMBOL: &[u8] = b"_caddy_plugin_create";

/// Symbol name for the plugin metadata function
const PLUGIN_METADATA_SYMBOL: &[u8] = b"_caddy_plugin_metadata";

/// Dynamic plugin loader
pub struct PluginLoader {
    /// Loaded libraries (kept alive to prevent unloading)
    libraries: HashMap<String, Library>,
    /// Reference to the plugin registry
    registry: Arc<PluginRegistry>,
}

impl PluginLoader {
    /// Create a new plugin loader
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self {
            libraries: HashMap::new(),
            registry,
        }
    }

    /// Load a plugin from a dynamic library file
    ///
    /// # Safety
    /// Loading dynamic libraries is inherently unsafe. The library must:
    /// - Be compiled with the same Rust version and ABI
    /// - Export the required symbols with correct signatures
    /// - Not have undefined behavior in its code
    pub unsafe fn load_plugin(&mut self, path: impl AsRef<Path>) -> Result<String> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading dynamic plugin");

        // Load the library
        let library = Library::new(path).map_err(|e| {
            PluginError::LoadFailed(format!("Failed to load library {}: {}", path.display(), e))
        })?;

        // Get the factory function
        let factory: Symbol<PluginFactory> =
            library.get(PLUGIN_FACTORY_SYMBOL).map_err(|e| {
                PluginError::LoadFailed(format!(
                    "Plugin {} missing factory symbol: {}",
                    path.display(),
                    e
                ))
            })?;

        // Create a temporary instance to get metadata
        let temp_instance = factory();
        let metadata = temp_instance.metadata().clone();
        let plugin_name = metadata.name.clone();

        // Check API version
        if metadata.api_version != crate::PLUGIN_API_VERSION {
            return Err(PluginError::AbiMismatch {
                expected: crate::PLUGIN_API_VERSION,
                actual: metadata.api_version,
            });
        }

        // Register the factory
        // We need to keep a raw function pointer since the library must stay loaded
        let factory_fn: PluginFactory = *factory;
        self.registry.register_factory(&plugin_name, factory_fn)?;

        // Store the library to keep it loaded
        self.libraries.insert(plugin_name.clone(), library);

        info!(
            plugin = %plugin_name,
            version = %metadata.version,
            "Successfully loaded dynamic plugin"
        );

        Ok(plugin_name)
    }

    /// Load all plugins from a directory
    ///
    /// # Safety
    /// See `load_plugin` for safety requirements
    pub unsafe fn load_plugins_from_dir(&mut self, dir: impl AsRef<Path>) -> Result<Vec<String>> {
        let dir = dir.as_ref();
        let mut loaded = Vec::new();

        if !dir.exists() {
            debug!(path = %dir.display(), "Plugin directory does not exist");
            return Ok(loaded);
        }

        let entries = std::fs::read_dir(dir).map_err(|e| {
            PluginError::LoadFailed(format!("Failed to read plugin directory: {}", e))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if is_plugin_file(&path) {
                match self.load_plugin(&path) {
                    Ok(name) => loaded.push(name),
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to load plugin"
                        );
                    }
                }
            }
        }

        info!(count = loaded.len(), "Loaded plugins from directory");
        Ok(loaded)
    }

    /// Unload a plugin by name
    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        // First remove from registry
        self.registry.remove_instance(name)?;

        // Then drop the library (this will unload it)
        if self.libraries.remove(name).is_some() {
            info!(plugin = %name, "Unloaded dynamic plugin");
        }

        Ok(())
    }

    /// Check if a plugin is loaded
    pub fn is_loaded(&self, name: &str) -> bool {
        self.libraries.contains_key(name)
    }

    /// List loaded plugin names
    pub fn loaded_plugins(&self) -> Vec<String> {
        self.libraries.keys().cloned().collect()
    }
}

/// Check if a path is a valid plugin file
fn is_plugin_file(path: &Path) -> bool {
    let extension = path.extension().and_then(OsStr::to_str);
    matches!(extension, Some("so") | Some("dylib") | Some("dll"))
}

/// Macro to declare a plugin's entry points
///
/// Usage:
/// ```ignore
/// caddy_plugin::declare_plugin!(MyPlugin);
/// ```
#[macro_export]
macro_rules! declare_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn _caddy_plugin_create() -> Box<dyn $crate::Plugin> {
            Box::new(<$plugin_type>::default())
        }
    };
    ($plugin_type:ty, $constructor:expr) => {
        #[no_mangle]
        pub extern "C" fn _caddy_plugin_create() -> Box<dyn $crate::Plugin> {
            Box::new($constructor)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_plugin_file() {
        assert!(is_plugin_file(Path::new("plugin.so")));
        assert!(is_plugin_file(Path::new("plugin.dylib")));
        assert!(is_plugin_file(Path::new("plugin.dll")));
        assert!(!is_plugin_file(Path::new("plugin.txt")));
        assert!(!is_plugin_file(Path::new("plugin")));
    }
}
