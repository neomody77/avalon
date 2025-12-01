//! WASM plugin runtime using wasmtime
//!
//! This module provides sandboxed execution of WebAssembly plugins

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestInfo, ResponseInfo};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use wasmtime::*;

/// WASM plugin runtime configuration
#[derive(Debug, Clone)]
pub struct WasmConfig {
    /// Maximum memory pages (64KB each)
    pub max_memory_pages: u32,
    /// Maximum fuel (execution steps)
    pub max_fuel: u64,
    /// Enable WASI support
    pub enable_wasi: bool,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory_pages: 256, // 16MB
            max_fuel: 1_000_000,
            enable_wasi: false,
        }
    }
}

/// A loaded WASM plugin instance
pub struct WasmPlugin {
    name: String,
    engine: Engine,
    module: Module,
    store: Store<WasmPluginState>,
    instance: Instance,
}

/// State for a WASM plugin instance
struct WasmPluginState {
    /// Plugin name
    name: String,
    /// Memory limit reached
    memory_exhausted: bool,
    /// Fuel exhausted
    fuel_exhausted: bool,
}

impl WasmPlugin {
    /// Load a WASM plugin from bytes
    pub fn from_bytes(
        name: impl Into<String>,
        bytes: &[u8],
        config: &WasmConfig,
    ) -> Result<Self> {
        let name = name.into();
        info!(plugin = %name, "Loading WASM plugin");

        // Configure the engine
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);
        engine_config.wasm_memory64(false);

        let engine = Engine::new(&engine_config).map_err(|e| {
            PluginError::WasmError(format!("Failed to create WASM engine: {}", e))
        })?;

        // Compile the module
        let module = Module::new(&engine, bytes).map_err(|e| {
            PluginError::WasmError(format!("Failed to compile WASM module: {}", e))
        })?;

        // Create store with state
        let state = WasmPluginState {
            name: name.clone(),
            memory_exhausted: false,
            fuel_exhausted: false,
        };
        let mut store = Store::new(&engine, state);
        store.set_fuel(config.max_fuel).map_err(|e| {
            PluginError::WasmError(format!("Failed to set fuel: {}", e))
        })?;

        // Create linker and add host functions
        let mut linker = Linker::new(&engine);
        Self::add_host_functions(&mut linker)?;

        // Instantiate the module
        let instance = linker.instantiate(&mut store, &module).map_err(|e| {
            PluginError::WasmError(format!("Failed to instantiate WASM module: {}", e))
        })?;

        info!(plugin = %name, "Successfully loaded WASM plugin");

        Ok(Self {
            name,
            engine,
            module,
            store,
            instance,
        })
    }

    /// Load a WASM plugin from a file
    pub fn from_file(
        name: impl Into<String>,
        path: impl AsRef<Path>,
        config: &WasmConfig,
    ) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| {
            PluginError::WasmError(format!("Failed to read WASM file: {}", e))
        })?;
        Self::from_bytes(name, &bytes, config)
    }

    /// Add host functions to the linker
    fn add_host_functions(linker: &mut Linker<WasmPluginState>) -> Result<()> {
        // Log function: log(level: i32, ptr: i32, len: i32)
        linker
            .func_wrap("env", "log", |_caller: Caller<'_, WasmPluginState>, level: i32, _ptr: i32, _len: i32| {
                // In a real implementation, we'd read the string from memory
                debug!(level = level, "WASM plugin log");
            })
            .map_err(|e| PluginError::WasmError(format!("Failed to add log function: {}", e)))?;

        // Get header function: get_header(name_ptr: i32, name_len: i32, out_ptr: i32, out_len: i32) -> i32
        linker
            .func_wrap(
                "env",
                "get_header",
                |_caller: Caller<'_, WasmPluginState>, _name_ptr: i32, _name_len: i32, _out_ptr: i32, _out_len: i32| -> i32 {
                    // In a real implementation, we'd read/write from memory
                    0 // Return 0 = not found
                },
            )
            .map_err(|e| PluginError::WasmError(format!("Failed to add get_header function: {}", e)))?;

        // Set header function: set_header(name_ptr: i32, name_len: i32, val_ptr: i32, val_len: i32)
        linker
            .func_wrap(
                "env",
                "set_header",
                |_caller: Caller<'_, WasmPluginState>, _name_ptr: i32, _name_len: i32, _val_ptr: i32, _val_len: i32| {
                    // In a real implementation, we'd read from memory and modify headers
                },
            )
            .map_err(|e| PluginError::WasmError(format!("Failed to add set_header function: {}", e)))?;

        Ok(())
    }

    /// Call the plugin's on_request hook
    pub fn on_request(&mut self, _request: &RequestInfo, _ctx: &mut PluginContext) -> Result<HookAction> {
        // Get the exported function
        let func = self
            .instance
            .get_typed_func::<(), i32>(&mut self.store, "on_request")
            .ok();

        if let Some(func) = func {
            let result = func.call(&mut self.store, ()).map_err(|e| {
                PluginError::WasmError(format!("WASM on_request failed: {}", e))
            })?;

            // Interpret the result
            match result {
                0 => Ok(HookAction::Continue),
                1 => Ok(HookAction::SkipPhase),
                2 => Ok(HookAction::ShortCircuit),
                _ => {
                    warn!(plugin = %self.name, result = result, "Unknown hook action");
                    Ok(HookAction::Continue)
                }
            }
        } else {
            // No on_request function exported
            Ok(HookAction::Continue)
        }
    }

    /// Call the plugin's on_response hook
    pub fn on_response(&mut self, _response: &mut ResponseInfo, _ctx: &mut PluginContext) -> Result<HookAction> {
        let func = self
            .instance
            .get_typed_func::<(), i32>(&mut self.store, "on_response")
            .ok();

        if let Some(func) = func {
            let result = func.call(&mut self.store, ()).map_err(|e| {
                PluginError::WasmError(format!("WASM on_response failed: {}", e))
            })?;

            match result {
                0 => Ok(HookAction::Continue),
                1 => Ok(HookAction::SkipPhase),
                2 => Ok(HookAction::ShortCircuit),
                _ => Ok(HookAction::Continue),
            }
        } else {
            Ok(HookAction::Continue)
        }
    }

    /// Get the plugin name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reset fuel for the next request
    pub fn reset_fuel(&mut self, fuel: u64) -> Result<()> {
        self.store.set_fuel(fuel).map_err(|e| {
            PluginError::WasmError(format!("Failed to reset fuel: {}", e))
        })?;
        Ok(())
    }
}

/// WASM plugin manager
pub struct WasmPluginManager {
    config: WasmConfig,
    plugins: HashMap<String, WasmPlugin>,
}

impl WasmPluginManager {
    /// Create a new WASM plugin manager
    pub fn new(config: WasmConfig) -> Self {
        Self {
            config,
            plugins: HashMap::new(),
        }
    }

    /// Load a WASM plugin from bytes
    pub fn load_from_bytes(&mut self, name: impl Into<String>, bytes: &[u8]) -> Result<()> {
        let name = name.into();
        let plugin = WasmPlugin::from_bytes(&name, bytes, &self.config)?;
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Load a WASM plugin from a file
    pub fn load_from_file(&mut self, name: impl Into<String>, path: impl AsRef<Path>) -> Result<()> {
        let name = name.into();
        let plugin = WasmPlugin::from_file(&name, path, &self.config)?;
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Unload a plugin
    pub fn unload(&mut self, name: &str) -> bool {
        self.plugins.remove(name).is_some()
    }

    /// Get a mutable reference to a plugin
    pub fn get_mut(&mut self, name: &str) -> Option<&mut WasmPlugin> {
        self.plugins.get_mut(name)
    }

    /// List loaded plugins
    pub fn list(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    /// Run on_request for all plugins
    pub fn run_on_request(&mut self, request: &RequestInfo, ctx: &mut PluginContext) -> Result<HookAction> {
        for plugin in self.plugins.values_mut() {
            plugin.reset_fuel(self.config.max_fuel)?;
            match plugin.on_request(request, ctx)? {
                HookAction::Continue => continue,
                action => return Ok(action),
            }
        }
        Ok(HookAction::Continue)
    }

    /// Run on_response for all plugins
    pub fn run_on_response(&mut self, response: &mut ResponseInfo, ctx: &mut PluginContext) -> Result<HookAction> {
        for plugin in self.plugins.values_mut() {
            plugin.reset_fuel(self.config.max_fuel)?;
            match plugin.on_response(response, ctx)? {
                HookAction::Continue => continue,
                action => return Ok(action),
            }
        }
        Ok(HookAction::Continue)
    }
}

impl Default for WasmPluginManager {
    fn default() -> Self {
        Self::new(WasmConfig::default())
    }
}
