//! caddy-plugin: Plugin system for caddy-rs
//!
//! This crate provides a plugin architecture supporting:
//! - Static compilation (built-in plugins via Cargo features)
//! - Dynamic loading (.so/.dylib via libloading)
//! - WASM sandboxed plugins (via wasmtime)

pub mod context;
pub mod error;
pub mod executor;
pub mod hooks;
pub mod manager;
pub mod plugin;
pub mod plugins;
pub mod priority;
pub mod registry;

#[cfg(feature = "dynamic")]
pub mod loader;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "wasm")]
pub use wasm::{WasmConfig, WasmPlugin, WasmPluginManager};

pub use context::PluginContext;
pub use error::{PluginError, Result};
pub use executor::HookExecutor;
pub use hooks::*;
pub use manager::{PluginCommand, PluginConfig, PluginManager, PluginType as ManagerPluginType};
pub use plugin::{Plugin, PluginMetadata, PluginType};
pub use priority::HookPriority;
pub use registry::PluginRegistry;

#[cfg(feature = "dynamic")]
pub use loader::PluginLoader;

/// Plugin API version for compatibility checking
pub const PLUGIN_API_VERSION: u32 = 1;
