//! Plugin error types

use thiserror::Error;

/// Plugin error type
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Initialization error: {0}")]
    InitError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("API version mismatch: expected {expected}, got {actual}")]
    AbiMismatch { expected: u32, actual: u32 },

    #[error("Loading error: {0}")]
    LoadError(String),

    #[error("Hook execution error: {0}")]
    HookError(String),

    #[error("Plugin already registered: {0}")]
    AlreadyRegistered(String),

    #[error("Plugin state error: {0}")]
    StateError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Load failed: {0}")]
    LoadFailed(String),

    #[error("WASM error: {0}")]
    WasmError(String),

    #[error("{0}")]
    Other(String),
}

/// Result type alias for plugin operations
pub type Result<T> = std::result::Result<T, PluginError>;
