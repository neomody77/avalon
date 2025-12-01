//! avalon-core: Core configuration and utilities for avalon
//!
//! This crate provides configuration parsing, validation, and hot reload
//! functionality for the avalon web server.

pub mod config;
pub mod watcher;

pub use config::*;
pub use watcher::{ConfigWatcher, ReloadManager};
