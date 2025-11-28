//! caddy-core: Core configuration and utilities for caddy-rs
//!
//! This crate provides configuration parsing, validation, and hot reload
//! functionality for the caddy-rs web server.

pub mod config;
pub mod watcher;

pub use config::*;
pub use watcher::{ConfigWatcher, ReloadManager};
