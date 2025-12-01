//! Admin API Plugin
//!
//! Provides HTTP API endpoints for server administration:
//! - GET /admin/config - View current configuration
//! - POST /admin/config/reload - Trigger config reload
//! - GET /admin/status - Server status and statistics
//! - GET /admin/upstreams - Upstream server status
//! - POST /admin/upstreams/{name}/enable - Enable an upstream
//! - POST /admin/upstreams/{name}/disable - Disable an upstream
//! - GET /admin/plugins - List loaded plugins

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestFilterHook, RequestInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::info;

/// Admin API plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AdminPluginConfig {
    /// Path prefix for admin endpoints (default: /admin)
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    /// Enable authentication for admin API
    #[serde(default)]
    pub require_auth: bool,
    /// API key for authentication (if require_auth is true)
    #[serde(default)]
    pub api_key: Option<String>,
    /// Allowed IP addresses (empty = allow all)
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Enable config reload endpoint
    #[serde(default = "default_true")]
    pub enable_reload: bool,
    /// Enable upstream management endpoints
    #[serde(default = "default_true")]
    pub enable_upstream_management: bool,
}

fn default_path_prefix() -> String {
    "/admin".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for AdminPluginConfig {
    fn default() -> Self {
        Self {
            path_prefix: default_path_prefix(),
            require_auth: false,
            api_key: None,
            allowed_ips: Vec::new(),
            enable_reload: true,
            enable_upstream_management: true,
        }
    }
}

/// Server statistics
#[derive(Debug, Clone, Serialize)]
pub struct ServerStats {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub active_connections: u64,
    pub requests_per_second: f64,
    pub avg_response_time_ms: f64,
}

/// Upstream status
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub name: String,
    pub address: String,
    pub healthy: bool,
    pub enabled: bool,
    pub weight: u32,
    pub active_connections: u64,
    pub total_requests: u64,
    pub failed_requests: u64,
    pub avg_response_time_ms: f64,
}

/// Admin API response
#[derive(Debug, Serialize)]
pub struct AdminResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> AdminResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Admin state shared across requests
pub struct AdminState {
    start_time: Instant,
    total_requests: AtomicU64,
    active_connections: AtomicU64,
    total_response_time_ms: AtomicU64,
    config_path: RwLock<Option<String>>,
    reload_callback: RwLock<Option<Box<dyn Fn() -> std::result::Result<(), String> + Send + Sync>>>,
    upstreams: RwLock<HashMap<String, UpstreamInfo>>,
}

#[derive(Clone)]
struct UpstreamInfo {
    address: String,
    healthy: bool,
    enabled: bool,
    weight: u32,
    active_connections: u64,
    total_requests: u64,
    failed_requests: u64,
    total_response_time_ms: u64,
}

impl AdminState {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_response_time_ms: AtomicU64::new(0),
            config_path: RwLock::new(None),
            reload_callback: RwLock::new(None),
            upstreams: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_config_path(&self, path: String) {
        *self.config_path.write() = Some(path);
    }

    pub fn set_reload_callback<F>(&self, callback: F)
    where
        F: Fn() -> std::result::Result<(), String> + Send + Sync + 'static,
    {
        *self.reload_callback.write() = Some(Box::new(callback));
    }

    pub fn trigger_reload(&self) -> std::result::Result<(), String> {
        if let Some(callback) = self.reload_callback.read().as_ref() {
            callback()
        } else {
            Err("Reload callback not configured".to_string())
        }
    }

    pub fn record_request(&self, response_time_ms: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_ms
            .fetch_add(response_time_ms, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> ServerStats {
        let uptime = self.start_time.elapsed();
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        let total_response_time = self.total_response_time_ms.load(Ordering::Relaxed);

        let requests_per_second = if uptime.as_secs() > 0 {
            total_requests as f64 / uptime.as_secs_f64()
        } else {
            0.0
        };

        let avg_response_time = if total_requests > 0 {
            total_response_time as f64 / total_requests as f64
        } else {
            0.0
        };

        ServerStats {
            uptime_secs: uptime.as_secs(),
            total_requests,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            requests_per_second,
            avg_response_time_ms: avg_response_time,
        }
    }

    pub fn update_upstream(&self, name: &str, info: UpstreamInfo) {
        self.upstreams.write().insert(name.to_string(), info);
    }

    pub fn get_upstreams(&self) -> Vec<UpstreamStatus> {
        self.upstreams
            .read()
            .iter()
            .map(|(name, info)| {
                let avg_response_time = if info.total_requests > 0 {
                    info.total_response_time_ms as f64 / info.total_requests as f64
                } else {
                    0.0
                };
                UpstreamStatus {
                    name: name.clone(),
                    address: info.address.clone(),
                    healthy: info.healthy,
                    enabled: info.enabled,
                    weight: info.weight,
                    active_connections: info.active_connections,
                    total_requests: info.total_requests,
                    failed_requests: info.failed_requests,
                    avg_response_time_ms: avg_response_time,
                }
            })
            .collect()
    }

    pub fn set_upstream_enabled(&self, name: &str, enabled: bool) -> bool {
        if let Some(info) = self.upstreams.write().get_mut(name) {
            info.enabled = enabled;
            true
        } else {
            false
        }
    }
}

impl Default for AdminState {
    fn default() -> Self {
        Self::new()
    }
}

/// Admin API Plugin
pub struct AdminPlugin {
    metadata: PluginMetadata,
    config: AdminPluginConfig,
    state: Option<Arc<AdminState>>,
    running: bool,
}

impl AdminPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("admin", "0.1.0", PluginType::Middleware)
            .with_description("HTTP Admin API for server management")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: true,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: AdminPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_request_hook(&self) -> Option<AdminRequestHook> {
        self.state.as_ref().map(|s| AdminRequestHook {
            state: s.clone(),
            config: self.config.clone(),
        })
    }

    pub fn state(&self) -> Option<Arc<AdminState>> {
        self.state.clone()
    }
}

impl Default for AdminPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for AdminPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = AdminPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(AdminState::new()));
        self.running = true;

        info!(
            path_prefix = %self.config.path_prefix,
            require_auth = self.config.require_auth,
            "Admin API plugin started"
        );

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        info!("Admin API plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.state.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Request hook for handling admin API requests
pub struct AdminRequestHook {
    state: Arc<AdminState>,
    config: AdminPluginConfig,
}

impl AdminRequestHook {
    fn check_auth(&self, request: &RequestInfo) -> bool {
        if !self.config.require_auth {
            return true;
        }

        // Check API key from header
        if let Some(api_key) = &self.config.api_key {
            if let Some(provided_key) = request.headers.get("x-admin-api-key") {
                return provided_key == api_key;
            }
            // Also check Authorization header with Bearer token
            if let Some(auth) = request.headers.get("authorization") {
                if let Some(token) = auth.strip_prefix("Bearer ") {
                    return token == api_key;
                }
            }
        }

        false
    }

    fn check_ip(&self, request: &RequestInfo, ctx: &PluginContext) -> bool {
        if self.config.allowed_ips.is_empty() {
            return true;
        }

        // Try to get client IP from context (set by proxy layer) or X-Forwarded-For header
        let client_ip = ctx
            .get::<String>("client_ip")
            .or_else(|| request.headers.get("x-forwarded-for").cloned())
            .or_else(|| request.headers.get("x-real-ip").cloned());

        if let Some(ip) = client_ip {
            self.config.allowed_ips.iter().any(|allowed| {
                // Support CIDR notation in the future
                allowed == &ip || allowed == "*"
            })
        } else {
            // If no client IP found but allowed_ips is set, deny access
            false
        }
    }

    fn set_response(&self, ctx: &mut PluginContext, status: u16, body: String, content_type: &str) {
        ctx.set("admin_response_status", status);
        ctx.set("admin_response_body", body);
        ctx.set("admin_response_content_type", content_type.to_string());
    }

    fn handle_status(&self) -> (u16, String) {
        let stats = self.state.get_stats();
        let response = AdminResponse::ok(stats);
        (200, serde_json::to_string_pretty(&response).unwrap_or_default())
    }

    fn handle_upstreams(&self) -> (u16, String) {
        let upstreams = self.state.get_upstreams();
        let response = AdminResponse::ok(upstreams);
        (200, serde_json::to_string_pretty(&response).unwrap_or_default())
    }

    fn handle_reload(&self) -> (u16, String) {
        if !self.config.enable_reload {
            let response: AdminResponse<()> = AdminResponse::error("Reload endpoint is disabled");
            return (403, serde_json::to_string_pretty(&response).unwrap_or_default());
        }

        match self.state.trigger_reload() {
            Ok(()) => {
                #[derive(Serialize)]
                struct ReloadResult {
                    message: String,
                    timestamp: u64,
                }
                let result = ReloadResult {
                    message: "Configuration reloaded successfully".to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                let response = AdminResponse::ok(result);
                (200, serde_json::to_string_pretty(&response).unwrap_or_default())
            }
            Err(e) => {
                let response: AdminResponse<()> = AdminResponse::error(&e);
                (500, serde_json::to_string_pretty(&response).unwrap_or_default())
            }
        }
    }

    fn handle_upstream_enable(&self, name: &str, enable: bool) -> (u16, String) {
        if !self.config.enable_upstream_management {
            let response: AdminResponse<()> =
                AdminResponse::error("Upstream management is disabled");
            return (403, serde_json::to_string_pretty(&response).unwrap_or_default());
        }

        if self.state.set_upstream_enabled(name, enable) {
            #[derive(Serialize)]
            struct UpstreamResult {
                name: String,
                enabled: bool,
            }
            let result = UpstreamResult {
                name: name.to_string(),
                enabled: enable,
            };
            let response = AdminResponse::ok(result);
            (200, serde_json::to_string_pretty(&response).unwrap_or_default())
        } else {
            let response: AdminResponse<()> =
                AdminResponse::error(&format!("Upstream '{}' not found", name));
            (404, serde_json::to_string_pretty(&response).unwrap_or_default())
        }
    }

    fn handle_plugins(&self) -> (u16, String) {
        // Return list of built-in plugins
        #[derive(Serialize)]
        struct PluginInfo {
            name: String,
            version: String,
            description: String,
        }

        let plugins = vec![
            PluginInfo {
                name: "admin".to_string(),
                version: "0.1.0".to_string(),
                description: "HTTP Admin API for server management".to_string(),
            },
            PluginInfo {
                name: "access_log".to_string(),
                version: "0.1.0".to_string(),
                description: "Access logging with multiple formats".to_string(),
            },
            PluginInfo {
                name: "rate_limit".to_string(),
                version: "0.1.0".to_string(),
                description: "Rate limiting based on client IP".to_string(),
            },
            PluginInfo {
                name: "auth".to_string(),
                version: "0.1.0".to_string(),
                description: "Authentication (Basic, API Key, JWT)".to_string(),
            },
            PluginInfo {
                name: "cache".to_string(),
                version: "0.1.0".to_string(),
                description: "Response caching".to_string(),
            },
            PluginInfo {
                name: "compression".to_string(),
                version: "0.1.0".to_string(),
                description: "Response compression (gzip, brotli)".to_string(),
            },
            PluginInfo {
                name: "headers".to_string(),
                version: "0.1.0".to_string(),
                description: "Request/response header manipulation".to_string(),
            },
            PluginInfo {
                name: "request_id".to_string(),
                version: "0.1.0".to_string(),
                description: "Request ID generation for tracing".to_string(),
            },
            PluginInfo {
                name: "metrics".to_string(),
                version: "0.1.0".to_string(),
                description: "Prometheus metrics collection".to_string(),
            },
            PluginInfo {
                name: "rewrite".to_string(),
                version: "0.1.0".to_string(),
                description: "URL rewriting and redirects".to_string(),
            },
        ];

        let response = AdminResponse::ok(plugins);
        (200, serde_json::to_string_pretty(&response).unwrap_or_default())
    }

    fn handle_not_found(&self, path: &str) -> (u16, String) {
        let response: AdminResponse<()> =
            AdminResponse::error(&format!("Admin endpoint not found: {}", path));
        (404, serde_json::to_string_pretty(&response).unwrap_or_default())
    }

    fn handle_method_not_allowed(&self, method: &str) -> (u16, String) {
        let response: AdminResponse<()> =
            AdminResponse::error(&format!("Method not allowed: {}", method));
        (405, serde_json::to_string_pretty(&response).unwrap_or_default())
    }
}

#[async_trait]
impl RequestFilterHook for AdminRequestHook {
    fn priority(&self) -> HookPriority {
        HookPriority::FIRST // Handle admin requests before other processing
    }

    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let path = &request.path;

        // Check if this is an admin request
        if !path.starts_with(&self.config.path_prefix) {
            return Ok(HookAction::Continue);
        }

        // Check IP allowlist
        if !self.check_ip(request, ctx) {
            self.set_response(
                ctx,
                403,
                r#"{"success":false,"error":"Access denied: IP not allowed"}"#.to_string(),
                "application/json",
            );
            return Ok(HookAction::ShortCircuit);
        }

        // Check authentication
        if !self.check_auth(request) {
            self.set_response(
                ctx,
                401,
                r#"{"success":false,"error":"Authentication required"}"#.to_string(),
                "application/json",
            );
            ctx.set("admin_response_www_authenticate", "Bearer".to_string());
            return Ok(HookAction::ShortCircuit);
        }

        // Route to appropriate handler
        let admin_path = path.strip_prefix(&self.config.path_prefix).unwrap_or("");
        let method = request.method.as_str();

        let (status, body) = match (method, admin_path) {
            ("GET", "/status") | ("GET", "/status/") => self.handle_status(),
            ("GET", "/upstreams") | ("GET", "/upstreams/") => self.handle_upstreams(),
            ("GET", "/plugins") | ("GET", "/plugins/") => self.handle_plugins(),
            ("POST", "/config/reload") | ("POST", "/config/reload/") => self.handle_reload(),
            ("POST", path) if path.starts_with("/upstreams/") && path.ends_with("/enable") => {
                let name = path
                    .strip_prefix("/upstreams/")
                    .and_then(|s| s.strip_suffix("/enable"))
                    .unwrap_or("");
                self.handle_upstream_enable(name, true)
            }
            ("POST", path) if path.starts_with("/upstreams/") && path.ends_with("/disable") => {
                let name = path
                    .strip_prefix("/upstreams/")
                    .and_then(|s| s.strip_suffix("/disable"))
                    .unwrap_or("");
                self.handle_upstream_enable(name, false)
            }
            ("GET", _) | ("POST", _) => self.handle_not_found(admin_path),
            _ => self.handle_method_not_allowed(method),
        };

        self.set_response(ctx, status, body, "application/json");
        Ok(HookAction::ShortCircuit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = AdminPlugin::new();
        assert_eq!(plugin.metadata().name, "admin");
        assert_eq!(plugin.metadata().plugin_type, PluginType::Middleware);
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = AdminPlugin::new();
        let config = r#"{"path_prefix": "/api/admin", "require_auth": true, "api_key": "secret123"}"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.path_prefix, "/api/admin");
        assert!(plugin.config.require_auth);
        assert_eq!(plugin.config.api_key, Some("secret123".to_string()));
    }

    #[test]
    fn test_admin_state() {
        let state = AdminState::new();

        // Test request recording
        state.record_request(100);
        state.record_request(200);

        let stats = state.get_stats();
        assert_eq!(stats.total_requests, 2);

        // Test connection tracking
        state.increment_connections();
        state.increment_connections();
        state.decrement_connections();

        let stats = state.get_stats();
        assert_eq!(stats.active_connections, 1);
    }

    #[test]
    fn test_upstream_management() {
        let state = AdminState::new();

        state.update_upstream(
            "backend1",
            UpstreamInfo {
                address: "127.0.0.1:8080".to_string(),
                healthy: true,
                enabled: true,
                weight: 1,
                active_connections: 0,
                total_requests: 0,
                failed_requests: 0,
                total_response_time_ms: 0,
            },
        );

        let upstreams = state.get_upstreams();
        assert_eq!(upstreams.len(), 1);
        assert!(upstreams[0].enabled);

        // Disable upstream
        assert!(state.set_upstream_enabled("backend1", false));
        let upstreams = state.get_upstreams();
        assert!(!upstreams[0].enabled);

        // Non-existent upstream
        assert!(!state.set_upstream_enabled("nonexistent", false));
    }

    #[test]
    fn test_start_stop() {
        let mut plugin = AdminPlugin::new();
        plugin.init("").unwrap();
        plugin.start().unwrap();
        assert!(plugin.health_check());
        assert!(plugin.state().is_some());

        plugin.stop().unwrap();
        assert!(!plugin.health_check());
    }
}
