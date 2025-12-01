//! Headers Plugin
//!
//! Modify request and response headers.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestFilterHook, RequestInfo, ResponseFilterHook, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Header operation
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum HeaderOp {
    /// Set header (overwrites existing)
    Set { name: String, value: String },
    /// Add header (appends to existing)
    Add { name: String, value: String },
    /// Delete header
    Delete { name: String },
    /// Rename header
    Rename { from: String, to: String },
}

/// Headers plugin configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HeadersPluginConfig {
    /// Operations on request headers
    #[serde(default)]
    pub request: Vec<HeaderOp>,
    /// Operations on response headers
    #[serde(default)]
    pub response: Vec<HeaderOp>,
    /// CORS configuration
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Security headers
    #[serde(default)]
    pub security: Option<SecurityHeaders>,
}

/// CORS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub max_age: Option<u32>,
}

/// Security headers preset
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityHeaders {
    #[serde(default = "default_true")]
    pub x_content_type_options: bool,
    #[serde(default = "default_true")]
    pub x_frame_options: bool,
    #[serde(default = "default_true")]
    pub x_xss_protection: bool,
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default)]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub referrer_policy: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Headers state
struct HeadersState {
    request_ops: Vec<HeaderOp>,
    response_ops: Vec<HeaderOp>,
    cors: Option<CorsConfig>,
    security: Option<SecurityHeaders>,
}

impl HeadersState {
    fn from_config(config: &HeadersPluginConfig) -> Self {
        Self {
            request_ops: config.request.clone(),
            response_ops: config.response.clone(),
            cors: config.cors.clone(),
            security: config.security.clone(),
        }
    }

    fn apply_request_ops(&self, headers: &mut HashMap<String, String>) {
        for op in &self.request_ops {
            match op {
                HeaderOp::Set { name, value } => {
                    headers.insert(name.to_lowercase(), value.clone());
                }
                HeaderOp::Add { name, value } => {
                    let key = name.to_lowercase();
                    if let Some(existing) = headers.get_mut(&key) {
                        existing.push_str(", ");
                        existing.push_str(value);
                    } else {
                        headers.insert(key, value.clone());
                    }
                }
                HeaderOp::Delete { name } => {
                    headers.remove(&name.to_lowercase());
                }
                HeaderOp::Rename { from, to } => {
                    if let Some(value) = headers.remove(&from.to_lowercase()) {
                        headers.insert(to.to_lowercase(), value);
                    }
                }
            }
        }
    }

    fn apply_response_ops(&self, headers: &mut HashMap<String, String>) {
        // Apply custom ops
        for op in &self.response_ops {
            match op {
                HeaderOp::Set { name, value } => {
                    headers.insert(name.to_lowercase(), value.clone());
                }
                HeaderOp::Add { name, value } => {
                    let key = name.to_lowercase();
                    if let Some(existing) = headers.get_mut(&key) {
                        existing.push_str(", ");
                        existing.push_str(value);
                    } else {
                        headers.insert(key, value.clone());
                    }
                }
                HeaderOp::Delete { name } => {
                    headers.remove(&name.to_lowercase());
                }
                HeaderOp::Rename { from, to } => {
                    if let Some(value) = headers.remove(&from.to_lowercase()) {
                        headers.insert(to.to_lowercase(), value);
                    }
                }
            }
        }

        // Apply security headers
        if let Some(security) = &self.security {
            if security.x_content_type_options {
                headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
            }
            if security.x_frame_options {
                headers.insert("x-frame-options".to_string(), "SAMEORIGIN".to_string());
            }
            if security.x_xss_protection {
                headers.insert("x-xss-protection".to_string(), "1; mode=block".to_string());
            }
            if let Some(csp) = &security.content_security_policy {
                headers.insert("content-security-policy".to_string(), csp.clone());
            }
            if let Some(hsts) = &security.strict_transport_security {
                headers.insert("strict-transport-security".to_string(), hsts.clone());
            }
            if let Some(rp) = &security.referrer_policy {
                headers.insert("referrer-policy".to_string(), rp.clone());
            }
        }
    }

    fn apply_cors(&self, origin: Option<&str>, headers: &mut HashMap<String, String>) {
        if let Some(cors) = &self.cors {
            // Check if origin is allowed
            let origin_allowed = if cors.allow_origins.is_empty() {
                false
            } else if cors.allow_origins.contains(&"*".to_string()) {
                true
            } else {
                origin.map(|o| cors.allow_origins.contains(&o.to_string())).unwrap_or(false)
            };

            if origin_allowed {
                if cors.allow_origins.contains(&"*".to_string()) {
                    headers.insert("access-control-allow-origin".to_string(), "*".to_string());
                } else if let Some(o) = origin {
                    headers.insert("access-control-allow-origin".to_string(), o.to_string());
                }

                if !cors.allow_methods.is_empty() {
                    headers.insert(
                        "access-control-allow-methods".to_string(),
                        cors.allow_methods.join(", "),
                    );
                }

                if !cors.allow_headers.is_empty() {
                    headers.insert(
                        "access-control-allow-headers".to_string(),
                        cors.allow_headers.join(", "),
                    );
                }

                if !cors.expose_headers.is_empty() {
                    headers.insert(
                        "access-control-expose-headers".to_string(),
                        cors.expose_headers.join(", "),
                    );
                }

                if cors.allow_credentials {
                    headers.insert("access-control-allow-credentials".to_string(), "true".to_string());
                }

                if let Some(max_age) = cors.max_age {
                    headers.insert("access-control-max-age".to_string(), max_age.to_string());
                }
            }
        }
    }
}

/// Headers Plugin
pub struct HeadersPlugin {
    metadata: PluginMetadata,
    config: HeadersPluginConfig,
    state: Option<Arc<HeadersState>>,
    running: bool,
}

impl HeadersPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("headers", "0.1.0", PluginType::Middleware)
            .with_description("Header manipulation plugin with CORS and security support")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: HeadersPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_request_hook(&self) -> Option<HeadersRequestHook> {
        self.state.as_ref().map(|s| HeadersRequestHook {
            state: s.clone(),
        })
    }

    pub fn get_response_hook(&self) -> Option<HeadersResponseHook> {
        self.state.as_ref().map(|s| HeadersResponseHook {
            state: s.clone(),
        })
    }
}

impl Default for HeadersPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for HeadersPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = HeadersPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(HeadersState::from_config(&self.config)));
        self.running = true;
        tracing::info!(
            request_ops = self.config.request.len(),
            response_ops = self.config.response.len(),
            has_cors = self.config.cors.is_some(),
            has_security = self.config.security.is_some(),
            "Headers plugin started"
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("Headers plugin stopped");
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

/// Request headers hook
pub struct HeadersRequestHook {
    state: Arc<HeadersState>,
}

#[async_trait]
impl RequestFilterHook for HeadersRequestHook {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let mut modified_headers = request.headers.clone();
        self.state.apply_request_ops(&mut modified_headers);

        if modified_headers != request.headers {
            ctx.set("modified_request_headers", modified_headers);
        }

        Ok(HookAction::Continue)
    }
}

/// Response headers hook
pub struct HeadersResponseHook {
    state: Arc<HeadersState>,
}

#[async_trait]
impl ResponseFilterHook for HeadersResponseHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE // Apply headers after other processing
    }

    async fn on_response(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Get origin from context for CORS
        let origin = ctx.get::<String>("request_origin");

        self.state.apply_response_ops(&mut response.headers);
        self.state.apply_cors(origin.as_deref(), &mut response.headers);

        Ok(HookAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = HeadersPlugin::new();
        assert_eq!(plugin.metadata().name, "headers");
    }

    #[test]
    fn test_header_set() {
        let config = HeadersPluginConfig {
            request: vec![HeaderOp::Set {
                name: "X-Custom".to_string(),
                value: "test-value".to_string(),
            }],
            ..Default::default()
        };
        let state = HeadersState::from_config(&config);

        let mut headers = HashMap::new();
        state.apply_request_ops(&mut headers);
        assert_eq!(headers.get("x-custom"), Some(&"test-value".to_string()));
    }

    #[test]
    fn test_header_delete() {
        let config = HeadersPluginConfig {
            response: vec![HeaderOp::Delete {
                name: "Server".to_string(),
            }],
            ..Default::default()
        };
        let state = HeadersState::from_config(&config);

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx".to_string());
        state.apply_response_ops(&mut headers);
        assert!(!headers.contains_key("server"));
    }

    #[test]
    fn test_security_headers() {
        let config = HeadersPluginConfig {
            security: Some(SecurityHeaders {
                x_content_type_options: true,
                x_frame_options: true,
                x_xss_protection: true,
                content_security_policy: Some("default-src 'self'".to_string()),
                strict_transport_security: Some("max-age=31536000".to_string()),
                referrer_policy: None,
            }),
            ..Default::default()
        };
        let state = HeadersState::from_config(&config);

        let mut headers = HashMap::new();
        state.apply_response_ops(&mut headers);

        assert_eq!(headers.get("x-content-type-options"), Some(&"nosniff".to_string()));
        assert_eq!(headers.get("x-frame-options"), Some(&"SAMEORIGIN".to_string()));
        assert!(headers.contains_key("content-security-policy"));
    }

    #[test]
    fn test_cors() {
        let config = HeadersPluginConfig {
            cors: Some(CorsConfig {
                allow_origins: vec!["https://example.com".to_string()],
                allow_methods: vec!["GET".to_string(), "POST".to_string()],
                allow_headers: vec!["Content-Type".to_string()],
                expose_headers: vec![],
                allow_credentials: true,
                max_age: Some(3600),
            }),
            ..Default::default()
        };
        let state = HeadersState::from_config(&config);

        let mut headers = HashMap::new();
        state.apply_cors(Some("https://example.com"), &mut headers);

        assert_eq!(headers.get("access-control-allow-origin"), Some(&"https://example.com".to_string()));
        assert_eq!(headers.get("access-control-allow-credentials"), Some(&"true".to_string()));
    }
}
