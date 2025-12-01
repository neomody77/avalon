//! Request ID Plugin
//!
//! This plugin generates unique request IDs for tracing and correlation.
//! It implements EarlyRequestHook to add the ID at the earliest stage.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{EarlyRequestHook, HookAction, RequestInfo, ResponseFilterHook, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use serde::Deserialize;
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Request ID plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RequestIdPluginConfig {
    /// Header name for request ID (default: X-Request-ID)
    #[serde(default = "default_header_name")]
    pub header_name: String,
    /// Whether to use incoming request ID if present (default: true)
    #[serde(default = "default_trust_incoming")]
    pub trust_incoming: bool,
    /// ID format: "uuid", "ulid", or "counter" (default: "uuid")
    #[serde(default = "default_format")]
    pub format: String,
    /// Prefix for generated IDs (optional)
    #[serde(default)]
    pub prefix: Option<String>,
    /// Add to response headers (default: true)
    #[serde(default = "default_add_to_response")]
    pub add_to_response: bool,
}

fn default_header_name() -> String {
    "X-Request-ID".to_string()
}
fn default_trust_incoming() -> bool {
    true
}
fn default_format() -> String {
    "uuid".to_string()
}
fn default_add_to_response() -> bool {
    true
}

impl Default for RequestIdPluginConfig {
    fn default() -> Self {
        Self {
            header_name: default_header_name(),
            trust_incoming: default_trust_incoming(),
            format: default_format(),
            prefix: None,
            add_to_response: default_add_to_response(),
        }
    }
}

/// ID Generator state
struct IdGenerator {
    counter: AtomicU64,
    prefix: Option<String>,
    format: String,
}

impl IdGenerator {
    fn new(config: &RequestIdPluginConfig) -> Self {
        // Initialize counter with timestamp for uniqueness across restarts
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            counter: AtomicU64::new(start),
            prefix: config.prefix.clone(),
            format: config.format.clone(),
        }
    }

    fn generate(&self) -> String {
        let id = match self.format.as_str() {
            "uuid" => self.generate_uuid(),
            "ulid" => self.generate_ulid(),
            "counter" => self.generate_counter(),
            _ => self.generate_uuid(),
        };

        match &self.prefix {
            Some(prefix) => format!("{}-{}", prefix, id),
            None => id,
        }
    }

    fn generate_uuid(&self) -> String {
        // Simple UUID v4-like generation using counter and random bits
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = time.as_nanos() as u64;

        // Create a pseudo-UUID format
        format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            (nanos >> 32) as u32,
            (nanos >> 16) as u16 & 0xFFFF,
            counter as u16 & 0x0FFF,
            0x8000 | (counter as u16 & 0x3FFF),
            counter & 0xFFFFFFFFFFFF
        )
    }

    fn generate_ulid(&self) -> String {
        // Simplified ULID-like format: timestamp + random
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Base32 Crockford encoding (simplified)
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut result = String::with_capacity(26);

        // Encode timestamp (10 chars)
        let mut t = time;
        for _ in 0..10 {
            result.insert(0, ALPHABET[(t & 0x1F) as usize] as char);
            t >>= 5;
        }

        // Encode random/counter (16 chars)
        let mut c = counter;
        for _ in 0..16 {
            result.push(ALPHABET[(c & 0x1F) as usize] as char);
            c >>= 5;
        }

        result
    }

    fn generate_counter(&self) -> String {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}", counter)
    }
}

/// Request ID Plugin
pub struct RequestIdPlugin {
    metadata: PluginMetadata,
    config: RequestIdPluginConfig,
    generator: Option<Arc<IdGenerator>>,
    running: bool,
}

impl RequestIdPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("request_id", "0.1.0", PluginType::Middleware)
            .with_description("Generates unique request IDs for tracing and correlation")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: RequestIdPluginConfig::default(),
            generator: None,
            running: false,
        }
    }

    pub fn get_early_hook(&self) -> Option<RequestIdEarlyHook> {
        self.generator.as_ref().map(|g| RequestIdEarlyHook {
            generator: g.clone(),
            header_name: self.config.header_name.clone(),
            trust_incoming: self.config.trust_incoming,
        })
    }

    pub fn get_response_hook(&self) -> Option<RequestIdResponseHook> {
        if self.config.add_to_response {
            Some(RequestIdResponseHook {
                header_name: self.config.header_name.clone(),
            })
        } else {
            None
        }
    }
}

impl Default for RequestIdPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for RequestIdPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = RequestIdPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.generator = Some(Arc::new(IdGenerator::new(&self.config)));
        self.running = true;

        info!(
            header = %self.config.header_name,
            format = %self.config.format,
            trust_incoming = self.config.trust_incoming,
            "Request ID plugin started"
        );

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.generator = None;
        info!("Request ID plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.generator.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Early request hook for adding request ID
pub struct RequestIdEarlyHook {
    generator: Arc<IdGenerator>,
    header_name: String,
    trust_incoming: bool,
}

#[async_trait]
impl EarlyRequestHook for RequestIdEarlyHook {
    fn priority(&self) -> HookPriority {
        HookPriority::FIRST // Run first to ensure ID is available to all other hooks
    }

    async fn on_early_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Check for existing request ID if trust_incoming is enabled
        let request_id = if self.trust_incoming {
            request
                .headers
                .get(&self.header_name)
                .or_else(|| request.headers.get(&self.header_name.to_lowercase()))
                .cloned()
        } else {
            None
        };

        // Generate new ID if none present
        let request_id = request_id.unwrap_or_else(|| self.generator.generate());

        // Store in context for other plugins and logging
        ctx.set("request_id", request_id.clone());
        ctx.set("x_request_id", request_id.clone());

        // Add to tracing span
        tracing::Span::current().record("request_id", &request_id);

        Ok(HookAction::Continue)
    }
}

/// Response hook for adding request ID to response
pub struct RequestIdResponseHook {
    header_name: String,
}

#[async_trait]
impl ResponseFilterHook for RequestIdResponseHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE // Run late to ensure other hooks have run
    }

    async fn on_response(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Get request ID from context
        if let Some(request_id) = ctx.get::<String>("request_id") {
            response
                .headers
                .insert(self.header_name.clone(), request_id.clone());
        }

        Ok(HookAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = RequestIdPlugin::new();
        assert_eq!(plugin.metadata().name, "request_id");
        assert_eq!(plugin.metadata().plugin_type, PluginType::Middleware);
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = RequestIdPlugin::new();
        let config = r#"{"header_name": "X-Correlation-ID", "format": "ulid", "prefix": "srv1"}"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.header_name, "X-Correlation-ID");
        assert_eq!(plugin.config.format, "ulid");
        assert_eq!(plugin.config.prefix, Some("srv1".to_string()));
    }

    #[test]
    fn test_uuid_generation() {
        let config = RequestIdPluginConfig::default();
        let generator = IdGenerator::new(&config);

        let id1 = generator.generate();
        let id2 = generator.generate();

        assert_ne!(id1, id2);
        assert!(id1.contains('-')); // UUID format
    }

    #[test]
    fn test_ulid_generation() {
        let config = RequestIdPluginConfig {
            format: "ulid".to_string(),
            ..Default::default()
        };
        let generator = IdGenerator::new(&config);

        let id1 = generator.generate();
        let id2 = generator.generate();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 26); // ULID length
    }

    #[test]
    fn test_counter_generation() {
        let config = RequestIdPluginConfig {
            format: "counter".to_string(),
            ..Default::default()
        };
        let generator = IdGenerator::new(&config);

        let id1 = generator.generate();
        let id2 = generator.generate();

        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16); // Hex counter length
    }

    #[test]
    fn test_prefix() {
        let config = RequestIdPluginConfig {
            prefix: Some("test".to_string()),
            ..Default::default()
        };
        let generator = IdGenerator::new(&config);

        let id = generator.generate();
        assert!(id.starts_with("test-"));
    }

    #[test]
    fn test_start_stop() {
        let mut plugin = RequestIdPlugin::new();
        plugin.init("").unwrap();
        plugin.start().unwrap();
        assert!(plugin.health_check());
        assert!(plugin.get_early_hook().is_some());
        assert!(plugin.get_response_hook().is_some());

        plugin.stop().unwrap();
        assert!(!plugin.health_check());
    }
}
