//! Compression Plugin
//!
//! Response compression with gzip and brotli support.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, ResponseFilterHook, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

#[cfg(feature = "compression")]
use flate2::write::GzEncoder;
#[cfg(feature = "compression")]
use flate2::Compression;
#[cfg(feature = "compression")]
use std::io::Write;

/// Compression encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    Gzip,
    Brotli,
    Identity,
}

impl CompressionEncoding {
    pub fn header_value(&self) -> &'static str {
        match self {
            CompressionEncoding::Gzip => "gzip",
            CompressionEncoding::Brotli => "br",
            CompressionEncoding::Identity => "identity",
        }
    }
}

/// Compression plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CompressionPluginConfig {
    #[serde(default = "default_true")]
    pub gzip: bool,
    #[serde(default = "default_true")]
    pub brotli: bool,
    #[serde(default = "default_min_size")]
    pub min_size: usize,
    #[serde(default = "default_level")]
    pub level: u32,
}

fn default_true() -> bool { true }
fn default_min_size() -> usize { 1024 }
fn default_level() -> u32 { 6 }

impl Default for CompressionPluginConfig {
    fn default() -> Self {
        Self {
            gzip: true,
            brotli: true,
            min_size: 1024,
            level: 6,
        }
    }
}

/// Compression state
struct CompressionState {
    config: CompressionPluginConfig,
}

impl CompressionState {
    fn new(config: CompressionPluginConfig) -> Self {
        Self { config }
    }

    fn select_encoding(&self, accept_encoding: Option<&str>) -> CompressionEncoding {
        let accept = match accept_encoding {
            Some(ae) => ae.to_lowercase(),
            None => return CompressionEncoding::Identity,
        };

        if self.config.brotli && accept.contains("br") {
            return CompressionEncoding::Brotli;
        }
        if self.config.gzip && (accept.contains("gzip") || accept.contains("*")) {
            return CompressionEncoding::Gzip;
        }
        CompressionEncoding::Identity
    }

    fn should_compress_content_type(content_type: Option<&str>) -> bool {
        let ct = match content_type {
            Some(ct) => ct.to_lowercase(),
            None => return false,
        };

        ct.starts_with("text/")
            || ct.contains("application/json")
            || ct.contains("application/xml")
            || ct.contains("application/javascript")
            || ct.contains("image/svg+xml")
    }

    fn is_already_compressed(content_encoding: Option<&str>) -> bool {
        match content_encoding {
            Some(ce) => {
                let ce = ce.to_lowercase();
                ce.contains("gzip") || ce.contains("br") || ce.contains("deflate")
            }
            None => false,
        }
    }

    #[cfg(feature = "compression")]
    fn compress(&self, data: &[u8], encoding: CompressionEncoding) -> std::io::Result<Bytes> {
        match encoding {
            CompressionEncoding::Gzip => self.compress_gzip(data),
            CompressionEncoding::Brotli => self.compress_brotli(data),
            CompressionEncoding::Identity => Ok(Bytes::copy_from_slice(data)),
        }
    }

    #[cfg(feature = "compression")]
    fn compress_gzip(&self, data: &[u8]) -> std::io::Result<Bytes> {
        let level = self.config.level.min(9) as u32;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(data)?;
        Ok(Bytes::from(encoder.finish()?))
    }

    #[cfg(feature = "compression")]
    fn compress_brotli(&self, data: &[u8]) -> std::io::Result<Bytes> {
        let level = self.config.level.min(11) as u32;
        let mut compressed = Vec::new();
        let mut params = brotli::enc::BrotliEncoderParams::default();
        params.quality = level as i32;
        let mut encoder = brotli::CompressorWriter::with_params(&mut compressed, 4096, &params);
        encoder.write_all(data)?;
        drop(encoder);
        Ok(Bytes::from(compressed))
    }

    #[cfg(not(feature = "compression"))]
    fn compress(&self, data: &[u8], _encoding: CompressionEncoding) -> std::io::Result<Bytes> {
        Ok(Bytes::copy_from_slice(data))
    }
}

/// Compression Plugin
pub struct CompressionPlugin {
    metadata: PluginMetadata,
    config: CompressionPluginConfig,
    state: Option<Arc<CompressionState>>,
    running: bool,
}

impl CompressionPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("compression", "0.1.0", PluginType::Middleware)
            .with_description("Response compression plugin (gzip, brotli)")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: CompressionPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_hook(&self) -> Option<CompressionHook> {
        self.state.as_ref().map(|s| CompressionHook { state: s.clone() })
    }
}

impl Default for CompressionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CompressionPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = CompressionPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(CompressionState::new(self.config.clone())));
        self.running = true;

        #[cfg(feature = "compression")]
        tracing::info!(
            gzip = self.config.gzip,
            brotli = self.config.brotli,
            min_size = self.config.min_size,
            level = self.config.level,
            "Compression plugin started"
        );

        #[cfg(not(feature = "compression"))]
        tracing::warn!("Compression plugin started but compression feature is disabled");

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("Compression plugin stopped");
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

/// Compression hook
pub struct CompressionHook {
    state: Arc<CompressionState>,
}

#[async_trait]
impl ResponseFilterHook for CompressionHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE
    }

    async fn on_response(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Check if already compressed
        let content_encoding = response.headers.get("content-encoding").map(|s| s.as_str());
        if CompressionState::is_already_compressed(content_encoding) {
            return Ok(HookAction::Continue);
        }

        // Check content type
        let content_type = response.headers.get("content-type").map(|s| s.as_str());
        if !CompressionState::should_compress_content_type(content_type) {
            return Ok(HookAction::Continue);
        }

        // Get accept-encoding from context
        let accept_encoding = ctx.get::<String>("accept_encoding");
        let encoding = self.state.select_encoding(accept_encoding.as_deref());

        if encoding == CompressionEncoding::Identity {
            return Ok(HookAction::Continue);
        }

        // Get response body
        let body = match ctx.get::<Bytes>("response_body") {
            Some(b) => b,
            None => return Ok(HookAction::Continue),
        };

        // Check min size
        if body.len() < self.state.config.min_size {
            return Ok(HookAction::Continue);
        }

        // Compress
        match self.state.compress(&body, encoding) {
            Ok(compressed) => {
                ctx.set("compressed_body", compressed);
                ctx.set("content_encoding", encoding.header_value().to_string());
                response.headers.insert("content-encoding".to_string(), encoding.header_value().to_string());
                tracing::debug!(
                    original_size = body.len(),
                    encoding = encoding.header_value(),
                    "Response compressed"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Compression failed");
            }
        }

        Ok(HookAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CompressionPlugin::new();
        assert_eq!(plugin.metadata().name, "compression");
    }

    #[test]
    fn test_select_encoding() {
        let state = CompressionState::new(CompressionPluginConfig::default());

        let encoding = state.select_encoding(Some("gzip, deflate, br"));
        assert_eq!(encoding, CompressionEncoding::Brotli);

        let encoding = state.select_encoding(Some("gzip"));
        assert_eq!(encoding, CompressionEncoding::Gzip);

        let encoding = state.select_encoding(None);
        assert_eq!(encoding, CompressionEncoding::Identity);
    }

    #[test]
    fn test_should_compress() {
        assert!(CompressionState::should_compress_content_type(Some("text/html")));
        assert!(CompressionState::should_compress_content_type(Some("application/json")));
        assert!(!CompressionState::should_compress_content_type(Some("image/png")));
    }

    #[test]
    fn test_is_already_compressed() {
        assert!(CompressionState::is_already_compressed(Some("gzip")));
        assert!(CompressionState::is_already_compressed(Some("br")));
        assert!(!CompressionState::is_already_compressed(None));
    }
}
