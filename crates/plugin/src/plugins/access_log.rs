//! Access Log Plugin
//!
//! This plugin implements LoggingHook to write access logs in various formats.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{LoggingHook, RequestInfo, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::Deserialize;
use std::any::Any;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Log format type
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Apache Common Log Format
    #[default]
    Common,
    /// Apache Combined Log Format
    Combined,
    /// JSON format
    Json,
}

/// Access log plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AccessLogConfig {
    /// Path to log file
    #[serde(default = "default_log_path")]
    pub path: PathBuf,
    /// Log format
    #[serde(default)]
    pub format: LogFormat,
    /// Buffer size (bytes) before flushing
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_log_path() -> PathBuf {
    PathBuf::from("./access.log")
}

fn default_buffer_size() -> usize {
    8192
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            path: default_log_path(),
            format: LogFormat::default(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Access log plugin state
struct LogWriter {
    writer: BufWriter<File>,
    format: LogFormat,
}

impl LogWriter {
    fn new(path: &PathBuf, format: LogFormat, buffer_size: usize) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let writer = BufWriter::with_capacity(buffer_size, file);
        Ok(Self { writer, format })
    }

    fn log(&mut self, request: &RequestInfo, response: Option<&ResponseInfo>, ctx: &PluginContext) {
        let line = match self.format {
            LogFormat::Common => self.format_common(request, response, ctx),
            LogFormat::Combined => self.format_combined(request, response, ctx),
            LogFormat::Json => self.format_json(request, response, ctx),
        };

        let _ = writeln!(self.writer, "{}", line);
        let _ = self.writer.flush();
    }

    fn format_common(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        ctx: &PluginContext,
    ) -> String {
        let status = response.map(|r| r.status).unwrap_or(0);
        let bytes = ctx.get::<u64>("bytes_sent").unwrap_or(0);
        let client_ip = ctx.get::<String>("client_ip")
            .unwrap_or_else(|| "-".to_string());
        let timestamp = chrono::Utc::now().format("%d/%b/%Y:%H:%M:%S %z");

        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {}",
            client_ip,
            timestamp,
            request.method,
            request.path,
            status,
            bytes
        )
    }

    fn format_combined(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        ctx: &PluginContext,
    ) -> String {
        let status = response.map(|r| r.status).unwrap_or(0);
        let bytes = ctx.get::<u64>("bytes_sent").unwrap_or(0);
        let client_ip = ctx.get::<String>("client_ip")
            .unwrap_or_else(|| "-".to_string());
        let user_agent = request.headers.get("user-agent")
            .map(|s| s.as_str())
            .unwrap_or("-");
        let referer = request.headers.get("referer")
            .map(|s| s.as_str())
            .unwrap_or("-");
        let timestamp = chrono::Utc::now().format("%d/%b/%Y:%H:%M:%S %z");

        format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
            client_ip,
            timestamp,
            request.method,
            request.path,
            status,
            bytes,
            referer,
            user_agent
        )
    }

    fn format_json(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        ctx: &PluginContext,
    ) -> String {
        let status = response.map(|r| r.status).unwrap_or(0);
        let bytes = ctx.get::<u64>("bytes_sent").unwrap_or(0);
        let client_ip = ctx.get::<String>("client_ip")
            .unwrap_or_default();
        let user_agent = request.headers.get("user-agent")
            .map(|s| s.as_str())
            .unwrap_or("");
        let referer = request.headers.get("referer")
            .map(|s| s.as_str())
            .unwrap_or("");
        let duration_ms = ctx.get::<u64>("duration_ms").unwrap_or(0);
        let host = request.host.as_deref().unwrap_or("");
        let timestamp = chrono::Utc::now().to_rfc3339();

        format!(
            r#"{{"timestamp":"{}","client_ip":"{}","method":"{}","path":"{}","host":"{}","status":{},"bytes_sent":{},"user_agent":"{}","referer":"{}","duration_ms":{}}}"#,
            timestamp,
            escape_json(&client_ip),
            escape_json(&request.method),
            escape_json(&request.path),
            escape_json(host),
            status,
            bytes,
            escape_json(user_agent),
            escape_json(referer),
            duration_ms
        )
    }
}

/// Escape special characters for JSON strings
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Access Log Plugin
pub struct AccessLogPlugin {
    metadata: PluginMetadata,
    config: AccessLogConfig,
    writer: Option<Arc<Mutex<LogWriter>>>,
    running: bool,
}

impl AccessLogPlugin {
    /// Create a new AccessLogPlugin with default configuration
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("access_log", "0.1.0", PluginType::Logger)
            .with_description("Access logging plugin supporting Common, Combined, and JSON formats")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: AccessLogConfig::default(),
            writer: None,
            running: false,
        }
    }

    /// Get the log writer for the LoggingHook implementation
    pub fn get_hook(&self) -> Option<AccessLogHook> {
        self.writer.as_ref().map(|w| AccessLogHook {
            writer: w.clone(),
        })
    }
}

impl Default for AccessLogPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for AccessLogPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = AccessLogConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        let log_writer = LogWriter::new(
            &self.config.path,
            self.config.format.clone(),
            self.config.buffer_size,
        ).map_err(|e| PluginError::InitError(format!("Failed to open log file: {}", e)))?;

        self.writer = Some(Arc::new(Mutex::new(log_writer)));
        self.running = true;

        info!(
            path = %self.config.path.display(),
            format = ?self.config.format,
            "Access log plugin started"
        );

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.writer = None;
        info!("Access log plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.writer.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Hook implementation for access logging
pub struct AccessLogHook {
    writer: Arc<Mutex<LogWriter>>,
}

#[async_trait]
impl LoggingHook for AccessLogHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE // Log after all processing is done
    }

    async fn on_request_complete(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        _error: Option<&str>,
        ctx: &PluginContext,
    ) {
        let mut writer = self.writer.lock();
        writer.log(request, response, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plugin_creation() {
        let plugin = AccessLogPlugin::new();
        assert_eq!(plugin.metadata().name, "access_log");
        assert_eq!(plugin.metadata().plugin_type, PluginType::Logger);
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = AccessLogPlugin::new();
        let config = r#"{"path": "/tmp/test.log", "format": "json"}"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.path, PathBuf::from("/tmp/test.log"));
        assert_eq!(plugin.config.format, LogFormat::Json);
    }

    #[test]
    fn test_start_stop() {
        let tmp = NamedTempFile::new().unwrap();
        let mut plugin = AccessLogPlugin::new();
        let config = format!(r#"{{"path": "{}"}}"#, tmp.path().display());
        plugin.init(&config).unwrap();
        plugin.start().unwrap();
        assert!(plugin.health_check());
        plugin.stop().unwrap();
        assert!(!plugin.health_check());
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
    }
}
