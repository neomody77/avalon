//! URL Rewrite Plugin
//!
//! Supports regex-based URL rewriting and redirects.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{EarlyRequestHook, HookAction, RequestInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;
use tracing::debug;

/// Rewrite rule configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RewriteRule {
    /// Regex pattern to match
    pub pattern: String,
    /// Replacement string (supports $1, $2, etc. for captures)
    pub replacement: String,
    /// Whether to redirect (301/302) or rewrite internally
    #[serde(default)]
    pub redirect: Option<u16>,
    /// Stop processing after this rule matches
    #[serde(default = "default_stop")]
    pub stop: bool,
}

fn default_stop() -> bool {
    true
}

/// Compiled rewrite rule
struct CompiledRule {
    regex: Regex,
    replacement: String,
    redirect: Option<u16>,
    stop: bool,
}

/// Rewrite plugin configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RewritePluginConfig {
    #[serde(default)]
    pub rules: Vec<RewriteRule>,
    /// Strip prefix from path
    #[serde(default)]
    pub strip_prefix: Option<String>,
    /// Add prefix to path
    #[serde(default)]
    pub add_prefix: Option<String>,
}

/// Rewrite state
struct RewriteState {
    rules: Vec<CompiledRule>,
    strip_prefix: Option<String>,
    add_prefix: Option<String>,
}

impl RewriteState {
    fn from_config(config: &RewritePluginConfig) -> Result<Self> {
        let mut rules = Vec::new();
        for rule in &config.rules {
            let regex = Regex::new(&rule.pattern)
                .map_err(|e| PluginError::ConfigError(format!("Invalid regex: {}", e)))?;
            rules.push(CompiledRule {
                regex,
                replacement: rule.replacement.clone(),
                redirect: rule.redirect,
                stop: rule.stop,
            });
        }
        Ok(Self {
            rules,
            strip_prefix: config.strip_prefix.clone(),
            add_prefix: config.add_prefix.clone(),
        })
    }

    fn rewrite(&self, path: &str) -> Option<RewriteResult> {
        let mut current_path = path.to_string();

        // Strip prefix if configured
        if let Some(prefix) = &self.strip_prefix {
            if current_path.starts_with(prefix) {
                current_path = current_path[prefix.len()..].to_string();
                if current_path.is_empty() {
                    current_path = "/".to_string();
                }
            }
        }

        // Add prefix if configured
        if let Some(prefix) = &self.add_prefix {
            current_path = format!("{}{}", prefix, current_path);
        }

        // Apply rewrite rules
        for rule in &self.rules {
            if let Some(captures) = rule.regex.captures(&current_path) {
                let mut result = rule.replacement.clone();

                // Replace capture groups
                for (i, cap) in captures.iter().enumerate() {
                    if let Some(m) = cap {
                        result = result.replace(&format!("${}", i), m.as_str());
                    }
                }

                if let Some(status) = rule.redirect {
                    return Some(RewriteResult::Redirect {
                        location: result,
                        status,
                    });
                } else {
                    current_path = result;
                }

                if rule.stop {
                    break;
                }
            }
        }

        if current_path != path {
            Some(RewriteResult::Rewrite { new_path: current_path })
        } else {
            None
        }
    }
}

/// Result of rewrite processing
enum RewriteResult {
    Rewrite { new_path: String },
    Redirect { location: String, status: u16 },
}

/// Rewrite Plugin
pub struct RewritePlugin {
    metadata: PluginMetadata,
    config: RewritePluginConfig,
    state: Option<Arc<RewriteState>>,
    running: bool,
}

impl RewritePlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("rewrite", "0.1.0", PluginType::Middleware)
            .with_description("URL rewrite plugin with regex support")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: false,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: RewritePluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_hook(&self) -> Option<RewriteHook> {
        self.state.as_ref().map(|s| RewriteHook {
            state: s.clone(),
        })
    }
}

impl Default for RewritePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for RewritePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = RewritePluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(RewriteState::from_config(&self.config)?));
        self.running = true;
        tracing::info!(
            rules_count = self.config.rules.len(),
            strip_prefix = ?self.config.strip_prefix,
            add_prefix = ?self.config.add_prefix,
            "Rewrite plugin started"
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("Rewrite plugin stopped");
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

/// Rewrite hook implementation
pub struct RewriteHook {
    state: Arc<RewriteState>,
}

#[async_trait]
impl EarlyRequestHook for RewriteHook {
    fn priority(&self) -> HookPriority {
        HookPriority::EARLY // Rewrite should happen early
    }

    async fn on_early_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        if let Some(result) = self.state.rewrite(&request.path) {
            match result {
                RewriteResult::Rewrite { new_path } => {
                    debug!(from = %request.path, to = %new_path, "URL rewritten");
                    ctx.set("rewritten_path", new_path);
                    Ok(HookAction::Continue)
                }
                RewriteResult::Redirect { location, status } => {
                    debug!(to = %location, status = status, "Redirecting");
                    ctx.set("redirect_location", location);
                    ctx.set("redirect_status", status);
                    Ok(HookAction::ShortCircuit)
                }
            }
        } else {
            Ok(HookAction::Continue)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = RewritePlugin::new();
        assert_eq!(plugin.metadata().name, "rewrite");
    }

    #[test]
    fn test_strip_prefix() {
        let config = RewritePluginConfig {
            strip_prefix: Some("/api/v1".to_string()),
            ..Default::default()
        };
        let state = RewriteState::from_config(&config).unwrap();

        let result = state.rewrite("/api/v1/users");
        assert!(matches!(result, Some(RewriteResult::Rewrite { new_path }) if new_path == "/users"));
    }

    #[test]
    fn test_add_prefix() {
        let config = RewritePluginConfig {
            add_prefix: Some("/backend".to_string()),
            ..Default::default()
        };
        let state = RewriteState::from_config(&config).unwrap();

        let result = state.rewrite("/users");
        assert!(matches!(result, Some(RewriteResult::Rewrite { new_path }) if new_path == "/backend/users"));
    }

    #[test]
    fn test_regex_rewrite() {
        let config = RewritePluginConfig {
            rules: vec![RewriteRule {
                pattern: r"^/old/(.*)$".to_string(),
                replacement: "/new/$1".to_string(),
                redirect: None,
                stop: true,
            }],
            ..Default::default()
        };
        let state = RewriteState::from_config(&config).unwrap();

        let result = state.rewrite("/old/path/to/file");
        assert!(matches!(result, Some(RewriteResult::Rewrite { new_path }) if new_path == "/new/path/to/file"));
    }

    #[test]
    fn test_redirect() {
        let config = RewritePluginConfig {
            rules: vec![RewriteRule {
                pattern: r"^/legacy$".to_string(),
                replacement: "/modern".to_string(),
                redirect: Some(301),
                stop: true,
            }],
            ..Default::default()
        };
        let state = RewriteState::from_config(&config).unwrap();

        let result = state.rewrite("/legacy");
        assert!(matches!(result, Some(RewriteResult::Redirect { location, status })
            if location == "/modern" && status == 301));
    }
}
