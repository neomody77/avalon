//! Authentication Plugin
//!
//! Supports Basic Auth, API Key, and JWT authentication.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, RequestFilterHook, RequestInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::any::Any;
use std::sync::Arc;
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

/// Basic auth credential
#[derive(Debug, Clone, Deserialize)]
pub struct BasicCredential {
    pub username: String,
    pub password: String,
}

/// API key configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyConfig {
    pub key: String,
    #[serde(default = "default_header_name")]
    pub header_name: String,
    #[serde(default)]
    pub query_param: Option<String>,
}

fn default_header_name() -> String {
    "X-API-Key".to_string()
}

/// JWT configuration
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_jwt_header")]
    pub header_name: String,
    #[serde(default)]
    pub cookie_name: Option<String>,
}

fn default_jwt_header() -> String {
    "Authorization".to_string()
}

/// Auth plugin configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthPluginConfig {
    #[serde(default)]
    pub basic: Vec<BasicCredential>,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    #[serde(default = "default_realm")]
    pub realm: String,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

fn default_realm() -> String {
    "Restricted".to_string()
}

/// Compiled auth state for efficient checking
struct AuthState {
    basic_credentials: Vec<(String, String)>,
    api_keys: Vec<ApiKeyConfig>,
    jwt_config: Option<JwtConfig>,
    realm: String,
    exclude_paths: Vec<String>,
}

impl AuthState {
    fn from_config(config: &AuthPluginConfig) -> Self {
        Self {
            basic_credentials: config.basic.iter()
                .map(|c| (c.username.clone(), c.password.clone()))
                .collect(),
            api_keys: config.api_keys.clone(),
            jwt_config: config.jwt.clone(),
            realm: config.realm.clone(),
            exclude_paths: config.exclude_paths.clone(),
        }
    }

    fn has_auth(&self) -> bool {
        !self.basic_credentials.is_empty()
            || !self.api_keys.is_empty()
            || self.jwt_config.is_some()
    }

    fn is_path_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| path.starts_with(p))
    }

    fn check_basic_auth(&self, auth_header: &str) -> Option<String> {
        if !auth_header.starts_with("Basic ") {
            return None;
        }

        let encoded = &auth_header[6..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let credentials = String::from_utf8(decoded).ok()?;
        let mut parts = credentials.splitn(2, ':');
        let username = parts.next()?;
        let password = parts.next()?;

        for (u, p) in &self.basic_credentials {
            if u == username && p == password {
                return Some(username.to_string());
            }
        }
        None
    }

    fn check_api_key(&self, headers: &std::collections::HashMap<String, String>, query: Option<&str>) -> Option<String> {
        for api_key_config in &self.api_keys {
            // Check header
            if let Some(header_value) = headers.get(&api_key_config.header_name.to_lowercase()) {
                if header_value == &api_key_config.key {
                    return Some(format!("api_key:{}", &api_key_config.key[..8.min(api_key_config.key.len())]));
                }
            }

            // Check query parameter
            if let Some(param_name) = &api_key_config.query_param {
                if let Some(query_str) = query {
                    for pair in query_str.split('&') {
                        let mut kv = pair.splitn(2, '=');
                        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                            if k == param_name && v == api_key_config.key {
                                return Some(format!("api_key:{}", &api_key_config.key[..8.min(api_key_config.key.len())]));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn check_jwt(&self, auth_header: Option<&str>) -> Option<String> {
        let jwt_config = self.jwt_config.as_ref()?;

        let token = if let Some(header) = auth_header {
            if header.starts_with("Bearer ") {
                &header[7..]
            } else {
                return None;
            }
        } else {
            return None;
        };

        // Simple JWT validation (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Verify signature
        let message = format!("{}.{}", parts[0], parts[1]);
        let mut mac = HmacSha256::new_from_slice(jwt_config.secret.as_bytes()).ok()?;
        mac.update(message.as_bytes());

        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .ok()?;

        if mac.verify_slice(&signature).is_ok() {
            // Decode payload to get subject
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .ok()?;
            let payload_str = String::from_utf8(payload).ok()?;

            // Simple JSON parsing for "sub" claim
            if let Some(start) = payload_str.find("\"sub\"") {
                let rest = &payload_str[start + 5..];
                if let Some(colon) = rest.find(':') {
                    let value_part = rest[colon + 1..].trim();
                    if value_part.starts_with('"') {
                        if let Some(end) = value_part[1..].find('"') {
                            return Some(value_part[1..end + 1].to_string());
                        }
                    }
                }
            }
            Some("jwt_user".to_string())
        } else {
            None
        }
    }
}

/// Authentication Plugin
pub struct AuthPlugin {
    metadata: PluginMetadata,
    config: AuthPluginConfig,
    state: Option<Arc<AuthState>>,
    running: bool,
}

impl AuthPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("auth", "0.1.0", PluginType::Middleware)
            .with_description("Authentication plugin supporting Basic, API Key, and JWT")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: true,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: AuthPluginConfig::default(),
            state: None,
            running: false,
        }
    }

    pub fn get_hook(&self) -> Option<AuthHook> {
        self.state.as_ref().map(|s| AuthHook {
            state: s.clone(),
        })
    }
}

impl Default for AuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for AuthPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = AuthPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.state = Some(Arc::new(AuthState::from_config(&self.config)));
        self.running = true;
        tracing::info!(
            basic_count = self.config.basic.len(),
            api_key_count = self.config.api_keys.len(),
            has_jwt = self.config.jwt.is_some(),
            "Auth plugin started"
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.state = None;
        tracing::info!("Auth plugin stopped");
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

/// Auth hook implementation
pub struct AuthHook {
    state: Arc<AuthState>,
}

#[async_trait]
impl RequestFilterHook for AuthHook {
    fn priority(&self) -> HookPriority {
        HookPriority::EARLY // Auth should run early
    }

    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        // Skip if no auth configured
        if !self.state.has_auth() {
            return Ok(HookAction::Continue);
        }

        // Check excluded paths
        if self.state.is_path_excluded(&request.path) {
            debug!(path = %request.path, "Path excluded from auth");
            return Ok(HookAction::Continue);
        }

        let auth_header = request.headers.get("authorization").map(|s| s.as_str());

        // Try Basic auth
        if let Some(header) = auth_header {
            if let Some(identity) = self.state.check_basic_auth(header) {
                ctx.set("auth_identity", identity);
                ctx.set("auth_method", "basic".to_string());
                return Ok(HookAction::Continue);
            }
        }

        // Try API key
        if let Some(identity) = self.state.check_api_key(&request.headers, request.query.as_deref()) {
            ctx.set("auth_identity", identity);
            ctx.set("auth_method", "api_key".to_string());
            return Ok(HookAction::Continue);
        }

        // Try JWT
        if let Some(identity) = self.state.check_jwt(auth_header) {
            ctx.set("auth_identity", identity);
            ctx.set("auth_method", "jwt".to_string());
            return Ok(HookAction::Continue);
        }

        // Auth failed
        warn!(path = %request.path, "Authentication failed");
        ctx.set("auth_failed", true);
        ctx.set("auth_realm", self.state.realm.clone());
        ctx.set("auth_status_code", 401u16);
        Ok(HookAction::ShortCircuit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = AuthPlugin::new();
        assert_eq!(plugin.metadata().name, "auth");
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = AuthPlugin::new();
        let config = r#"{
            "basic": [{"username": "admin", "password": "secret"}],
            "api_keys": [{"key": "test-key-123", "header_name": "X-API-Key"}],
            "realm": "TestRealm"
        }"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.basic.len(), 1);
        assert_eq!(plugin.config.api_keys.len(), 1);
        assert_eq!(plugin.config.realm, "TestRealm");
    }

    #[test]
    fn test_basic_auth() {
        let config = AuthPluginConfig {
            basic: vec![BasicCredential {
                username: "admin".to_string(),
                password: "secret".to_string(),
            }],
            ..Default::default()
        };
        let state = AuthState::from_config(&config);

        // Valid credentials
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        assert!(state.check_basic_auth(&format!("Basic {}", encoded)).is_some());

        // Invalid credentials
        let bad = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        assert!(state.check_basic_auth(&format!("Basic {}", bad)).is_none());
    }

    #[test]
    fn test_api_key() {
        let config = AuthPluginConfig {
            api_keys: vec![ApiKeyConfig {
                key: "secret-key-12345".to_string(),
                header_name: "X-API-Key".to_string(),
                query_param: Some("api_key".to_string()),
            }],
            ..Default::default()
        };
        let state = AuthState::from_config(&config);

        // Valid header
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-api-key".to_string(), "secret-key-12345".to_string());
        assert!(state.check_api_key(&headers, None).is_some());

        // Valid query param
        let headers = std::collections::HashMap::new();
        assert!(state.check_api_key(&headers, Some("api_key=secret-key-12345")).is_some());

        // Invalid key
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-api-key".to_string(), "wrong-key".to_string());
        assert!(state.check_api_key(&headers, None).is_none());
    }

    #[test]
    fn test_excluded_paths() {
        let config = AuthPluginConfig {
            exclude_paths: vec!["/health".to_string(), "/public/".to_string()],
            ..Default::default()
        };
        let state = AuthState::from_config(&config);

        assert!(state.is_path_excluded("/health"));
        assert!(state.is_path_excluded("/health/check"));
        assert!(state.is_path_excluded("/public/file.txt"));
        assert!(!state.is_path_excluded("/api/data"));
    }
}
