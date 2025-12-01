//! Configuration structures and parsing for avalon

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Configuration error
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global settings
    #[serde(default)]
    pub global: GlobalConfig,

    /// TLS settings
    #[serde(default)]
    pub tls: TlsConfig,

    /// Plugin configuration
    #[serde(default)]
    pub plugins: PluginsConfig,

    /// Server configurations
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

impl Config {
    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check that servers have listen addresses
        for server in &self.servers {
            if server.listen.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Server '{}' has no listen addresses",
                    server.name
                )));
            }

            // Check that reverse_proxy routes have upstreams
            for route in &server.routes {
                if let HandlerConfig::ReverseProxy(proxy_config) = &route.handle {
                    if proxy_config.upstreams.is_empty() {
                        return Err(ConfigError::Validation(
                            "Reverse proxy handler has no upstreams".to_string(),
                        ));
                    }
                }
            }
        }

        // Check ACME email if enabled
        if self.tls.acme_enabled && self.tls.email.is_empty() {
            return Err(ConfigError::Validation(
                "ACME is enabled but no email is configured".to_string(),
            ));
        }

        Ok(())
    }

    /// Get all domains that need TLS certificates
    pub fn get_tls_domains(&self) -> Vec<String> {
        let mut domains = Vec::new();

        for server in &self.servers {
            // Check if server has HTTPS listeners
            let has_https = server.listen.iter().any(|addr| {
                addr.contains(":443") || addr.starts_with("https://")
            });

            if !has_https {
                continue;
            }

            // Collect domains from routes
            for route in &server.routes {
                if let Some(hosts) = &route.match_rule.host {
                    for host in hosts {
                        // Skip wildcards and localhost
                        if !host.starts_with('*') && host != "localhost" {
                            domains.push(host.clone());
                        }
                    }
                }
            }
        }

        domains.sort();
        domains.dedup();
        domains
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            tls: TlsConfig::default(),
            plugins: PluginsConfig::default(),
            servers: Vec::new(),
        }
    }
}

/// Plugin system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Enable the plugin system
    #[serde(default)]
    pub enabled: bool,

    /// Directory to search for dynamic plugins
    #[serde(default = "default_plugin_dir")]
    pub plugin_dir: PathBuf,

    /// List of plugins to load
    #[serde(default)]
    pub plugins: Vec<PluginEntry>,

    /// WASM plugin configuration
    #[serde(default)]
    pub wasm: WasmPluginConfig,
}

fn default_plugin_dir() -> PathBuf {
    PathBuf::from("./plugins")
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugin_dir: default_plugin_dir(),
            plugins: Vec::new(),
            wasm: WasmPluginConfig::default(),
        }
    }
}

/// Individual plugin entry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    /// Plugin name (unique identifier)
    pub name: String,

    /// Plugin type: "static", "dynamic", or "wasm"
    #[serde(default = "default_plugin_type")]
    pub plugin_type: PluginType,

    /// Path to the plugin file (for dynamic/wasm plugins)
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// Whether the plugin is enabled
    #[serde(default = "default_plugin_enabled")]
    pub enabled: bool,

    /// Plugin-specific configuration (passed to plugin init)
    #[serde(default)]
    pub config: HashMap<String, toml::Value>,
}

fn default_plugin_type() -> PluginType {
    PluginType::Static
}

fn default_plugin_enabled() -> bool {
    true
}

/// Plugin type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Statically compiled plugin (built into binary)
    Static,
    /// Dynamically loaded native plugin (.so/.dylib/.dll)
    Dynamic,
    /// WebAssembly plugin (.wasm)
    Wasm,
}

impl Default for PluginType {
    fn default() -> Self {
        PluginType::Static
    }
}

/// WASM plugin runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPluginConfig {
    /// Enable WASM plugin support
    #[serde(default)]
    pub enabled: bool,

    /// Memory limit per WASM instance in bytes (default: 16MB)
    #[serde(default = "default_wasm_memory_limit")]
    pub memory_limit: usize,

    /// Fuel limit for WASM execution (prevents infinite loops, 0 = unlimited)
    #[serde(default = "default_wasm_fuel_limit")]
    pub fuel_limit: u64,

    /// Allow WASM plugins to access network
    #[serde(default)]
    pub allow_network: bool,

    /// Allow WASM plugins to read filesystem
    #[serde(default)]
    pub allow_fs_read: bool,

    /// Allowed filesystem paths for WASM plugins
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,
}

fn default_wasm_memory_limit() -> usize {
    16 * 1024 * 1024 // 16MB
}

fn default_wasm_fuel_limit() -> u64 {
    1_000_000_000 // 1 billion instructions
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            memory_limit: default_wasm_memory_limit(),
            fuel_limit: default_wasm_fuel_limit(),
            allow_network: false,
            allow_fs_read: false,
            allowed_paths: Vec::new(),
        }
    }
}

/// Global configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Admin API listen address
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Access log file path (optional)
    #[serde(default)]
    pub access_log: Option<String>,

    /// Access log format: "common", "json", or "combined"
    #[serde(default = "default_log_format")]
    pub access_log_format: String,

    /// Compression configuration
    #[serde(default)]
    pub compression: CompressionOptions,

    /// Response caching configuration
    #[serde(default)]
    pub cache: CacheOptions,

    /// Grace period for graceful shutdown in seconds (default: 30)
    #[serde(default = "default_grace_period")]
    pub grace_period: u64,

    /// OpenTelemetry tracing configuration
    #[serde(default)]
    pub tracing: TracingConfig,
}

/// OpenTelemetry tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable OpenTelemetry tracing
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint (e.g., "http://localhost:4317")
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Sampling ratio (0.0 to 1.0, default: 1.0 = sample everything)
    #[serde(default = "default_sampling_ratio")]
    pub sampling_ratio: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: default_otlp_endpoint(),
            service_name: default_service_name(),
            sampling_ratio: default_sampling_ratio(),
        }
    }
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_service_name() -> String {
    "avalon".to_string()
}

fn default_sampling_ratio() -> f64 {
    1.0
}

/// Compression configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionOptions {
    /// Enable compression (default: true)
    #[serde(default = "default_compression_enabled")]
    pub enabled: bool,

    /// Enable gzip compression (default: true)
    #[serde(default = "default_compression_enabled")]
    pub gzip: bool,

    /// Enable brotli compression (default: true)
    #[serde(default = "default_compression_enabled")]
    pub brotli: bool,

    /// Minimum response size to compress in bytes (default: 1024)
    #[serde(default = "default_compression_min_size")]
    pub min_size: usize,

    /// Compression level: 1-9 for gzip, 0-11 for brotli (default: 6)
    #[serde(default = "default_compression_level")]
    pub level: u32,
}

/// Response caching configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheOptions {
    /// Enable response caching (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Default TTL for cached responses in seconds (default: 300)
    #[serde(default = "default_cache_ttl")]
    pub default_ttl: u64,

    /// Maximum cache entry size in bytes (default: 10MB)
    #[serde(default = "default_cache_max_entry_size")]
    pub max_entry_size: usize,

    /// Maximum total cache size in bytes (default: 100MB)
    #[serde(default = "default_cache_max_size")]
    pub max_cache_size: usize,

    /// Cacheable status codes (default: [200, 301, 302, 304, 307, 308])
    #[serde(default = "default_cacheable_status")]
    pub cacheable_status: Vec<u16>,

    /// Cacheable HTTP methods (default: ["GET", "HEAD"])
    #[serde(default = "default_cacheable_methods")]
    pub cacheable_methods: Vec<String>,
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_cache_max_entry_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_cache_max_size() -> usize {
    100 * 1024 * 1024 // 100MB
}

fn default_cacheable_status() -> Vec<u16> {
    vec![200, 301, 302, 304, 307, 308]
}

fn default_cacheable_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            default_ttl: default_cache_ttl(),
            max_entry_size: default_cache_max_entry_size(),
            max_cache_size: default_cache_max_size(),
            cacheable_status: default_cacheable_status(),
            cacheable_methods: default_cacheable_methods(),
        }
    }
}

fn default_compression_enabled() -> bool {
    true
}

fn default_compression_min_size() -> usize {
    1024
}

fn default_compression_level() -> u32 {
    6
}

impl Default for CompressionOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            gzip: true,
            brotli: true,
            min_size: 1024,
            level: 6,
        }
    }
}

fn default_log_format() -> String {
    "common".to_string()
}

fn default_admin_listen() -> String {
    "localhost:2019".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_grace_period() -> u64 {
    30
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            admin_listen: default_admin_listen(),
            log_level: default_log_level(),
            access_log: None,
            access_log_format: default_log_format(),
            compression: CompressionOptions::default(),
            cache: CacheOptions::default(),
            grace_period: default_grace_period(),
            tracing: TracingConfig::default(),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// ACME account email
    #[serde(default)]
    pub email: String,

    /// ACME CA directory URL
    #[serde(default = "default_acme_ca")]
    pub acme_ca: String,

    /// Certificate storage path
    #[serde(default = "default_storage_path")]
    pub storage_path: PathBuf,

    /// Enable ACME
    #[serde(default = "default_acme_enabled")]
    pub acme_enabled: bool,

    /// Explicit certificate file path (takes priority over auto-discovery and ACME)
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Explicit private key file path (takes priority over auto-discovery and ACME)
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_acme_ca() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("./certs")
}

fn default_acme_enabled() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            email: String::new(),
            acme_ca: default_acme_ca(),
            storage_path: default_storage_path(),
            acme_enabled: default_acme_enabled(),
            cert_path: None,
            key_path: None,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name (for logging)
    #[serde(default = "default_server_name")]
    pub name: String,

    /// Listen addresses
    pub listen: Vec<String>,

    /// Routes
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Enable automatic HTTPS redirect
    #[serde(default)]
    pub https_redirect: bool,
}

fn default_server_name() -> String {
    "default".to_string()
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Match conditions
    #[serde(rename = "match", default)]
    pub match_rule: MatchConfig,

    /// Handler configuration
    pub handle: HandlerConfig,
}

/// Match conditions for a route
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchConfig {
    /// Match by host
    pub host: Option<Vec<String>>,

    /// Match by path prefix
    pub path: Option<Vec<String>>,

    /// Match by HTTP method
    pub method: Option<Vec<String>>,

    /// Match by header
    pub header: Option<HashMap<String, String>>,
}

impl MatchConfig {
    /// Check if this matcher matches the given request
    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        // Check host
        if let Some(hosts) = &self.host {
            if let Some(req_host) = host {
                if !hosts.iter().any(|h| h == req_host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check path
        if let Some(paths) = &self.path {
            if !paths.iter().any(|p| path.starts_with(p)) {
                return false;
            }
        }

        // Check method
        if let Some(methods) = &self.method {
            if !methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                return false;
            }
        }

        true
    }
}

/// Handler configuration (tagged enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandlerConfig {
    /// Reverse proxy handler
    ReverseProxy(ReverseProxyConfig),

    /// Static file server
    FileServer(FileServerConfig),

    /// Static response
    StaticResponse(StaticResponseConfig),

    /// Redirect
    Redirect(RedirectConfig),

    /// Script handler (Rhai)
    Script(ScriptConfig),
}

/// Reverse proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseProxyConfig {
    /// Upstream server addresses
    pub upstreams: Vec<String>,

    /// Load balancing strategy
    #[serde(default)]
    pub load_balancing: LoadBalancingStrategy,

    /// Health check configuration
    pub health_check: Option<HealthCheckConfig>,

    /// Headers to add to upstream requests
    #[serde(default)]
    pub headers_up: HashMap<String, String>,

    /// Headers to add to downstream responses
    #[serde(default)]
    pub headers_down: HashMap<String, String>,

    /// Connection timeout (in seconds) - deprecated, use timeouts.connect instead
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Detailed timeout configuration
    #[serde(default)]
    pub timeouts: TimeoutConfig,

    /// Use TLS for upstream connections
    #[serde(default)]
    pub upstream_tls: bool,

    /// Session affinity (sticky sessions) configuration
    pub session_affinity: Option<SessionAffinityConfig>,

    /// Request rewrite configuration
    #[serde(default)]
    pub rewrite: Option<RewriteConfig>,

    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Total duration to try upstream connections before giving up (in milliseconds)
    /// Set to 0 to disable retry (default). Only retries on connection failure,
    /// never after response headers have been received (Caddy-style behavior).
    #[serde(default)]
    pub lb_try_duration: u64,

    /// Interval between retry attempts (in milliseconds, default: 250)
    #[serde(default = "default_lb_try_interval")]
    pub lb_try_interval: u64,

    /// CORS configuration
    #[serde(default)]
    pub cors: Option<CorsConfig>,

    /// Maximum request body size in bytes (0 = unlimited)
    #[serde(default)]
    pub max_request_body_size: u64,

    /// Enable HTTP/2 for upstream connections (requires upstream_tls)
    #[serde(default)]
    pub upstream_http2: bool,

    /// mTLS configuration for upstream connections
    #[serde(default)]
    pub upstream_mtls: Option<UpstreamMtlsConfig>,

    /// Circuit breaker configuration (optional)
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfigDef>,

    /// IP filter configuration (optional whitelist/blacklist)
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfigDef>,
}

/// Circuit breaker configuration for upstream protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfigDef {
    /// Number of consecutive failures to trip the circuit (default: 5)
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,

    /// Number of consecutive successes in half-open state to close circuit (default: 2)
    #[serde(default = "default_cb_success_threshold")]
    pub success_threshold: u32,

    /// How long to wait before transitioning from Open to HalfOpen (seconds, default: 30)
    #[serde(default = "default_cb_timeout")]
    pub timeout: u64,

    /// Sliding window size for failure counting (seconds, 0 = count all, default: 60)
    #[serde(default = "default_cb_window_size")]
    pub window_size: u64,
}

fn default_cb_failure_threshold() -> u32 {
    5
}

fn default_cb_success_threshold() -> u32 {
    2
}

fn default_cb_timeout() -> u64 {
    30
}

fn default_cb_window_size() -> u64 {
    60
}

impl Default for CircuitBreakerConfigDef {
    fn default() -> Self {
        Self {
            failure_threshold: default_cb_failure_threshold(),
            success_threshold: default_cb_success_threshold(),
            timeout: default_cb_timeout(),
            window_size: default_cb_window_size(),
        }
    }
}

/// IP filter configuration for whitelist/blacklist
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterConfigDef {
    /// IPs to allow (whitelist mode) - supports CIDR notation
    /// Example: ["192.168.1.0/24", "10.0.0.1"]
    #[serde(default)]
    pub allow: Vec<String>,

    /// IPs to deny (blacklist mode) - supports CIDR notation
    /// Example: ["192.168.1.100", "10.0.0.0/8"]
    #[serde(default)]
    pub deny: Vec<String>,
}

/// mTLS configuration for upstream connections (mutual TLS / client certificate auth)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamMtlsConfig {
    /// Path to client certificate file (PEM format)
    pub client_cert: String,

    /// Path to client private key file (PEM format)
    pub client_key: String,

    /// Path to CA certificate for verifying upstream server (optional)
    /// If not provided, system root CAs will be used
    #[serde(default)]
    pub ca_cert: Option<String>,

    /// Skip verification of upstream server certificate (default: false)
    /// WARNING: Setting this to true is insecure and should only be used for testing
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Timeout configuration for upstream connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Connection timeout in seconds (time to establish TCP connection)
    #[serde(default = "default_connect_timeout")]
    pub connect: u64,

    /// Read timeout in seconds (time to wait for upstream response)
    #[serde(default = "default_read_timeout")]
    pub read: u64,

    /// Write timeout in seconds (time to send request to upstream)
    #[serde(default = "default_write_timeout")]
    pub write: u64,

    /// Idle timeout in seconds (time to keep connection alive when idle)
    #[serde(default = "default_idle_timeout")]
    pub idle: u64,

    /// Enable TCP keepalive for upstream connections (default: true)
    #[serde(default = "default_keepalive_enabled")]
    pub keepalive: bool,

    /// TCP keepalive interval in seconds (default: 60)
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,

    /// TCP keepalive probe count (default: 3)
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_read_timeout() -> u64 {
    30
}

fn default_write_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    60
}

fn default_keepalive_enabled() -> bool {
    true
}

fn default_keepalive_interval() -> u64 {
    60
}

fn default_keepalive_count() -> u32 {
    3
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect: default_connect_timeout(),
            read: default_read_timeout(),
            write: default_write_timeout(),
            idle: default_idle_timeout(),
            keepalive: default_keepalive_enabled(),
            keepalive_interval: default_keepalive_interval(),
            keepalive_count: default_keepalive_count(),
        }
    }
}

/// CORS (Cross-Origin Resource Sharing) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins. Use "*" for wildcard or specify exact origins.
    /// Example: ["https://example.com", "https://app.example.com"]
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods. Default: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed request headers. Default: ["Content-Type", "Authorization", "X-Requested-With"]
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,

    /// Headers to expose to the client. Default: []
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Whether to allow credentials (cookies, authorization headers).
    /// Cannot be used with allowed_origins = ["*"]
    #[serde(default)]
    pub allow_credentials: bool,

    /// Max age for preflight cache in seconds. Default: 86400 (24 hours)
    #[serde(default = "default_cors_max_age")]
    pub max_age: u64,
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "OPTIONS".to_string(),
        "PATCH".to_string(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".to_string(),
        "Authorization".to_string(),
        "X-Requested-With".to_string(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400 // 24 hours
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: default_cors_methods(),
            allowed_headers: default_cors_headers(),
            expose_headers: Vec::new(),
            allow_credentials: false,
            max_age: default_cors_max_age(),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Basic authentication credentials
    #[serde(default)]
    pub basic: Vec<BasicAuthCredential>,

    /// API key authentication
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,

    /// JWT authentication configuration
    #[serde(default)]
    pub jwt: Option<JwtAuthConfig>,

    /// Custom realm for authentication challenges
    #[serde(default = "default_auth_realm")]
    pub realm: String,

    /// Paths to exclude from authentication (e.g., health checks)
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

fn default_auth_realm() -> String {
    "Restricted".to_string()
}

/// Basic authentication credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    /// Username
    pub username: String,

    /// Password (plain text or bcrypt hash with "$2" prefix)
    pub password: String,
}

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// The API key value
    pub key: String,

    /// Optional name/identifier for this key
    #[serde(default)]
    pub name: Option<String>,

    /// Where to look for the key: "header" or "query"
    #[serde(default = "default_api_key_source")]
    pub source: String,

    /// Header name or query parameter name (default: "X-API-Key" for header, "api_key" for query)
    #[serde(default)]
    pub param_name: Option<String>,
}

fn default_api_key_source() -> String {
    "header".to_string()
}

/// JWT authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthConfig {
    /// Secret key for HMAC algorithms (HS256, HS384, HS512)
    #[serde(default)]
    pub secret: Option<String>,

    /// Algorithm to use (default: HS256)
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,

    /// Header name to look for JWT (default: "Authorization")
    #[serde(default = "default_jwt_header")]
    pub header: String,

    /// Expected issuer (optional)
    #[serde(default)]
    pub issuer: Option<String>,

    /// Expected audience (optional)
    #[serde(default)]
    pub audience: Option<String>,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_jwt_header() -> String {
    "Authorization".to_string()
}

/// Request/response rewrite configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RewriteConfig {
    /// Strip path prefix (e.g., "/api" -> request to upstream without /api prefix)
    #[serde(default)]
    pub strip_path_prefix: Option<String>,

    /// Add path prefix (e.g., add "/v1" prefix to upstream request)
    #[serde(default)]
    pub add_path_prefix: Option<String>,

    /// Replace path using regex (pattern, replacement)
    #[serde(default)]
    pub path_regex: Option<PathRegex>,

    /// Replace entire URI path
    #[serde(default)]
    pub replace_path: Option<String>,

    /// Headers to add to the request (won't override existing)
    #[serde(default)]
    pub request_headers_add: HashMap<String, String>,

    /// Headers to set on the request (will override existing)
    #[serde(default)]
    pub request_headers_set: HashMap<String, String>,

    /// Headers to remove from the request
    #[serde(default)]
    pub request_headers_delete: Vec<String>,

    /// Headers to add to the response (won't override existing)
    #[serde(default)]
    pub response_headers_add: HashMap<String, String>,

    /// Headers to set on the response (will override existing)
    #[serde(default)]
    pub response_headers_set: HashMap<String, String>,

    /// Headers to remove from the response
    #[serde(default)]
    pub response_headers_delete: Vec<String>,

    /// Rhai scripting rewrite rules (advanced)
    #[serde(default)]
    pub rhai_rules: Vec<RhaiRewriteRuleConfig>,
}

/// Rhai-based rewrite rule configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RhaiRewriteRuleConfig {
    /// Condition expression (Rhai) - rule only applies when this evaluates to true
    #[serde(default)]
    pub when: Option<String>,

    /// Path expression (Rhai) - new path value
    #[serde(default)]
    pub path: Option<String>,

    /// Query expression (Rhai) - new query string
    #[serde(default)]
    pub query: Option<String>,

    /// Headers to set (value is Rhai expression)
    #[serde(default)]
    pub headers_set: HashMap<String, String>,

    /// Headers to add (value is Rhai expression)
    #[serde(default)]
    pub headers_add: HashMap<String, String>,

    /// Headers to delete
    #[serde(default)]
    pub headers_delete: Vec<String>,

    /// Action type: "continue", "redirect", "reject"
    #[serde(default)]
    pub action: Option<String>,

    /// Redirect location (Rhai expression)
    #[serde(default)]
    pub redirect_location: Option<String>,

    /// Redirect status code (default: 302)
    #[serde(default)]
    pub redirect_status: Option<u16>,

    /// Reject status code (default: 403)
    #[serde(default)]
    pub reject_status: Option<u16>,

    /// Reject body
    #[serde(default)]
    pub reject_body: Option<String>,

    /// Stop processing further rules after this one matches (default: true)
    #[serde(default)]
    pub stop: Option<bool>,

    /// Full Rhai script for imperative rewrite logic
    /// When set, this script is executed and can directly modify the request object
    #[serde(default)]
    pub script: Option<String>,
}

/// Path regex replacement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRegex {
    /// Regex pattern to match
    pub pattern: String,

    /// Replacement string (can use $1, $2, etc. for capture groups)
    pub replacement: String,
}

/// Session affinity configuration for sticky sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAffinityConfig {
    /// Affinity type: "cookie" or "ip_hash"
    #[serde(default = "default_affinity_type")]
    pub affinity_type: String,

    /// Cookie name for cookie-based affinity
    #[serde(default = "default_affinity_cookie")]
    pub cookie_name: String,

    /// Cookie max age in seconds (0 = session cookie)
    #[serde(default)]
    pub cookie_max_age: u64,
}

fn default_affinity_type() -> String {
    "cookie".to_string()
}

fn default_affinity_cookie() -> String {
    "srv_id".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_lb_try_interval() -> u64 {
    250 // 250ms default
}

/// Load balancing strategy
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    #[default]
    RoundRobin,
    Random,
    LeastConn,
    IpHash,
    First,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check path
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Check interval (e.g., "10s", "1m")
    #[serde(default = "default_health_interval")]
    pub interval: String,

    /// Timeout per check
    #[serde(default = "default_health_timeout")]
    pub timeout: String,

    /// Expected HTTP status code
    #[serde(default = "default_health_status")]
    pub expected_status: u16,
}

fn default_health_path() -> String {
    "/".to_string()
}

fn default_health_interval() -> String {
    "30s".to_string()
}

fn default_health_timeout() -> String {
    "5s".to_string()
}

fn default_health_status() -> u16 {
    200
}

/// File server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileServerConfig {
    /// Root directory to serve files from
    pub root: PathBuf,

    /// Enable directory browsing
    #[serde(default)]
    pub browse: bool,

    /// Index files to look for
    #[serde(default = "default_index_files")]
    pub index: Vec<String>,

    /// Enable compression
    #[serde(default = "default_compression")]
    pub compress: bool,
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}

fn default_compression() -> bool {
    true
}

/// Static response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticResponseConfig {
    /// HTTP status code
    #[serde(default = "default_static_status")]
    pub status: u16,

    /// Response body
    #[serde(default)]
    pub body: String,

    /// Response headers
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_static_status() -> u16 {
    200
}

/// Redirect configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectConfig {
    /// Redirect target URL
    pub to: String,

    /// HTTP status code (301, 302, 307, 308)
    #[serde(default = "default_redirect_code")]
    pub code: u16,
}

fn default_redirect_code() -> u16 {
    302
}

/// Script handler configuration (Rhai)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptConfig {
    /// Rhai script code
    pub script: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.servers.is_empty());
        assert_eq!(config.global.log_level, "info");
    }

    #[test]
    fn test_parse_config() {
        let toml = r#"
[global]
log_level = "debug"

[tls]
email = "test@example.com"
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.match]
host = ["example.com"]
path = ["/api"]

[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:9090"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, "test");
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn test_match_config() {
        let matcher = MatchConfig {
            host: Some(vec!["example.com".to_string()]),
            path: Some(vec!["/api".to_string()]),
            method: None,
            header: None,
        };

        assert!(matcher.matches(Some("example.com"), "/api/users", "GET"));
        assert!(!matcher.matches(Some("other.com"), "/api/users", "GET"));
        assert!(!matcher.matches(Some("example.com"), "/web", "GET"));
    }

    #[test]
    fn test_match_config_empty() {
        let matcher = MatchConfig::default();
        assert!(matcher.matches(Some("any.com"), "/any/path", "GET"));
        assert!(matcher.matches(None, "/", "POST"));
    }

    #[test]
    fn test_match_host() {
        let matcher = MatchConfig {
            host: Some(vec!["a.com".to_string(), "b.com".to_string()]),
            path: None,
            method: None,
            header: None,
        };

        assert!(matcher.matches(Some("a.com"), "/", "GET"));
        assert!(matcher.matches(Some("b.com"), "/", "GET"));
        assert!(!matcher.matches(Some("c.com"), "/", "GET"));
        assert!(!matcher.matches(None, "/", "GET"));
    }

    #[test]
    fn test_validation_no_listen() {
        let config = Config {
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![],
                routes: vec![],
                https_redirect: false,
            }],
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_no_upstreams() {
        let config = Config {
            tls: TlsConfig {
                acme_enabled: false,
                ..Default::default()
            },
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![":8080".to_string()],
                routes: vec![RouteConfig {
                    match_rule: MatchConfig::default(),
                    handle: HandlerConfig::ReverseProxy(ReverseProxyConfig {
                        upstreams: vec![],
                        load_balancing: LoadBalancingStrategy::RoundRobin,
                        health_check: None,
                        headers_up: HashMap::new(),
                        headers_down: HashMap::new(),
                        timeout: 30,
                        timeouts: TimeoutConfig::default(),
                        upstream_tls: false,
                        session_affinity: None,
                        rewrite: None,
                        auth: None,
                        cors: None,
                        lb_try_duration: 0,
                        lb_try_interval: 250,
                        max_request_body_size: 0,
                        circuit_breaker: None,
                        ip_filter: None,
                    }),
                }],
                https_redirect: false,
            }],
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_acme_no_email() {
        let config = Config {
            tls: TlsConfig {
                email: String::new(),
                acme_enabled: true,
                ..Default::default()
            },
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![":8080".to_string()],
                routes: vec![],
                https_redirect: false,
            }],
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_tls_domains() {
        let config = Config {
            tls: TlsConfig {
                acme_enabled: false,
                ..Default::default()
            },
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![":443".to_string()],
                routes: vec![
                    RouteConfig {
                        match_rule: MatchConfig {
                            host: Some(vec!["example.com".to_string(), "www.example.com".to_string()]),
                            path: None,
                            method: None,
                            header: None,
                        },
                        handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                            status: 200,
                            body: String::new(),
                            headers: HashMap::new(),
                        }),
                    },
                ],
                https_redirect: false,
            }],
            ..Default::default()
        };

        let domains = config.get_tls_domains();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn test_tls_domains_wildcard_excluded() {
        let config = Config {
            tls: TlsConfig {
                acme_enabled: false,
                ..Default::default()
            },
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![":443".to_string()],
                routes: vec![RouteConfig {
                    match_rule: MatchConfig {
                        host: Some(vec!["*.example.com".to_string(), "example.com".to_string()]),
                        path: None,
                        method: None,
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: String::new(),
                        headers: HashMap::new(),
                    }),
                }],
                https_redirect: false,
            }],
            ..Default::default()
        };

        let domains = config.get_tls_domains();
        assert_eq!(domains.len(), 1);
        assert!(domains.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_tls_domains_non_https_excluded() {
        let config = Config {
            tls: TlsConfig {
                acme_enabled: false,
                ..Default::default()
            },
            servers: vec![ServerConfig {
                name: "test".to_string(),
                listen: vec![":8080".to_string()],
                routes: vec![RouteConfig {
                    match_rule: MatchConfig {
                        host: Some(vec!["example.com".to_string()]),
                        path: None,
                        method: None,
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: String::new(),
                        headers: HashMap::new(),
                    }),
                }],
                https_redirect: false,
            }],
            ..Default::default()
        };

        let domains = config.get_tls_domains();
        assert!(domains.is_empty());
    }

    #[test]
    fn test_load_balancing_strategies() {
        let toml = r#"
[tls]
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:9090"]
load_balancing = "least_conn"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        if let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handle {
            assert_eq!(proxy.load_balancing, LoadBalancingStrategy::LeastConn);
        } else {
            panic!("Expected ReverseProxy handler");
        }
    }

    #[test]
    fn test_health_check_config() {
        let toml = r#"
[tls]
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "reverse_proxy"
upstreams = ["127.0.0.1:9090"]

[servers.routes.handle.health_check]
path = "/health"
interval = "10s"
timeout = "2s"
expected_status = 200
"#;

        let config: Config = toml::from_str(toml).unwrap();
        if let HandlerConfig::ReverseProxy(proxy) = &config.servers[0].routes[0].handle {
            let hc = proxy.health_check.as_ref().unwrap();
            assert_eq!(hc.path, "/health");
            assert_eq!(hc.interval, "10s");
            assert_eq!(hc.timeout, "2s");
            assert_eq!(hc.expected_status, 200);
        } else {
            panic!("Expected ReverseProxy handler");
        }
    }

    #[test]
    fn test_file_server_config() {
        let toml = r#"
[tls]
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "file_server"
root = "/var/www"
browse = true
index = ["index.html", "default.html"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        if let HandlerConfig::FileServer(fs) = &config.servers[0].routes[0].handle {
            assert_eq!(fs.root, PathBuf::from("/var/www"));
            assert!(fs.browse);
            assert_eq!(fs.index, vec!["index.html", "default.html"]);
        } else {
            panic!("Expected FileServer handler");
        }
    }

    #[test]
    fn test_static_response_config() {
        let toml = r#"
[tls]
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "static_response"
status = 418
body = "I'm a teapot"

[servers.routes.handle.headers]
X-Custom = "value"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        if let HandlerConfig::StaticResponse(sr) = &config.servers[0].routes[0].handle {
            assert_eq!(sr.status, 418);
            assert_eq!(sr.body, "I'm a teapot");
            assert_eq!(sr.headers.get("X-Custom"), Some(&"value".to_string()));
        } else {
            panic!("Expected StaticResponse handler");
        }
    }

    #[test]
    fn test_redirect_config() {
        let toml = r#"
[tls]
acme_enabled = false

[[servers]]
name = "test"
listen = [":8080"]

[[servers.routes]]
[servers.routes.handle]
type = "redirect"
to = "https://example.com"
code = 301
"#;

        let config: Config = toml::from_str(toml).unwrap();
        if let HandlerConfig::Redirect(r) = &config.servers[0].routes[0].handle {
            assert_eq!(r.to, "https://example.com");
            assert_eq!(r.code, 301);
        } else {
            panic!("Expected Redirect handler");
        }
    }

    #[test]
    fn test_plugins_config_default() {
        let plugins = PluginsConfig::default();
        assert!(!plugins.enabled);
        assert_eq!(plugins.plugin_dir, PathBuf::from("./plugins"));
        assert!(plugins.plugins.is_empty());
        assert!(!plugins.wasm.enabled);
    }

    #[test]
    fn test_plugins_config_parse() {
        let toml = r#"
[tls]
acme_enabled = false

[plugins]
enabled = true
plugin_dir = "/opt/avalon-plugins"

[[plugins.plugins]]
name = "rate-limiter"
plugin_type = "static"
enabled = true

[[plugins.plugins]]
name = "custom-auth"
plugin_type = "dynamic"
path = "/opt/avalon-plugins/libauth.so"
enabled = true

[plugins.plugins.config]
timeout = 30
max_retries = 3

[[plugins.plugins]]
name = "wasm-filter"
plugin_type = "wasm"
path = "/opt/avalon-plugins/filter.wasm"

[plugins.wasm]
enabled = true
memory_limit = 33554432
fuel_limit = 2000000000
allow_network = false
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.plugins.enabled);
        assert_eq!(config.plugins.plugin_dir, PathBuf::from("/opt/avalon-plugins"));
        assert_eq!(config.plugins.plugins.len(), 3);

        // Check static plugin
        let static_plugin = &config.plugins.plugins[0];
        assert_eq!(static_plugin.name, "rate-limiter");
        assert_eq!(static_plugin.plugin_type, PluginType::Static);
        assert!(static_plugin.enabled);

        // Check dynamic plugin
        let dynamic_plugin = &config.plugins.plugins[1];
        assert_eq!(dynamic_plugin.name, "custom-auth");
        assert_eq!(dynamic_plugin.plugin_type, PluginType::Dynamic);
        assert_eq!(dynamic_plugin.path, Some(PathBuf::from("/opt/avalon-plugins/libauth.so")));

        // Check WASM plugin
        let wasm_plugin = &config.plugins.plugins[2];
        assert_eq!(wasm_plugin.name, "wasm-filter");
        assert_eq!(wasm_plugin.plugin_type, PluginType::Wasm);
        assert_eq!(wasm_plugin.path, Some(PathBuf::from("/opt/avalon-plugins/filter.wasm")));

        // Check WASM config
        assert!(config.plugins.wasm.enabled);
        assert_eq!(config.plugins.wasm.memory_limit, 33554432);
        assert_eq!(config.plugins.wasm.fuel_limit, 2000000000);
        assert!(!config.plugins.wasm.allow_network);
    }

    #[test]
    fn test_plugin_type_serde() {
        assert_eq!(PluginType::default(), PluginType::Static);

        let json_static = serde_json::to_string(&PluginType::Static).unwrap();
        assert_eq!(json_static, "\"static\"");

        let json_dynamic = serde_json::to_string(&PluginType::Dynamic).unwrap();
        assert_eq!(json_dynamic, "\"dynamic\"");

        let json_wasm = serde_json::to_string(&PluginType::Wasm).unwrap();
        assert_eq!(json_wasm, "\"wasm\"");
    }
}
