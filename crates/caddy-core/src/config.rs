//! Configuration structures and parsing for caddy-rs

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
            servers: Vec::new(),
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
}

fn default_admin_listen() -> String {
    "localhost:2019".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            admin_listen: default_admin_listen(),
            log_level: default_log_level(),
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

    /// Connection timeout (in seconds)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Use TLS for upstream connections
    #[serde(default)]
    pub upstream_tls: bool,
}

fn default_timeout() -> u64 {
    30
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
                        upstream_tls: false,
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
}
