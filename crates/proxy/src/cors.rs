//! CORS (Cross-Origin Resource Sharing) handling

use config::CorsConfig;
use tracing::debug;

/// Compiled CORS configuration for efficient runtime checking
#[derive(Debug, Clone)]
pub struct CompiledCors {
    config: CorsConfig,
    /// Pre-computed Allow-Methods header value
    allow_methods: String,
    /// Pre-computed Allow-Headers header value
    allow_headers: String,
    /// Pre-computed Expose-Headers header value (empty if none)
    expose_headers: String,
    /// Pre-computed Max-Age header value
    max_age: String,
    /// Whether wildcard origin is allowed
    is_wildcard: bool,
}

impl CompiledCors {
    pub fn from_config(config: &CorsConfig) -> Self {
        let is_wildcard = config.allowed_origins.iter().any(|o| o == "*");

        Self {
            allow_methods: config.allowed_methods.join(", "),
            allow_headers: config.allowed_headers.join(", "),
            expose_headers: config.expose_headers.join(", "),
            max_age: config.max_age.to_string(),
            is_wildcard,
            config: config.clone(),
        }
    }

    /// Check if the given origin is allowed
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.is_wildcard {
            return true;
        }

        self.config.allowed_origins.iter().any(|allowed| {
            allowed == origin || allowed == "*"
        })
    }

    /// Get the appropriate Access-Control-Allow-Origin value for the given request origin
    pub fn get_allow_origin(&self, request_origin: Option<&str>) -> Option<String> {
        let origin = request_origin?;

        if !self.is_origin_allowed(origin) {
            return None;
        }

        // If wildcard and credentials not allowed, return "*"
        if self.is_wildcard && !self.config.allow_credentials {
            return Some("*".to_string());
        }

        // Otherwise, echo back the specific origin
        Some(origin.to_string())
    }

    /// Check if the request method is allowed
    pub fn is_method_allowed(&self, method: &str) -> bool {
        self.config.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }

    /// Check if all requested headers are allowed
    pub fn are_headers_allowed(&self, requested_headers: &str) -> bool {
        if requested_headers.is_empty() {
            return true;
        }

        // Parse comma-separated headers and check each one
        for header in requested_headers.split(',') {
            let header = header.trim();
            if !self.config.allowed_headers.iter().any(|h| h.eq_ignore_ascii_case(header)) {
                return false;
            }
        }
        true
    }

    /// Generate CORS headers for a preflight (OPTIONS) response
    pub fn preflight_headers(&self, request_origin: Option<&str>, request_method: Option<&str>, request_headers: Option<&str>) -> Option<Vec<(String, String)>> {
        let allow_origin = self.get_allow_origin(request_origin)?;

        // Check if the requested method is allowed
        if let Some(method) = request_method {
            if !self.is_method_allowed(method) {
                debug!(method = %method, "CORS: Preflight rejected - method not allowed");
                return None;
            }
        }

        // Check if the requested headers are allowed
        if let Some(headers) = request_headers {
            if !self.are_headers_allowed(headers) {
                debug!(headers = %headers, "CORS: Preflight rejected - headers not allowed");
                return None;
            }
        }

        let mut cors_headers = vec![
            ("Access-Control-Allow-Origin".to_string(), allow_origin),
            ("Access-Control-Allow-Methods".to_string(), self.allow_methods.clone()),
            ("Access-Control-Allow-Headers".to_string(), self.allow_headers.clone()),
            ("Access-Control-Max-Age".to_string(), self.max_age.clone()),
        ];

        if self.config.allow_credentials {
            cors_headers.push(("Access-Control-Allow-Credentials".to_string(), "true".to_string()));
        }

        if !self.expose_headers.is_empty() {
            cors_headers.push(("Access-Control-Expose-Headers".to_string(), self.expose_headers.clone()));
        }

        // Add Vary header for cacheability
        cors_headers.push(("Vary".to_string(), "Origin, Access-Control-Request-Method, Access-Control-Request-Headers".to_string()));

        Some(cors_headers)
    }

    /// Generate CORS headers for a normal (non-preflight) response
    pub fn response_headers(&self, request_origin: Option<&str>) -> Option<Vec<(String, String)>> {
        let allow_origin = self.get_allow_origin(request_origin)?;

        let mut cors_headers = vec![
            ("Access-Control-Allow-Origin".to_string(), allow_origin),
        ];

        if self.config.allow_credentials {
            cors_headers.push(("Access-Control-Allow-Credentials".to_string(), "true".to_string()));
        }

        if !self.expose_headers.is_empty() {
            cors_headers.push(("Access-Control-Expose-Headers".to_string(), self.expose_headers.clone()));
        }

        // Add Vary header for cacheability
        cors_headers.push(("Vary".to_string(), "Origin".to_string()));

        Some(cors_headers)
    }

    /// Check if CORS is enabled (has any allowed origins)
    pub fn is_enabled(&self) -> bool {
        !self.config.allowed_origins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec!["https://example.com".to_string(), "https://app.example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            expose_headers: vec!["X-Custom-Header".to_string()],
            allow_credentials: true,
            max_age: 3600,
        }
    }

    #[test]
    fn test_origin_allowed() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        assert!(cors.is_origin_allowed("https://example.com"));
        assert!(cors.is_origin_allowed("https://app.example.com"));
        assert!(!cors.is_origin_allowed("https://other.com"));
    }

    #[test]
    fn test_wildcard_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        };
        let cors = CompiledCors::from_config(&config);

        assert!(cors.is_origin_allowed("https://any-site.com"));
        assert!(cors.is_wildcard);
    }

    #[test]
    fn test_get_allow_origin_specific() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        // Should echo back the specific origin
        assert_eq!(
            cors.get_allow_origin(Some("https://example.com")),
            Some("https://example.com".to_string())
        );

        // Should reject unknown origins
        assert_eq!(cors.get_allow_origin(Some("https://other.com")), None);

        // Should reject missing origin
        assert_eq!(cors.get_allow_origin(None), None);
    }

    #[test]
    fn test_get_allow_origin_wildcard() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: false,
            ..Default::default()
        };
        let cors = CompiledCors::from_config(&config);

        // Should return "*" for wildcard without credentials
        assert_eq!(
            cors.get_allow_origin(Some("https://any-site.com")),
            Some("*".to_string())
        );
    }

    #[test]
    fn test_get_allow_origin_wildcard_with_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        let cors = CompiledCors::from_config(&config);

        // Should echo back specific origin when credentials are allowed
        assert_eq!(
            cors.get_allow_origin(Some("https://any-site.com")),
            Some("https://any-site.com".to_string())
        );
    }

    #[test]
    fn test_method_allowed() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        assert!(cors.is_method_allowed("GET"));
        assert!(cors.is_method_allowed("get")); // case insensitive
        assert!(cors.is_method_allowed("POST"));
        assert!(cors.is_method_allowed("PUT"));
        assert!(!cors.is_method_allowed("DELETE"));
    }

    #[test]
    fn test_headers_allowed() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        assert!(cors.are_headers_allowed("Content-Type"));
        assert!(cors.are_headers_allowed("content-type")); // case insensitive
        assert!(cors.are_headers_allowed("Content-Type, Authorization"));
        assert!(!cors.are_headers_allowed("X-Custom"));
        assert!(cors.are_headers_allowed("")); // empty is always allowed
    }

    #[test]
    fn test_preflight_headers() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        let headers = cors.preflight_headers(
            Some("https://example.com"),
            Some("POST"),
            Some("Content-Type")
        ).unwrap();

        let headers_map: std::collections::HashMap<_, _> = headers.into_iter().collect();

        assert_eq!(headers_map.get("Access-Control-Allow-Origin"), Some(&"https://example.com".to_string()));
        assert_eq!(headers_map.get("Access-Control-Allow-Methods"), Some(&"GET, POST, PUT".to_string()));
        assert_eq!(headers_map.get("Access-Control-Allow-Headers"), Some(&"Content-Type, Authorization".to_string()));
        assert_eq!(headers_map.get("Access-Control-Allow-Credentials"), Some(&"true".to_string()));
        assert_eq!(headers_map.get("Access-Control-Max-Age"), Some(&"3600".to_string()));
        assert_eq!(headers_map.get("Access-Control-Expose-Headers"), Some(&"X-Custom-Header".to_string()));
    }

    #[test]
    fn test_preflight_rejected_bad_origin() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        let headers = cors.preflight_headers(
            Some("https://evil.com"),
            Some("POST"),
            Some("Content-Type")
        );

        assert!(headers.is_none());
    }

    #[test]
    fn test_preflight_rejected_bad_method() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        let headers = cors.preflight_headers(
            Some("https://example.com"),
            Some("DELETE"),
            Some("Content-Type")
        );

        assert!(headers.is_none());
    }

    #[test]
    fn test_preflight_rejected_bad_header() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        let headers = cors.preflight_headers(
            Some("https://example.com"),
            Some("POST"),
            Some("X-Evil-Header")
        );

        assert!(headers.is_none());
    }

    #[test]
    fn test_response_headers() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);

        let headers = cors.response_headers(Some("https://example.com")).unwrap();
        let headers_map: std::collections::HashMap<_, _> = headers.into_iter().collect();

        assert_eq!(headers_map.get("Access-Control-Allow-Origin"), Some(&"https://example.com".to_string()));
        assert_eq!(headers_map.get("Access-Control-Allow-Credentials"), Some(&"true".to_string()));
        assert_eq!(headers_map.get("Access-Control-Expose-Headers"), Some(&"X-Custom-Header".to_string()));
        // No Allow-Methods or Allow-Headers in normal response
        assert!(headers_map.get("Access-Control-Allow-Methods").is_none());
    }

    #[test]
    fn test_is_enabled() {
        let config = make_test_config();
        let cors = CompiledCors::from_config(&config);
        assert!(cors.is_enabled());

        let empty_config = CorsConfig::default();
        let empty_cors = CompiledCors::from_config(&empty_config);
        assert!(!empty_cors.is_enabled());
    }
}
