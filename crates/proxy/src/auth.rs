//! Authentication middleware for avalon
//!
//! Supports:
//! - Basic authentication (username/password)
//! - API key authentication (header or query parameter)
//! - JWT authentication (HMAC-based)

use base64::Engine;
use config::{ApiKeyConfig, AuthConfig, JwtAuthConfig};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication successful
    Authenticated {
        /// Optional identity information
        identity: Option<String>,
    },
    /// Authentication failed
    Denied {
        /// Error message
        reason: String,
        /// Whether to request authentication (e.g., send WWW-Authenticate header)
        request_auth: bool,
        /// Realm for Basic auth challenge
        realm: Option<String>,
    },
    /// No authentication required or configured
    NotRequired,
}

/// Compiled authentication rules for efficient checking
#[derive(Clone)]
pub struct CompiledAuth {
    /// Basic auth credentials
    basic_credentials: Vec<(String, String)>,
    /// API keys configuration
    api_keys: Vec<ApiKeyConfig>,
    /// JWT configuration
    jwt_config: Option<JwtAuthConfig>,
    /// Realm for auth challenges
    realm: String,
    /// Paths to exclude from authentication
    exclude_paths: Vec<String>,
}

impl CompiledAuth {
    /// Create a new compiled auth from config
    pub fn from_config(config: &AuthConfig) -> Self {
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

    /// Check if any authentication method is configured
    pub fn has_auth(&self) -> bool {
        !self.basic_credentials.is_empty()
            || !self.api_keys.is_empty()
            || self.jwt_config.is_some()
    }

    /// Check if a path should be excluded from authentication
    pub fn is_path_excluded(&self, path: &str) -> bool {
        for exclude in &self.exclude_paths {
            if path.starts_with(exclude) {
                return true;
            }
        }
        false
    }

    /// Authenticate a request
    ///
    /// Returns AuthResult indicating success, failure, or not required
    pub fn authenticate(
        &self,
        authorization_header: Option<&str>,
        api_key_header: Option<&str>,
        query_string: Option<&str>,
        path: &str,
    ) -> AuthResult {
        // Check if auth is configured
        if !self.has_auth() {
            return AuthResult::NotRequired;
        }

        // Check if path is excluded
        if self.is_path_excluded(path) {
            debug!(path = %path, "Path excluded from authentication");
            return AuthResult::NotRequired;
        }

        // Try Basic auth if credentials are configured
        if !self.basic_credentials.is_empty() {
            if let Some(auth) = authorization_header {
                if let Some(result) = self.check_basic_auth(auth) {
                    return result;
                }
            }
        }

        // Try API key auth if configured
        if !self.api_keys.is_empty() {
            if let Some(result) = self.check_api_key(api_key_header, query_string) {
                return result;
            }
        }

        // Try JWT auth if configured
        if self.jwt_config.is_some() {
            if let Some(auth) = authorization_header {
                if let Some(result) = self.check_jwt(auth) {
                    return result;
                }
            }
        }

        // No valid authentication found
        let needs_basic = !self.basic_credentials.is_empty();
        AuthResult::Denied {
            reason: "Authentication required".to_string(),
            request_auth: needs_basic,
            realm: if needs_basic { Some(self.realm.clone()) } else { None },
        }
    }

    /// Check Basic authentication
    fn check_basic_auth(&self, auth_header: &str) -> Option<AuthResult> {
        // Parse "Basic base64encoded"
        let auth_header = auth_header.trim();
        if !auth_header.to_lowercase().starts_with("basic ") {
            return None;
        }

        let encoded = &auth_header[6..].trim();
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(e) => {
                debug!(error = %e, "Failed to decode Basic auth credentials");
                return Some(AuthResult::Denied {
                    reason: "Invalid Basic auth encoding".to_string(),
                    request_auth: true,
                    realm: Some(self.realm.clone()),
                });
            }
        };

        let credentials = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Invalid UTF-8 in Basic auth credentials");
                return Some(AuthResult::Denied {
                    reason: "Invalid Basic auth encoding".to_string(),
                    request_auth: true,
                    realm: Some(self.realm.clone()),
                });
            }
        };

        // Split into username:password
        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Some(AuthResult::Denied {
                reason: "Invalid Basic auth format".to_string(),
                request_auth: true,
                realm: Some(self.realm.clone()),
            });
        }

        let username = parts[0];
        let password = parts[1];

        // Check against configured credentials
        for (expected_user, expected_pass) in &self.basic_credentials {
            if username == expected_user && self.verify_password(password, expected_pass) {
                debug!(username = %username, "Basic auth successful");
                return Some(AuthResult::Authenticated {
                    identity: Some(username.to_string()),
                });
            }
        }

        warn!(username = %username, "Basic auth failed: invalid credentials");
        Some(AuthResult::Denied {
            reason: "Invalid username or password".to_string(),
            request_auth: true,
            realm: Some(self.realm.clone()),
        })
    }

    /// Verify password (supports plain text comparison)
    fn verify_password(&self, provided: &str, expected: &str) -> bool {
        // Constant-time comparison for plain passwords
        if provided.len() != expected.len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in provided.bytes().zip(expected.bytes()) {
            result |= a ^ b;
        }
        result == 0
    }

    /// Check API key authentication
    fn check_api_key(&self, header_value: Option<&str>, query_string: Option<&str>) -> Option<AuthResult> {
        for api_key_config in &self.api_keys {
            let key = match api_key_config.source.as_str() {
                "header" => {
                    // Check header
                    header_value
                }
                "query" => {
                    // Parse query string for API key
                    if let Some(qs) = query_string {
                        let param_name = api_key_config.param_name
                            .as_deref()
                            .unwrap_or("api_key");

                        // Simple query string parsing
                        qs.split('&')
                            .find_map(|pair| {
                                let mut parts = pair.splitn(2, '=');
                                let key = parts.next()?;
                                let value = parts.next()?;
                                if key == param_name {
                                    Some(value)
                                } else {
                                    None
                                }
                            })
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(provided_key) = key {
                // Constant-time comparison
                if constant_time_compare(provided_key, &api_key_config.key) {
                    debug!(
                        key_name = ?api_key_config.name,
                        "API key authentication successful"
                    );
                    return Some(AuthResult::Authenticated {
                        identity: api_key_config.name.clone(),
                    });
                }
            }
        }

        None
    }

    /// Check JWT authentication
    fn check_jwt(&self, auth_header: &str) -> Option<AuthResult> {
        let jwt_config = self.jwt_config.as_ref()?;
        let secret = jwt_config.secret.as_ref()?;

        // Parse "Bearer token"
        let auth_header = auth_header.trim();
        if !auth_header.to_lowercase().starts_with("bearer ") {
            return None;
        }

        let token = &auth_header[7..].trim();

        // Parse JWT (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Some(AuthResult::Denied {
                reason: "Invalid JWT format".to_string(),
                request_auth: false,
                realm: None,
            });
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // Verify signature (HMAC-SHA256)
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "Failed to create HMAC for JWT verification");
                return Some(AuthResult::Denied {
                    reason: "JWT verification failed".to_string(),
                    request_auth: false,
                    realm: None,
                });
            }
        };

        mac.update(signing_input.as_bytes());

        // Decode signature (base64url)
        let signature = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature_b64) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to decode JWT signature");
                return Some(AuthResult::Denied {
                    reason: "Invalid JWT signature encoding".to_string(),
                    request_auth: false,
                    realm: None,
                });
            }
        };

        if mac.verify_slice(&signature).is_err() {
            warn!("JWT signature verification failed");
            return Some(AuthResult::Denied {
                reason: "Invalid JWT signature".to_string(),
                request_auth: false,
                realm: None,
            });
        }

        // Decode payload to extract claims
        let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "Failed to decode JWT payload");
                return Some(AuthResult::Denied {
                    reason: "Invalid JWT payload encoding".to_string(),
                    request_auth: false,
                    realm: None,
                });
            }
        };

        // Parse payload as JSON to check expiration and claims
        if let Ok(payload_str) = String::from_utf8(payload_bytes) {
            // Simple JSON parsing for exp claim
            if let Some(exp) = extract_json_number(&payload_str, "exp") {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if exp < now {
                    return Some(AuthResult::Denied {
                        reason: "JWT has expired".to_string(),
                        request_auth: false,
                        realm: None,
                    });
                }
            }

            // Check issuer if configured
            if let Some(ref expected_iss) = jwt_config.issuer {
                if let Some(iss) = extract_json_string(&payload_str, "iss") {
                    if &iss != expected_iss {
                        return Some(AuthResult::Denied {
                            reason: "JWT issuer mismatch".to_string(),
                            request_auth: false,
                            realm: None,
                        });
                    }
                }
            }

            // Check audience if configured
            if let Some(ref expected_aud) = jwt_config.audience {
                if let Some(aud) = extract_json_string(&payload_str, "aud") {
                    if &aud != expected_aud {
                        return Some(AuthResult::Denied {
                            reason: "JWT audience mismatch".to_string(),
                            request_auth: false,
                            realm: None,
                        });
                    }
                }
            }

            // Extract subject for identity
            let identity = extract_json_string(&payload_str, "sub");

            debug!("JWT authentication successful");
            return Some(AuthResult::Authenticated { identity });
        }

        Some(AuthResult::Authenticated { identity: None })
    }

    /// Get the realm for authentication challenges
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Simple JSON string extraction (avoids full JSON parsing dependency)
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];

    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();

    // Find opening quote
    if !trimmed.starts_with('"') {
        return None;
    }

    let value_start = 1;
    let rest = &trimmed[value_start..];

    // Find closing quote (handle escaped quotes)
    let mut chars = rest.chars().peekable();
    let mut value = String::new();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                value.push(next);
                chars.next();
            }
        } else if c == '"' {
            return Some(value);
        } else {
            value.push(c);
        }
    }

    None
}

/// Simple JSON number extraction
fn extract_json_number(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];

    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();

    // Parse number
    let end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
    trimmed[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{AuthConfig, BasicAuthCredential};

    fn make_basic_auth_config() -> AuthConfig {
        AuthConfig {
            basic: vec![BasicAuthCredential {
                username: "admin".to_string(),
                password: "secret".to_string(),
            }],
            api_keys: vec![],
            jwt: None,
            realm: "Test Realm".to_string(),
            exclude_paths: vec!["/health".to_string()],
        }
    }

    fn make_api_key_config() -> AuthConfig {
        AuthConfig {
            basic: vec![],
            api_keys: vec![ApiKeyConfig {
                key: "test-api-key-123".to_string(),
                name: Some("TestKey".to_string()),
                source: "header".to_string(),
                param_name: Some("X-API-Key".to_string()),
            }],
            jwt: None,
            realm: "API".to_string(),
            exclude_paths: vec![],
        }
    }

    #[test]
    fn test_basic_auth_success() {
        let config = make_basic_auth_config();
        let auth = CompiledAuth::from_config(&config);

        // Base64 encode "admin:secret"
        let credentials = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let header = format!("Basic {}", credentials);

        let result = auth.authenticate(Some(&header), None, None, "/api");

        match result {
            AuthResult::Authenticated { identity } => {
                assert_eq!(identity, Some("admin".to_string()));
            }
            _ => panic!("Expected authenticated result"),
        }
    }

    #[test]
    fn test_basic_auth_failure() {
        let config = make_basic_auth_config();
        let auth = CompiledAuth::from_config(&config);

        let credentials = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        let header = format!("Basic {}", credentials);

        let result = auth.authenticate(Some(&header), None, None, "/api");

        match result {
            AuthResult::Denied { reason, request_auth, realm } => {
                assert!(reason.contains("Invalid"));
                assert!(request_auth);
                assert_eq!(realm, Some("Test Realm".to_string()));
            }
            _ => panic!("Expected denied result"),
        }
    }

    #[test]
    fn test_excluded_path() {
        let config = make_basic_auth_config();
        let auth = CompiledAuth::from_config(&config);

        let result = auth.authenticate(None, None, None, "/health");

        match result {
            AuthResult::NotRequired => {}
            _ => panic!("Expected not required for excluded path"),
        }
    }

    #[test]
    fn test_api_key_auth_success() {
        let config = make_api_key_config();
        let auth = CompiledAuth::from_config(&config);

        let result = auth.authenticate(None, Some("test-api-key-123"), None, "/api");

        match result {
            AuthResult::Authenticated { identity } => {
                assert_eq!(identity, Some("TestKey".to_string()));
            }
            _ => panic!("Expected authenticated result"),
        }
    }

    #[test]
    fn test_api_key_auth_failure() {
        let config = make_api_key_config();
        let auth = CompiledAuth::from_config(&config);

        let result = auth.authenticate(None, Some("wrong-key"), None, "/api");

        match result {
            AuthResult::Denied { .. } => {}
            _ => panic!("Expected denied result"),
        }
    }

    #[test]
    fn test_no_auth_configured() {
        let config = AuthConfig::default();
        let auth = CompiledAuth::from_config(&config);

        let result = auth.authenticate(None, None, None, "/api");

        match result {
            AuthResult::NotRequired => {}
            _ => panic!("Expected not required when no auth configured"),
        }
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"sub":"user123","iss":"test"}"#;
        assert_eq!(extract_json_string(json, "sub"), Some("user123".to_string()));
        assert_eq!(extract_json_string(json, "iss"), Some("test".to_string()));
        assert_eq!(extract_json_string(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_number() {
        let json = r#"{"exp":1234567890,"iat":1234567800}"#;
        assert_eq!(extract_json_number(json, "exp"), Some(1234567890));
        assert_eq!(extract_json_number(json, "iat"), Some(1234567800));
        assert_eq!(extract_json_number(json, "missing"), None);
    }
}
