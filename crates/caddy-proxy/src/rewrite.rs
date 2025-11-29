//! Request and response rewriting functionality

use caddy_core::RewriteConfig;
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

/// Compiled rewrite rules for efficient execution
pub struct CompiledRewrite {
    /// Strip path prefix
    pub strip_path_prefix: Option<String>,

    /// Add path prefix
    pub add_path_prefix: Option<String>,

    /// Compiled regex for path replacement
    pub path_regex: Option<(Regex, String)>,

    /// Replace entire path
    pub replace_path: Option<String>,

    /// Headers to add to request (won't override)
    pub request_headers_add: HashMap<String, String>,

    /// Headers to set on request (will override)
    pub request_headers_set: HashMap<String, String>,

    /// Headers to remove from request
    pub request_headers_delete: Vec<String>,

    /// Headers to add to response (won't override)
    pub response_headers_add: HashMap<String, String>,

    /// Headers to set on response (will override)
    pub response_headers_set: HashMap<String, String>,

    /// Headers to remove from response
    pub response_headers_delete: Vec<String>,
}

impl CompiledRewrite {
    /// Compile a RewriteConfig into a CompiledRewrite
    pub fn from_config(config: &RewriteConfig) -> Result<Self, regex::Error> {
        let path_regex = if let Some(ref pr) = config.path_regex {
            let regex = Regex::new(&pr.pattern)?;
            Some((regex, pr.replacement.clone()))
        } else {
            None
        };

        Ok(Self {
            strip_path_prefix: config.strip_path_prefix.clone(),
            add_path_prefix: config.add_path_prefix.clone(),
            path_regex,
            replace_path: config.replace_path.clone(),
            request_headers_add: config.request_headers_add.clone(),
            request_headers_set: config.request_headers_set.clone(),
            request_headers_delete: config.request_headers_delete.clone(),
            response_headers_add: config.response_headers_add.clone(),
            response_headers_set: config.response_headers_set.clone(),
            response_headers_delete: config.response_headers_delete.clone(),
        })
    }

    /// Rewrite the request path
    pub fn rewrite_path(&self, original_path: &str) -> String {
        let mut path = original_path.to_string();

        // 1. Replace entire path if specified
        if let Some(ref new_path) = self.replace_path {
            debug!(original = %original_path, new = %new_path, "Replacing entire path");
            return new_path.clone();
        }

        // 2. Strip path prefix
        if let Some(ref prefix) = self.strip_path_prefix {
            if path.starts_with(prefix) {
                path = path[prefix.len()..].to_string();
                if path.is_empty() {
                    path = "/".to_string();
                }
                debug!(original = %original_path, prefix = %prefix, new = %path, "Stripped path prefix");
            }
        }

        // 3. Apply regex replacement
        if let Some((ref regex, ref replacement)) = self.path_regex {
            let new_path = regex.replace_all(&path, replacement).to_string();
            if new_path != path {
                debug!(original = %path, pattern = %regex.as_str(), new = %new_path, "Applied path regex");
                path = new_path;
            }
        }

        // 4. Add path prefix
        if let Some(ref prefix) = self.add_path_prefix {
            let new_path = format!("{}{}", prefix, path);
            debug!(original = %path, prefix = %prefix, new = %new_path, "Added path prefix");
            path = new_path;
        }

        path
    }

    /// Check if this rewrite has any path modifications
    pub fn has_path_rewrite(&self) -> bool {
        self.strip_path_prefix.is_some()
            || self.add_path_prefix.is_some()
            || self.path_regex.is_some()
            || self.replace_path.is_some()
    }

    /// Check if this rewrite has any request header modifications
    pub fn has_request_header_rewrite(&self) -> bool {
        !self.request_headers_add.is_empty()
            || !self.request_headers_set.is_empty()
            || !self.request_headers_delete.is_empty()
    }

    /// Check if this rewrite has any response header modifications
    pub fn has_response_header_rewrite(&self) -> bool {
        !self.response_headers_add.is_empty()
            || !self.response_headers_set.is_empty()
            || !self.response_headers_delete.is_empty()
    }
}

/// Rewrite request path with URI containing query string
pub fn rewrite_uri(uri: &str, rewrite: &CompiledRewrite) -> String {
    // Split path and query
    let (path, query) = match uri.find('?') {
        Some(idx) => (&uri[..idx], Some(&uri[idx..])),
        None => (uri, None),
    };

    // Rewrite the path portion
    let new_path = rewrite.rewrite_path(path);

    // Reconstruct URI with query string
    match query {
        Some(q) => format!("{}{}", new_path, q),
        None => new_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_core::PathRegex;

    fn make_config() -> RewriteConfig {
        RewriteConfig::default()
    }

    #[test]
    fn test_strip_path_prefix() {
        let mut config = make_config();
        config.strip_path_prefix = Some("/api".to_string());

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite.rewrite_path("/api/users"), "/users");
        assert_eq!(rewrite.rewrite_path("/api"), "/");
        assert_eq!(rewrite.rewrite_path("/other"), "/other");
    }

    #[test]
    fn test_add_path_prefix() {
        let mut config = make_config();
        config.add_path_prefix = Some("/v1".to_string());

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite.rewrite_path("/users"), "/v1/users");
        assert_eq!(rewrite.rewrite_path("/"), "/v1/");
    }

    #[test]
    fn test_strip_and_add_prefix() {
        let mut config = make_config();
        config.strip_path_prefix = Some("/api".to_string());
        config.add_path_prefix = Some("/v2".to_string());

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite.rewrite_path("/api/users"), "/v2/users");
    }

    #[test]
    fn test_replace_path() {
        let mut config = make_config();
        config.replace_path = Some("/new/path".to_string());

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite.rewrite_path("/api/users"), "/new/path");
        assert_eq!(rewrite.rewrite_path("/anything"), "/new/path");
    }

    #[test]
    fn test_path_regex() {
        let mut config = make_config();
        config.path_regex = Some(PathRegex {
            pattern: r"^/api/v(\d+)/(.*)$".to_string(),
            replacement: "/version/$1/$2".to_string(),
        });

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite.rewrite_path("/api/v1/users"), "/version/1/users");
        assert_eq!(rewrite.rewrite_path("/api/v2/items"), "/version/2/items");
        assert_eq!(rewrite.rewrite_path("/other"), "/other");
    }

    #[test]
    fn test_rewrite_uri_with_query() {
        let mut config = make_config();
        config.strip_path_prefix = Some("/api".to_string());

        let rewrite = CompiledRewrite::from_config(&config).unwrap();

        assert_eq!(rewrite_uri("/api/users?page=1", &rewrite), "/users?page=1");
        assert_eq!(rewrite_uri("/api/search?q=test&limit=10", &rewrite), "/search?q=test&limit=10");
    }

    #[test]
    fn test_has_path_rewrite() {
        let config = make_config();
        let rewrite = CompiledRewrite::from_config(&config).unwrap();
        assert!(!rewrite.has_path_rewrite());

        let mut config = make_config();
        config.strip_path_prefix = Some("/api".to_string());
        let rewrite = CompiledRewrite::from_config(&config).unwrap();
        assert!(rewrite.has_path_rewrite());
    }

    #[test]
    fn test_has_header_rewrite() {
        let config = make_config();
        let rewrite = CompiledRewrite::from_config(&config).unwrap();
        assert!(!rewrite.has_request_header_rewrite());
        assert!(!rewrite.has_response_header_rewrite());

        let mut config = make_config();
        config.request_headers_set.insert("X-Custom".to_string(), "value".to_string());
        let rewrite = CompiledRewrite::from_config(&config).unwrap();
        assert!(rewrite.has_request_header_rewrite());

        let mut config = make_config();
        config.response_headers_delete.push("Server".to_string());
        let rewrite = CompiledRewrite::from_config(&config).unwrap();
        assert!(rewrite.has_response_header_rewrite());
    }

    #[test]
    fn test_invalid_regex() {
        let mut config = make_config();
        config.path_regex = Some(PathRegex {
            pattern: r"[invalid".to_string(),
            replacement: "".to_string(),
        });

        assert!(CompiledRewrite::from_config(&config).is_err());
    }
}
