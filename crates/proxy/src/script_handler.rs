//! Script handler - Rhai-based dynamic request handler
//!
//! Allows writing custom request handling logic using Rhai scripts.
//! The script can return a response directly or delegate to other handlers.
//!
//! ## Example
//!
//! ```toml
//! [[servers.routes]]
//! [servers.routes.handle]
//! type = "script"
//! script = '''
//! if request.path == "/health" {
//!     #{ status: 200, body: `{"status": "ok"}`, headers: #{"Content-Type": "application/json"} }
//! } else if request.path.starts_with("/api") {
//!     #{ action: "proxy", upstream: "http://127.0.0.1:3000" }
//! } else {
//!     #{ status: 404, body: "Not Found" }
//! }
//! '''
//! ```

use once_cell::sync::Lazy;
use rhai::{Dynamic, Engine, Map, Scope, AST};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Script handler error types
#[derive(Debug, Error)]
pub enum ScriptHandlerError {
    #[error("Script compilation failed: {0}")]
    CompileError(String),

    #[error("Script execution failed: {0}")]
    RuntimeError(String),

    #[error("Invalid script result: {0}")]
    InvalidResult(String),
}

/// Request context exposed to Rhai scripts
#[derive(Debug, Clone)]
pub struct ScriptRequestContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: Option<String>,
    pub client_ip: Option<String>,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

impl ScriptRequestContext {
    /// Create a new request context
    pub fn new(
        method: &str,
        path: &str,
        query: Option<&str>,
        host: Option<&str>,
        client_ip: Option<&str>,
        headers: HashMap<String, String>,
    ) -> Self {
        let query_params = query
            .map(|q| parse_query_string(q))
            .unwrap_or_default();

        Self {
            method: method.to_string(),
            path: path.to_string(),
            query: query.unwrap_or("").to_string(),
            host: host.map(|s| s.to_string()),
            client_ip: client_ip.map(|s| s.to_string()),
            headers,
            query_params,
        }
    }

    /// Convert to Rhai Dynamic map
    fn to_dynamic(&self) -> Dynamic {
        let mut map = Map::new();

        map.insert("method".into(), self.method.clone().into());
        map.insert("path".into(), self.path.clone().into());
        map.insert("query".into(), self.query.clone().into());
        map.insert(
            "host".into(),
            self.host.clone().unwrap_or_default().into(),
        );
        map.insert(
            "client_ip".into(),
            self.client_ip.clone().unwrap_or_default().into(),
        );

        // Convert headers to Rhai map
        let mut headers_map = Map::new();
        for (k, v) in &self.headers {
            headers_map.insert(k.clone().into(), v.clone().into());
        }
        map.insert("headers".into(), Dynamic::from_map(headers_map));

        // Convert query params to Rhai map
        let mut query_map = Map::new();
        for (k, v) in &self.query_params {
            query_map.insert(k.clone().into(), v.clone().into());
        }
        map.insert("query_params".into(), Dynamic::from_map(query_map));

        Dynamic::from_map(map)
    }
}

/// Script execution result
#[derive(Debug, Clone)]
pub enum ScriptResult {
    /// Return a static response
    Response {
        status: u16,
        body: String,
        headers: HashMap<String, String>,
    },
    /// Redirect to another URL
    Redirect {
        location: String,
        code: u16,
    },
    /// Proxy to an upstream server
    Proxy {
        upstream: String,
    },
    /// Serve a static file
    File {
        path: String,
    },
}

impl Default for ScriptResult {
    fn default() -> Self {
        Self::Response {
            status: 200,
            body: String::new(),
            headers: HashMap::new(),
        }
    }
}

/// Thread-safe Rhai engine singleton (shared with rhai_rewrite)
static SCRIPT_ENGINE: Lazy<Arc<Engine>> = Lazy::new(|| {
    let mut engine = Engine::new();

    // Security: Limit script resources
    engine.set_max_expr_depths(64, 32);
    engine.set_max_call_levels(32);
    engine.set_max_operations(100_000);
    engine.set_max_modules(10);
    engine.set_max_string_size(1024 * 1024); // 1MB
    engine.set_max_array_size(10_000);
    engine.set_max_map_size(10_000);

    // Register built-in functions
    register_builtin_functions(&mut engine);

    Arc::new(engine)
});

/// Register built-in functions for Rhai scripts
fn register_builtin_functions(engine: &mut Engine) {
    // String functions
    engine.register_fn("contains", |s: &str, sub: &str| s.contains(sub));
    engine.register_fn("starts_with", |s: &str, prefix: &str| s.starts_with(prefix));
    engine.register_fn("ends_with", |s: &str, suffix: &str| s.ends_with(suffix));
    engine.register_fn("to_lower", |s: &str| s.to_lowercase());
    engine.register_fn("to_upper", |s: &str| s.to_uppercase());
    engine.register_fn("trim", |s: &str| s.trim().to_string());
    engine.register_fn("replace", |s: &str, from: &str, to: &str| {
        s.replace(from, to)
    });
    engine.register_fn("split", |s: &str, sep: &str| -> rhai::Array {
        s.split(sep).map(|p| Dynamic::from(p.to_string())).collect()
    });

    // URL encoding/decoding
    engine.register_fn("url_encode", |s: &str| {
        urlencoding::encode(s).to_string()
    });
    engine.register_fn("url_decode", |s: &str| {
        urlencoding::decode(s).unwrap_or_else(|_| s.into()).to_string()
    });

    // Base64
    engine.register_fn("base64_encode", |s: &str| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    });
    engine.register_fn("base64_decode", |s: &str| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default()
    });

    // Hash function (deterministic)
    engine.register_fn("hash", |s: &str| -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish() as i64
    });

    // Timestamp
    engine.register_fn("now", || -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    // JSON serialization helpers
    engine.register_fn("json", |map: Map| -> String {
        map_to_json(&map)
    });

    // Regex match
    engine.register_fn("matches", |s: &str, pattern: &str| -> bool {
        regex::Regex::new(pattern)
            .map(|re| re.is_match(s))
            .unwrap_or(false)
    });

    // Regex replace
    engine.register_fn("regex_replace", |s: &str, pattern: &str, replacement: &str| -> String {
        regex::Regex::new(pattern)
            .map(|re| re.replace_all(s, replacement).to_string())
            .unwrap_or_else(|_| s.to_string())
    });

    // Response builder helpers
    engine.register_fn("response", |status: i64, body: &str| -> Map {
        let mut map = Map::new();
        map.insert("status".into(), Dynamic::from(status));
        map.insert("body".into(), Dynamic::from(body.to_string()));
        map.insert("headers".into(), Dynamic::from_map(Map::new()));
        map
    });

    engine.register_fn("json_response", |status: i64, data: Map| -> Map {
        let mut headers = Map::new();
        headers.insert("Content-Type".into(), Dynamic::from("application/json".to_string()));

        let mut map = Map::new();
        map.insert("status".into(), Dynamic::from(status));
        map.insert("body".into(), Dynamic::from(map_to_json(&data)));
        map.insert("headers".into(), Dynamic::from_map(headers));
        map
    });

    engine.register_fn("redirect", |location: &str| -> Map {
        let mut map = Map::new();
        map.insert("action".into(), Dynamic::from("redirect".to_string()));
        map.insert("location".into(), Dynamic::from(location.to_string()));
        map.insert("code".into(), Dynamic::from(302_i64));
        map
    });

    engine.register_fn("redirect", |location: &str, code: i64| -> Map {
        let mut map = Map::new();
        map.insert("action".into(), Dynamic::from("redirect".to_string()));
        map.insert("location".into(), Dynamic::from(location.to_string()));
        map.insert("code".into(), Dynamic::from(code));
        map
    });

    engine.register_fn("proxy", |upstream: &str| -> Map {
        let mut map = Map::new();
        map.insert("action".into(), Dynamic::from("proxy".to_string()));
        map.insert("upstream".into(), Dynamic::from(upstream.to_string()));
        map
    });
}

/// Convert a Rhai map to JSON string
fn map_to_json(map: &Map) -> String {
    fn value_to_json(val: &Dynamic) -> String {
        if val.is_string() {
            let s = val.clone().into_string().unwrap_or_default();
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
        } else if val.is_int() {
            val.as_int().map(|n| n.to_string()).unwrap_or_default()
        } else if val.is_float() {
            val.as_float().map(|n| n.to_string()).unwrap_or_default()
        } else if val.is_bool() {
            val.as_bool().map(|b| b.to_string()).unwrap_or_default()
        } else if val.is_array() {
            let arr = val.clone().into_array().unwrap_or_default();
            let items: Vec<String> = arr.iter().map(value_to_json).collect();
            format!("[{}]", items.join(","))
        } else if val.is_map() {
            let m = val.clone().try_cast::<Map>().unwrap_or_default();
            map_to_json(&m)
        } else if val.is_unit() {
            "null".to_string()
        } else {
            format!("\"{}\"", val.to_string().replace('\\', "\\\\").replace('"', "\\\""))
        }
    }

    let items: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("\"{}\":{}", k, value_to_json(v)))
        .collect();
    format!("{{{}}}", items.join(","))
}

/// Compiled script handler
pub struct CompiledScriptHandler {
    ast: AST,
}

impl CompiledScriptHandler {
    /// Compile a script
    pub fn compile(script: &str) -> Result<Self, ScriptHandlerError> {
        let engine = &*SCRIPT_ENGINE;
        let ast = engine
            .compile(script)
            .map_err(|e| ScriptHandlerError::CompileError(e.to_string()))?;

        Ok(Self { ast })
    }

    /// Execute the script with the given request context
    pub fn execute(&self, ctx: &ScriptRequestContext) -> Result<ScriptResult, ScriptHandlerError> {
        let engine = &*SCRIPT_ENGINE;
        let mut scope = Scope::new();

        // Add request context
        scope.push("request", ctx.to_dynamic());

        // Execute script
        let result: Dynamic = engine
            .eval_ast_with_scope(&mut scope, &self.ast)
            .map_err(|e| ScriptHandlerError::RuntimeError(e.to_string()))?;

        // Parse result
        self.parse_result(result)
    }

    /// Parse the script result into a ScriptResult
    fn parse_result(&self, result: Dynamic) -> Result<ScriptResult, ScriptHandlerError> {
        // Handle map result
        if let Some(map) = result.clone().try_cast::<Map>() {
            return self.parse_map_result(&map);
        }

        // Handle string result (treated as response body)
        if result.is_string() {
            let body = result.into_string().unwrap_or_default();
            return Ok(ScriptResult::Response {
                status: 200,
                body,
                headers: HashMap::new(),
            });
        }

        // Handle unit (empty) result
        if result.is_unit() {
            return Ok(ScriptResult::Response {
                status: 200,
                body: String::new(),
                headers: HashMap::new(),
            });
        }

        Err(ScriptHandlerError::InvalidResult(format!(
            "Expected map or string, got: {}",
            result.type_name()
        )))
    }

    /// Parse a map result
    fn parse_map_result(&self, map: &Map) -> Result<ScriptResult, ScriptHandlerError> {
        // Check for action field
        if let Some(action) = map.get("action") {
            if let Ok(action_str) = action.clone().into_string() {
                match action_str.as_str() {
                    "redirect" => {
                        let location = map
                            .get("location")
                            .and_then(|v| v.clone().into_string().ok())
                            .unwrap_or_default();
                        let code = map
                            .get("code")
                            .and_then(|v| v.as_int().ok())
                            .unwrap_or(302) as u16;
                        return Ok(ScriptResult::Redirect { location, code });
                    }
                    "proxy" => {
                        let upstream = map
                            .get("upstream")
                            .and_then(|v| v.clone().into_string().ok())
                            .unwrap_or_default();
                        return Ok(ScriptResult::Proxy { upstream });
                    }
                    "file" => {
                        let path = map
                            .get("path")
                            .and_then(|v| v.clone().into_string().ok())
                            .unwrap_or_default();
                        return Ok(ScriptResult::File { path });
                    }
                    _ => {}
                }
            }
        }

        // Default: treat as response
        let status = map
            .get("status")
            .and_then(|v| v.as_int().ok())
            .unwrap_or(200) as u16;

        let body = map
            .get("body")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let mut headers = HashMap::new();
        if let Some(headers_val) = map.get("headers") {
            if let Some(headers_map) = headers_val.clone().try_cast::<Map>() {
                for (k, v) in headers_map.iter() {
                    if let Ok(value) = v.clone().into_string() {
                        headers.insert(k.to_string(), value);
                    }
                }
            }
        }

        Ok(ScriptResult::Response {
            status,
            body,
            headers,
        })
    }
}

/// Parse query string into key-value pairs
fn parse_query_string(query: &str) -> HashMap<String, String> {
    let query = query.trim_start_matches('?');
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((
                urlencoding::decode(key).unwrap_or_else(|_| key.into()).to_string(),
                urlencoding::decode(value).unwrap_or_else(|_| value.into()).to_string(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> ScriptRequestContext {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());

        ScriptRequestContext::new(
            "GET",
            "/api/users",
            Some("page=1&limit=10"),
            Some("example.com"),
            Some("192.168.1.1"),
            headers,
        )
    }

    #[test]
    fn test_simple_response() {
        let script = r#"
            #{ status: 200, body: "Hello, World!" }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { status, body, .. } => {
                assert_eq!(status, 200);
                assert_eq!(body, "Hello, World!");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_health_check() {
        let script = r#"
            if request.path == "/health" {
                #{ status: 200, body: `{"status": "ok"}`, headers: #{"Content-Type": "application/json"} }
            } else {
                #{ status: 404, body: "Not Found" }
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();

        // Test /health path
        let mut ctx = make_context();
        ctx.path = "/health".to_string();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { status, body, headers } => {
                assert_eq!(status, 200);
                assert!(body.contains("ok"));
                assert_eq!(headers.get("Content-Type"), Some(&"application/json".to_string()));
            }
            _ => panic!("Expected Response"),
        }

        // Test other path
        ctx.path = "/other".to_string();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { status, body, .. } => {
                assert_eq!(status, 404);
                assert_eq!(body, "Not Found");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_redirect() {
        let script = r#"
            if request.path == "/old" {
                redirect("/new", 301)
            } else {
                #{ status: 200, body: "OK" }
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();

        let mut ctx = make_context();
        ctx.path = "/old".to_string();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Redirect { location, code } => {
                assert_eq!(location, "/new");
                assert_eq!(code, 301);
            }
            _ => panic!("Expected Redirect"),
        }
    }

    #[test]
    fn test_proxy() {
        let script = r#"
            if request.path.starts_with("/api") {
                proxy("http://127.0.0.1:3000")
            } else {
                #{ status: 404, body: "Not Found" }
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Proxy { upstream } => {
                assert_eq!(upstream, "http://127.0.0.1:3000");
            }
            _ => panic!("Expected Proxy"),
        }
    }

    #[test]
    fn test_json_response() {
        let script = r#"
            let data = #{
                health: "ok",
                version: "1.0.0"
            };
            json_response(200, data)
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { status, body, headers } => {
                assert_eq!(status, 200);
                assert!(body.contains("health"));
                assert!(body.contains("ok"));
                assert_eq!(headers.get("Content-Type"), Some(&"application/json".to_string()));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_request_access() {
        let script = r#"
            let path = request.path;
            let method = request.method;
            let host = request.host;
            let ua = request.headers["User-Agent"];

            #{
                status: 200,
                body: `Path: ${path}, Method: ${method}, Host: ${host}, UA: ${ua}`
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { body, .. } => {
                assert!(body.contains("/api/users"));
                assert!(body.contains("GET"));
                assert!(body.contains("example.com"));
                assert!(body.contains("Mozilla"));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_query_params() {
        let script = r#"
            let page = request.query_params["page"];
            let limit = request.query_params["limit"];

            #{
                status: 200,
                body: `Page: ${page}, Limit: ${limit}`
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { body, .. } => {
                assert!(body.contains("Page: 1"));
                assert!(body.contains("Limit: 10"));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_string_return() {
        let script = r#"
            "Just a string response"
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { status, body, .. } => {
                assert_eq!(status, 200);
                assert_eq!(body, "Just a string response");
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_builtin_functions() {
        let script = r#"
            let encoded = url_encode("hello world");
            let decoded = url_decode("hello%20world");
            let upper = to_upper("hello");
            let lower = to_lower("HELLO");
            let now_ts = now();

            #{
                status: 200,
                body: `Encoded: ${encoded}, Decoded: ${decoded}, Upper: ${upper}, Lower: ${lower}, Now: ${now_ts}`
            }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx).unwrap();

        match result {
            ScriptResult::Response { body, .. } => {
                assert!(body.contains("hello%20world"));
                assert!(body.contains("Decoded: hello world"));
                assert!(body.contains("Upper: HELLO"));
                assert!(body.contains("Lower: hello"));
            }
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_compile_error() {
        let script = "this is not valid rhai {{{{";
        let result = CompiledScriptHandler::compile(script);
        assert!(result.is_err());
    }

    #[test]
    fn test_runtime_error() {
        let script = r#"
            let x = undefined_variable;
            #{ status: 200 }
        "#;

        let handler = CompiledScriptHandler::compile(script).unwrap();
        let ctx = make_context();
        let result = handler.execute(&ctx);
        assert!(result.is_err());
    }
}
