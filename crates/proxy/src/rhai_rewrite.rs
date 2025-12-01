//! Rhai-based request rewriting engine
//!
//! Provides powerful URL rewriting using Rhai scripting language.
//! Supports conditional rewriting based on headers, query params, path, etc.

use once_cell::sync::Lazy;
use rhai::{Dynamic, Engine, Map, Scope, AST};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

/// Rhai rewrite error types
#[derive(Debug, Error)]
pub enum RhaiRewriteError {
    #[error("Script compilation failed: {0}")]
    CompileError(String),

    #[error("Script execution failed: {0}")]
    RuntimeError(String),

    #[error("Invalid script result type: expected {expected}, got {got}")]
    TypeError { expected: String, got: String },
}

/// Request context exposed to Rhai scripts
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: Option<String>,
    pub client_ip: Option<String>,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

impl RequestContext {
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
            .map(parse_query_string)
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

/// Rewrite result from Rhai script
#[derive(Debug, Clone, Default)]
pub struct RewriteResult {
    /// New path (if changed)
    pub path: Option<String>,
    /// New query string (if changed)
    pub query: Option<String>,
    /// Headers to set
    pub headers_set: HashMap<String, String>,
    /// Headers to add
    pub headers_add: HashMap<String, String>,
    /// Headers to delete
    pub headers_delete: Vec<String>,
    /// Whether to stop processing further rules
    pub stop: bool,
    /// Action type: "continue", "redirect", "reject"
    pub action: String,
    /// Redirect location (for redirect action)
    pub redirect_location: Option<String>,
    /// Redirect status code
    pub redirect_status: u16,
    /// Reject status code
    pub reject_status: u16,
    /// Reject body
    pub reject_body: Option<String>,
}

impl RewriteResult {
    fn new() -> Self {
        Self {
            action: "continue".to_string(),
            redirect_status: 302,
            reject_status: 403,
            ..Default::default()
        }
    }
}

/// Thread-safe Rhai engine singleton
static RHAI_ENGINE: Lazy<Arc<Engine>> = Lazy::new(|| {
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

    // UUID generation
    engine.register_fn("uuid", || {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            (now.as_nanos() & 0xFFFFFFFF) as u32,
            (now.as_nanos() >> 32 & 0xFFFF) as u16,
            (now.as_nanos() >> 48 & 0x0FFF) as u16,
            ((now.as_nanos() >> 60 & 0x3FFF) | 0x8000) as u16,
            (now.as_nanos() >> 76) as u64 & 0xFFFFFFFFFFFF,
        )
    });

    // Timestamp
    engine.register_fn("now", || -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    // Coalesce (first non-empty value)
    engine.register_fn("coalesce", |a: &str, b: &str| {
        if a.is_empty() { b.to_string() } else { a.to_string() }
    });

    // Default value
    engine.register_fn("default", |val: &str, fallback: &str| {
        if val.is_empty() { fallback.to_string() } else { val.to_string() }
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
}

/// Expression mode data for compiled Rhai rule
pub struct ExpressionRule {
    /// Compiled condition expression (when clause)
    pub condition: Option<AST>,
    /// Compiled path expression
    pub path_expr: Option<AST>,
    /// Compiled query expression
    pub query_expr: Option<AST>,
    /// Headers to set (key -> compiled expression)
    pub headers_set: Vec<(String, AST)>,
    /// Headers to add (key -> compiled expression)
    pub headers_add: Vec<(String, AST)>,
    /// Headers to delete
    pub headers_delete: Vec<String>,
    /// Action: "continue", "redirect", "reject"
    pub action: String,
    /// Redirect configuration
    pub redirect_location: Option<AST>,
    pub redirect_status: u16,
    /// Reject configuration
    pub reject_status: u16,
    pub reject_body: Option<String>,
    /// Stop processing after this rule
    pub stop: bool,
}

/// Compiled Rhai rewrite rule - supports both expression mode and script mode
pub enum CompiledRhaiRule {
    /// Expression mode (declarative)
    Expression(Box<ExpressionRule>),
    /// Script mode (imperative) - modifies request object directly
    Script {
        /// Compiled full script
        ast: AST,
    },
}

impl CompiledRhaiRule {
    /// Create a new compiled rule from configuration
    pub fn compile(config: &RhaiRewriteConfig) -> Result<Self, RhaiRewriteError> {
        let engine = &*RHAI_ENGINE;

        // Script mode takes precedence
        if let Some(ref script) = config.script {
            let ast = engine
                .compile(script)
                .map_err(|e| RhaiRewriteError::CompileError(e.to_string()))?;
            return Ok(Self::Script { ast });
        }

        // Expression mode (declarative)
        // Compile condition
        let condition = if let Some(ref when) = config.when {
            Some(compile_expr(engine, when)?)
        } else {
            None
        };

        // Compile path expression
        let path_expr = if let Some(ref path) = config.path {
            Some(compile_expr(engine, path)?)
        } else {
            None
        };

        // Compile query expression
        let query_expr = if let Some(ref query) = config.query {
            Some(compile_expr(engine, query)?)
        } else {
            None
        };

        // Compile header expressions
        let mut headers_set = Vec::new();
        for (k, v) in &config.headers_set {
            let ast = compile_expr(engine, v)?;
            headers_set.push((k.clone(), ast));
        }

        let mut headers_add = Vec::new();
        for (k, v) in &config.headers_add {
            let ast = compile_expr(engine, v)?;
            headers_add.push((k.clone(), ast));
        }

        // Compile redirect location
        let redirect_location = if let Some(ref loc) = config.redirect_location {
            Some(compile_expr(engine, loc)?)
        } else {
            None
        };

        Ok(Self::Expression(Box::new(ExpressionRule {
            condition,
            path_expr,
            query_expr,
            headers_set,
            headers_add,
            headers_delete: config.headers_delete.clone(),
            action: config.action.clone().unwrap_or_else(|| "continue".to_string()),
            redirect_location,
            redirect_status: config.redirect_status.unwrap_or(302),
            reject_status: config.reject_status.unwrap_or(403),
            reject_body: config.reject_body.clone(),
            stop: config.stop.unwrap_or(true),
        })))
    }

    /// Evaluate whether this rule matches the request
    pub fn matches(&self, ctx: &RequestContext) -> Result<bool, RhaiRewriteError> {
        match self {
            Self::Script { .. } => Ok(true), // Script mode always runs
            Self::Expression(expr) => match &expr.condition {
                Some(ast) => {
                    let engine = &*RHAI_ENGINE;
                    let mut scope = Scope::new();
                    scope.push("request", ctx.to_dynamic());

                    let result: Dynamic = engine
                        .eval_ast_with_scope(&mut scope, ast)
                        .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;

                    result.as_bool().map_err(|_| RhaiRewriteError::TypeError {
                        expected: "bool".to_string(),
                        got: result.type_name().to_string(),
                    })
                }
                None => Ok(true), // No condition means always match
            },
        }
    }

    /// Apply this rule to get rewrite result
    pub fn apply(&self, ctx: &RequestContext) -> Result<RewriteResult, RhaiRewriteError> {
        match self {
            Self::Script { ast } => Self::apply_script(ast, ctx),
            Self::Expression(expr) => Self::apply_expression(
                ctx,
                expr.path_expr.as_ref(),
                expr.query_expr.as_ref(),
                &expr.headers_set,
                &expr.headers_add,
                &expr.headers_delete,
                &expr.action,
                expr.redirect_location.as_ref(),
                expr.redirect_status,
                expr.reject_status,
                expr.reject_body.as_ref(),
                expr.stop,
            ),
        }
    }

    /// Apply script mode - modifies request object directly
    fn apply_script(ast: &AST, ctx: &RequestContext) -> Result<RewriteResult, RhaiRewriteError> {
        let engine = &*RHAI_ENGINE;
        let mut scope = Scope::new();

        // Create mutable request object
        let request = ctx.to_dynamic();
        scope.push("request", request.clone());

        // Run the script
        engine
            .run_ast_with_scope(&mut scope, ast)
            .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;

        // Extract modified request from scope
        let modified_request = scope
            .get_value::<Dynamic>("request")
            .unwrap_or(request);

        // Build result from modified request
        let mut result = RewriteResult::new();

        if let Some(map) = modified_request.try_cast::<Map>() {
            // Extract path
            if let Some(path) = map.get("path") {
                if let Ok(s) = path.clone().into_string() {
                    if s != ctx.path {
                        result.path = Some(s);
                    }
                }
            }

            // Extract query
            if let Some(query) = map.get("query") {
                if let Ok(s) = query.clone().into_string() {
                    if s != ctx.query {
                        result.query = Some(s);
                    }
                }
            }

            // Extract headers - compare with original to find changes
            if let Some(headers) = map.get("headers") {
                if let Some(headers_map) = headers.clone().try_cast::<Map>() {
                    for (k, v) in headers_map.iter() {
                        let key = k.to_string();
                        if let Ok(value) = v.clone().into_string() {
                            // Check if this is a new or modified header
                            match ctx.headers.get(&key) {
                                Some(orig) if orig == &value => {} // unchanged
                                _ => {
                                    result.headers_set.insert(key, value);
                                }
                            }
                        }
                    }
                }
            }

            // Extract action
            if let Some(action) = map.get("action") {
                if let Ok(s) = action.clone().into_string() {
                    result.action = s;
                }
            }

            // Extract redirect_location
            if let Some(loc) = map.get("redirect_location") {
                if let Ok(s) = loc.clone().into_string() {
                    result.redirect_location = Some(s);
                }
            }

            // Extract redirect_status
            if let Some(status) = map.get("redirect_status") {
                if let Ok(n) = status.as_int() {
                    result.redirect_status = n as u16;
                }
            }

            // Extract reject_status
            if let Some(status) = map.get("reject_status") {
                if let Ok(n) = status.as_int() {
                    result.reject_status = n as u16;
                }
            }

            // Extract reject_body
            if let Some(body) = map.get("reject_body") {
                if let Ok(s) = body.clone().into_string() {
                    result.reject_body = Some(s);
                }
            }

            // Extract stop flag
            if let Some(stop) = map.get("stop") {
                if let Ok(b) = stop.as_bool() {
                    result.stop = b;
                }
            }
        }

        Ok(result)
    }

    /// Apply expression mode (declarative)
    #[allow(clippy::too_many_arguments)]
    fn apply_expression(
        ctx: &RequestContext,
        path_expr: Option<&AST>,
        query_expr: Option<&AST>,
        headers_set: &[(String, AST)],
        headers_add: &[(String, AST)],
        headers_delete: &[String],
        action: &str,
        redirect_location: Option<&AST>,
        redirect_status: u16,
        reject_status: u16,
        reject_body: Option<&String>,
        stop: bool,
    ) -> Result<RewriteResult, RhaiRewriteError> {
        let engine = &*RHAI_ENGINE;
        let mut result = RewriteResult::new();
        result.action = action.to_string();
        result.stop = stop;
        result.redirect_status = redirect_status;
        result.reject_status = reject_status;
        result.reject_body = reject_body.cloned();

        let mut scope = Scope::new();
        scope.push("request", ctx.to_dynamic());

        // Evaluate path expression
        if let Some(ast) = path_expr {
            let path: Dynamic = engine
                .eval_ast_with_scope(&mut scope, ast)
                .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;
            result.path = Some(path.into_string().map_err(|_| RhaiRewriteError::TypeError {
                expected: "string".to_string(),
                got: "unknown".to_string(),
            })?);
        }

        // Evaluate query expression
        if let Some(ast) = query_expr {
            let query: Dynamic = engine
                .eval_ast_with_scope(&mut scope, ast)
                .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;
            result.query = Some(query.into_string().map_err(|_| RhaiRewriteError::TypeError {
                expected: "string".to_string(),
                got: "unknown".to_string(),
            })?);
        }

        // Evaluate header set expressions
        for (key, ast) in headers_set {
            let value: Dynamic = engine
                .eval_ast_with_scope(&mut scope, ast)
                .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;
            if let Ok(s) = value.into_string() {
                result.headers_set.insert(key.clone(), s);
            }
        }

        // Evaluate header add expressions
        for (key, ast) in headers_add {
            let value: Dynamic = engine
                .eval_ast_with_scope(&mut scope, ast)
                .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;
            if let Ok(s) = value.into_string() {
                result.headers_add.insert(key.clone(), s);
            }
        }

        // Copy headers to delete
        result.headers_delete = headers_delete.to_vec();

        // Evaluate redirect location
        if let Some(ast) = redirect_location {
            let location: Dynamic = engine
                .eval_ast_with_scope(&mut scope, ast)
                .map_err(|e| RhaiRewriteError::RuntimeError(e.to_string()))?;
            result.redirect_location =
                Some(location.into_string().map_err(|_| RhaiRewriteError::TypeError {
                    expected: "string".to_string(),
                    got: "unknown".to_string(),
                })?);
        }

        Ok(result)
    }
}

/// Compile a Rhai expression
fn compile_expr(engine: &Engine, source: &str) -> Result<AST, RhaiRewriteError> {
    engine
        .compile_expression(source)
        .map_err(|e| RhaiRewriteError::CompileError(e.to_string()))
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

/// Rhai rewrite rule configuration (from TOML)
#[derive(Debug, Clone, Default)]
pub struct RhaiRewriteConfig {
    /// Full Rhai script (imperative mode)
    pub script: Option<String>,
    /// Condition expression (Rhai)
    pub when: Option<String>,
    /// Path expression (Rhai)
    pub path: Option<String>,
    /// Query expression (Rhai)
    pub query: Option<String>,
    /// Headers to set
    pub headers_set: HashMap<String, String>,
    /// Headers to add
    pub headers_add: HashMap<String, String>,
    /// Headers to delete
    pub headers_delete: Vec<String>,
    /// Action type
    pub action: Option<String>,
    /// Redirect location expression
    pub redirect_location: Option<String>,
    /// Redirect status code
    pub redirect_status: Option<u16>,
    /// Reject status code
    pub reject_status: Option<u16>,
    /// Reject body
    pub reject_body: Option<String>,
    /// Stop processing after this rule
    pub stop: Option<bool>,
}

/// Rhai rewrite engine
pub struct RhaiRewriteEngine {
    rules: Vec<CompiledRhaiRule>,
}

impl RhaiRewriteEngine {
    /// Create a new rewrite engine from configuration
    pub fn new(configs: Vec<RhaiRewriteConfig>) -> Result<Self, RhaiRewriteError> {
        let mut rules = Vec::with_capacity(configs.len());
        for config in configs {
            rules.push(CompiledRhaiRule::compile(&config)?);
        }
        Ok(Self { rules })
    }

    /// Process a request through all rules
    pub fn process(&self, ctx: &RequestContext) -> Result<RewriteResult, RhaiRewriteError> {
        let mut final_result = RewriteResult::new();
        let mut current_ctx = ctx.clone();

        for rule in &self.rules {
            // Check if rule matches
            if !rule.matches(&current_ctx)? {
                continue;
            }

            debug!("Rhai rewrite rule matched");

            // Apply the rule
            let result = rule.apply(&current_ctx)?;

            // Merge results
            if let Some(ref path) = result.path {
                final_result.path = Some(path.clone());
                current_ctx.path = path.clone();
            }
            if let Some(ref query) = result.query {
                final_result.query = Some(query.clone());
                current_ctx.query = query.clone();
            }

            // Merge headers
            for (k, v) in result.headers_set {
                final_result.headers_set.insert(k, v);
            }
            for (k, v) in result.headers_add {
                final_result.headers_add.insert(k, v);
            }
            for h in result.headers_delete {
                final_result.headers_delete.push(h);
            }

            // Handle special actions
            if result.action == "redirect" || result.action == "reject" {
                final_result.action = result.action;
                final_result.redirect_location = result.redirect_location;
                final_result.redirect_status = result.redirect_status;
                final_result.reject_status = result.reject_status;
                final_result.reject_body = result.reject_body;
                break;
            }

            // Check if we should stop
            if result.stop {
                break;
            }
        }

        Ok(final_result)
    }

    /// Check if this engine has any rules
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> RequestContext {
        let mut headers = HashMap::new();
        headers.insert("X-Version".to_string(), "v2".to_string());
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());

        RequestContext::new(
            "GET",
            "/api/users",
            Some("page=1&limit=10"),
            Some("example.com"),
            Some("192.168.1.1"),
            headers,
        )
    }

    #[test]
    fn test_request_context_to_dynamic() {
        let ctx = make_context();
        let dynamic = ctx.to_dynamic();
        assert!(dynamic.is_map());
    }

    #[test]
    fn test_simple_condition() {
        let config = RhaiRewriteConfig {
            when: Some(r#"request.headers["X-Version"] == "v2""#.to_string()),
            path: Some(r#""/v2" + request.path"#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        assert!(rule.matches(&ctx).unwrap());

        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.path, Some("/v2/api/users".to_string()));
    }

    #[test]
    fn test_condition_not_match() {
        let config = RhaiRewriteConfig {
            when: Some(r#"request.headers["X-Version"] == "v3""#.to_string()),
            path: Some(r#""/v3" + request.path"#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        assert!(!rule.matches(&ctx).unwrap());
    }

    #[test]
    fn test_header_manipulation() {
        let mut headers_set = HashMap::new();
        headers_set.insert("X-Forwarded-For".to_string(), "request.client_ip".to_string());

        let config = RhaiRewriteConfig {
            headers_set,
            headers_delete: vec!["User-Agent".to_string()],
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();
        let result = rule.apply(&ctx).unwrap();

        assert_eq!(
            result.headers_set.get("X-Forwarded-For"),
            Some(&"192.168.1.1".to_string())
        );
        assert!(result.headers_delete.contains(&"User-Agent".to_string()));
    }

    #[test]
    fn test_builtin_functions() {
        let config = RhaiRewriteConfig {
            when: Some(r#"contains(request.path, "/api")"#.to_string()),
            path: Some(r#"replace(request.path, "/api", "/backend")"#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        assert!(rule.matches(&ctx).unwrap());
        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.path, Some("/backend/users".to_string()));
    }

    #[test]
    fn test_hash_function() {
        let config = RhaiRewriteConfig {
            when: Some(r#"hash("test-user") % 100 < 50"#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        // Hash is deterministic, so this should always succeed
        let _ = rule.matches(&ctx).unwrap();
    }

    #[test]
    fn test_rewrite_engine() {
        let configs = vec![
            RhaiRewriteConfig {
                when: Some(r#"request.headers["X-Version"] == "v2""#.to_string()),
                path: Some(r#""/v2" + request.path"#.to_string()),
                stop: Some(false),
                ..Default::default()
            },
            RhaiRewriteConfig {
                when: Some(r#"contains(request.path, "/v2")"#.to_string()),
                path: Some(r#"request.path + "/processed""#.to_string()),
                ..Default::default()
            },
        ];

        let engine = RhaiRewriteEngine::new(configs).unwrap();
        let ctx = make_context();

        let result = engine.process(&ctx).unwrap();
        assert_eq!(result.path, Some("/v2/api/users/processed".to_string()));
    }

    #[test]
    fn test_redirect_action() {
        let config = RhaiRewriteConfig {
            when: Some(r#"request.path == "/old""#.to_string()),
            action: Some("redirect".to_string()),
            redirect_location: Some(r#""/new""#.to_string()),
            redirect_status: Some(301),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let mut ctx = make_context();
        ctx.path = "/old".to_string();

        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.action, "redirect");
        assert_eq!(result.redirect_location, Some("/new".to_string()));
        assert_eq!(result.redirect_status, 301);
    }

    #[test]
    fn test_reject_action() {
        let config = RhaiRewriteConfig {
            when: Some(r#"contains(request.headers["User-Agent"], "Bot")"#.to_string()),
            action: Some("reject".to_string()),
            reject_status: Some(403),
            reject_body: Some("Bots not allowed".to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let mut ctx = make_context();
        ctx.headers.insert("User-Agent".to_string(), "GoogleBot".to_string());

        assert!(rule.matches(&ctx).unwrap());
        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.action, "reject");
        assert_eq!(result.reject_status, 403);
    }

    #[test]
    fn test_script_mode() {
        let config = RhaiRewriteConfig {
            script: Some(r#"
                request.path = "/v2" + request.path;
                request.headers["X-Script-Applied"] = "true";
                request.query = request.query + "&from_script=yes";
            "#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        // Script mode always matches (no condition)
        assert!(rule.matches(&ctx).unwrap());

        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.path, Some("/v2/api/users".to_string()));
        assert_eq!(result.query, Some("page=1&limit=10&from_script=yes".to_string()));
        assert_eq!(
            result.headers_set.get("X-Script-Applied"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn test_script_mode_with_conditional() {
        let config = RhaiRewriteConfig {
            script: Some(r#"
                if request.headers["X-Version"] == "v2" {
                    request.path = "/v2" + request.path;
                    request.headers["X-Routed"] = "v2";
                }
            "#.to_string()),
            ..Default::default()
        };

        let rule = CompiledRhaiRule::compile(&config).unwrap();
        let ctx = make_context();

        let result = rule.apply(&ctx).unwrap();
        assert_eq!(result.path, Some("/v2/api/users".to_string()));
        assert_eq!(
            result.headers_set.get("X-Routed"),
            Some(&"v2".to_string())
        );
    }
}
