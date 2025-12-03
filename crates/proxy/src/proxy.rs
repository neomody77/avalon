//! Main proxy implementation using Pingora's ProxyHttp trait

use crate::access_log::{AccessLogEntry, AccessLogger, LogFormat};
use crate::auth::{AuthResult, CompiledAuth};
use crate::cache::{CacheConfig, CacheKey, CachedResponse, ResponseCache};
use crate::cors::CompiledCors;
use crate::compression::{
    CompressionConfig, CompressionEncoding, is_already_compressed,
    select_encoding, should_compress_content_type, compress,
};
use crate::file_server::FileServer;
use crate::metrics::metrics;
use crate::rewrite::CompiledRewrite;
use crate::rhai_rewrite::{RhaiRewriteEngine, RequestContext as RhaiRequestContext};
use crate::route::RoutingContext;
use crate::script_handler::{ScriptRequestContext, ScriptResult};
use crate::upstream::{UpstreamSelector, UpstreamServer};
use async_trait::async_trait;
use bytes::Bytes;
use config::{Config, HandlerConfig};
use tls::ChallengeTokens;
use chrono::Utc;
use http::StatusCode;
use parking_lot::RwLock;
use pingora::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

#[cfg(feature = "plugins")]
use crate::plugin_integration::{
    PluginState, SyncHookRunner, HookResult,
    to_plugin_request, to_plugin_response, to_upstream_info,
    from_plugin_request, from_plugin_response,
};
#[cfg(feature = "plugins")]
use plugin::PluginContext;

use crate::error::ProxyError;

/// Per-request context
pub struct RequestCtx {
    pub upstream: Option<Arc<UpstreamServer>>,
    pub is_acme_challenge: bool,
    pub acme_response: Option<String>,
    pub handler_type: Option<HandlerType>,
    pub static_body: Option<String>,
    pub redirect_to: Option<String>,
    pub redirect_code: Option<u16>,
    pub custom_headers_down: Vec<(String, String)>,
    pub is_websocket: bool,
    pub request_start: Instant,
    /// Selected compression encoding based on Accept-Encoding header
    pub compression_encoding: CompressionEncoding,
    /// Buffer for response body (for compression)
    pub response_body_buffer: Vec<u8>,
    /// Content-Type of the response
    pub response_content_type: Option<String>,
    /// Whether the response is already compressed
    pub response_already_compressed: bool,
    /// Session affinity cookie to set on response (name, value, max_age)
    pub affinity_cookie: Option<(String, String, u64)>,
    /// Cache key for caching responses
    pub cache_key: Option<CacheKey>,
    /// Whether this response should be cached
    pub should_cache: bool,
    /// Response status for caching
    pub response_status: u16,
    /// Response headers for caching
    pub response_headers: Vec<(String, String)>,
    /// Compiled rewrite rules for this request
    pub rewrite: Option<Arc<CompiledRewrite>>,
    /// Compiled Rhai rewrite engine for this request
    pub rhai_rewrite: Option<Arc<RhaiRewriteEngine>>,
    /// Compiled auth rules for this request
    pub auth: Option<Arc<CompiledAuth>>,
    /// Plugin context for this request (when plugins feature is enabled)
    #[cfg(feature = "plugins")]
    pub plugin_ctx: PluginContext,
    /// Upstream servers that have already been tried (for retry logic)
    pub tried_upstreams: Vec<Arc<UpstreamServer>>,
    /// Deadline for retry attempts (when lb_try_duration is set)
    pub retry_deadline: Option<Instant>,
    /// Retry duration in milliseconds (from config)
    pub lb_try_duration: u64,
    /// Retry interval in milliseconds (from config)
    pub lb_try_interval: u64,
    /// Reference to upstream selector for retry logic
    pub upstream_selector: Option<Arc<UpstreamSelector>>,
    /// Compiled CORS configuration for this request
    pub cors: Option<Arc<CompiledCors>>,
    /// Request Origin header value for CORS
    pub request_origin: Option<String>,
    /// Timeout configuration for upstream connections
    pub timeouts: Option<config::TimeoutConfig>,
    /// Maximum request body size in bytes (0 = unlimited)
    pub max_request_body_size: u64,
    /// Enable HTTP/2 for upstream connections
    pub upstream_http2: bool,
    /// mTLS configuration for upstream connections
    pub upstream_mtls: Option<config::UpstreamMtlsConfig>,
}

#[derive(Clone)]
pub enum HandlerType {
    ReverseProxy,
    StaticResponse,
    Redirect,
    FileServer,
    Script,
}

impl RequestCtx {
    pub fn new() -> Self {
        Self {
            upstream: None,
            is_acme_challenge: false,
            acme_response: None,
            handler_type: None,
            static_body: None,
            redirect_to: None,
            redirect_code: None,
            custom_headers_down: Vec::new(),
            is_websocket: false,
            request_start: Instant::now(),
            compression_encoding: CompressionEncoding::Identity,
            response_body_buffer: Vec::new(),
            response_content_type: None,
            response_already_compressed: false,
            affinity_cookie: None,
            cache_key: None,
            should_cache: false,
            response_status: 0,
            response_headers: Vec::new(),
            rewrite: None,
            rhai_rewrite: None,
            auth: None,
            #[cfg(feature = "plugins")]
            plugin_ctx: PluginContext::default(),
            tried_upstreams: Vec::new(),
            retry_deadline: None,
            lb_try_duration: 0,
            lb_try_interval: 250,
            upstream_selector: None,
            cors: None,
            request_origin: None,
            timeouts: None,
            max_request_body_size: 0,
            upstream_http2: false,
            upstream_mtls: None,
        }
    }
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// Main Avalon proxy implementation
pub struct AvalonProxy {
    routing: Arc<RoutingContext>,
    acme_tokens: ChallengeTokens,
    config: Arc<RwLock<Config>>,
    access_logger: Option<AccessLogger>,
    compression_config: CompressionConfig,
    cache: Option<ResponseCache>,
    /// Plugin state (when plugins feature is enabled)
    #[cfg(feature = "plugins")]
    plugin_state: Option<PluginState>,
}

impl AvalonProxy {
    pub fn new(config: Config, acme_tokens: ChallengeTokens) -> Result<Self, ProxyError> {
        let routing = Arc::new(RoutingContext::new());
        routing
            .load_config(&config.servers)
            .map_err(|e| ProxyError::ConfigError(e.to_string()))?;

        // Initialize access logger if configured
        let access_logger = if let Some(path) = &config.global.access_log {
            let format: LogFormat = config.global.access_log_format.parse().unwrap_or_default();
            match AccessLogger::new(path, format) {
                Ok(logger) => {
                    info!(path = %path, "Access logging enabled");
                    Some(logger)
                }
                Err(e) => {
                    warn!(error = %e, path = %path, "Failed to create access log, logging disabled");
                    None
                }
            }
        } else {
            None
        };

        // Initialize compression config from global settings
        let compression_opts = &config.global.compression;
        let compression_config = if compression_opts.enabled {
            CompressionConfig {
                gzip: compression_opts.gzip,
                brotli: compression_opts.brotli,
                min_size: compression_opts.min_size,
                level: compression_opts.level,
            }
        } else {
            CompressionConfig {
                gzip: false,
                brotli: false,
                min_size: 0,
                level: 0,
            }
        };

        if compression_opts.enabled {
            info!(
                gzip = compression_opts.gzip,
                brotli = compression_opts.brotli,
                min_size = compression_opts.min_size,
                level = compression_opts.level,
                "Compression enabled"
            );
        }

        // Initialize response cache if configured
        let cache_opts = &config.global.cache;
        let cache = if cache_opts.enabled {
            let cache_config = CacheConfig {
                enabled: true,
                default_ttl: cache_opts.default_ttl,
                max_entry_size: cache_opts.max_entry_size,
                max_cache_size: cache_opts.max_cache_size,
                cacheable_status: cache_opts.cacheable_status.clone(),
                cacheable_methods: cache_opts.cacheable_methods.clone(),
            };
            info!(
                default_ttl = cache_opts.default_ttl,
                max_entry_size = cache_opts.max_entry_size,
                max_cache_size = cache_opts.max_cache_size,
                "Response caching enabled"
            );
            Some(ResponseCache::new(cache_config))
        } else {
            None
        };

        Ok(Self {
            routing,
            acme_tokens,
            config: Arc::new(RwLock::new(config)),
            access_logger,
            compression_config,
            cache,
            #[cfg(feature = "plugins")]
            plugin_state: None,
        })
    }

    /// Set the plugin state for this proxy
    #[cfg(feature = "plugins")]
    pub fn with_plugin_state(mut self, state: PluginState) -> Self {
        self.plugin_state = Some(state);
        self
    }

    /// Get a reference to the plugin state
    #[cfg(feature = "plugins")]
    pub fn plugin_state(&self) -> Option<&PluginState> {
        self.plugin_state.as_ref()
    }

    pub fn reload_config(&self, config: Config) -> Result<(), ProxyError> {
        self.routing
            .load_config(&config.servers)
            .map_err(|e| ProxyError::ConfigError(e.to_string()))?;
        *self.config.write() = config;
        info!("Configuration reloaded");
        Ok(())
    }

    pub fn get_all_upstreams(&self) -> Vec<Arc<crate::upstream::UpstreamSelector>> {
        self.routing.get_all_upstreams()
    }

    fn check_acme_challenge(&self, path: &str) -> Option<String> {
        const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

        if let Some(token) = path.strip_prefix(ACME_CHALLENGE_PREFIX) {
            if let Some(entry) = self.acme_tokens.get(token) {
                debug!(token = %token, "Responding to ACME challenge");
                return Some(entry.value().clone());
            }
        }
        None
    }

    fn get_host<'a>(&self, session: &'a Session) -> Option<&'a str> {
        session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h))
    }
}

impl Clone for AvalonProxy {
    fn clone(&self) -> Self {
        Self {
            routing: self.routing.clone(),
            acme_tokens: self.acme_tokens.clone(),
            config: self.config.clone(),
            access_logger: self.access_logger.clone(),
            compression_config: self.compression_config.clone(),
            cache: self.cache.clone(),
            #[cfg(feature = "plugins")]
            plugin_state: self.plugin_state.clone(),
        }
    }
}

#[async_trait]
impl ProxyHttp for AvalonProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::new()
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let path = session.req_header().uri.path();

        if let Some(response) = self.check_acme_challenge(path) {
            ctx.is_acme_challenge = true;
            ctx.acme_response = Some(response);
        }

        // Detect WebSocket upgrade request
        let headers = &session.req_header().headers;
        let is_upgrade = headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false);

        let is_websocket = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase() == "websocket")
            .unwrap_or(false);

        if is_upgrade && is_websocket {
            ctx.is_websocket = true;
            debug!(path = %path, "WebSocket upgrade request detected");
        }

        // Parse Accept-Encoding for compression
        let accept_encoding = headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok());
        ctx.compression_encoding = select_encoding(accept_encoding, &self.compression_config);

        // Extract Origin header for CORS handling
        ctx.request_origin = headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Build cache key if caching is enabled
        if self.cache.is_some() && !ctx.is_websocket {
            let host = headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let method = session.req_header().method.as_str();
            let query = session.req_header().uri.query();

            ctx.cache_key = Some(CacheKey::new(method, host, path, query));
        }

        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path();

        // Handle built-in endpoints for metrics and health checks
        match path {
            "/metrics" => {
                let body = metrics().export();
                let mut header = ResponseHeader::build(StatusCode::OK, None)?;
                header.insert_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                header.insert_header("Server", "avalon")?;

                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(body.into()), true).await?;
                return Ok(true);
            }
            "/health" | "/healthz" => {
                let body = r#"{"status":"healthy"}"#;
                let mut header = ResponseHeader::build(StatusCode::OK, None)?;
                header.insert_header("Content-Type", "application/json")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                header.insert_header("Server", "avalon")?;

                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(body.into()), true).await?;
                return Ok(true);
            }
            "/ready" | "/readyz" => {
                // Check if we have any healthy upstreams
                let upstreams = self.get_all_upstreams();
                let has_healthy = upstreams.is_empty() || upstreams.iter().any(|u| u.has_healthy_server());

                let (status, body) = if has_healthy {
                    (StatusCode::OK, r#"{"status":"ready"}"#)
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"not_ready","reason":"no healthy upstreams"}"#)
                };

                let mut header = ResponseHeader::build(status, None)?;
                header.insert_header("Content-Type", "application/json")?;
                header.insert_header("Content-Length", body.len().to_string())?;
                header.insert_header("Server", "avalon")?;

                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(body.into()), true).await?;
                return Ok(true);
            }
            _ => {}
        }

        // Handle ACME challenge
        if ctx.is_acme_challenge {
            let response = ctx.acme_response.as_ref().unwrap();

            let mut header = ResponseHeader::build(StatusCode::OK, None)?;
            header.insert_header("Content-Type", "text/plain")?;
            header.insert_header("Content-Length", response.len().to_string())?;

            session.write_response_header(Box::new(header), false).await?;
            session.write_response_body(Some(response.clone().into()), true).await?;

            return Ok(true);
        }

        // Check cache before proxying
        if let (Some(cache), Some(cache_key)) = (&self.cache, &ctx.cache_key) {
            if let Some(cached) = cache.get(cache_key) {
                debug!(key = %cache_key.to_string_key(), "Serving from cache");
                metrics().cache_hits.inc();

                let status = cached.status;
                let mut header = ResponseHeader::build(status, None)?;

                for (name, value) in cached.headers.clone() {
                    header.insert_header(name, value)?;
                }
                header.insert_header("X-Cache", "HIT")?;
                header.insert_header("Content-Length", cached.body.len().to_string())?;

                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(cached.body.clone()), true).await?;

                return Ok(true);
            } else {
                metrics().cache_misses.inc();
            }
        }

        let host = self.get_host(session);
        let path = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        // Check for HTTPS redirect (only on non-TLS connections)
        // TODO: detect actual TLS state from session
        for table in self.routing.tables() {
            if table.should_redirect_https() {
                if let Some(host) = host {
                    let query = session.req_header().uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
                    let location = format!("https://{}{}{}", host, path, query);

                    let mut header = ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None)?;
                    header.insert_header("Location", location)?;
                    header.insert_header("Server", "avalon")?;

                    session.write_response_header(Box::new(header), true).await?;
                    return Ok(true);
                }
            }
        }

        // Find matching route
        for table in self.routing.tables() {
            if let Some(route) = table.match_route(host, path, method) {
                match &route.handler {
                    HandlerConfig::ReverseProxy(proxy_config) => {
                        if let Some(upstream_selector) = &route.upstream {
                            // Handle session affinity if configured
                            let (upstream, affinity_cookie) = if let Some(affinity_config) = &proxy_config.session_affinity {
                                // Get affinity key based on type
                                let affinity_key = match affinity_config.affinity_type.as_str() {
                                    "cookie" => {
                                        // Extract cookie value from request
                                        session.req_header().headers
                                            .get("cookie")
                                            .and_then(|v| v.to_str().ok())
                                            .and_then(|cookies| {
                                                cookies.split(';')
                                                    .map(|c| c.trim())
                                                    .find(|c| c.starts_with(&format!("{}=", affinity_config.cookie_name)))
                                                    .and_then(|c| c.split('=').nth(1))
                                                    .map(|v| v.to_string())
                                            })
                                    }
                                    "ip_hash" => {
                                        // Use client IP as affinity key
                                        session.client_addr()
                                            .map(|a| {
                                                let s = a.to_string();
                                                s.split(':').next().unwrap_or(&s).to_string()
                                            })
                                    }
                                    _ => None,
                                };

                                match upstream_selector.select_with_affinity(affinity_key.as_deref()) {
                                    Ok((server, idx)) => {
                                        // Only set cookie if using cookie affinity
                                        let cookie = if affinity_config.affinity_type == "cookie" {
                                            Some((
                                                affinity_config.cookie_name.clone(),
                                                idx.to_string(),
                                                affinity_config.cookie_max_age,
                                            ))
                                        } else {
                                            None
                                        };
                                        (Ok(server), cookie)
                                    }
                                    Err(e) => (Err(e), None),
                                }
                            } else {
                                // No affinity, use normal selection
                                (upstream_selector.select(), None)
                            };

                            match upstream {
                                Ok(upstream) => {
                                    ctx.handler_type = Some(HandlerType::ReverseProxy);
                                    ctx.upstream = Some(upstream);
                                    ctx.affinity_cookie = affinity_cookie;
                                    ctx.rewrite = route.rewrite.clone();
                                    ctx.rhai_rewrite = route.rhai_rewrite.clone();
                                    ctx.auth = route.auth.clone();
                                    ctx.cors = route.cors.clone();

                                    // Handle CORS preflight (OPTIONS) request
                                    if method == "OPTIONS" {
                                        if let Some(cors) = &ctx.cors {
                                            let request_method = session.req_header().headers
                                                .get("access-control-request-method")
                                                .and_then(|v| v.to_str().ok());
                                            let request_headers = session.req_header().headers
                                                .get("access-control-request-headers")
                                                .and_then(|v| v.to_str().ok());

                                            if let Some(cors_headers) = cors.preflight_headers(
                                                ctx.request_origin.as_deref(),
                                                request_method,
                                                request_headers,
                                            ) {
                                                debug!("CORS preflight request accepted");
                                                return self.send_cors_preflight_response(session, cors_headers).await;
                                            } else {
                                                debug!("CORS preflight request rejected");
                                                return self.send_error_response(session, 403, "CORS preflight rejected").await;
                                            }
                                        }
                                    }

                                    // Store retry configuration
                                    ctx.lb_try_duration = proxy_config.lb_try_duration;
                                    ctx.lb_try_interval = proxy_config.lb_try_interval;
                                    ctx.upstream_selector = Some(upstream_selector.clone());
                                    if proxy_config.lb_try_duration > 0 {
                                        ctx.retry_deadline = Some(Instant::now() + Duration::from_millis(proxy_config.lb_try_duration));
                                    }

                                    // Store timeout configuration for connection pool
                                    ctx.timeouts = Some(proxy_config.timeouts.clone());

                                    // Store max request body size for size limiting
                                    ctx.max_request_body_size = proxy_config.max_request_body_size;

                                    // Store HTTP/2 upstream configuration
                                    ctx.upstream_http2 = proxy_config.upstream_http2;

                                    // Store mTLS configuration for upstream connections
                                    ctx.upstream_mtls = proxy_config.upstream_mtls.clone();

                                    // Check request body size limit
                                    if ctx.max_request_body_size > 0 {
                                        if let Some(content_length) = session.req_header().headers
                                            .get("content-length")
                                            .and_then(|v| v.to_str().ok())
                                            .and_then(|s| s.parse::<u64>().ok())
                                        {
                                            if content_length > ctx.max_request_body_size {
                                                warn!(
                                                    content_length = content_length,
                                                    max_size = ctx.max_request_body_size,
                                                    "Request body too large"
                                                );
                                                return self.send_error_response(session, 413, "Payload Too Large").await;
                                            }
                                        }
                                    }

                                    // Check authentication if configured
                                    if let Some(auth) = &ctx.auth {
                                        // Extract auth info from request
                                        let headers = &session.req_header().headers;
                                        let auth_header = headers
                                            .get("authorization")
                                            .and_then(|v| v.to_str().ok());
                                        let api_key_header = headers
                                            .get("x-api-key")
                                            .and_then(|v| v.to_str().ok());
                                        let query = session.req_header().uri.query();

                                        let result = auth.authenticate(auth_header, api_key_header, query, path);

                                        match result {
                                            AuthResult::Authenticated { identity } => {
                                                if let Some(id) = identity {
                                                    debug!(identity = %id, "Request authenticated");
                                                }
                                            }
                                            AuthResult::Denied { reason, request_auth, realm } => {
                                                warn!(reason = %reason, path = %path, "Authentication denied");
                                                return self.send_auth_response(session, request_auth, realm.as_deref()).await;
                                            }
                                            AuthResult::NotRequired => {
                                                // Path is excluded from auth, continue
                                            }
                                        }
                                    }

                                    for (key, value) in &proxy_config.headers_down {
                                        ctx.custom_headers_down.push((key.clone(), value.clone()));
                                    }

                                    return Ok(false);
                                }
                                Err(e) => {
                                    warn!(error = %e, "Failed to select upstream");
                                    return self.send_error_response(session, 502, "Bad Gateway").await;
                                }
                            }
                        }
                    }
                    HandlerConfig::StaticResponse(config) => {
                        let status = config.status;
                        let headers: Vec<(String, String)> = config.headers.iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        let body = config.body.clone();

                        let mut header = ResponseHeader::build(
                            StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                            None,
                        )?;

                        for (key, value) in headers {
                            header.insert_header(key, value)?;
                        }

                        if !body.is_empty() {
                            header.insert_header("Content-Length", body.len().to_string())?;
                        }

                        session.write_response_header(Box::new(header), body.is_empty()).await?;
                        if !body.is_empty() {
                            session.write_response_body(Some(body.into()), true).await?;
                        }

                        return Ok(true);
                    }
                    HandlerConfig::Redirect(config) => {
                        let code = config.code;
                        let location = config.to.clone();

                        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);
                        let mut header = ResponseHeader::build(status, None)?;
                        header.insert_header("Location", location)?;

                        session.write_response_header(Box::new(header), true).await?;
                        return Ok(true);
                    }
                    HandlerConfig::FileServer(config) => {
                        let file_server = FileServer::new(&config.root)
                            .with_browse(config.browse)
                            .with_index_files(config.index.clone());

                        let response = file_server.serve(path).await;

                        let mut header = ResponseHeader::build(response.status, None)?;
                        header.insert_header("Content-Type", response.content_type.clone())?;
                        header.insert_header("Content-Length", response.body.len().to_string())?;
                        header.insert_header("Server", "avalon")?;

                        for (key, value) in &response.headers {
                            header.insert_header(key.clone(), value.clone())?;
                        }

                        session.write_response_header(Box::new(header), response.body.is_empty()).await?;
                        if !response.body.is_empty() {
                            session.write_response_body(Some(response.body), true).await?;
                        }

                        return Ok(true);
                    }
                    HandlerConfig::Script(_) => {
                        // Handle script handler using compiled handler from route
                        if let Some(script_handler) = &route.script_handler {
                            // Build request context
                            let headers: std::collections::HashMap<String, String> = session
                                .req_header()
                                .headers
                                .iter()
                                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                                .collect();

                            let client_ip = session.client_addr().map(|a| {
                                let s = a.to_string();
                                s.split(':').next().unwrap_or(&s).to_string()
                            });

                            let query = session.req_header().uri.query();

                            let script_ctx = ScriptRequestContext::new(
                                method,
                                path,
                                query,
                                host,
                                client_ip.as_deref(),
                                headers,
                            );

                            // Execute script
                            match script_handler.execute(&script_ctx) {
                                Ok(result) => {
                                    return self.handle_script_result(session, result).await;
                                }
                                Err(e) => {
                                    warn!(error = %e, "Script execution failed");
                                    return self.send_error_response(session, 500, "Script Error").await;
                                }
                            }
                        } else {
                            warn!("Script handler not compiled");
                            return self.send_error_response(session, 500, "Script Not Compiled").await;
                        }
                    }
                }
            }
        }

        self.send_error_response(session, 404, "Not Found").await
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let upstream = ctx.upstream.as_ref().ok_or_else(|| {
            pingora_core::Error::new(pingora_core::ErrorType::ConnectProxyFailure)
        })?;

        upstream.increment_connections();

        let mut peer = HttpPeer::new(
            upstream.address,
            upstream.use_tls,
            upstream.sni.clone().unwrap_or_default(),
        );

        // Apply timeout and connection pool configuration
        if let Some(ref timeouts) = ctx.timeouts {
            // Set connection timeout
            peer.options.connection_timeout = Some(Duration::from_secs(timeouts.connect));

            // Set read timeout
            peer.options.read_timeout = Some(Duration::from_secs(timeouts.read));

            // Set write timeout
            peer.options.write_timeout = Some(Duration::from_secs(timeouts.write));

            // Set idle timeout for connection pool
            peer.options.idle_timeout = Some(Duration::from_secs(timeouts.idle));

            // Configure TCP keepalive if enabled
            if timeouts.keepalive {
                peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
                    idle: Duration::from_secs(timeouts.keepalive_interval),
                    interval: Duration::from_secs(timeouts.keepalive_interval),
                    count: timeouts.keepalive_count as usize,
                    #[cfg(target_os = "linux")]
                    user_timeout: Duration::from_secs(0),
                });
            }

            debug!(
                connect_timeout = timeouts.connect,
                read_timeout = timeouts.read,
                write_timeout = timeouts.write,
                idle_timeout = timeouts.idle,
                keepalive = timeouts.keepalive,
                "Applied connection pool configuration"
            );
        }

        // Configure HTTP/2 upstream via ALPN if enabled (requires TLS)
        if ctx.upstream_http2 && upstream.use_tls {
            peer.options.alpn = pingora_core::protocols::ALPN::H2;
            debug!(upstream = %upstream.address_str, "Using HTTP/2 for upstream connection");
        }

        // Configure mTLS (mutual TLS) for upstream connections if enabled
        if let Some(ref mtls_config) = ctx.upstream_mtls {
            if upstream.use_tls {
                // Load client certificate and key
                match crate::upstream::load_mtls_connector(mtls_config) {
                    Ok(cert_key) => {
                        peer.client_cert_key = Some(cert_key);
                        debug!(
                            upstream = %upstream.address_str,
                            client_cert = %mtls_config.client_cert,
                            "Using mTLS for upstream connection"
                        );
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            upstream = %upstream.address_str,
                            "Failed to load mTLS configuration, continuing without client certificate"
                        );
                    }
                }
            } else {
                warn!(
                    upstream = %upstream.address_str,
                    "mTLS configuration ignored: upstream_tls is not enabled"
                );
            }
        }

        debug!(upstream = %upstream.address_str, "Connecting to upstream");
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // For WebSocket requests, ensure upgrade headers are preserved
        if ctx.is_websocket {
            // Collect WebSocket headers into owned strings to avoid lifetime issues
            let ws_headers: Vec<(String, String)> = {
                let original_headers = &session.req_header().headers;
                let mut headers = Vec::new();

                // Connection header
                if let Some(connection) = original_headers.get("connection") {
                    if let Ok(val) = connection.to_str() {
                        headers.push(("Connection".to_string(), val.to_string()));
                    }
                }

                // Upgrade header
                if let Some(upgrade) = original_headers.get("upgrade") {
                    if let Ok(val) = upgrade.to_str() {
                        headers.push(("Upgrade".to_string(), val.to_string()));
                    }
                }

                // Sec-WebSocket-* headers
                for (name, value) in original_headers.iter() {
                    let name_str = name.as_str().to_lowercase();
                    if name_str.starts_with("sec-websocket-") {
                        if let Ok(val) = value.to_str() {
                            headers.push((name.as_str().to_string(), val.to_string()));
                        }
                    }
                }

                headers
            };

            // Now insert the collected headers
            for (name, value) in ws_headers {
                upstream_request.insert_header(name, value)?;
            }

            debug!("WebSocket upgrade headers forwarded to upstream");
        }

        // Apply path rewriting if configured
        if let Some(rewrite) = &ctx.rewrite {
            if rewrite.has_path_rewrite() {
                let original_uri = upstream_request.uri.to_string();
                let new_uri = crate::rewrite::rewrite_uri(&original_uri, rewrite);

                if new_uri != original_uri {
                    debug!(original = %original_uri, new = %new_uri, "Rewriting request URI");
                    if let Ok(uri) = new_uri.parse() {
                        upstream_request.set_uri(uri);
                    }
                }
            }

            // Apply request header additions (won't override existing)
            for (name, value) in &rewrite.request_headers_add {
                if !upstream_request.headers.contains_key(name.as_str()) {
                    upstream_request.insert_header(name.clone(), value.clone())?;
                }
            }

            // Apply request header sets (will override)
            for (name, value) in &rewrite.request_headers_set {
                upstream_request.insert_header(name.clone(), value.clone())?;
            }

            // Apply request header deletions
            for name in &rewrite.request_headers_delete {
                upstream_request.remove_header(name);
            }
        }

        // Apply Rhai rewrite rules if configured
        if let Some(rhai_engine) = &ctx.rhai_rewrite {
            // Build request context for Rhai evaluation
            let uri = upstream_request.uri.to_string();
            let (path, query) = match uri.find('?') {
                Some(idx) => (uri[..idx].to_string(), uri[idx + 1..].to_string()),
                None => (uri.clone(), String::new()),
            };

            // Parse query string into params
            let query_params: std::collections::HashMap<String, String> = query
                .split('&')
                .filter(|p| !p.is_empty())
                .filter_map(|p| {
                    let mut parts = p.splitn(2, '=');
                    Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
                })
                .collect();

            // Collect headers
            let headers: std::collections::HashMap<String, String> = upstream_request
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let client_ip = session.client_addr().map(|a| {
                let s = a.to_string();
                s.split(':').next().unwrap_or(&s).to_string()
            });

            let rhai_ctx = RhaiRequestContext {
                method: upstream_request.method.as_str().to_string(),
                path,
                query,
                host: self.get_host(session).map(|s| s.to_string()),
                client_ip,
                headers,
                query_params,
            };

            // Process all rules
            match rhai_engine.process(&rhai_ctx) {
                Ok(result) => {
                    // Apply path rewrite from Rhai
                    if let Some(new_path) = &result.path {
                        let new_uri = if let Some(new_query) = &result.query {
                            if new_query.is_empty() {
                                new_path.clone()
                            } else {
                                format!("{}?{}", new_path, new_query)
                            }
                        } else if !rhai_ctx.query_params.is_empty() {
                            format!("{}?{}", new_path, rhai_ctx.query_params.iter()
                                .map(|(k, v)| format!("{}={}", k, v))
                                .collect::<Vec<_>>()
                                .join("&"))
                        } else {
                            new_path.clone()
                        };

                        debug!(original = %uri, new = %new_uri, "Rhai path rewrite");
                        if let Ok(parsed_uri) = new_uri.parse() {
                            upstream_request.set_uri(parsed_uri);
                        }
                    }

                    // Apply header additions
                    for (name, value) in &result.headers_add {
                        if !upstream_request.headers.contains_key(name.as_str()) {
                            let _ = upstream_request.insert_header(name.clone(), value.clone());
                        }
                    }

                    // Apply header sets
                    for (name, value) in &result.headers_set {
                        let _ = upstream_request.insert_header(name.clone(), value.clone());
                    }

                    // Apply header deletions
                    for name in &result.headers_delete {
                        upstream_request.remove_header(name);
                    }

                    debug!("Applied Rhai rewrite rules");
                }
                Err(e) => {
                    warn!(error = %e, "Rhai rewrite evaluation failed");
                }
            }
        }

        // Add X-Forwarded-For and X-Real-IP
        if let Some(client_addr) = session.client_addr() {
            let client_ip = client_addr.to_string();
            let client_ip = client_ip.split(':').next().unwrap_or(&client_ip);

            if let Some(existing) = upstream_request.headers.get("x-forwarded-for") {
                let new_value = format!("{}, {}", existing.to_str().unwrap_or(""), client_ip);
                upstream_request.insert_header("X-Forwarded-For", new_value)?;
            } else {
                upstream_request.insert_header("X-Forwarded-For", client_ip)?;
            }

            upstream_request.insert_header("X-Real-IP", client_ip)?;
        }

        // Add X-Forwarded-Host
        if let Some(host) = self.get_host(session) {
            upstream_request.insert_header("X-Forwarded-Host", host)?;
        }

        // Add X-Forwarded-Proto (TODO: detect TLS from session)
        let proto = if ctx.upstream.as_ref().is_some_and(|u| u.use_tls) {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header("X-Forwarded-Proto", proto)?;

        // Add custom upstream headers from config
        if let Some(HandlerType::ReverseProxy) = &ctx.handler_type {
            // Headers are already stored in ctx from request_filter
        }

        Ok(())
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        // Add failed upstream to tried list
        if let Some(upstream) = ctx.upstream.take() {
            warn!(upstream = %upstream.address_str, error = %e, "Failed to connect");
            ctx.tried_upstreams.push(upstream);
        }

        // Check if retry is enabled and we're within the deadline
        if ctx.lb_try_duration > 0 {
            if let Some(deadline) = ctx.retry_deadline {
                if Instant::now() < deadline {
                    // Try to select a different upstream
                    if let Some(selector) = &ctx.upstream_selector {
                        match selector.select_excluding(&ctx.tried_upstreams) {
                            Ok(new_upstream) => {
                                debug!(
                                    upstream = %new_upstream.address_str,
                                    tried = ctx.tried_upstreams.len(),
                                    "Retrying with different upstream"
                                );
                                ctx.upstream = Some(new_upstream);
                                e.set_retry(true);
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    tried = ctx.tried_upstreams.len(),
                                    "No more upstreams available for retry"
                                );
                            }
                        }
                    }
                } else {
                    warn!(
                        tried = ctx.tried_upstreams.len(),
                        "Retry deadline exceeded"
                    );
                }
            }
        }

        e
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let headers: Vec<(String, String)> = ctx.custom_headers_down
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (key, value) in headers {
            upstream_response.insert_header(key, value)?;
        }

        upstream_response.insert_header("Server", "avalon")?;

        // Add CORS headers to response if configured
        if let Some(cors) = &ctx.cors {
            if let Some(cors_headers) = cors.response_headers(ctx.request_origin.as_deref()) {
                for (name, value) in cors_headers {
                    upstream_response.insert_header(name, value)?;
                }
                debug!("CORS headers added to response");
            }
        }

        // Set session affinity cookie if needed
        if let Some((name, value, max_age)) = &ctx.affinity_cookie {
            let cookie = if *max_age > 0 {
                format!("{}={}; Path=/; Max-Age={}; HttpOnly", name, value, max_age)
            } else {
                format!("{}={}; Path=/; HttpOnly", name, value)
            };
            upstream_response.insert_header("Set-Cookie", cookie)?;
            debug!(cookie_name = %name, server_idx = %value, "Set session affinity cookie");
        }

        // Apply response header rewrites if configured
        if let Some(rewrite) = &ctx.rewrite {
            if rewrite.has_response_header_rewrite() {
                // Apply response header additions (won't override existing)
                for (name, value) in &rewrite.response_headers_add {
                    if !upstream_response.headers.contains_key(name.as_str()) {
                        upstream_response.insert_header(name.clone(), value.clone())?;
                    }
                }

                // Apply response header sets (will override)
                for (name, value) in &rewrite.response_headers_set {
                    upstream_response.insert_header(name.clone(), value.clone())?;
                }

                // Apply response header deletions
                for name in &rewrite.response_headers_delete {
                    upstream_response.remove_header(name);
                }

                debug!("Applied response header rewrites");
            }
        }

        // Check content type for compression eligibility
        let content_type = upstream_response.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        ctx.response_content_type = content_type.clone();

        // Check if already compressed
        let content_encoding = upstream_response.headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok());
        ctx.response_already_compressed = is_already_compressed(content_encoding);

        // Store response status for caching
        ctx.response_status = upstream_response.status.as_u16();

        // Check if response is cacheable and store headers
        if let (Some(cache), Some(cache_key)) = (&self.cache, &ctx.cache_key) {
            // Collect response headers for caching (excluding hop-by-hop headers)
            let cacheable_headers: Vec<(String, String)> = upstream_response.headers
                .iter()
                .filter(|(name, _)| {
                    let n = name.as_str().to_lowercase();
                    !["connection", "keep-alive", "transfer-encoding", "te",
                      "trailer", "proxy-authorization", "proxy-authenticate",
                      "upgrade", "content-length"].contains(&n.as_str())
                })
                .map(|(name, value)| {
                    (name.as_str().to_string(), value.to_str().unwrap_or("").to_string())
                })
                .collect();

            ctx.response_headers = cacheable_headers.clone();

            // Check if we should cache this response
            let method = cache_key.method.as_str();
            if cache.is_cacheable(method, ctx.response_status, &cacheable_headers) {
                ctx.should_cache = true;
                upstream_response.insert_header("X-Cache", "MISS")?;
                debug!(key = %cache_key.to_string_key(), status = ctx.response_status, "Response will be cached");
            }
        }

        // Determine if we should compress this response
        let should_compress = ctx.compression_encoding != CompressionEncoding::Identity
            && !ctx.response_already_compressed
            && !ctx.is_websocket
            && should_compress_content_type(content_type.as_deref());

        // Check Content-Length to skip compression for small responses
        // This prevents the "invalid header" error when we set Content-Encoding
        // but the body is too small to actually compress
        let content_length = upstream_response.headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        // Only skip compression if we KNOW the size is too small
        // For chunked/streaming responses (no Content-Length), we always try to compress
        let skip_due_to_size = content_length
            .map(|len| len < self.compression_config.min_size)
            .unwrap_or(false);

        if should_compress && !skip_due_to_size {
            // Remove Content-Length as it will change after compression
            upstream_response.remove_header("content-length");
            // Set Transfer-Encoding: chunked since we don't know the compressed size yet
            upstream_response.insert_header("Transfer-Encoding", "chunked")?;
            // Set Content-Encoding header
            upstream_response.insert_header("Content-Encoding", ctx.compression_encoding.header_value())?;
            // Add Vary header to indicate content varies by Accept-Encoding
            upstream_response.insert_header("Vary", "Accept-Encoding")?;

            debug!(
                encoding = %ctx.compression_encoding.header_value(),
                content_type = ?content_type,
                content_length = ?content_length,
                "Response will be compressed"
            );
        } else if should_compress && skip_due_to_size {
            // Reset compression encoding since we won't compress
            ctx.compression_encoding = CompressionEncoding::Identity;
            debug!(
                content_length = ?content_length,
                min_size = self.compression_config.min_size,
                "Skipping compression: response too small"
            );
        }

        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Determine if we need compression
        let should_compress = ctx.compression_encoding != CompressionEncoding::Identity
            && !ctx.response_already_compressed
            && !ctx.is_websocket
            && should_compress_content_type(ctx.response_content_type.as_deref());

        // We need to buffer if we're compressing OR caching
        let should_buffer = should_compress || ctx.should_cache;

        if !should_buffer {
            return Ok(None);
        }

        // Buffer the response body
        if let Some(b) = body.take() {
            ctx.response_body_buffer.extend_from_slice(&b);
        }

        // Process when we have the complete response
        if end_of_stream && !ctx.response_body_buffer.is_empty() {
            // Store in cache if caching is enabled (always cache uncompressed body)
            if ctx.should_cache {
                if let (Some(cache), Some(cache_key)) = (&self.cache, &ctx.cache_key) {
                    let ttl = cache.parse_ttl(&ctx.response_headers);

                    let cached_response = CachedResponse {
                        status: StatusCode::from_u16(ctx.response_status).unwrap_or(StatusCode::OK),
                        headers: ctx.response_headers.clone(),
                        body: Bytes::copy_from_slice(&ctx.response_body_buffer),
                        cached_at: Instant::now(),
                        ttl,
                        etag: ctx.response_headers.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                            .map(|(_, v)| v.clone()),
                        last_modified: ctx.response_headers.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
                            .map(|(_, v)| v.clone()),
                    };

                    cache.put(cache_key, cached_response);
                    debug!(
                        key = %cache_key.to_string_key(),
                        size = ctx.response_body_buffer.len(),
                        ttl = ?ttl,
                        "Response cached"
                    );
                }
            }

            // Apply compression if needed
            // Note: Size check was already done in upstream_response_filter based on Content-Length
            // If we're here with should_compress=true, we should always compress
            if should_compress {
                // Compress the body
                match compress(&ctx.response_body_buffer, ctx.compression_encoding, self.compression_config.level) {
                    Ok(compressed) => {
                        debug!(
                            original_size = ctx.response_body_buffer.len(),
                            compressed_size = compressed.len(),
                            encoding = %ctx.compression_encoding.header_value(),
                            "Response compressed"
                        );
                        *body = Some(compressed);
                    }
                    Err(e) => {
                        warn!(error = %e, "Compression failed, sending uncompressed");
                        *body = Some(Bytes::copy_from_slice(&ctx.response_body_buffer));
                    }
                }
            } else {
                // Just pass through the buffered body (caching without compression)
                *body = Some(Bytes::copy_from_slice(&ctx.response_body_buffer));
            }
        }

        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        if let Some(upstream) = &ctx.upstream {
            upstream.decrement_connections();
            // Record upstream request metric
            metrics().upstream_requests.inc(&upstream.address_str);
        }

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let method = session.req_header().method.as_str();
        let path = session.req_header().uri.path();
        let host = self.get_host(session).unwrap_or("-");
        let duration_ms = ctx.request_start.elapsed().as_millis() as u64;
        let duration_secs = ctx.request_start.elapsed().as_secs_f64();

        // Record metrics
        metrics().requests_total.inc();
        metrics().requests_by_status.inc(&status.to_string());
        metrics().requests_by_method.inc(method);
        metrics().requests_by_host.inc(host);
        metrics().request_duration.observe(duration_secs);

        // Write to access log if configured
        if let Some(logger) = &self.access_logger {
            let client_ip = session
                .client_addr()
                .map(|a| {
                    let s = a.to_string();
                    s.split(':').next().unwrap_or(&s).to_string()
                })
                .unwrap_or_else(|| "-".to_string());

            let user_agent = session
                .req_header()
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string();

            let referer = session
                .req_header()
                .headers
                .get("referer")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string();

            let entry = AccessLogEntry {
                timestamp: Utc::now(),
                client_ip,
                method: method.to_string(),
                path: path.to_string(),
                host: host.to_string(),
                status,
                bytes_sent: 0, // TODO: track actual bytes sent
                user_agent,
                referer,
                duration_ms,
                is_websocket: ctx.is_websocket,
            };

            logger.log(&entry);
        }

        // Also log via tracing
        if ctx.is_websocket {
            info!(method = %method, path = %path, host = %host, status = %status, duration_ms = %duration_ms, websocket = true, "WebSocket request completed");
        } else {
            info!(method = %method, path = %path, host = %host, status = %status, duration_ms = %duration_ms, "Request completed");
        }
    }
}

impl AvalonProxy {
    async fn send_error_response(&self, session: &mut Session, status: u16, message: &str) -> Result<bool> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = format!("{} {}", status, message);

        let mut header = ResponseHeader::build(status_code, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Server", "avalon")?;

        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(body.into()), true).await?;

        Ok(true)
    }

    async fn send_auth_response(&self, session: &mut Session, request_auth: bool, realm: Option<&str>) -> Result<bool> {
        let (status_code, body) = if request_auth {
            (StatusCode::UNAUTHORIZED, "401 Unauthorized")
        } else {
            (StatusCode::FORBIDDEN, "403 Forbidden")
        };

        let mut header = ResponseHeader::build(status_code, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Server", "avalon")?;

        // Add WWW-Authenticate header for 401 responses (Basic auth challenge)
        if request_auth {
            let realm_value = realm.unwrap_or("Restricted");
            header.insert_header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm_value))?;
        }

        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(body.into()), true).await?;

        Ok(true)
    }

    async fn send_cors_preflight_response(&self, session: &mut Session, cors_headers: Vec<(String, String)>) -> Result<bool> {
        let mut header = ResponseHeader::build(StatusCode::NO_CONTENT, None)?;
        header.insert_header("Server", "avalon")?;
        header.insert_header("Content-Length", "0")?;

        for (name, value) in cors_headers {
            header.insert_header(name, value)?;
        }

        session.write_response_header(Box::new(header), true).await?;
        Ok(true)
    }

    async fn handle_script_result(&self, session: &mut Session, result: ScriptResult) -> Result<bool> {
        match result {
            ScriptResult::Response { status, body, headers } => {
                let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                let mut header = ResponseHeader::build(status_code, None)?;
                header.insert_header("Server", "avalon")?;

                for (name, value) in headers {
                    header.insert_header(name, value)?;
                }

                if !body.is_empty() {
                    header.insert_header("Content-Length", body.len().to_string())?;
                }

                session.write_response_header(Box::new(header), body.is_empty()).await?;
                if !body.is_empty() {
                    session.write_response_body(Some(body.into()), true).await?;
                }

                Ok(true)
            }
            ScriptResult::Redirect { location, code } => {
                let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);
                let mut header = ResponseHeader::build(status, None)?;
                header.insert_header("Location", location)?;
                header.insert_header("Server", "avalon")?;

                session.write_response_header(Box::new(header), true).await?;
                Ok(true)
            }
            ScriptResult::Proxy { upstream } => {
                // For now, just return an error - proxy delegation would need more work
                // to integrate with the upstream selection system
                warn!(upstream = %upstream, "Script proxy delegation not yet implemented");
                self.send_error_response(session, 501, "Script proxy not implemented").await
            }
            ScriptResult::File { path } => {
                // Serve file using FileServer
                let file_server = FileServer::new("/").with_browse(false);
                let response = file_server.serve(&path).await;

                let mut header = ResponseHeader::build(response.status, None)?;
                header.insert_header("Content-Type", response.content_type.clone())?;
                header.insert_header("Content-Length", response.body.len().to_string())?;
                header.insert_header("Server", "avalon")?;

                for (key, value) in &response.headers {
                    header.insert_header(key.clone(), value.clone())?;
                }

                session.write_response_header(Box::new(header), response.body.is_empty()).await?;
                if !response.body.is_empty() {
                    session.write_response_body(Some(response.body), true).await?;
                }

                Ok(true)
            }
        }
    }
}
