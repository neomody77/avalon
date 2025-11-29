//! Main proxy implementation using Pingora's ProxyHttp trait

use crate::access_log::{AccessLogEntry, AccessLogger, LogFormat};
use crate::compression::{
    CompressionConfig, CompressionEncoding, is_already_compressed,
    select_encoding, should_compress_content_type, compress,
};
use crate::file_server::FileServer;
use crate::route::RoutingContext;
use crate::upstream::UpstreamServer;
use async_trait::async_trait;
use bytes::Bytes;
use caddy_core::{Config, HandlerConfig};
use caddy_tls::ChallengeTokens;
use chrono::Utc;
use http::StatusCode;
use parking_lot::RwLock;
use pingora::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

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
}

#[derive(Clone)]
pub enum HandlerType {
    ReverseProxy,
    StaticResponse,
    Redirect,
    FileServer,
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
        }
    }
}

impl Default for RequestCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// Main Caddy proxy implementation
pub struct CaddyProxy {
    routing: Arc<RoutingContext>,
    acme_tokens: ChallengeTokens,
    config: Arc<RwLock<Config>>,
    access_logger: Option<AccessLogger>,
    compression_config: CompressionConfig,
}

impl CaddyProxy {
    pub fn new(config: Config, acme_tokens: ChallengeTokens) -> Result<Self, ProxyError> {
        let routing = Arc::new(RoutingContext::new());
        routing
            .load_config(&config.servers)
            .map_err(|e| ProxyError::ConfigError(e.to_string()))?;

        // Initialize access logger if configured
        let access_logger = if let Some(path) = &config.global.access_log {
            let format = LogFormat::from_str(&config.global.access_log_format);
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

        Ok(Self {
            routing,
            acme_tokens,
            config: Arc::new(RwLock::new(config)),
            access_logger,
            compression_config,
        })
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

impl Clone for CaddyProxy {
    fn clone(&self) -> Self {
        Self {
            routing: self.routing.clone(),
            acme_tokens: self.acme_tokens.clone(),
            config: self.config.clone(),
            access_logger: self.access_logger.clone(),
            compression_config: self.compression_config.clone(),
        }
    }
}

#[async_trait]
impl ProxyHttp for CaddyProxy {
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

        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
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
                    header.insert_header("Server", "caddy-rs")?;

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
                            match upstream_selector.select() {
                                Ok(upstream) => {
                                    ctx.handler_type = Some(HandlerType::ReverseProxy);
                                    ctx.upstream = Some(upstream);

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
                        header.insert_header("Server", "caddy-rs")?;

                        for (key, value) in &response.headers {
                            header.insert_header(key.clone(), value.clone())?;
                        }

                        session.write_response_header(Box::new(header), response.body.is_empty()).await?;
                        if !response.body.is_empty() {
                            session.write_response_body(Some(response.body), true).await?;
                        }

                        return Ok(true);
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

        let peer = HttpPeer::new(
            upstream.address,
            upstream.use_tls,
            upstream.sni.clone().unwrap_or_default(),
        );

        debug!(upstream = %upstream.address_str, "Connecting to upstream");
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
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
        let proto = if ctx.upstream.as_ref().map_or(false, |u| u.use_tls) {
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
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        if let Some(upstream) = &ctx.upstream {
            warn!(upstream = %upstream.address_str, error = %e, "Failed to connect");
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

        upstream_response.insert_header("Server", "caddy-rs")?;

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

        // Determine if we should compress this response
        let should_compress = ctx.compression_encoding != CompressionEncoding::Identity
            && !ctx.response_already_compressed
            && !ctx.is_websocket
            && should_compress_content_type(content_type.as_deref());

        if should_compress {
            // Remove Content-Length as it will change after compression
            upstream_response.remove_header("content-length");
            // Set Content-Encoding header
            upstream_response.insert_header("Content-Encoding", ctx.compression_encoding.header_value())?;
            // Add Vary header to indicate content varies by Accept-Encoding
            upstream_response.insert_header("Vary", "Accept-Encoding")?;

            debug!(
                encoding = %ctx.compression_encoding.header_value(),
                content_type = ?content_type,
                "Response will be compressed"
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
        // Skip compression for WebSocket, already compressed, or non-compressible content
        let should_compress = ctx.compression_encoding != CompressionEncoding::Identity
            && !ctx.response_already_compressed
            && !ctx.is_websocket
            && should_compress_content_type(ctx.response_content_type.as_deref());

        if !should_compress {
            return Ok(None);
        }

        // Buffer the response body
        if let Some(b) = body.take() {
            ctx.response_body_buffer.extend_from_slice(&b);
        }

        // Only compress when we have the complete response
        if end_of_stream && !ctx.response_body_buffer.is_empty() {
            // Skip if body is too small
            if ctx.response_body_buffer.len() < self.compression_config.min_size {
                *body = Some(Bytes::copy_from_slice(&ctx.response_body_buffer));
                return Ok(None);
            }

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
        }

        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        if let Some(upstream) = &ctx.upstream {
            upstream.decrement_connections();
        }

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let method = session.req_header().method.as_str();
        let path = session.req_header().uri.path();
        let host = self.get_host(session).unwrap_or("-");
        let duration_ms = ctx.request_start.elapsed().as_millis() as u64;

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

impl CaddyProxy {
    async fn send_error_response(&self, session: &mut Session, status: u16, message: &str) -> Result<bool> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = format!("{} {}", status, message);

        let mut header = ResponseHeader::build(status_code, None)?;
        header.insert_header("Content-Type", "text/plain")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Server", "caddy-rs")?;

        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(body.into()), true).await?;

        Ok(true)
    }
}
