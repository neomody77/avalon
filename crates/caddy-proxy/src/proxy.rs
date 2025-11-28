//! Main proxy implementation using Pingora's ProxyHttp trait

use crate::file_server::FileServer;
use crate::route::RoutingContext;
use crate::upstream::UpstreamServer;
use async_trait::async_trait;
use caddy_core::{Config, HandlerConfig};
use caddy_tls::ChallengeTokens;
use http::StatusCode;
use parking_lot::RwLock;
use pingora::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
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
}

impl CaddyProxy {
    pub fn new(config: Config, acme_tokens: ChallengeTokens) -> Result<Self, ProxyError> {
        let routing = Arc::new(RoutingContext::new());
        routing
            .load_config(&config.servers)
            .map_err(|e| ProxyError::ConfigError(e.to_string()))?;

        Ok(Self {
            routing,
            acme_tokens,
            config: Arc::new(RwLock::new(config)),
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
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
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

        upstream_request.insert_header("X-Forwarded-Proto", "http")?;

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

        Ok(())
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

        info!(method = %method, path = %path, host = %host, status = %status, "Request completed");
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
