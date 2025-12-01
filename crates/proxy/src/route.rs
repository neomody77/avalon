//! Route matching and routing table

use crate::auth::CompiledAuth;
use crate::cors::CompiledCors;
use crate::error::Result;
use crate::ip_filter::{CompiledIpFilter, IpFilterConfig};
use crate::rewrite::CompiledRewrite;
use crate::rhai_rewrite::{RhaiRewriteConfig, RhaiRewriteEngine};
use crate::script_handler::CompiledScriptHandler;
use crate::upstream::UpstreamSelector;
use config::{HandlerConfig, MatchConfig, RouteConfig, ServerConfig};
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, warn};

/// A compiled route ready for matching
pub struct CompiledRoute {
    pub matcher: MatchConfig,
    pub handler: HandlerConfig,
    pub upstream: Option<Arc<UpstreamSelector>>,
    pub rewrite: Option<Arc<CompiledRewrite>>,
    pub rhai_rewrite: Option<Arc<RhaiRewriteEngine>>,
    pub auth: Option<Arc<CompiledAuth>>,
    pub cors: Option<Arc<CompiledCors>>,
    pub script_handler: Option<Arc<CompiledScriptHandler>>,
    pub ip_filter: Option<Arc<CompiledIpFilter>>,
}

impl CompiledRoute {
    pub fn from_config(config: &RouteConfig) -> Result<Self> {
        let (upstream, rewrite, rhai_rewrite, auth, cors, script_handler, ip_filter) = match &config.handle {
            HandlerConfig::ReverseProxy(proxy_config) => {
                let selector = UpstreamSelector::new(
                    &proxy_config.upstreams,
                    proxy_config.load_balancing.clone(),
                    proxy_config.upstream_tls,
                )?;

                // Compile rewrite rules if configured
                let compiled_rewrite = if let Some(ref rewrite_config) = proxy_config.rewrite {
                    match CompiledRewrite::from_config(rewrite_config) {
                        Ok(r) => {
                            debug!(
                                strip_prefix = ?rewrite_config.strip_path_prefix,
                                add_prefix = ?rewrite_config.add_path_prefix,
                                "Compiled rewrite rules"
                            );
                            Some(Arc::new(r))
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to compile rewrite rules, skipping");
                            None
                        }
                    }
                } else {
                    None
                };

                // Compile Rhai rewrite rules if configured
                let compiled_rhai_rewrite = if let Some(ref rewrite_config) = proxy_config.rewrite {
                    if !rewrite_config.rhai_rules.is_empty() {
                        let rhai_configs: Vec<RhaiRewriteConfig> = rewrite_config.rhai_rules.iter().map(|r| {
                            RhaiRewriteConfig {
                                when: r.when.clone(),
                                path: r.path.clone(),
                                query: r.query.clone(),
                                headers_set: r.headers_set.clone(),
                                headers_add: r.headers_add.clone(),
                                headers_delete: r.headers_delete.clone(),
                                action: r.action.clone(),
                                redirect_location: r.redirect_location.clone(),
                                redirect_status: r.redirect_status,
                                reject_status: r.reject_status,
                                reject_body: r.reject_body.clone(),
                                stop: r.stop,
                                script: r.script.clone(),
                            }
                        }).collect();

                        match RhaiRewriteEngine::new(rhai_configs) {
                            Ok(engine) => {
                                debug!(rules = rewrite_config.rhai_rules.len(), "Compiled Rhai rewrite rules");
                                Some(Arc::new(engine))
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to compile Rhai rewrite rules, skipping");
                                None
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Compile auth rules if configured
                let compiled_auth = if let Some(ref auth_config) = proxy_config.auth {
                    let auth = CompiledAuth::from_config(auth_config);
                    if auth.has_auth() {
                        debug!("Compiled auth rules for route");
                        Some(Arc::new(auth))
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Compile CORS rules if configured
                let compiled_cors = if let Some(ref cors_config) = proxy_config.cors {
                    let cors = CompiledCors::from_config(cors_config);
                    if cors.is_enabled() {
                        debug!("Compiled CORS rules for route");
                        Some(Arc::new(cors))
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Compile IP filter rules if configured
                let compiled_ip_filter = if let Some(ref ip_filter_config) = proxy_config.ip_filter {
                    let filter_config = IpFilterConfig {
                        allow: ip_filter_config.allow.clone(),
                        deny: ip_filter_config.deny.clone(),
                    };
                    let filter = CompiledIpFilter::from_config(&filter_config);
                    if filter.is_active() {
                        debug!("Compiled IP filter rules for route");
                        Some(Arc::new(filter))
                    } else {
                        None
                    }
                } else {
                    None
                };

                (Some(Arc::new(selector)), compiled_rewrite, compiled_rhai_rewrite, compiled_auth, compiled_cors, None, compiled_ip_filter)
            }
            HandlerConfig::Script(script_config) => {
                match CompiledScriptHandler::compile(&script_config.script) {
                    Ok(handler) => {
                        debug!("Compiled script handler");
                        (None, None, None, None, None, Some(Arc::new(handler)), None)
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to compile script handler, skipping");
                        (None, None, None, None, None, None, None)
                    }
                }
            }
            _ => (None, None, None, None, None, None, None),
        };

        Ok(Self {
            matcher: config.match_rule.clone(),
            handler: config.handle.clone(),
            upstream,
            rewrite,
            rhai_rewrite,
            auth,
            cors,
            script_handler,
            ip_filter,
        })
    }

    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        self.matcher.matches(host, path, method)
    }
}

/// Route table for a server
pub struct RouteTable {
    pub routes: Vec<CompiledRoute>,
    server_name: String,
    pub https_redirect: bool,
}

impl RouteTable {
    pub fn from_config(config: &ServerConfig) -> Result<Self> {
        let routes: Result<Vec<_>> = config.routes.iter().map(CompiledRoute::from_config).collect();

        Ok(Self {
            routes: routes?,
            server_name: config.name.clone(),
            https_redirect: config.https_redirect,
        })
    }

    pub fn should_redirect_https(&self) -> bool {
        self.https_redirect
    }

    pub fn match_route(&self, host: Option<&str>, path: &str, method: &str) -> Option<&CompiledRoute> {
        for route in &self.routes {
            if route.matches(host, path, method) {
                debug!(server = %self.server_name, host = ?host, path = %path, "Route matched");
                return Some(route);
            }
        }

        debug!(server = %self.server_name, host = ?host, path = %path, "No route matched");
        None
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Global routing context
pub struct RoutingContext {
    tables: RwLock<Vec<Arc<RouteTable>>>,
}

impl RoutingContext {
    pub fn new() -> Self {
        Self {
            tables: RwLock::new(Vec::new()),
        }
    }

    pub fn load_config(&self, servers: &[ServerConfig]) -> Result<()> {
        let tables: Result<Vec<_>> = servers
            .iter()
            .map(|s| Ok(Arc::new(RouteTable::from_config(s)?)))
            .collect();

        *self.tables.write() = tables?;
        Ok(())
    }

    pub fn tables(&self) -> Vec<Arc<RouteTable>> {
        self.tables.read().clone()
    }

    pub fn get_all_upstreams(&self) -> Vec<Arc<UpstreamSelector>> {
        let tables = self.tables.read();
        let mut upstreams = Vec::new();

        for table in tables.iter() {
            for route in &table.routes {
                if let Some(upstream) = &route.upstream {
                    upstreams.push(upstream.clone());
                }
            }
        }

        upstreams
    }
}

impl Default for RoutingContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{LoadBalancingStrategy, ReverseProxyConfig, StaticResponseConfig, RedirectConfig, TimeoutConfig};
    use std::collections::HashMap;

    fn make_test_config() -> ServerConfig {
        ServerConfig {
            name: "test".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![RouteConfig {
                match_rule: MatchConfig {
                    host: Some(vec!["example.com".to_string()]),
                    path: Some(vec!["/api".to_string()]),
                    method: None,
                    header: None,
                },
                handle: HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
                    upstreams: vec!["127.0.0.1:9090".to_string()],
                    load_balancing: LoadBalancingStrategy::RoundRobin,
                    health_check: None,
                    headers_up: Default::default(),
                    headers_down: Default::default(),
                    timeout: 30,
                    upstream_tls: false,
                    session_affinity: None,
                    rewrite: None,
                    auth: None,
                    cors: None,
                    lb_try_duration: 0,
                    lb_try_interval: 250,
                    timeouts: TimeoutConfig::default(),
                    max_request_body_size: 0,
                    circuit_breaker: None,
                    ip_filter: None,
                    upstream_http2: false,
                    upstream_mtls: None,
                })),
            }],
            https_redirect: false,
        }
    }

    #[test]
    fn test_route_matching() {
        let config = make_test_config();
        let table = RouteTable::from_config(&config).unwrap();

        assert!(table.match_route(Some("example.com"), "/api/users", "GET").is_some());
        assert!(table.match_route(Some("other.com"), "/api/users", "GET").is_none());
        assert!(table.match_route(Some("example.com"), "/web", "GET").is_none());
    }

    #[test]
    fn test_route_table_len() {
        let config = make_test_config();
        let table = RouteTable::from_config(&config).unwrap();
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_route_table_empty() {
        let config = ServerConfig {
            name: "empty".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![],
            https_redirect: false,
        };
        let table = RouteTable::from_config(&config).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_multiple_routes_priority() {
        let config = ServerConfig {
            name: "multi".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![
                RouteConfig {
                    match_rule: MatchConfig {
                        host: Some(vec!["example.com".to_string()]),
                        path: Some(vec!["/api/v2".to_string()]),
                        method: None,
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: "v2".to_string(),
                        headers: HashMap::new(),
                    }),
                },
                RouteConfig {
                    match_rule: MatchConfig {
                        host: Some(vec!["example.com".to_string()]),
                        path: Some(vec!["/api".to_string()]),
                        method: None,
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: "v1".to_string(),
                        headers: HashMap::new(),
                    }),
                },
            ],
            https_redirect: false,
        };
        let table = RouteTable::from_config(&config).unwrap();

        let matched = table.match_route(Some("example.com"), "/api/v2/users", "GET").unwrap();
        if let HandlerConfig::StaticResponse(cfg) = &matched.handler {
            assert_eq!(cfg.body, "v2");
        }
    }

    #[test]
    fn test_catch_all_route() {
        let config = ServerConfig {
            name: "catchall".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![
                RouteConfig {
                    match_rule: MatchConfig {
                        host: Some(vec!["api.example.com".to_string()]),
                        path: None,
                        method: None,
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: "api".to_string(),
                        headers: HashMap::new(),
                    }),
                },
                RouteConfig {
                    match_rule: MatchConfig::default(),
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 404,
                        body: "not found".to_string(),
                        headers: HashMap::new(),
                    }),
                },
            ],
            https_redirect: false,
        };
        let table = RouteTable::from_config(&config).unwrap();

        let matched = table.match_route(Some("other.com"), "/anything", "GET").unwrap();
        if let HandlerConfig::StaticResponse(cfg) = &matched.handler {
            assert_eq!(cfg.body, "not found");
        }
    }

    #[test]
    fn test_method_matching() {
        let config = ServerConfig {
            name: "methods".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![
                RouteConfig {
                    match_rule: MatchConfig {
                        host: None,
                        path: Some(vec!["/api".to_string()]),
                        method: Some(vec!["POST".to_string()]),
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: "write".to_string(),
                        headers: HashMap::new(),
                    }),
                },
                RouteConfig {
                    match_rule: MatchConfig {
                        host: None,
                        path: Some(vec!["/api".to_string()]),
                        method: Some(vec!["GET".to_string()]),
                        header: None,
                    },
                    handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                        status: 200,
                        body: "read".to_string(),
                        headers: HashMap::new(),
                    }),
                },
            ],
            https_redirect: false,
        };
        let table = RouteTable::from_config(&config).unwrap();

        let matched = table.match_route(None, "/api/resource", "POST").unwrap();
        if let HandlerConfig::StaticResponse(cfg) = &matched.handler {
            assert_eq!(cfg.body, "write");
        }

        let matched = table.match_route(None, "/api/resource", "GET").unwrap();
        if let HandlerConfig::StaticResponse(cfg) = &matched.handler {
            assert_eq!(cfg.body, "read");
        }

        assert!(table.match_route(None, "/api/resource", "DELETE").is_none());
    }

    #[test]
    fn test_routing_context() {
        let servers = vec![ServerConfig {
            name: "server1".to_string(),
            listen: vec![":8080".to_string()],
            routes: vec![RouteConfig {
                match_rule: MatchConfig {
                    host: Some(vec!["server1.com".to_string()]),
                    path: None,
                    method: None,
                    header: None,
                },
                handle: HandlerConfig::StaticResponse(StaticResponseConfig {
                    status: 200,
                    body: "server1".to_string(),
                    headers: HashMap::new(),
                }),
            }],
            https_redirect: false,
        }];

        let ctx = RoutingContext::new();
        ctx.load_config(&servers).unwrap();

        assert_eq!(ctx.tables().len(), 1);
    }

    #[test]
    fn test_compiled_route_with_upstream() {
        let route_config = RouteConfig {
            match_rule: MatchConfig::default(),
            handle: HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
                upstreams: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
                load_balancing: LoadBalancingStrategy::RoundRobin,
                health_check: None,
                headers_up: HashMap::new(),
                headers_down: HashMap::new(),
                timeout: 30,
                upstream_tls: false,
                session_affinity: None,
                rewrite: None,
                auth: None,
                cors: None,
                lb_try_duration: 0,
                lb_try_interval: 250,
                timeouts: TimeoutConfig::default(),
                max_request_body_size: 0,
                circuit_breaker: None,
                ip_filter: None,
                upstream_http2: false,
                upstream_mtls: None,
            })),
        };

        let compiled = CompiledRoute::from_config(&route_config).unwrap();
        assert!(compiled.upstream.is_some());
        assert_eq!(compiled.upstream.as_ref().unwrap().servers().len(), 2);
    }

    #[test]
    fn test_compiled_route_without_upstream() {
        let route_config = RouteConfig {
            match_rule: MatchConfig::default(),
            handle: HandlerConfig::Redirect(RedirectConfig {
                to: "https://example.com".to_string(),
                code: 301,
            }),
        };

        let compiled = CompiledRoute::from_config(&route_config).unwrap();
        assert!(compiled.upstream.is_none());
    }
}
