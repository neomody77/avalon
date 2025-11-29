//! Plugin integration module for CaddyProxy
//!
//! This module provides integration between the proxy and the plugin system,
//! including hook execution at various stages of request processing.

use caddy_plugin::{
    HookAction, HookExecutor, PluginContext, PluginRegistry,
    RequestInfo, ResponseInfo, UpstreamInfo, UpstreamSelection,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// Plugin system state
pub struct PluginState {
    /// The plugin registry
    pub registry: Arc<PluginRegistry>,
    /// The hook executor
    pub executor: HookExecutor,
}

impl PluginState {
    /// Create a new plugin state with an empty registry
    pub fn new() -> Self {
        let registry = Arc::new(PluginRegistry::new());
        let executor = HookExecutor::new(registry.clone());
        Self { registry, executor }
    }

    /// Create a plugin state with an existing registry
    pub fn with_registry(registry: Arc<PluginRegistry>) -> Self {
        let executor = HookExecutor::new(registry.clone());
        Self { registry, executor }
    }
}

impl Default for PluginState {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for PluginState {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            executor: HookExecutor::new(self.registry.clone()),
        }
    }
}

/// Convert Pingora request info to plugin RequestInfo
pub fn to_plugin_request(
    method: &str,
    path: &str,
    host: Option<&str>,
    query: Option<&str>,
    headers: &[(String, String)],
) -> RequestInfo {
    let mut info = RequestInfo {
        method: method.to_string(),
        path: path.to_string(),
        host: host.map(|s| s.to_string()),
        query: query.map(|s| s.to_string()),
        headers: HashMap::new(),
    };
    for (k, v) in headers {
        info.headers.insert(k.clone(), v.clone());
    }
    info
}

/// Convert plugin RequestInfo back to headers
pub fn from_plugin_request(info: &RequestInfo) -> Vec<(String, String)> {
    info.headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Convert response status and headers to plugin ResponseInfo
pub fn to_plugin_response(status: u16, headers: &[(String, String)]) -> ResponseInfo {
    let mut info = ResponseInfo {
        status,
        headers: HashMap::new(),
    };
    for (k, v) in headers {
        info.headers.insert(k.clone(), v.clone());
    }
    info
}

/// Convert plugin ResponseInfo back to headers
pub fn from_plugin_response(info: &ResponseInfo) -> Vec<(String, String)> {
    info.headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Create UpstreamInfo from upstream data
pub fn to_upstream_info(
    address: &str,
    healthy: bool,
    weight: u32,
    active_connections: usize,
    total_requests: u64,
    failed_requests: u64,
) -> UpstreamInfo {
    UpstreamInfo {
        address: address.to_string(),
        healthy,
        weight,
        active_connections,
        total_requests,
        failed_requests,
    }
}

/// Helper trait for running hooks with error handling
pub trait HookRunner {
    /// Run early request hooks
    fn run_early_request(
        &self,
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult;

    /// Run request filter hooks
    fn run_request_filter(
        &self,
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult;

    /// Run route selection hooks
    fn run_route_selection(
        &self,
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Option<String>;

    /// Run upstream selection hooks
    fn run_upstream_selection(
        &self,
        executor: &HookExecutor,
        upstreams: &[UpstreamInfo],
        ctx: &mut PluginContext,
    ) -> Option<UpstreamSelection>;

    /// Run upstream request hooks
    fn run_upstream_request(
        &self,
        executor: &HookExecutor,
        request: &mut RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult;

    /// Run response filter hooks
    fn run_response_filter(
        &self,
        executor: &HookExecutor,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> HookResult;

    /// Run logging hooks
    fn run_logging(
        &self,
        executor: &HookExecutor,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        error: Option<&str>,
        ctx: &PluginContext,
    );
}

/// Result of hook execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookResult {
    /// Continue normal processing
    Continue,
    /// Short-circuit the request (response already sent)
    ShortCircuit,
    /// An error occurred
    Error,
}

impl From<HookAction> for HookResult {
    fn from(action: HookAction) -> Self {
        match action {
            HookAction::Continue => HookResult::Continue,
            HookAction::SkipPhase => HookResult::Continue,
            HookAction::ShortCircuit => HookResult::ShortCircuit,
        }
    }
}

/// Synchronous hook runner implementation
pub struct SyncHookRunner;

impl SyncHookRunner {
    /// Run early request hooks synchronously
    pub async fn run_early_request(
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult {
        match executor.run_early_request_hooks(request, ctx).await {
            Ok(action) => action.into(),
            Err(e) => {
                warn!(error = %e, "Early request hook error");
                HookResult::Error
            }
        }
    }

    /// Run request filter hooks synchronously
    pub async fn run_request_filter(
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult {
        match executor.run_request_filter_hooks(request, ctx).await {
            Ok(action) => action.into(),
            Err(e) => {
                warn!(error = %e, "Request filter hook error");
                HookResult::Error
            }
        }
    }

    /// Run route selection hooks
    pub async fn run_route_selection(
        executor: &HookExecutor,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Option<String> {
        match executor.run_route_hooks(request, ctx).await {
            Ok(route) => route,
            Err(e) => {
                warn!(error = %e, "Route hook error");
                None
            }
        }
    }

    /// Run upstream selection hooks
    pub async fn run_upstream_selection(
        executor: &HookExecutor,
        upstreams: &[UpstreamInfo],
        ctx: &mut PluginContext,
    ) -> Option<UpstreamSelection> {
        match executor.run_upstream_select_hooks(upstreams, ctx).await {
            Ok(selection) => selection,
            Err(e) => {
                warn!(error = %e, "Upstream select hook error");
                None
            }
        }
    }

    /// Run upstream request hooks
    pub async fn run_upstream_request(
        executor: &HookExecutor,
        request: &mut RequestInfo,
        ctx: &mut PluginContext,
    ) -> HookResult {
        match executor.run_upstream_request_hooks(request, ctx).await {
            Ok(action) => action.into(),
            Err(e) => {
                warn!(error = %e, "Upstream request hook error");
                HookResult::Error
            }
        }
    }

    /// Run response filter hooks
    pub async fn run_response_filter(
        executor: &HookExecutor,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> HookResult {
        match executor.run_response_filter_hooks(response, ctx).await {
            Ok(action) => action.into(),
            Err(e) => {
                warn!(error = %e, "Response filter hook error");
                HookResult::Error
            }
        }
    }

    /// Run logging hooks
    pub async fn run_logging(
        executor: &HookExecutor,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        error: Option<&str>,
        ctx: &PluginContext,
    ) {
        executor.run_logging_hooks(request, response, error, ctx).await;
    }

    /// Run connection failure hooks
    pub fn run_connection_failure(
        executor: &HookExecutor,
        upstream: &str,
        error: &str,
        ctx: &mut PluginContext,
    ) -> Option<String> {
        executor.run_connection_failure_hooks(upstream, error, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_state_creation() {
        let state = PluginState::new();
        assert!(state.registry.list_factories().is_empty());
    }

    #[test]
    fn test_to_plugin_request() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let request = to_plugin_request("GET", "/api/test", Some("example.com"), None, &headers);

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.host, Some("example.com".to_string()));
        assert_eq!(request.headers.get("content-type"), Some(&"application/json".to_string()));
    }

    #[test]
    fn test_hook_result_from_action() {
        assert_eq!(HookResult::from(HookAction::Continue), HookResult::Continue);
        assert_eq!(HookResult::from(HookAction::SkipPhase), HookResult::Continue);
        assert_eq!(HookResult::from(HookAction::ShortCircuit), HookResult::ShortCircuit);
    }
}
