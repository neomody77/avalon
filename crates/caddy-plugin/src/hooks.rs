//! Hook traits for the plugin pipeline
//!
//! These hooks correspond to the stages in Pingora's ProxyHttp trait

use crate::context::PluginContext;
use crate::error::Result;
use crate::priority::HookPriority;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

/// Hook execution result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    /// Continue to next hook/processing
    Continue,
    /// Skip remaining hooks in this phase, continue pipeline
    SkipPhase,
    /// Short-circuit entire request (response already handled)
    ShortCircuit,
}

impl Default for HookAction {
    fn default() -> Self {
        HookAction::Continue
    }
}

/// HTTP request headers (simplified)
#[derive(Debug, Clone, Default)]
pub struct RequestInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub query: Option<String>,
}

/// HTTP response info
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

impl Default for ResponseInfo {
    fn default() -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
        }
    }
}

/// Upstream server info for load balancing
#[derive(Debug, Clone)]
pub struct UpstreamInfo {
    pub address: String,
    pub healthy: bool,
    pub weight: u32,
    pub active_connections: usize,
    pub total_requests: u64,
    pub failed_requests: u64,
}

/// Upstream selection result
#[derive(Debug, Clone)]
pub struct UpstreamSelection {
    pub index: usize,
    pub address: String,
}

// =============================================================================
// HOOK TRAITS
// =============================================================================

/// Hook 1: Early request interception (before any processing)
/// Maps to: ProxyHttp::early_request_filter
#[async_trait]
pub trait EarlyRequestHook: Send + Sync {
    /// Get the priority for this hook
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Called at the earliest stage of request processing
    async fn on_early_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction>;
}

/// Hook 2: Request filter (after parsing, before routing)
/// Maps to: ProxyHttp::request_filter
#[async_trait]
pub trait RequestFilterHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Called after request parsing, before routing decisions
    async fn on_request(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction>;
}

/// Hook 3: Route selection (custom routing logic)
#[async_trait]
pub trait RouteHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Return Some(route_name) to override route selection, None for default
    async fn select_route(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<Option<String>>;
}

/// Hook 4: Upstream selection (custom load balancing)
/// Maps to: ProxyHttp::upstream_peer
#[async_trait]
pub trait UpstreamSelectHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Select an upstream from available servers
    /// Return Some to override, None for default selection
    async fn select_upstream(
        &self,
        available: &[UpstreamInfo],
        ctx: &mut PluginContext,
    ) -> Result<Option<UpstreamSelection>>;
}

/// Hook 5: Upstream request modification
/// Maps to: ProxyHttp::upstream_request_filter
#[async_trait]
pub trait UpstreamRequestHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Modify the request before sending to upstream
    async fn on_upstream_request(
        &self,
        request: &mut RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction>;
}

/// Hook 6: Response header modification
/// Maps to: ProxyHttp::response_filter
#[async_trait]
pub trait ResponseFilterHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Modify response headers before sending to client
    async fn on_response(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction>;
}

/// Hook 7: Response body transformation
/// Maps to: ProxyHttp::response_body_filter
pub trait ResponseBodyHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Called for each response body chunk
    fn on_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut PluginContext,
    ) -> Result<Option<Duration>>;
}

/// Hook 8: Logging/telemetry
/// Maps to: ProxyHttp::logging
#[async_trait]
pub trait LoggingHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Called when request is complete
    async fn on_request_complete(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        error: Option<&str>,
        ctx: &PluginContext,
    );
}

/// Hook 9: Connection failure handling
/// Maps to: ProxyHttp::fail_to_connect
pub trait ConnectionFailureHook: Send + Sync {
    fn priority(&self) -> HookPriority {
        HookPriority::NORMAL
    }

    /// Called when connection to upstream fails
    fn on_connect_failure(
        &self,
        upstream: &str,
        error: &str,
        ctx: &mut PluginContext,
    ) -> Option<String>;
}

// =============================================================================
// BOXED HOOK TYPES for storage
// =============================================================================

pub type BoxedEarlyRequestHook = Box<dyn EarlyRequestHook>;
pub type BoxedRequestFilterHook = Box<dyn RequestFilterHook>;
pub type BoxedRouteHook = Box<dyn RouteHook>;
pub type BoxedUpstreamSelectHook = Box<dyn UpstreamSelectHook>;
pub type BoxedUpstreamRequestHook = Box<dyn UpstreamRequestHook>;
pub type BoxedResponseFilterHook = Box<dyn ResponseFilterHook>;
pub type BoxedResponseBodyHook = Box<dyn ResponseBodyHook>;
pub type BoxedLoggingHook = Box<dyn LoggingHook>;
pub type BoxedConnectionFailureHook = Box<dyn ConnectionFailureHook>;
