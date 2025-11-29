//! Hook executor for running hooks in priority order

use crate::context::PluginContext;
use crate::error::Result;
use crate::hooks::*;
use crate::registry::PluginRegistry;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Hook executor that runs hooks in priority order
pub struct HookExecutor {
    registry: Arc<PluginRegistry>,
}

impl HookExecutor {
    /// Create a new hook executor
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    /// Run all early request hooks
    pub async fn run_early_request_hooks(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let hooks = self.registry.get_early_request_hooks();
        trace!(count = hooks.len(), "Running early request hooks");

        for hook in hooks {
            match hook.on_early_request(request, ctx).await {
                Ok(HookAction::Continue) => continue,
                Ok(HookAction::SkipPhase) => {
                    debug!("Early request hook requested phase skip");
                    return Ok(HookAction::Continue);
                }
                Ok(HookAction::ShortCircuit) => {
                    debug!("Early request hook short-circuited request");
                    return Ok(HookAction::ShortCircuit);
                }
                Err(e) => {
                    warn!(error = %e, "Early request hook error");
                    return Err(e);
                }
            }
        }

        Ok(HookAction::Continue)
    }

    /// Run all request filter hooks
    pub async fn run_request_filter_hooks(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let hooks = self.registry.get_request_filter_hooks();
        trace!(count = hooks.len(), "Running request filter hooks");

        for hook in hooks {
            match hook.on_request(request, ctx).await {
                Ok(HookAction::Continue) => continue,
                Ok(HookAction::SkipPhase) => {
                    debug!("Request filter hook requested phase skip");
                    return Ok(HookAction::Continue);
                }
                Ok(HookAction::ShortCircuit) => {
                    debug!("Request filter hook short-circuited request");
                    return Ok(HookAction::ShortCircuit);
                }
                Err(e) => {
                    warn!(error = %e, "Request filter hook error");
                    return Err(e);
                }
            }
        }

        Ok(HookAction::Continue)
    }

    /// Run route hooks to get custom route selection
    pub async fn run_route_hooks(
        &self,
        request: &RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<Option<String>> {
        let hooks = self.registry.get_route_hooks();
        trace!(count = hooks.len(), "Running route hooks");

        for hook in hooks {
            match hook.select_route(request, ctx).await {
                Ok(Some(route)) => {
                    debug!(route = %route, "Route hook selected custom route");
                    return Ok(Some(route));
                }
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %e, "Route hook error");
                    return Err(e);
                }
            }
        }

        Ok(None)
    }

    /// Run upstream select hooks
    pub async fn run_upstream_select_hooks(
        &self,
        available: &[UpstreamInfo],
        ctx: &mut PluginContext,
    ) -> Result<Option<UpstreamSelection>> {
        let hooks = self.registry.get_upstream_select_hooks();
        trace!(count = hooks.len(), "Running upstream select hooks");

        for hook in hooks {
            match hook.select_upstream(available, ctx).await {
                Ok(Some(selection)) => {
                    debug!(upstream = %selection.address, "Upstream select hook chose upstream");
                    return Ok(Some(selection));
                }
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %e, "Upstream select hook error");
                    return Err(e);
                }
            }
        }

        Ok(None)
    }

    /// Run all upstream request hooks
    pub async fn run_upstream_request_hooks(
        &self,
        request: &mut RequestInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let hooks = self.registry.get_upstream_request_hooks();
        trace!(count = hooks.len(), "Running upstream request hooks");

        for hook in hooks {
            match hook.on_upstream_request(request, ctx).await {
                Ok(HookAction::Continue) => continue,
                Ok(HookAction::SkipPhase) => {
                    debug!("Upstream request hook requested phase skip");
                    return Ok(HookAction::Continue);
                }
                Ok(HookAction::ShortCircuit) => {
                    debug!("Upstream request hook short-circuited");
                    return Ok(HookAction::ShortCircuit);
                }
                Err(e) => {
                    warn!(error = %e, "Upstream request hook error");
                    return Err(e);
                }
            }
        }

        Ok(HookAction::Continue)
    }

    /// Run all response filter hooks
    pub async fn run_response_filter_hooks(
        &self,
        response: &mut ResponseInfo,
        ctx: &mut PluginContext,
    ) -> Result<HookAction> {
        let hooks = self.registry.get_response_filter_hooks();
        trace!(count = hooks.len(), "Running response filter hooks");

        for hook in hooks {
            match hook.on_response(response, ctx).await {
                Ok(HookAction::Continue) => continue,
                Ok(HookAction::SkipPhase) => {
                    debug!("Response filter hook requested phase skip");
                    return Ok(HookAction::Continue);
                }
                Ok(HookAction::ShortCircuit) => {
                    debug!("Response filter hook short-circuited");
                    return Ok(HookAction::ShortCircuit);
                }
                Err(e) => {
                    warn!(error = %e, "Response filter hook error");
                    return Err(e);
                }
            }
        }

        Ok(HookAction::Continue)
    }

    /// Run all response body hooks
    pub fn run_response_body_hooks(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut PluginContext,
    ) -> Result<Option<Duration>> {
        let hooks = self.registry.get_response_body_hooks();
        trace!(count = hooks.len(), eos = end_of_stream, "Running response body hooks");

        let mut max_delay: Option<Duration> = None;

        for hook in hooks {
            match hook.on_body_chunk(body, end_of_stream, ctx) {
                Ok(delay) => {
                    if let Some(d) = delay {
                        max_delay = Some(max_delay.map_or(d, |m| m.max(d)));
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Response body hook error");
                    return Err(e);
                }
            }
        }

        Ok(max_delay)
    }

    /// Run all logging hooks
    pub async fn run_logging_hooks(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        error: Option<&str>,
        ctx: &PluginContext,
    ) {
        let hooks = self.registry.get_logging_hooks();
        trace!(count = hooks.len(), "Running logging hooks");

        for hook in hooks {
            hook.on_request_complete(request, response, error, ctx).await;
        }
    }

    /// Run connection failure hooks
    pub fn run_connection_failure_hooks(
        &self,
        upstream: &str,
        error: &str,
        ctx: &mut PluginContext,
    ) -> Option<String> {
        let hooks = self.registry.get_connection_failure_hooks();
        trace!(count = hooks.len(), upstream = %upstream, "Running connection failure hooks");

        for hook in hooks {
            if let Some(new_error) = hook.on_connect_failure(upstream, error, ctx) {
                return Some(new_error);
            }
        }

        None
    }
}
