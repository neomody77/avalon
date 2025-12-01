//! Metrics Plugin
//!
//! This plugin collects and exposes metrics in Prometheus format.
//! It implements LoggingHook to collect request metrics.

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{LoggingHook, RequestInfo, ResponseInfo};
use crate::plugin::{Plugin, PluginCapabilities, PluginMetadata, PluginType};
use crate::priority::HookPriority;
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::Deserialize;
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Metrics plugin configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsPluginConfig {
    /// Metric name prefix (default: "avalon")
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Enable latency histogram (default: true)
    #[serde(default = "default_enable_latency")]
    pub enable_latency: bool,
    /// Histogram buckets in milliseconds (default: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000])
    #[serde(default = "default_buckets")]
    pub buckets: Vec<f64>,
    /// Enable per-route metrics (default: true)
    #[serde(default = "default_enable_routes")]
    pub enable_routes: bool,
    /// Enable per-status-code metrics (default: true)
    #[serde(default = "default_enable_status")]
    pub enable_status: bool,
}

fn default_prefix() -> String {
    "avalon".to_string()
}
fn default_enable_latency() -> bool {
    true
}
fn default_buckets() -> Vec<f64> {
    vec![
        5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
    ]
}
fn default_enable_routes() -> bool {
    true
}
fn default_enable_status() -> bool {
    true
}

impl Default for MetricsPluginConfig {
    fn default() -> Self {
        Self {
            prefix: default_prefix(),
            enable_latency: default_enable_latency(),
            buckets: default_buckets(),
            enable_routes: default_enable_routes(),
            enable_status: default_enable_status(),
        }
    }
}

/// Histogram for latency distribution
struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(buckets: Vec<f64>) -> Self {
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: f64) {
        // Update sum (store as micros for precision)
        let micros = (value * 1000.0) as u64;
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update bucket counts
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn format_prometheus(&self, name: &str, labels: &str) -> String {
        let mut output = String::new();
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed) as f64 / 1000.0; // Convert back to ms

        // Bucket counts
        for (i, bucket) in self.buckets.iter().enumerate() {
            let bucket_count = self.counts[i].load(Ordering::Relaxed);
            if labels.is_empty() {
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    name, bucket, bucket_count
                ));
            } else {
                output.push_str(&format!(
                    "{}_bucket{{{},le=\"{}\"}} {}\n",
                    name, labels, bucket, bucket_count
                ));
            }
        }

        // +Inf bucket
        if labels.is_empty() {
            output.push_str(&format!("{}_bucket{{le=\"+Inf\"}} {}\n", name, count));
        } else {
            output.push_str(&format!(
                "{}_bucket{{{},le=\"+Inf\"}} {}\n",
                name, labels, count
            ));
        }

        // Sum and count
        if labels.is_empty() {
            output.push_str(&format!("{}_sum {}\n", name, sum));
            output.push_str(&format!("{}_count {}\n", name, count));
        } else {
            output.push_str(&format!("{}_sum{{{}}} {}\n", name, labels, sum));
            output.push_str(&format!("{}_count{{{}}} {}\n", name, labels, count));
        }

        output
    }
}

/// Counter metric
struct Counter {
    value: AtomicU64,
}

impl Counter {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Gauge metric
struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Metrics collector state
pub struct MetricsCollector {
    config: MetricsPluginConfig,
    // Global counters
    requests_total: Counter,
    errors_total: Counter,
    // Active connections gauge
    active_connections: Gauge,
    // Per-status counters
    status_counters: DashMap<u16, Counter>,
    // Per-route counters
    route_counters: DashMap<String, Counter>,
    // Per-method counters
    method_counters: DashMap<String, Counter>,
    // Latency histogram
    latency_histogram: Option<Histogram>,
    // Per-route latency histograms
    route_latencies: DashMap<String, Histogram>,
    // Start time for uptime metric
    start_time: RwLock<Option<Instant>>,
}

impl MetricsCollector {
    fn new(config: MetricsPluginConfig) -> Self {
        let latency_histogram = if config.enable_latency {
            Some(Histogram::new(config.buckets.clone()))
        } else {
            None
        };

        Self {
            config,
            requests_total: Counter::new(),
            errors_total: Counter::new(),
            active_connections: Gauge::new(),
            status_counters: DashMap::new(),
            route_counters: DashMap::new(),
            method_counters: DashMap::new(),
            latency_histogram,
            route_latencies: DashMap::new(),
            start_time: RwLock::new(Some(Instant::now())),
        }
    }

    pub fn record_request(
        &self,
        method: &str,
        route: Option<&str>,
        status: u16,
        latency_ms: f64,
        is_error: bool,
    ) {
        // Increment total requests
        self.requests_total.inc();

        // Increment error counter if applicable
        if is_error {
            self.errors_total.inc();
        }

        // Per-status counter
        if self.config.enable_status {
            self.status_counters
                .entry(status)
                .or_insert_with(Counter::new)
                .inc();
        }

        // Per-method counter
        self.method_counters
            .entry(method.to_string())
            .or_insert_with(Counter::new)
            .inc();

        // Per-route counter and latency
        if self.config.enable_routes {
            if let Some(route) = route {
                self.route_counters
                    .entry(route.to_string())
                    .or_insert_with(Counter::new)
                    .inc();

                if self.config.enable_latency {
                    self.route_latencies
                        .entry(route.to_string())
                        .or_insert_with(|| Histogram::new(self.config.buckets.clone()))
                        .observe(latency_ms);
                }
            }
        }

        // Global latency histogram
        if let Some(ref histogram) = self.latency_histogram {
            histogram.observe(latency_ms);
        }
    }

    pub fn inc_connections(&self) {
        self.active_connections.inc();
    }

    pub fn dec_connections(&self) {
        self.active_connections.dec();
    }

    pub fn format_prometheus(&self) -> String {
        let prefix = &self.config.prefix;
        let mut output = String::new();

        // Uptime
        if let Some(start) = *self.start_time.read() {
            let uptime = start.elapsed().as_secs();
            output.push_str(&format!(
                "# HELP {}_uptime_seconds Server uptime in seconds\n",
                prefix
            ));
            output.push_str(&format!("# TYPE {}_uptime_seconds gauge\n", prefix));
            output.push_str(&format!("{}_uptime_seconds {}\n\n", prefix, uptime));
        }

        // Total requests
        output.push_str(&format!(
            "# HELP {}_requests_total Total number of HTTP requests\n",
            prefix
        ));
        output.push_str(&format!("# TYPE {}_requests_total counter\n", prefix));
        output.push_str(&format!(
            "{}_requests_total {}\n\n",
            prefix,
            self.requests_total.get()
        ));

        // Total errors
        output.push_str(&format!(
            "# HELP {}_errors_total Total number of HTTP errors\n",
            prefix
        ));
        output.push_str(&format!("# TYPE {}_errors_total counter\n", prefix));
        output.push_str(&format!(
            "{}_errors_total {}\n\n",
            prefix,
            self.errors_total.get()
        ));

        // Active connections
        output.push_str(&format!(
            "# HELP {}_active_connections Current number of active connections\n",
            prefix
        ));
        output.push_str(&format!(
            "# TYPE {}_active_connections gauge\n",
            prefix
        ));
        output.push_str(&format!(
            "{}_active_connections {}\n\n",
            prefix,
            self.active_connections.get()
        ));

        // Per-status counters
        if self.config.enable_status && !self.status_counters.is_empty() {
            output.push_str(&format!(
                "# HELP {}_requests_by_status_total HTTP requests by status code\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_requests_by_status_total counter\n",
                prefix
            ));
            for entry in self.status_counters.iter() {
                output.push_str(&format!(
                    "{}_requests_by_status_total{{status=\"{}\"}} {}\n",
                    prefix,
                    entry.key(),
                    entry.value().get()
                ));
            }
            output.push('\n');
        }

        // Per-method counters
        if !self.method_counters.is_empty() {
            output.push_str(&format!(
                "# HELP {}_requests_by_method_total HTTP requests by method\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_requests_by_method_total counter\n",
                prefix
            ));
            for entry in self.method_counters.iter() {
                output.push_str(&format!(
                    "{}_requests_by_method_total{{method=\"{}\"}} {}\n",
                    prefix,
                    entry.key(),
                    entry.value().get()
                ));
            }
            output.push('\n');
        }

        // Per-route counters
        if self.config.enable_routes && !self.route_counters.is_empty() {
            output.push_str(&format!(
                "# HELP {}_requests_by_route_total HTTP requests by route\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_requests_by_route_total counter\n",
                prefix
            ));
            for entry in self.route_counters.iter() {
                output.push_str(&format!(
                    "{}_requests_by_route_total{{route=\"{}\"}} {}\n",
                    prefix,
                    entry.key(),
                    entry.value().get()
                ));
            }
            output.push('\n');
        }

        // Global latency histogram
        if let Some(ref histogram) = self.latency_histogram {
            output.push_str(&format!(
                "# HELP {}_request_duration_ms HTTP request duration in milliseconds\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_request_duration_ms histogram\n",
                prefix
            ));
            output.push_str(&histogram.format_prometheus(
                &format!("{}_request_duration_ms", prefix),
                "",
            ));
            output.push('\n');
        }

        // Per-route latency histograms
        if self.config.enable_routes && self.config.enable_latency && !self.route_latencies.is_empty()
        {
            output.push_str(&format!(
                "# HELP {}_route_duration_ms HTTP request duration by route in milliseconds\n",
                prefix
            ));
            output.push_str(&format!(
                "# TYPE {}_route_duration_ms histogram\n",
                prefix
            ));
            for entry in self.route_latencies.iter() {
                output.push_str(&entry.value().format_prometheus(
                    &format!("{}_route_duration_ms", prefix),
                    &format!("route=\"{}\"", entry.key()),
                ));
            }
            output.push('\n');
        }

        output
    }
}

/// Metrics Plugin
pub struct MetricsPlugin {
    metadata: PluginMetadata,
    config: MetricsPluginConfig,
    collector: Option<Arc<MetricsCollector>>,
    running: bool,
}

impl MetricsPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata::new("metrics", "0.1.0", PluginType::Logger)
            .with_description("Prometheus-compatible metrics collection")
            .with_capabilities(PluginCapabilities {
                supports_reload: true,
                supports_metrics: true,
                thread_safe: true,
                async_init: false,
            });

        Self {
            metadata,
            config: MetricsPluginConfig::default(),
            collector: None,
            running: false,
        }
    }

    pub fn get_collector(&self) -> Option<Arc<MetricsCollector>> {
        self.collector.clone()
    }

    pub fn get_logging_hook(&self) -> Option<MetricsLoggingHook> {
        self.collector.as_ref().map(|c| MetricsLoggingHook {
            collector: c.clone(),
        })
    }

    /// Get Prometheus-formatted metrics output
    pub fn get_metrics(&self) -> String {
        self.collector
            .as_ref()
            .map(|c| c.format_prometheus())
            .unwrap_or_default()
    }
}

impl Default for MetricsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for MetricsPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn init(&mut self, config: &str) -> Result<()> {
        if config.is_empty() {
            self.config = MetricsPluginConfig::default();
        } else {
            self.config = serde_json::from_str(config)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.collector = Some(Arc::new(MetricsCollector::new(self.config.clone())));
        self.running = true;

        info!(
            prefix = %self.config.prefix,
            enable_latency = self.config.enable_latency,
            enable_routes = self.config.enable_routes,
            "Metrics plugin started"
        );

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.collector = None;
        info!("Metrics plugin stopped");
        Ok(())
    }

    fn health_check(&self) -> bool {
        self.running && self.collector.is_some()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Logging hook for collecting metrics
pub struct MetricsLoggingHook {
    collector: Arc<MetricsCollector>,
}

#[async_trait]
impl LoggingHook for MetricsLoggingHook {
    fn priority(&self) -> HookPriority {
        HookPriority::LATE // Run after other logging hooks
    }

    async fn on_request_complete(
        &self,
        request: &RequestInfo,
        response: Option<&ResponseInfo>,
        error: Option<&str>,
        ctx: &PluginContext,
    ) {
        let status = response.map(|r| r.status).unwrap_or(500);
        let is_error = error.is_some() || status >= 400;

        // Get latency from context (set by proxy)
        let latency_ms = ctx.get::<f64>("request_latency_ms").unwrap_or(0.0);

        // Get route from context
        let route: Option<String> = ctx.get::<String>("route_name");

        self.collector.record_request(
            &request.method,
            route.as_deref(),
            status,
            latency_ms,
            is_error,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = MetricsPlugin::new();
        assert_eq!(plugin.metadata().name, "metrics");
        assert_eq!(plugin.metadata().plugin_type, PluginType::Logger);
    }

    #[test]
    fn test_config_parsing() {
        let mut plugin = MetricsPlugin::new();
        let config = r#"{"prefix": "myapp", "enable_latency": false}"#;
        plugin.init(config).unwrap();
        assert_eq!(plugin.config.prefix, "myapp");
        assert!(!plugin.config.enable_latency);
    }

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        counter.inc();
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);
        gauge.inc();
        gauge.inc();
        assert_eq!(gauge.get(), 2);
        gauge.dec();
        assert_eq!(gauge.get(), 1);
        gauge.set(100);
        assert_eq!(gauge.get(), 100);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(vec![10.0, 50.0, 100.0]);
        histogram.observe(5.0);
        histogram.observe(25.0);
        histogram.observe(75.0);
        histogram.observe(150.0);

        let output = histogram.format_prometheus("test_latency", "");
        assert!(output.contains("test_latency_bucket{le=\"10\"} 1"));
        assert!(output.contains("test_latency_bucket{le=\"50\"} 2"));
        assert!(output.contains("test_latency_bucket{le=\"100\"} 3"));
        assert!(output.contains("test_latency_bucket{le=\"+Inf\"} 4"));
        assert!(output.contains("test_latency_count 4"));
    }

    #[test]
    fn test_metrics_collector() {
        let config = MetricsPluginConfig::default();
        let collector = MetricsCollector::new(config);

        collector.record_request("GET", Some("/api/users"), 200, 15.5, false);
        collector.record_request("POST", Some("/api/users"), 201, 25.0, false);
        collector.record_request("GET", Some("/api/users"), 500, 100.0, true);

        let output = collector.format_prometheus();

        assert!(output.contains("avalon_requests_total 3"));
        assert!(output.contains("avalon_errors_total 1"));
        assert!(output.contains("requests_by_status_total{status=\"200\"} 1"));
        assert!(output.contains("requests_by_status_total{status=\"201\"} 1"));
        assert!(output.contains("requests_by_status_total{status=\"500\"} 1"));
        assert!(output.contains("requests_by_method_total{method=\"GET\"} 2"));
        assert!(output.contains("requests_by_method_total{method=\"POST\"} 1"));
        assert!(output.contains("requests_by_route_total{route=\"/api/users\"} 3"));
    }

    #[test]
    fn test_start_stop() {
        let mut plugin = MetricsPlugin::new();
        plugin.init("").unwrap();
        plugin.start().unwrap();
        assert!(plugin.health_check());
        assert!(plugin.get_collector().is_some());

        let metrics = plugin.get_metrics();
        assert!(metrics.contains("avalon_requests_total"));

        plugin.stop().unwrap();
        assert!(!plugin.health_check());
    }
}
