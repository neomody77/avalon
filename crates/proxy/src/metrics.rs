//! Prometheus metrics for avalon proxy
//!
//! Provides metrics collection and export in Prometheus format.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Global metrics registry
pub struct MetricsRegistry {
    /// Total requests counter
    pub requests_total: Counter,
    /// Requests by status code
    pub requests_by_status: CounterVec,
    /// Requests by method
    pub requests_by_method: CounterVec,
    /// Requests by host
    pub requests_by_host: CounterVec,
    /// Request duration histogram
    pub request_duration: Histogram,
    /// Active connections gauge
    pub active_connections: Gauge,
    /// Upstream health status
    pub upstream_health: GaugeVec,
    /// Upstream request count
    pub upstream_requests: CounterVec,
    /// Cache hits/misses
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    /// Rate limit rejections
    pub rate_limit_rejections: Counter,
    /// TLS handshake errors
    pub tls_errors: Counter,
    /// Bytes sent/received
    pub bytes_sent: Counter,
    pub bytes_received: Counter,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            requests_total: Counter::new(),
            requests_by_status: CounterVec::new(),
            requests_by_method: CounterVec::new(),
            requests_by_host: CounterVec::new(),
            request_duration: Histogram::new(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            active_connections: Gauge::new(),
            upstream_health: GaugeVec::new(),
            upstream_requests: CounterVec::new(),
            cache_hits: Counter::new(),
            cache_misses: Counter::new(),
            rate_limit_rejections: Counter::new(),
            tls_errors: Counter::new(),
            bytes_sent: Counter::new(),
            bytes_received: Counter::new(),
            start_time: Instant::now(),
        }
    }

    /// Export metrics in Prometheus text format
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Process info
        output.push_str("# HELP avalon_info Avalon proxy information\n");
        output.push_str("# TYPE avalon_info gauge\n");
        output.push_str("avalon_info{version=\"0.1.0\"} 1\n\n");

        // Uptime
        output.push_str("# HELP avalon_uptime_seconds Proxy uptime in seconds\n");
        output.push_str("# TYPE avalon_uptime_seconds gauge\n");
        output.push_str(&format!(
            "avalon_uptime_seconds {}\n\n",
            self.start_time.elapsed().as_secs()
        ));

        // Total requests
        output.push_str("# HELP avalon_requests_total Total number of HTTP requests\n");
        output.push_str("# TYPE avalon_requests_total counter\n");
        output.push_str(&format!(
            "avalon_requests_total {}\n\n",
            self.requests_total.get()
        ));

        // Requests by status
        output.push_str("# HELP avalon_requests_by_status_total HTTP requests by status code\n");
        output.push_str("# TYPE avalon_requests_by_status_total counter\n");
        for (status, count) in self.requests_by_status.get_all() {
            output.push_str(&format!(
                "avalon_requests_by_status_total{{status=\"{}\"}} {}\n",
                status, count
            ));
        }
        output.push('\n');

        // Requests by method
        output.push_str("# HELP avalon_requests_by_method_total HTTP requests by method\n");
        output.push_str("# TYPE avalon_requests_by_method_total counter\n");
        for (method, count) in self.requests_by_method.get_all() {
            output.push_str(&format!(
                "avalon_requests_by_method_total{{method=\"{}\"}} {}\n",
                method, count
            ));
        }
        output.push('\n');

        // Requests by host
        output.push_str("# HELP avalon_requests_by_host_total HTTP requests by host\n");
        output.push_str("# TYPE avalon_requests_by_host_total counter\n");
        for (host, count) in self.requests_by_host.get_all() {
            output.push_str(&format!(
                "avalon_requests_by_host_total{{host=\"{}\"}} {}\n",
                host, count
            ));
        }
        output.push('\n');

        // Request duration histogram
        output.push_str(
            "# HELP avalon_request_duration_seconds Request duration in seconds\n",
        );
        output.push_str("# TYPE avalon_request_duration_seconds histogram\n");
        let (buckets, sum, count) = self.request_duration.get_stats();
        for (le, bucket_count) in buckets {
            output.push_str(&format!(
                "avalon_request_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                le, bucket_count
            ));
        }
        output.push_str(&format!(
            "avalon_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            count
        ));
        output.push_str(&format!("avalon_request_duration_seconds_sum {}\n", sum));
        output.push_str(&format!(
            "avalon_request_duration_seconds_count {}\n\n",
            count
        ));

        // Active connections
        output.push_str("# HELP avalon_active_connections Current active connections\n");
        output.push_str("# TYPE avalon_active_connections gauge\n");
        output.push_str(&format!(
            "avalon_active_connections {}\n\n",
            self.active_connections.get()
        ));

        // Upstream health
        output.push_str("# HELP avalon_upstream_healthy Upstream server health status (1=healthy, 0=unhealthy)\n");
        output.push_str("# TYPE avalon_upstream_healthy gauge\n");
        for (upstream, healthy) in self.upstream_health.get_all() {
            output.push_str(&format!(
                "avalon_upstream_healthy{{upstream=\"{}\"}} {}\n",
                upstream, healthy
            ));
        }
        output.push('\n');

        // Upstream requests
        output.push_str("# HELP avalon_upstream_requests_total Requests sent to upstream servers\n");
        output.push_str("# TYPE avalon_upstream_requests_total counter\n");
        for (upstream, count) in self.upstream_requests.get_all() {
            output.push_str(&format!(
                "avalon_upstream_requests_total{{upstream=\"{}\"}} {}\n",
                upstream, count
            ));
        }
        output.push('\n');

        // Cache metrics
        output.push_str("# HELP avalon_cache_hits_total Cache hit count\n");
        output.push_str("# TYPE avalon_cache_hits_total counter\n");
        output.push_str(&format!("avalon_cache_hits_total {}\n\n", self.cache_hits.get()));

        output.push_str("# HELP avalon_cache_misses_total Cache miss count\n");
        output.push_str("# TYPE avalon_cache_misses_total counter\n");
        output.push_str(&format!(
            "avalon_cache_misses_total {}\n\n",
            self.cache_misses.get()
        ));

        // Rate limit rejections
        output.push_str("# HELP avalon_rate_limit_rejections_total Rate limit rejection count\n");
        output.push_str("# TYPE avalon_rate_limit_rejections_total counter\n");
        output.push_str(&format!(
            "avalon_rate_limit_rejections_total {}\n\n",
            self.rate_limit_rejections.get()
        ));

        // TLS errors
        output.push_str("# HELP avalon_tls_errors_total TLS handshake error count\n");
        output.push_str("# TYPE avalon_tls_errors_total counter\n");
        output.push_str(&format!("avalon_tls_errors_total {}\n\n", self.tls_errors.get()));

        // Bytes transferred
        output.push_str("# HELP avalon_bytes_sent_total Total bytes sent to clients\n");
        output.push_str("# TYPE avalon_bytes_sent_total counter\n");
        output.push_str(&format!("avalon_bytes_sent_total {}\n\n", self.bytes_sent.get()));

        output.push_str("# HELP avalon_bytes_received_total Total bytes received from clients\n");
        output.push_str("# TYPE avalon_bytes_received_total counter\n");
        output.push_str(&format!(
            "avalon_bytes_received_total {}\n",
            self.bytes_received.get()
        ));

        output
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple atomic counter
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, v: u64) {
        self.value.fetch_add(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Counter with labels
pub struct CounterVec {
    values: RwLock<HashMap<String, u64>>,
}

impl CounterVec {
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    pub fn inc(&self, label: &str) {
        let mut values = self.values.write();
        *values.entry(label.to_string()).or_insert(0) += 1;
    }

    pub fn get(&self, label: &str) -> u64 {
        self.values.read().get(label).copied().unwrap_or(0)
    }

    pub fn get_all(&self) -> Vec<(String, u64)> {
        self.values
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }
}

impl Default for CounterVec {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple gauge (can go up and down)
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge with labels
pub struct GaugeVec {
    values: RwLock<HashMap<String, u64>>,
}

impl GaugeVec {
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    pub fn set(&self, label: &str, value: u64) {
        let mut values = self.values.write();
        values.insert(label.to_string(), value);
    }

    pub fn get(&self, label: &str) -> u64 {
        self.values.read().get(label).copied().unwrap_or(0)
    }

    pub fn get_all(&self) -> Vec<(String, u64)> {
        self.values
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }
}

impl Default for GaugeVec {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple histogram for request durations
pub struct Histogram {
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: RwLock<f64>,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let bucket_counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            bucket_counts,
            sum: RwLock::new(0.0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: f64) {
        // Update sum and count
        {
            let mut sum = self.sum.write();
            *sum += value;
        }
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update bucket counts
        for (i, &bucket_le) in self.buckets.iter().enumerate() {
            if value <= bucket_le {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn get_stats(&self) -> (Vec<(f64, u64)>, f64, u64) {
        let buckets: Vec<_> = self
            .buckets
            .iter()
            .zip(self.bucket_counts.iter())
            .map(|(&le, count)| (le, count.load(Ordering::Relaxed)))
            .collect();
        let sum = *self.sum.read();
        let count = self.count.load(Ordering::Relaxed);
        (buckets, sum, count)
    }
}

/// Global metrics instance
static METRICS: once_cell::sync::Lazy<Arc<MetricsRegistry>> =
    once_cell::sync::Lazy::new(|| Arc::new(MetricsRegistry::new()));

/// Get the global metrics registry
pub fn metrics() -> &'static Arc<MetricsRegistry> {
    &METRICS
}

/// Wait for active connections to drain (with timeout)
/// Returns true if all connections drained, false if timeout
pub fn wait_for_connections_drain(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let check_interval = std::time::Duration::from_millis(100);

    loop {
        let active = metrics().active_connections.get();
        if active == 0 {
            return true;
        }

        if start.elapsed() >= timeout {
            tracing::warn!(
                active_connections = active,
                "Grace period expired with active connections"
            );
            return false;
        }

        std::thread::sleep(check_interval);
    }
}

/// Request timing helper
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    pub fn new() -> Self {
        metrics().active_connections.inc();
        Self {
            start: Instant::now(),
        }
    }

    pub fn observe(self) {
        let duration = self.start.elapsed().as_secs_f64();
        metrics().request_duration.observe(duration);
        metrics().active_connections.dec();
    }
}

impl Default for RequestTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        // Note: observe() should be called explicitly for accurate timing
        // This is just a safety net
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_counter_vec() {
        let counter = CounterVec::new();
        counter.inc("200");
        counter.inc("200");
        counter.inc("404");
        assert_eq!(counter.get("200"), 2);
        assert_eq!(counter.get("404"), 1);
        assert_eq!(counter.get("500"), 0);
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
        gauge.set(10);
        assert_eq!(gauge.get(), 10);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(vec![0.1, 0.5, 1.0]);
        histogram.observe(0.05);
        histogram.observe(0.3);
        histogram.observe(0.8);
        histogram.observe(2.0);

        let (buckets, sum, count) = histogram.get_stats();
        assert_eq!(count, 4);
        assert!((sum - 3.15).abs() < 0.001);

        // Check bucket counts (cumulative)
        assert_eq!(buckets[0].1, 1); // <= 0.1
        assert_eq!(buckets[1].1, 2); // <= 0.5
        assert_eq!(buckets[2].1, 3); // <= 1.0
    }

    #[test]
    fn test_metrics_export() {
        let registry = MetricsRegistry::new();
        registry.requests_total.inc();
        registry.requests_by_status.inc("200");
        registry.requests_by_method.inc("GET");

        let output = registry.export();
        assert!(output.contains("avalon_requests_total 1"));
        assert!(output.contains("avalon_requests_by_status_total{status=\"200\"} 1"));
        assert!(output.contains("avalon_requests_by_method_total{method=\"GET\"} 1"));
    }
}
