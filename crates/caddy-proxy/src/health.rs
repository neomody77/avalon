//! Health checker for upstream servers

use crate::upstream::UpstreamServer;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub expected_status: u16,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            expected_status: 200,
        }
    }
}

impl HealthCheckConfig {
    pub fn parse_duration(s: &str) -> Option<Duration> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        if let Some(num) = s.strip_suffix("ms") {
            num.parse::<u64>().ok().map(Duration::from_millis)
        } else if let Some(num) = s.strip_suffix('s') {
            num.parse::<u64>().ok().map(Duration::from_secs)
        } else if let Some(num) = s.strip_suffix('m') {
            num.parse::<u64>().ok().map(|n| Duration::from_secs(n * 60))
        } else if let Some(num) = s.strip_suffix('h') {
            num.parse::<u64>().ok().map(|n| Duration::from_secs(n * 3600))
        } else {
            s.parse::<u64>().ok().map(Duration::from_secs)
        }
    }

    pub fn from_config(config: &caddy_core::HealthCheckConfig) -> Self {
        Self {
            path: config.path.clone(),
            interval: Self::parse_duration(&config.interval).unwrap_or(Duration::from_secs(30)),
            timeout: Self::parse_duration(&config.timeout).unwrap_or(Duration::from_secs(5)),
            expected_status: config.expected_status,
        }
    }
}

/// Health checker
pub struct HealthChecker {
    servers: Vec<Arc<UpstreamServer>>,
    config: HealthCheckConfig,
}

impl HealthChecker {
    pub fn new(servers: Vec<Arc<UpstreamServer>>, config: HealthCheckConfig) -> Self {
        Self { servers, config }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    async fn run(&self) {
        let mut check_interval = interval(self.config.interval);

        info!(
            interval = ?self.config.interval,
            path = %self.config.path,
            servers = self.servers.len(),
            "Health checker started"
        );

        loop {
            check_interval.tick().await;

            for server in &self.servers {
                let healthy = self.check_server(server).await;

                if healthy {
                    if !server.is_healthy() {
                        info!(upstream = %server.address_str, "Upstream marked healthy");
                    }
                    server.set_healthy(true);
                } else {
                    if server.is_healthy() {
                        warn!(upstream = %server.address_str, "Upstream marked unhealthy");
                    }
                    server.set_healthy(false);
                }
            }
        }
    }

    async fn check_server(&self, server: &UpstreamServer) -> bool {
        let result = timeout(self.config.timeout, self.do_health_check(server)).await;

        match result {
            Ok(healthy) => healthy,
            Err(_) => {
                debug!(upstream = %server.address_str, "Health check timed out");
                false
            }
        }
    }

    async fn do_health_check(&self, server: &UpstreamServer) -> bool {
        if server.use_tls {
            return self.check_tcp_connection(server).await;
        }

        let stream = match TcpStream::connect(server.address).await {
            Ok(s) => s,
            Err(e) => {
                debug!(upstream = %server.address_str, error = %e, "TCP connect failed");
                return false;
            }
        };

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.config.path, server.address_str
        );

        use tokio::io::AsyncReadExt;

        if let Err(e) = stream.try_write(request.as_bytes()) {
            debug!(upstream = %server.address_str, error = %e, "Write failed");
            return false;
        }

        let mut response = vec![0u8; 1024];
        let mut stream = stream;

        match stream.read(&mut response).await {
            Ok(n) if n > 0 => {
                let response_str = String::from_utf8_lossy(&response[..n]);
                if let Some(status_line) = response_str.lines().next() {
                    if let Some(status) = parse_http_status(status_line) {
                        let healthy = status == self.config.expected_status;
                        debug!(upstream = %server.address_str, status, healthy, "Health check");
                        return healthy;
                    }
                }
                false
            }
            _ => false,
        }
    }

    async fn check_tcp_connection(&self, server: &UpstreamServer) -> bool {
        match TcpStream::connect(server.address).await {
            Ok(_) => {
                debug!(upstream = %server.address_str, "TCP connection OK");
                true
            }
            Err(e) => {
                debug!(upstream = %server.address_str, error = %e, "TCP failed");
                false
            }
        }
    }
}

fn parse_http_status(status_line: &str) -> Option<u16> {
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
        parts[1].parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(HealthCheckConfig::parse_duration("30s"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(HealthCheckConfig::parse_duration("1m"), Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(HealthCheckConfig::parse_duration("500ms"), Some(Duration::from_millis(500)));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(HealthCheckConfig::parse_duration("1h"), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_duration_bare_number() {
        assert_eq!(HealthCheckConfig::parse_duration("10"), Some(Duration::from_secs(10)));
    }

    #[test]
    fn test_parse_duration_empty() {
        assert_eq!(HealthCheckConfig::parse_duration(""), None);
    }

    #[test]
    fn test_parse_http_status() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_http_status("HTTP/1.0 404 Not Found"), Some(404));
        assert_eq!(parse_http_status("invalid"), None);
    }

    #[test]
    fn test_default_config() {
        let config = HealthCheckConfig::default();
        assert_eq!(config.path, "/");
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.expected_status, 200);
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let server = Arc::new(UpstreamServer::new("127.0.0.1:8080", false).unwrap());
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(vec![server], config);
        assert_eq!(checker.servers.len(), 1);
    }

    #[tokio::test]
    async fn test_check_server_unreachable() {
        let server = Arc::new(UpstreamServer::new("127.0.0.1:59999", false).unwrap());
        let config = HealthCheckConfig {
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let checker = HealthChecker::new(vec![server.clone()], config);

        let healthy = checker.check_server(&server).await;
        assert!(!healthy);
    }
}
