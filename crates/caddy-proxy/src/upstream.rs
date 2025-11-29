//! Upstream server selection and load balancing

use crate::error::{ProxyError, Result};
use caddy_core::LoadBalancingStrategy;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::debug;

/// Information about an upstream server
#[derive(Debug)]
pub struct UpstreamServer {
    pub address: SocketAddr,
    pub address_str: String,
    pub healthy: AtomicBool,
    pub active_connections: AtomicUsize,
    pub use_tls: bool,
    pub sni: Option<String>,
}

impl UpstreamServer {
    pub fn new(address_str: &str, use_tls: bool) -> Result<Self> {
        let addr = parse_address(address_str)?;

        Ok(Self {
            address: addr,
            address_str: address_str.to_string(),
            healthy: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
            use_tls,
            sni: if use_tls {
                address_str.split(':').next().map(|s| s.to_string())
            } else {
                None
            },
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn connection_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

fn parse_address(addr: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    // Try direct parse first (e.g., "127.0.0.1:8080")
    if let Ok(addr) = addr.parse() {
        return Ok(addr);
    }

    // Try DNS resolution (e.g., "example.com:80")
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            addrs.next().ok_or_else(|| {
                ProxyError::ConfigError(format!("No addresses found for: {}", addr))
            })
        }
        Err(_) => {
            // Try adding default port if missing
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(ProxyError::ConfigError(format!(
                    "Invalid address (missing port): {}",
                    addr
                )));
            }
            Err(ProxyError::ConfigError(format!("Cannot resolve: {}", addr)))
        }
    }
}

/// Upstream selector with load balancing
pub struct UpstreamSelector {
    servers: Vec<Arc<UpstreamServer>>,
    strategy: LoadBalancingStrategy,
    counter: AtomicUsize,
}

impl UpstreamSelector {
    pub fn new(
        addresses: &[String],
        strategy: LoadBalancingStrategy,
        use_tls: bool,
    ) -> Result<Self> {
        let servers: Result<Vec<_>> = addresses
            .iter()
            .map(|addr| Ok(Arc::new(UpstreamServer::new(addr, use_tls)?)))
            .collect();

        Ok(Self {
            servers: servers?,
            strategy,
            counter: AtomicUsize::new(0),
        })
    }

    pub fn servers(&self) -> &[Arc<UpstreamServer>] {
        &self.servers
    }

    pub fn select(&self) -> Result<Arc<UpstreamServer>> {
        let healthy: Vec<_> = self.servers.iter().filter(|s| s.is_healthy()).collect();

        if healthy.is_empty() {
            return Err(ProxyError::NoHealthyUpstream);
        }

        let server = match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                healthy[idx]
            }
            LoadBalancingStrategy::Random => {
                let idx = rand_usize() % healthy.len();
                healthy[idx]
            }
            LoadBalancingStrategy::LeastConn => {
                // Safe: we already checked healthy.is_empty() above
                healthy
                    .iter()
                    .min_by_key(|s| s.connection_count())
                    .expect("healthy list is not empty")
            }
            LoadBalancingStrategy::First => healthy[0],
            LoadBalancingStrategy::IpHash => {
                // Simplified: just use round robin for now
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                healthy[idx]
            }
        };

        debug!(upstream = %server.address_str, strategy = ?self.strategy, "Selected upstream");
        Ok(server.clone())
    }

    /// Select an upstream server based on an affinity key (for session affinity)
    /// Returns (server, server_index) so the caller can set the affinity cookie
    pub fn select_with_affinity(&self, affinity_key: Option<&str>) -> Result<(Arc<UpstreamServer>, usize)> {
        let healthy: Vec<_> = self.servers.iter().enumerate().filter(|(_, s)| s.is_healthy()).collect();

        if healthy.is_empty() {
            return Err(ProxyError::NoHealthyUpstream);
        }

        // If we have an affinity key, try to use it
        if let Some(key) = affinity_key {
            // Try to parse as server index first
            if let Ok(idx) = key.parse::<usize>() {
                // Check if this index points to a healthy server
                if let Some((_, server)) = healthy.iter().find(|(i, _)| *i == idx) {
                    debug!(upstream = %server.address_str, affinity_key = %key, "Selected upstream by affinity");
                    return Ok(((*server).clone(), idx));
                }
            }

            // Fall back to hashing the key
            let hash = hash_string(key);
            let idx = hash % healthy.len();
            let (original_idx, server) = healthy[idx];
            debug!(upstream = %server.address_str, affinity_key = %key, "Selected upstream by hash");
            return Ok((server.clone(), original_idx));
        }

        // No affinity key, use normal selection
        let server = self.select()?;
        let idx = self.servers.iter().position(|s| Arc::ptr_eq(s, &server)).unwrap_or(0);
        Ok((server, idx))
    }
}

fn hash_string(s: &str) -> usize {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish() as usize
}

fn rand_usize() -> usize {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address() {
        assert!(parse_address("127.0.0.1:8080").is_ok());
        assert!(parse_address("localhost:8080").is_ok());
        assert!(parse_address("invalid").is_err());
    }

    #[test]
    fn test_parse_address_invalid() {
        assert!(parse_address("no-port").is_err());
        assert!(parse_address(":").is_err());
    }

    #[test]
    fn test_parse_address_dns() {
        // Test DNS resolution
        let result = parse_address("localhost:80");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_upstream_server_health() {
        let server = UpstreamServer::new("127.0.0.1:8080", false).unwrap();
        assert!(server.is_healthy());

        server.set_healthy(false);
        assert!(!server.is_healthy());

        server.set_healthy(true);
        assert!(server.is_healthy());
    }

    #[test]
    fn test_upstream_server_connections() {
        let server = UpstreamServer::new("127.0.0.1:8080", false).unwrap();
        assert_eq!(server.connection_count(), 0);

        server.increment_connections();
        assert_eq!(server.connection_count(), 1);

        server.increment_connections();
        assert_eq!(server.connection_count(), 2);

        server.decrement_connections();
        assert_eq!(server.connection_count(), 1);
    }

    #[test]
    fn test_upstream_server_tls() {
        let server = UpstreamServer::new("127.0.0.1:443", true).unwrap();
        assert!(server.use_tls);
        assert_eq!(server.sni, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_round_robin() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        let first = selector.select().unwrap();
        let second = selector.select().unwrap();

        assert_ne!(first.address, second.address);
    }

    #[test]
    fn test_round_robin_single_server() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        let first = selector.select().unwrap();
        let second = selector.select().unwrap();

        assert_eq!(first.address, second.address);
    }

    #[test]
    fn test_round_robin_skips_unhealthy() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        selector.servers[0].set_healthy(false);

        for _ in 0..5 {
            let server = selector.select().unwrap();
            assert_eq!(server.address_str, "127.0.0.1:8081");
        }
    }

    #[test]
    fn test_no_healthy_upstream() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        selector.servers[0].set_healthy(false);

        assert!(selector.select().is_err());
    }

    #[test]
    fn test_least_conn() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::LeastConn,
            false,
        )
        .unwrap();

        selector.servers[0].increment_connections();
        selector.servers[0].increment_connections();
        selector.servers[1].increment_connections();

        let server = selector.select().unwrap();
        assert_eq!(server.address_str, "127.0.0.1:8081");
    }

    #[test]
    fn test_least_conn_equal() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::LeastConn,
            false,
        )
        .unwrap();

        // Both have 0 connections, should return one of them
        let server = selector.select().unwrap();
        assert!(server.address_str == "127.0.0.1:8080" || server.address_str == "127.0.0.1:8081");
    }

    #[test]
    fn test_first_strategy() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::First,
            false,
        )
        .unwrap();

        for _ in 0..5 {
            let server = selector.select().unwrap();
            assert_eq!(server.address_str, "127.0.0.1:8080");
        }
    }

    #[test]
    fn test_first_strategy_with_unhealthy_first() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::First,
            false,
        )
        .unwrap();

        selector.servers[0].set_healthy(false);

        let server = selector.select().unwrap();
        assert_eq!(server.address_str, "127.0.0.1:8081");
    }

    #[test]
    fn test_random_strategy() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::Random,
            false,
        )
        .unwrap();

        // Just verify it doesn't panic
        for _ in 0..10 {
            let _ = selector.select().unwrap();
        }
    }

    #[test]
    fn test_mark_healthy_unhealthy() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        assert!(selector.servers[0].is_healthy());

        selector.servers[0].set_healthy(false);
        assert!(!selector.servers[0].is_healthy());

        selector.servers[0].set_healthy(true);
        assert!(selector.servers[0].is_healthy());
    }

    #[test]
    fn test_servers_getter() {
        let selector = UpstreamSelector::new(
            &["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            LoadBalancingStrategy::RoundRobin,
            false,
        )
        .unwrap();

        assert_eq!(selector.servers().len(), 2);
    }
}
