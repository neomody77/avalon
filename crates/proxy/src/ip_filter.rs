//! IP whitelist/blacklist filtering
//!
//! Provides IP-based access control for routes with support for:
//! - Individual IP addresses
//! - CIDR ranges
//! - Whitelist mode (only allow specified IPs)
//! - Blacklist mode (block specified IPs)

use std::net::IpAddr;
use std::str::FromStr;
use tracing::debug;

/// IP filter configuration
#[derive(Debug, Clone)]
pub struct IpFilterConfig {
    /// IPs to allow (whitelist mode)
    pub allow: Vec<String>,
    /// IPs to deny (blacklist mode)
    pub deny: Vec<String>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

/// A parsed CIDR range
#[derive(Debug, Clone)]
struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    fn parse(s: &str) -> Option<Self> {
        if let Some((addr_str, prefix_str)) = s.split_once('/') {
            let network = IpAddr::from_str(addr_str).ok()?;
            let prefix_len: u8 = prefix_str.parse().ok()?;

            // Validate prefix length
            let max_prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            if prefix_len > max_prefix {
                return None;
            }

            Some(Self { network, prefix_len })
        } else {
            // Treat as single IP with full prefix
            let network = IpAddr::from_str(s).ok()?;
            let prefix_len = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { network, prefix_len })
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(check)) => {
                let net_bits = u32::from(*net);
                let check_bits = u32::from(*check);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - self.prefix_len)
                };
                (net_bits & mask) == (check_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(check)) => {
                let net_bits = u128::from(*net);
                let check_bits = u128::from(*check);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - self.prefix_len)
                };
                (net_bits & mask) == (check_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

/// Compiled IP filter for efficient matching
#[derive(Debug)]
pub struct CompiledIpFilter {
    /// Whitelist ranges (if non-empty, only these IPs are allowed)
    allow_ranges: Vec<CidrRange>,
    /// Blacklist ranges (these IPs are denied)
    deny_ranges: Vec<CidrRange>,
}

impl CompiledIpFilter {
    /// Create a new compiled IP filter from configuration
    pub fn from_config(config: &IpFilterConfig) -> Self {
        let allow_ranges: Vec<_> = config.allow
            .iter()
            .filter_map(|s| CidrRange::parse(s))
            .collect();

        let deny_ranges: Vec<_> = config.deny
            .iter()
            .filter_map(|s| CidrRange::parse(s))
            .collect();

        Self {
            allow_ranges,
            deny_ranges,
        }
    }

    /// Check if an IP is allowed
    ///
    /// Logic:
    /// 1. If IP is in deny list, reject
    /// 2. If allow list is non-empty, IP must be in allow list
    /// 3. Otherwise, allow
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        // Check deny list first
        for range in &self.deny_ranges {
            if range.contains(ip) {
                debug!(ip = %ip, "IP denied by blacklist");
                return false;
            }
        }

        // If whitelist is configured, check it
        if !self.allow_ranges.is_empty() {
            for range in &self.allow_ranges {
                if range.contains(ip) {
                    debug!(ip = %ip, "IP allowed by whitelist");
                    return true;
                }
            }
            debug!(ip = %ip, "IP not in whitelist");
            return false;
        }

        // No whitelist, allow by default
        true
    }

    /// Check if this filter is active (has any rules)
    pub fn is_active(&self) -> bool {
        !self.allow_ranges.is_empty() || !self.deny_ranges.is_empty()
    }
}

/// Parse client IP from various sources
///
/// Priority:
/// 1. X-Forwarded-For header (first IP)
/// 2. X-Real-IP header
/// 3. Direct connection IP
pub fn parse_client_ip(
    xff_header: Option<&str>,
    xri_header: Option<&str>,
    remote_addr: Option<&str>,
) -> Option<IpAddr> {
    // Try X-Forwarded-For first (take first IP in chain)
    if let Some(xff) = xff_header {
        if let Some(first_ip) = xff.split(',').next() {
            if let Ok(ip) = IpAddr::from_str(first_ip.trim()) {
                return Some(ip);
            }
        }
    }

    // Try X-Real-IP
    if let Some(xri) = xri_header {
        if let Ok(ip) = IpAddr::from_str(xri.trim()) {
            return Some(ip);
        }
    }

    // Try remote address (may include port)
    if let Some(addr) = remote_addr {
        // Handle "ip:port" format
        let ip_str = if let Some((ip, _)) = addr.rsplit_once(':') {
            // Handle IPv6 in brackets: "[::1]:8080"
            if ip.starts_with('[') && ip.ends_with(']') {
                &ip[1..ip.len()-1]
            } else {
                ip
            }
        } else {
            addr
        };

        if let Ok(ip) = IpAddr::from_str(ip_str) {
            return Some(ip);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parse_ipv4() {
        let range = CidrRange::parse("192.168.1.0/24").unwrap();
        assert!(matches!(range.network, IpAddr::V4(_)));
        assert_eq!(range.prefix_len, 24);
    }

    #[test]
    fn test_cidr_parse_ipv6() {
        let range = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(matches!(range.network, IpAddr::V6(_)));
        assert_eq!(range.prefix_len, 32);
    }

    #[test]
    fn test_cidr_parse_single_ip() {
        let range = CidrRange::parse("192.168.1.1").unwrap();
        assert_eq!(range.prefix_len, 32);

        let range = CidrRange::parse("::1").unwrap();
        assert_eq!(range.prefix_len, 128);
    }

    #[test]
    fn test_cidr_contains_ipv4() {
        let range = CidrRange::parse("192.168.1.0/24").unwrap();

        assert!(range.contains(&"192.168.1.1".parse().unwrap()));
        assert!(range.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!range.contains(&"192.168.2.1".parse().unwrap()));
        assert!(!range.contains(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_contains_ipv6() {
        let range = CidrRange::parse("2001:db8::/32").unwrap();

        assert!(range.contains(&"2001:db8::1".parse().unwrap()));
        assert!(range.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!range.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_deny() {
        let config = IpFilterConfig {
            allow: vec![],
            deny: vec!["192.168.1.0/24".to_string()],
        };
        let filter = CompiledIpFilter::from_config(&config);

        assert!(!filter.is_allowed(&"192.168.1.100".parse().unwrap()));
        assert!(filter.is_allowed(&"192.168.2.100".parse().unwrap()));
        assert!(filter.is_allowed(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_allow() {
        let config = IpFilterConfig {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec![],
        };
        let filter = CompiledIpFilter::from_config(&config);

        assert!(filter.is_allowed(&"10.1.2.3".parse().unwrap()));
        assert!(!filter.is_allowed(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_deny_takes_precedence() {
        let config = IpFilterConfig {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec!["10.0.0.1".to_string()],
        };
        let filter = CompiledIpFilter::from_config(&config);

        // Specific IP is denied even though range is allowed
        assert!(!filter.is_allowed(&"10.0.0.1".parse().unwrap()));
        // Other IPs in range are allowed
        assert!(filter.is_allowed(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_parse_client_ip_xff() {
        let ip = parse_client_ip(
            Some("192.168.1.1, 10.0.0.1"),
            None,
            None,
        );
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_client_ip_xri() {
        let ip = parse_client_ip(
            None,
            Some("192.168.1.1"),
            None,
        );
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_client_ip_remote_addr() {
        let ip = parse_client_ip(None, None, Some("192.168.1.1:8080"));
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_client_ip_ipv6_remote_addr() {
        let ip = parse_client_ip(None, None, Some("[::1]:8080"));
        assert_eq!(ip, Some("::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_filter_inactive() {
        let config = IpFilterConfig::default();
        let filter = CompiledIpFilter::from_config(&config);

        assert!(!filter.is_active());
        assert!(filter.is_allowed(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_full_cidr_range() {
        // /0 should match all IPs of that type
        let range = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(range.contains(&"192.168.1.1".parse().unwrap()));
        assert!(range.contains(&"10.0.0.1".parse().unwrap()));
    }
}
