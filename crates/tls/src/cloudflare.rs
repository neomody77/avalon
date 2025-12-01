//! Cloudflare proxy detection
//!
//! Utilities to detect if a domain is behind Cloudflare proxy,
//! which affects ACME HTTP-01 challenge validation.

use std::net::IpAddr;
use tracing::{debug, info};

/// Cloudflare IPv4 ranges (as of 2024)
/// Source: https://www.cloudflare.com/ips-v4
const CLOUDFLARE_IPV4_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Cloudflare IPv6 ranges
/// Source: https://www.cloudflare.com/ips-v6
const CLOUDFLARE_IPV6_RANGES: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Result of Cloudflare detection
#[derive(Debug, Clone)]
pub struct CloudflareDetection {
    /// Whether the domain appears to be behind Cloudflare
    pub is_cloudflare: bool,
    /// Resolved IP addresses
    pub resolved_ips: Vec<IpAddr>,
    /// Detection method used
    pub method: DetectionMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Detected via IP range check
    IpRange,
    /// Detected via DNS TXT record
    DnsTxt,
    /// Not detected
    None,
}

/// Check if an IP address belongs to Cloudflare
pub fn is_cloudflare_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip_u32 = u32::from(ipv4);
            for range in CLOUDFLARE_IPV4_RANGES {
                if let Some((network, prefix)) = parse_cidr_v4(range) {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    if (ip_u32 & mask) == (network & mask) {
                        return true;
                    }
                }
            }
            false
        }
        IpAddr::V6(ipv6) => {
            let ip_u128 = u128::from(ipv6);
            for range in CLOUDFLARE_IPV6_RANGES {
                if let Some((network, prefix)) = parse_cidr_v6(range) {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u128 << (128 - prefix)
                    };
                    if (ip_u128 & mask) == (network & mask) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u32 = parts[1].parse().ok()?;
    Some((u32::from(ip), prefix))
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: std::net::Ipv6Addr = parts[0].parse().ok()?;
    let prefix: u32 = parts[1].parse().ok()?;
    Some((u128::from(ip), prefix))
}

/// Detect if a domain is behind Cloudflare by resolving its DNS
pub fn detect_cloudflare(domain: &str) -> CloudflareDetection {
    use std::net::ToSocketAddrs;

    let addr_str = format!("{}:443", domain);
    let resolved_ips: Vec<IpAddr> = match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(e) => {
            debug!(domain = %domain, error = %e, "Failed to resolve domain");
            return CloudflareDetection {
                is_cloudflare: false,
                resolved_ips: vec![],
                method: DetectionMethod::None,
            };
        }
    };

    let is_cloudflare = resolved_ips.iter().any(|ip| is_cloudflare_ip(*ip));

    if is_cloudflare {
        info!(domain = %domain, ips = ?resolved_ips, "Domain appears to be behind Cloudflare");
    } else {
        debug!(domain = %domain, ips = ?resolved_ips, "Domain is not behind Cloudflare");
    }

    CloudflareDetection {
        is_cloudflare,
        resolved_ips,
        method: if is_cloudflare {
            DetectionMethod::IpRange
        } else {
            DetectionMethod::None
        },
    }
}

/// Check if request headers indicate Cloudflare proxy
pub fn has_cloudflare_headers(headers: &[(String, String)]) -> bool {
    let cf_headers = ["cf-ray", "cf-connecting-ip", "cf-ipcountry", "cf-visitor"];

    for (name, _) in headers {
        let lower = name.to_lowercase();
        if cf_headers.iter().any(|h| lower == *h) {
            return true;
        }
    }
    false
}

/// Recommendations for ACME when behind Cloudflare
#[derive(Debug)]
pub struct CloudflareAcmeAdvice {
    pub can_use_http01: bool,
    pub recommendation: &'static str,
    pub alternatives: Vec<&'static str>,
}

/// Get ACME advice for a domain that may be behind Cloudflare
pub fn get_acme_advice(detection: &CloudflareDetection) -> CloudflareAcmeAdvice {
    if detection.is_cloudflare {
        CloudflareAcmeAdvice {
            can_use_http01: false,
            recommendation: "Domain is behind Cloudflare. HTTP-01 validation may fail.",
            alternatives: vec![
                "Use DNS-01 validation with Cloudflare API",
                "Temporarily disable Cloudflare proxy (DNS only mode)",
                "Use Cloudflare Origin CA certificates",
                "Use a self-signed certificate and let Cloudflare handle public TLS",
            ],
        }
    } else {
        CloudflareAcmeAdvice {
            can_use_http01: true,
            recommendation: "HTTP-01 validation should work normally.",
            alternatives: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cloudflare_ip_detection() {
        // Known Cloudflare IPs
        assert!(is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1))));
        assert!(is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(172, 64, 0, 1))));
        assert!(is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(162, 158, 0, 1))));

        // Non-Cloudflare IPs
        assert!(!is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))); // This is actually CF but different range
        assert!(!is_cloudflare_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_parse_cidr_v4() {
        let (network, prefix) = parse_cidr_v4("104.16.0.0/13").unwrap();
        assert_eq!(prefix, 13);
        assert_eq!(network, u32::from(Ipv4Addr::new(104, 16, 0, 0)));
    }

    #[test]
    fn test_cloudflare_headers() {
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("CF-Ray".to_string(), "abc123".to_string()),
        ];
        assert!(has_cloudflare_headers(&headers));

        let no_cf_headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("X-Custom".to_string(), "value".to_string()),
        ];
        assert!(!has_cloudflare_headers(&no_cf_headers));
    }

    #[test]
    fn test_acme_advice_cloudflare() {
        let detection = CloudflareDetection {
            is_cloudflare: true,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1))],
            method: DetectionMethod::IpRange,
        };
        let advice = get_acme_advice(&detection);
        assert!(!advice.can_use_http01);
        assert!(!advice.alternatives.is_empty());
    }

    #[test]
    fn test_acme_advice_no_cloudflare() {
        let detection = CloudflareDetection {
            is_cloudflare: false,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            method: DetectionMethod::None,
        };
        let advice = get_acme_advice(&detection);
        assert!(advice.can_use_http01);
        assert!(advice.alternatives.is_empty());
    }
}
