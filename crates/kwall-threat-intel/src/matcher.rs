//! High-speed threat intelligence matching using Bloom filters and Longest Prefix Match (LPM).

use crate::bloom::ThreatBloomFilter;
use crate::indicator::{IndicatorType, ThreatIndicator};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Parsed CIDR representation for Longest Prefix Match (LPM).
#[derive(Debug, Clone)]
struct CidrEntry {
    network: u32,
    mask: u32,
    prefix_len: u8,
    indicator: ThreatIndicator,
}

/// High-performance threat matcher combining Bloom filters, hash maps, and LPM prefix tries.
#[derive(Debug, Clone)]
pub struct ThreatIntelMatcher {
    bloom: ThreatBloomFilter,
    exact_ips: HashMap<Ipv4Addr, ThreatIndicator>,
    cidrs: Vec<CidrEntry>,
    domains: HashMap<String, ThreatIndicator>,
    hashes: HashMap<String, ThreatIndicator>,
}

impl Default for ThreatIntelMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelMatcher {
    /// Creates an empty ThreatIntelMatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bloom: ThreatBloomFilter::new(1024, 0.01),
            exact_ips: HashMap::new(),
            cidrs: Vec::new(),
            domains: HashMap::new(),
            hashes: HashMap::new(),
        }
    }

    /// Builds a matcher from an iterator of threat indicators.
    #[must_use]
    pub fn from_indicators(indicators: &[ThreatIndicator]) -> Self {
        let expected_elements = indicators.len().max(64);
        let mut bloom = ThreatBloomFilter::new(expected_elements, 0.01);
        let mut exact_ips = HashMap::new();
        let mut cidrs = Vec::new();
        let mut domains = HashMap::new();
        let mut hashes = HashMap::new();

        for ind in indicators {
            bloom.insert(&ind.value);

            match ind.indicator_type {
                IndicatorType::Ipv4 => {
                    if let Ok(ip) = Ipv4Addr::from_str(&ind.value) {
                        exact_ips.insert(ip, ind.clone());
                    }
                }
                IndicatorType::Cidr => {
                    if let Some(entry) = Self::parse_cidr(&ind.value, ind.clone()) {
                        cidrs.push(entry);
                    }
                }
                IndicatorType::Domain => {
                    domains.insert(ind.value.to_lowercase(), ind.clone());
                }
                IndicatorType::Sha256 => {
                    hashes.insert(ind.value.to_lowercase(), ind.clone());
                }
                IndicatorType::Ipv6 | IndicatorType::Url => {
                    // Retained in bloom filter
                }
            }
        }

        // Sort CIDRs by prefix length descending to achieve Longest Prefix Match (LPM)
        cidrs.sort_by_key(|a| std::cmp::Reverse(a.prefix_len));

        Self {
            bloom,
            exact_ips,
            cidrs,
            domains,
            hashes,
        }
    }

    /// Helper parsing an IPv4 CIDR string (e.g., "198.51.100.0/24") into a bitwise `CidrEntry`.
    fn parse_cidr(cidr_str: &str, indicator: ThreatIndicator) -> Option<CidrEntry> {
        let parts: Vec<&str> = cidr_str.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;
        if prefix_len > 32 {
            return None;
        }

        let mask = if prefix_len == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix_len)
        };

        let network = u32::from(ip) & mask;

        Some(CidrEntry {
            network,
            mask,
            prefix_len,
            indicator,
        })
    }

    /// Matches a destination IPv4 address against known malicious IPs and CIDR ranges.
    #[must_use]
    pub fn match_ip(&self, ip: Ipv4Addr) -> Option<&ThreatIndicator> {
        let ip_str = ip.to_string();

        // 1. Check exact IP map if Bloom filter indicates potential presence
        if self.bloom.contains(&ip_str) {
            if let Some(indicator) = self.exact_ips.get(&ip) {
                return Some(indicator);
            }
        }

        // 2. Longest Prefix Match (LPM) scan for enclosing CIDR blocks
        let ip_u32 = u32::from(ip);
        for entry in &self.cidrs {
            if (ip_u32 & entry.mask) == entry.network {
                return Some(&entry.indicator);
            }
        }

        None
    }

    /// Matches a domain name against known malicious FQDNs and wildcard parent domains.
    #[must_use]
    pub fn match_domain(&self, domain: &str) -> Option<&ThreatIndicator> {
        let normalized = domain.to_lowercase();
        let trimmed = normalized.trim_end_matches('.');

        // 1. Fast negative check via Bloom filter
        if !self.bloom.contains(trimmed) && !trimmed.contains('.') {
            return None;
        }

        // 2. Exact match
        if let Some(ind) = self.domains.get(trimmed) {
            return Some(ind);
        }

        // 3. Subdomain hierarchy check (e.g. "sub.evil.com" matches "evil.com")
        let parts: Vec<&str> = trimmed.split('.').collect();
        for i in 1..parts.len() {
            let parent_domain = parts[i..].join(".");
            if let Some(ind) = self.domains.get(&parent_domain) {
                return Some(ind);
            }
        }

        None
    }

    /// Matches a SHA-256 binary hash against known malicious indicators.
    #[must_use]
    pub fn match_hash(&self, hash: &str) -> Option<&ThreatIndicator> {
        let normalized = hash.to_lowercase();
        if !self.bloom.contains(&normalized) {
            return None;
        }

        self.hashes.get(&normalized)
    }

    /// Returns the total number of indicators compiled in the matcher.
    #[must_use]
    pub fn total_indicators(&self) -> usize {
        self.exact_ips.len() + self.cidrs.len() + self.domains.len() + self.hashes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_ip_and_cidr_lpm() {
        let ind_ip = ThreatIndicator::new(
            "198.51.100.42",
            IndicatorType::Ipv4,
            90,
            "c2",
            Some("APT29".to_string()),
            "feed",
            1_000,
            None,
            vec![],
        );

        let ind_cidr = ThreatIndicator::new(
            "203.0.113.0/24",
            IndicatorType::Cidr,
            80,
            "malicious_subnet",
            None,
            "feed",
            1_000,
            None,
            vec![],
        );

        let matcher = ThreatIntelMatcher::from_indicators(&[ind_ip, ind_cidr]);

        // Exact IP match
        let hit_ip = matcher.match_ip(Ipv4Addr::new(198, 51, 100, 42));
        assert!(hit_ip.is_some());
        assert_eq!(hit_ip.unwrap().threat_category, "c2");

        // CIDR LPM match
        let hit_cidr = matcher.match_ip(Ipv4Addr::new(203, 0, 113, 88));
        assert!(hit_cidr.is_some());
        assert_eq!(hit_cidr.unwrap().threat_category, "malicious_subnet");

        // Negative match
        assert!(matcher.match_ip(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(matcher.match_ip(Ipv4Addr::new(203, 0, 114, 1)).is_none());
    }

    #[test]
    fn test_matcher_domain_subdomain_and_hash() {
        let ind_domain = ThreatIndicator::new(
            "evil-c2.com",
            IndicatorType::Domain,
            95,
            "c2",
            None,
            "feed",
            1_000,
            None,
            vec![],
        );

        let ind_hash = ThreatIndicator::new(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IndicatorType::Sha256,
            99,
            "malware",
            None,
            "feed",
            1_000,
            None,
            vec![],
        );

        let matcher = ThreatIntelMatcher::from_indicators(&[ind_domain, ind_hash]);

        // Exact domain match
        assert!(matcher.match_domain("evil-c2.com").is_some());
        // Subdomain match
        assert!(matcher.match_domain("api.sub.evil-c2.com").is_some());
        // Unrelated domain
        assert!(matcher.match_domain("good-site.com").is_none());

        // Hash match
        assert!(matcher
            .match_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .is_some());
        assert!(matcher
            .match_hash("0000000000000000000000000000000000000000000000000000000000000000")
            .is_none());
    }
}
