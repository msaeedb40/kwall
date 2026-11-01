//! Threat intelligence indicator types and metadata definitions.

use serde::{Deserialize, Serialize};

/// Classification of a threat intelligence indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    /// Single IPv4 address (e.g., "198.51.100.2")
    Ipv4,
    /// Single IPv6 address (e.g., "2001:db8::1")
    Ipv6,
    /// Classless Inter-Domain Routing prefix (e.g., "198.51.100.0/24")
    Cidr,
    /// Domain name or Fully Qualified Domain Name (e.g., "c2-beacon.attacker.com")
    Domain,
    /// SHA-256 cryptographic file hash (64 hex characters)
    Sha256,
    /// Full URL string (e.g., "http://evil.com/payload.sh")
    Url,
}

/// A structured threat indicator representing a known malicious observable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// The observable indicator value (IP, CIDR, domain, SHA256, URL).
    pub value: String,
    /// Classification type of the indicator.
    pub indicator_type: IndicatorType,
    /// Confidence score on a scale from 0 to 100.
    pub confidence: u8,
    /// Threat category (e.g., "c2", "ransomware", "cryptominer", "phishing", "botnet").
    pub threat_category: String,
    /// Associated threat actor, APT group, or malware family if known (e.g., "APT29", "Mirai").
    pub actor: Option<String>,
    /// Originating feed name or provider identifier.
    pub source_feed: String,
    /// Nanosecond timestamp when the indicator was added or ingested.
    pub added_at_ns: u64,
    /// Optional expiration timestamp; None indicates indefinite validity.
    pub expires_at_ns: Option<u64>,
    /// Informational tags associated with the indicator.
    pub tags: Vec<String>,
}

impl ThreatIndicator {
    /// Constructs a new ThreatIndicator.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        value: impl Into<String>,
        indicator_type: IndicatorType,
        confidence: u8,
        threat_category: impl Into<String>,
        actor: Option<String>,
        source_feed: impl Into<String>,
        added_at_ns: u64,
        expires_at_ns: Option<u64>,
        tags: Vec<String>,
    ) -> Self {
        Self {
            value: value.into(),
            indicator_type,
            confidence: confidence.min(100),
            threat_category: threat_category.into(),
            actor,
            source_feed: source_feed.into(),
            added_at_ns,
            expires_at_ns,
            tags,
        }
    }

    /// Determines if the indicator has expired relative to a given nanosecond timestamp.
    #[must_use]
    pub fn is_expired(&self, current_time_ns: u64) -> bool {
        match self.expires_at_ns {
            Some(expiry) => current_time_ns >= expiry,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indicator_creation_and_expiration() {
        let ind = ThreatIndicator::new(
            "198.51.100.42",
            IndicatorType::Ipv4,
            95,
            "c2",
            Some("Lazarus".to_string()),
            "alienvault_otx",
            1_000_000_000,
            Some(1_005_000_000),
            vec!["apt".to_string(), "c2".to_string()],
        );

        assert_eq!(ind.value, "198.51.100.42");
        assert_eq!(ind.confidence, 95);
        assert!(!ind.is_expired(1_004_000_000));
        assert!(ind.is_expired(1_005_000_000));
        assert!(ind.is_expired(1_006_000_000));
    }
}
