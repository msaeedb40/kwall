//! Automated threat intelligence feed ingestion (STIX 2.1, MISP, and Plaintext blocklists).

use crate::indicator::{IndicatorType, ThreatIndicator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::RwLock;

/// Configuration metadata for an ingested threat feed source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Unique identifier for the feed source (e.g. "alienvault_otx", "feodo_tracker").
    pub feed_name: String,
    /// Default confidence score (0-100) assigned to indicators from this feed.
    pub default_confidence: u8,
    /// Default threat category (e.g. "c2", "ransomware", "botnet").
    pub default_category: String,
    /// Optional default actor attribution.
    pub default_actor: Option<String>,
    /// Optional Time-To-Live in nanoseconds for indicators from this feed.
    pub indicator_ttl_ns: Option<u64>,
}

/// Parses STIX 2.1 JSON bundle content into threat indicators.
pub fn parse_stix2_json(
    json_content: &str,
    config: &FeedConfig,
    timestamp_ns: u64,
) -> Vec<ThreatIndicator> {
    #[derive(Deserialize)]
    struct StixBundle {
        objects: Option<Vec<StixObject>>,
    }

    #[derive(Deserialize)]
    struct StixObject {
        #[serde(rename = "type")]
        obj_type: String,
        pattern: Option<String>,
        confidence: Option<u8>,
        labels: Option<Vec<String>>,
        name: Option<String>,
    }

    let bundle: StixBundle = match serde_json::from_str(json_content) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let mut indicators = Vec::new();
    let objects = match bundle.objects {
        Some(objs) => objs,
        None => return Vec::new(),
    };

    let expires_at_ns = config
        .indicator_ttl_ns
        .map(|ttl| timestamp_ns.saturating_add(ttl));

    for obj in objects {
        if obj.obj_type != "indicator" {
            continue;
        }

        if let Some(pattern) = obj.pattern {
            if let Some((ind_type, value)) = extract_stix_pattern(&pattern) {
                let confidence = obj.confidence.unwrap_or(config.default_confidence);
                let tags = obj.labels.unwrap_or_default();
                let actor = obj.name.clone().or_else(|| config.default_actor.clone());

                indicators.push(ThreatIndicator::new(
                    value,
                    ind_type,
                    confidence,
                    &config.default_category,
                    actor,
                    &config.feed_name,
                    timestamp_ns,
                    expires_at_ns,
                    tags,
                ));
            }
        }
    }

    indicators
}

/// Helper extracting indicator type and value from STIX pattern syntax (e.g. `[ipv4-addr:value = '198.51.100.2']`).
fn extract_stix_pattern(pattern: &str) -> Option<(IndicatorType, String)> {
    let trimmed = pattern
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    let parts: Vec<&str> = trimmed.split('=').map(str::trim).collect();
    if parts.len() != 2 {
        return None;
    }

    let key = parts[0];
    let raw_val = parts[1].trim_matches('\'').trim_matches('"');

    if key.starts_with("ipv4-addr") {
        Some((IndicatorType::Ipv4, raw_val.to_string()))
    } else if key.starts_with("ipv6-addr") {
        Some((IndicatorType::Ipv6, raw_val.to_string()))
    } else if key.starts_with("domain-name") {
        Some((IndicatorType::Domain, raw_val.to_lowercase()))
    } else if key.starts_with("file:hashes") {
        Some((IndicatorType::Sha256, raw_val.to_lowercase()))
    } else if key.starts_with("url") {
        Some((IndicatorType::Url, raw_val.to_string()))
    } else {
        None
    }
}

/// Parses MISP JSON export format into threat indicators.
pub fn parse_misp_json(
    json_content: &str,
    config: &FeedConfig,
    timestamp_ns: u64,
) -> Vec<ThreatIndicator> {
    #[derive(Deserialize)]
    struct MispRoot {
        #[serde(rename = "Event")]
        event_direct: Option<MispEvent>,
        response: Option<MispResponse>,
    }

    #[derive(Deserialize)]
    struct MispResponse {
        #[serde(rename = "Event")]
        event: Option<MispEvent>,
    }

    #[derive(Deserialize)]
    struct MispEvent {
        info: Option<String>,
        #[serde(rename = "Attribute")]
        attributes: Option<Vec<MispAttribute>>,
    }

    #[derive(Deserialize)]
    struct MispAttribute {
        #[serde(rename = "type")]
        attr_type: String,
        value: String,
        category: Option<String>,
    }

    let root: MispRoot = match serde_json::from_str(json_content) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let event = root
        .event_direct
        .or_else(|| root.response.and_then(|r| r.event));
    let (event_info, attributes) = match event {
        Some(ev) => (ev.info, ev.attributes.unwrap_or_default()),
        None => return Vec::new(),
    };

    let expires_at_ns = config
        .indicator_ttl_ns
        .map(|ttl| timestamp_ns.saturating_add(ttl));
    let mut indicators = Vec::new();

    for attr in attributes {
        let (ind_type, normalized_val) = match attr.attr_type.as_str() {
            "ip-dst" | "ip-src" => {
                if attr.value.contains('/') {
                    (IndicatorType::Cidr, attr.value.trim().to_string())
                } else if attr.value.contains(':') {
                    (IndicatorType::Ipv6, attr.value.trim().to_string())
                } else {
                    (IndicatorType::Ipv4, attr.value.trim().to_string())
                }
            }
            "domain" | "hostname" => (IndicatorType::Domain, attr.value.trim().to_lowercase()),
            "sha256" => (IndicatorType::Sha256, attr.value.trim().to_lowercase()),
            "url" => (IndicatorType::Url, attr.value.trim().to_string()),
            _ => continue,
        };

        let threat_category = attr
            .category
            .unwrap_or_else(|| config.default_category.clone());
        let actor = event_info.clone().or_else(|| config.default_actor.clone());

        indicators.push(ThreatIndicator::new(
            normalized_val,
            ind_type,
            config.default_confidence,
            threat_category,
            actor,
            &config.feed_name,
            timestamp_ns,
            expires_at_ns,
            vec!["misp".to_string()],
        ));
    }

    indicators
}

/// Parses plain text, CSV, or line-delimited blocklists (e.g. AlienVault OTX, Spamhaus, FireHOL).
pub fn parse_blocklist_text(
    text: &str,
    config: &FeedConfig,
    timestamp_ns: u64,
) -> Vec<ThreatIndicator> {
    let mut indicators = Vec::new();
    let expires_at_ns = config
        .indicator_ttl_ns
        .map(|ttl| timestamp_ns.saturating_add(ttl));

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Support CSV by taking the first token
        let token = trimmed.split(',').next().unwrap_or(trimmed).trim();
        if token.is_empty() {
            continue;
        }

        // Infer indicator type
        let (ind_type, val) = if token.contains('/') {
            (IndicatorType::Cidr, token.to_string())
        } else if Ipv4Addr::from_str(token).is_ok() {
            (IndicatorType::Ipv4, token.to_string())
        } else if token.contains(':') {
            (IndicatorType::Ipv6, token.to_string())
        } else if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            (IndicatorType::Sha256, token.to_lowercase())
        } else if token.contains('.') {
            (IndicatorType::Domain, token.to_lowercase())
        } else {
            continue;
        };

        indicators.push(ThreatIndicator::new(
            val,
            ind_type,
            config.default_confidence,
            &config.default_category,
            config.default_actor.clone(),
            &config.feed_name,
            timestamp_ns,
            expires_at_ns,
            vec!["blocklist".to_string()],
        ));
    }

    indicators
}

/// Manager coordinating multiple registered threat intelligence feeds.
pub struct ThreatFeedManager {
    feeds: RwLock<HashMap<String, FeedConfig>>,
    indicators: RwLock<HashMap<String, ThreatIndicator>>,
}

impl Default for ThreatFeedManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFeedManager {
    /// Creates a new ThreatFeedManager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feeds: RwLock::new(HashMap::new()),
            indicators: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a new threat intelligence feed.
    pub fn register_feed(&self, config: FeedConfig) {
        let mut feeds = self.feeds.write().unwrap();
        feeds.insert(config.feed_name.clone(), config);
    }

    /// Ingests a collection of indicators into the manager.
    pub fn ingest_indicators(&self, new_indicators: Vec<ThreatIndicator>) {
        let mut indicators = self.indicators.write().unwrap();
        for ind in new_indicators {
            indicators.insert(ind.value.clone(), ind);
        }
    }

    /// Returns a list of all active, non-expired indicators.
    #[must_use]
    pub fn get_active_indicators(&self, current_time_ns: u64) -> Vec<ThreatIndicator> {
        let indicators = self.indicators.read().unwrap();
        indicators
            .values()
            .filter(|ind| !ind.is_expired(current_time_ns))
            .cloned()
            .collect()
    }

    /// Total count of indicators currently retained.
    #[must_use]
    pub fn total_indicators(&self) -> usize {
        self.indicators.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stix2_json() {
        let stix_data = r#"{
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '203.0.113.195']",
                    "confidence": 90,
                    "labels": ["malicious-activity", "c2"]
                },
                {
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'evil-c2-beacon.org']",
                    "confidence": 95,
                    "labels": ["apt29"]
                }
            ]
        }"#;

        let config = FeedConfig {
            feed_name: "stix_test_feed".to_string(),
            default_confidence: 80,
            default_category: "c2".to_string(),
            default_actor: Some("APT29".to_string()),
            indicator_ttl_ns: None,
        };

        let parsed = parse_stix2_json(stix_data, &config, 1_000_000_000);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(parsed[0].value, "203.0.113.195");
        assert_eq!(parsed[0].confidence, 90);

        assert_eq!(parsed[1].indicator_type, IndicatorType::Domain);
        assert_eq!(parsed[1].value, "evil-c2-beacon.org");
    }

    #[test]
    fn test_parse_misp_json() {
        let misp_data = r#"{
            "Event": {
                "info": "Mirai Botnet Scan",
                "Attribute": [
                    {
                        "type": "ip-dst",
                        "value": "198.51.100.77",
                        "category": "Network activity"
                    },
                    {
                        "type": "sha256",
                        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "category": "Payload delivery"
                    }
                ]
            }
        }"#;

        let config = FeedConfig {
            feed_name: "misp_test".to_string(),
            default_confidence: 85,
            default_category: "botnet".to_string(),
            default_actor: None,
            indicator_ttl_ns: None,
        };

        let parsed = parse_misp_json(misp_data, &config, 1_000_000_000);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].value, "198.51.100.77");
        assert_eq!(parsed[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(parsed[1].indicator_type, IndicatorType::Sha256);
    }

    #[test]
    fn test_parse_blocklist_text() {
        let blocklist_data = r#"
        # C2 IP Blocklist
        198.51.100.100
        10.99.0.0/16
        malicious-domain.com
        # comment
        "#;

        let config = FeedConfig {
            feed_name: "plain_test".to_string(),
            default_confidence: 75,
            default_category: "c2".to_string(),
            default_actor: None,
            indicator_ttl_ns: None,
        };

        let parsed = parse_blocklist_text(blocklist_data, &config, 1_000_000_000);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(parsed[0].value, "198.51.100.100");
        assert_eq!(parsed[1].indicator_type, IndicatorType::Cidr);
        assert_eq!(parsed[1].value, "10.99.0.0/16");
        assert_eq!(parsed[2].indicator_type, IndicatorType::Domain);
        assert_eq!(parsed[2].value, "malicious-domain.com");
    }
}
