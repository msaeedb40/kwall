//! Network behavioral detectors: port scans, lateral movement, and data exfiltration.

use crate::alert::{ThreatAlert, ThreatCategory};
use kwall_core::types::Severity;
use kwall_event_enricher::enricher::EnrichedEvent;
use kwall_event_router::event::EventPayload;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::RwLock;

/// Configuration parameters for network anomaly detectors.
#[derive(Debug, Clone)]
pub struct NetworkDetectorConfig {
    /// Port scan threshold: number of distinct ports within window.
    pub port_scan_threshold: usize,
    /// Port scan sliding time window in nanoseconds (e.g. 5 seconds).
    pub port_scan_window_ns: u64,
    /// High-frequency egress packet rate limit per second.
    pub max_external_flows_per_sec: u64,
}

impl Default for NetworkDetectorConfig {
    fn default() -> Self {
        Self {
            port_scan_threshold: 10,
            port_scan_window_ns: 5_000_000_000, // 5s
            max_external_flows_per_sec: 100,
        }
    }
}

/// Key identifying source workload and destination IP pair.
pub type FlowEndpointKey = (String, String);
/// Port scan attempt timestamp and target destination port.
pub type PortAttempt = (u64, u16);
/// In-memory port scan sliding window state map.
pub type PortScanMap = HashMap<FlowEndpointKey, Vec<PortAttempt>>;

/// Evaluates network telemetry for port scans, lateral movement, and data exfiltration.
pub struct NetworkThreatDetector {
    config: NetworkDetectorConfig,
    /// Sliding window of (timestamp_ns, dst_port) keyed by (src_workload_id, dst_ip).
    port_scan_state: RwLock<PortScanMap>,
    /// Sliding window of external flow timestamps keyed by src_workload_id.
    egress_flow_state: RwLock<HashMap<String, Vec<u64>>>,
}

impl NetworkThreatDetector {
    /// Creates a new detector with given configuration.
    pub fn new(config: NetworkDetectorConfig) -> Self {
        Self {
            config,
            port_scan_state: RwLock::new(HashMap::new()),
            egress_flow_state: RwLock::new(HashMap::new()),
        }
    }

    /// Evaluates an event against network heuristic detectors.
    pub fn evaluate(&self, event: &EnrichedEvent) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        if let EventPayload::Network(net) = &event.base_event.payload {
            let src_id = event
                .src_workload
                .as_ref()
                .map(|w| format!("{}/{}", w.namespace, w.pod_name))
                .unwrap_or_else(|| net.src_ip.clone());

            // 1. Port scan detection (T1046)
            if let Some(alert) = self.detect_port_scan(event, &src_id, &net.dst_ip, net.dst_port) {
                alerts.push(alert);
            }

            // 2. Lateral movement detection (T1021)
            if let Some(alert) = self.detect_lateral_movement(event) {
                alerts.push(alert);
            }

            // 3. High-frequency external egress detection (T1048)
            if let Some(alert) = self.detect_data_exfiltration(event, &src_id, &net.dst_ip) {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Detects scanning attempts across sequential/multiple destination ports.
    fn detect_port_scan(
        &self,
        event: &EnrichedEvent,
        src_id: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<ThreatAlert> {
        let now = event.base_event.timestamp_ns;
        let window = self.config.port_scan_window_ns;
        let threshold = self.config.port_scan_threshold;

        let mut lock = self.port_scan_state.write().ok()?;
        let entries = lock
            .entry((src_id.to_string(), dst_ip.to_string()))
            .or_default();

        // Prune expired entries
        entries.retain(|(ts, _)| now.saturating_sub(*ts) <= window);
        entries.push((now, dst_port));

        let unique_ports: HashSet<u16> = entries.iter().map(|(_, p)| *p).collect();
        if unique_ports.len() >= threshold {
            entries.clear(); // Reset to prevent spamming duplicate alerts
            Some(ThreatAlert::new(
                format!("threat-portscan-{}", event.base_event.event_id),
                now,
                Severity::Error,
                ThreatCategory::NetworkScan,
                Some("T1046"),
                format!("Network Port Scan Detected against {dst_ip}"),
                format!(
                    "Workload '{src_id}' probed {} distinct ports on destination '{dst_ip}' within window.",
                    unique_ports.len()
                ),
                event.src_workload.clone(),
                serde_json::json!({
                    "src_workload": src_id,
                    "dst_ip": dst_ip,
                    "distinct_ports_count": unique_ports.len(),
                    "window_ns": window
                }),
                "Enforce egress network policy or apply immediate microsegmentation",
            ))
        } else {
            None
        }
    }

    /// Detects lateral movement into protected namespaces like `kube-system`.
    fn detect_lateral_movement(&self, event: &EnrichedEvent) -> Option<ThreatAlert> {
        if let (Some(src), Some(dst)) = (&event.src_workload, &event.dst_workload) {
            // Check if cross-namespace communication into kube-system occurs from non-kube-system pod
            if src.namespace != "kube-system" && dst.namespace == "kube-system" {
                return Some(ThreatAlert::new(
                    format!("threat-lateral-{}", event.base_event.event_id),
                    event.base_event.timestamp_ns,
                    Severity::Error,
                    ThreatCategory::LateralMovement,
                    Some("T1021"),
                    format!(
                        "Unauthorized Lateral Flow to kube-system from {}",
                        src.namespace
                    ),
                    format!(
                        "Pod '{}/{}' initiated direct connection to internal system pod '{}/{}'.",
                        src.namespace, src.pod_name, dst.namespace, dst.pod_name
                    ),
                    Some(src.clone()),
                    serde_json::json!({
                        "src_pod": src.pod_name,
                        "src_ns": src.namespace,
                        "dst_pod": dst.pod_name,
                        "dst_ns": dst.namespace
                    }),
                    "Deny cross-namespace connection to cluster control plane services",
                ));
            }
        }
        None
    }

    /// Detects abnormal egress traffic bursts to non-RFC1918 public IP addresses.
    fn detect_data_exfiltration(
        &self,
        event: &EnrichedEvent,
        src_id: &str,
        dst_ip: &str,
    ) -> Option<ThreatAlert> {
        if !is_public_ipv4(dst_ip) {
            return None;
        }

        let now = event.base_event.timestamp_ns;
        let window = 1_000_000_000; // 1 second

        let mut lock = self.egress_flow_state.write().ok()?;
        let timestamps = lock.entry(src_id.to_string()).or_default();

        timestamps.retain(|ts| now.saturating_sub(*ts) <= window);
        timestamps.push(now);

        if (timestamps.len() as u64) > self.config.max_external_flows_per_sec {
            let count = timestamps.len();
            timestamps.clear();

            Some(ThreatAlert::new(
                format!("threat-exfil-{}", event.base_event.event_id),
                now,
                Severity::Critical,
                ThreatCategory::DataExfiltration,
                Some("T1048"),
                format!("High-Frequency External Egress Flow from {src_id}"),
                format!(
                    "Workload '{src_id}' initiated {count} external outbound connections within 1s to {dst_ip}."
                ),
                event.src_workload.clone(),
                serde_json::json!({
                    "src_workload": src_id,
                    "dst_ip": dst_ip,
                    "flows_per_sec": count
                }),
                "Throttle or terminate workload network interface to mitigate data exfiltration",
            ))
        } else {
            None
        }
    }
}

/// Helper function to determine if an IPv4 address is public (non-RFC1918, non-loopback, non-linklocal).
fn is_public_ipv4(ip_str: &str) -> bool {
    if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
        let octets = ip.octets();
        // 10.0.0.0/8
        if octets[0] == 10 {
            return false;
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return false;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return false;
        }
        // 127.0.0.0/8
        if octets[0] == 127 {
            return false;
        }
        // 169.254.0.0/16 (link local)
        if octets[0] == 169 && octets[1] == 254 {
            return false;
        }
        // Multicast / Broadcast
        if octets[0] >= 224 {
            return false;
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{EventSource, NodeId};
    use kwall_event_enricher::enricher::EnrichedWorkloadContext;
    use kwall_event_router::event::{KwallEvent, NetworkEventData};

    #[test]
    fn test_port_scan_detection() {
        let config = NetworkDetectorConfig {
            port_scan_threshold: 3,
            port_scan_window_ns: 1_000_000_000,
            max_external_flows_per_sec: 100,
        };
        let detector = NetworkThreatDetector::new(config);

        let make_event = |id: u128, port: u16| EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: id,
                timestamp_ns: 1000 + (id as u64) * 10,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::Tc,
                payload: EventPayload::Network(NetworkEventData {
                    src_ip: "10.244.0.5".to_string(),
                    dst_ip: "10.244.0.10".to_string(),
                    src_port: 45000,
                    dst_port: port,
                    protocol: 6,
                    action: "pass".to_string(),
                    packet_len: 64,
                    ifindex: 2,
                }),
            },
            src_workload: Some(EnrichedWorkloadContext {
                pod_name: "scanner".to_string(),
                namespace: "default".to_string(),
                workload_owner: None,
                service_account: "default".to_string(),
                spiffe_id: "spiffe://cluster.local/ns/default/sa/default".to_string(),
                labels: Default::default(),
            }),
            dst_workload: None,
        };

        assert!(detector.evaluate(&make_event(1, 80)).is_empty());
        assert!(detector.evaluate(&make_event(2, 443)).is_empty());

        let alerts = detector.evaluate(&make_event(3, 8080));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::NetworkScan);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1046"));
    }

    #[test]
    fn test_lateral_movement_to_kube_system() {
        let detector = NetworkThreatDetector::new(NetworkDetectorConfig::default());
        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 20,
                timestamp_ns: 5000,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::Tc,
                payload: EventPayload::Network(NetworkEventData {
                    src_ip: "10.244.1.2".to_string(),
                    dst_ip: "10.244.0.1".to_string(),
                    src_port: 50000,
                    dst_port: 443,
                    protocol: 6,
                    action: "pass".to_string(),
                    packet_len: 64,
                    ifindex: 2,
                }),
            },
            src_workload: Some(EnrichedWorkloadContext {
                pod_name: "untrusted-app".to_string(),
                namespace: "tenant-a".to_string(),
                workload_owner: None,
                service_account: "default".to_string(),
                spiffe_id: "spiffe://cluster.local/ns/tenant-a/sa/default".to_string(),
                labels: Default::default(),
            }),
            dst_workload: Some(EnrichedWorkloadContext {
                pod_name: "kube-dns".to_string(),
                namespace: "kube-system".to_string(),
                workload_owner: None,
                service_account: "kube-dns".to_string(),
                spiffe_id: "spiffe://cluster.local/ns/kube-system/sa/kube-dns".to_string(),
                labels: Default::default(),
            }),
        };

        let alerts = detector.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::LateralMovement);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1021"));
    }
}
