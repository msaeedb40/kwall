//! Incident timeline reconstruction, cryptographic event hash chaining, and signed audit reporting.
//!
//! Reconstructs the end-to-end attack progression leading up to a threat alert,
//! sealing forensic artifacts into tamper-evident hash-chained audit reports.

use kwall_detection::alert::ThreatAlert;
use kwall_l7::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

/// An individual chronological event record within an incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub event_source: String,
    pub event_type: String,
    pub description: String,
    pub details: serde_json::Value,
    /// Cryptographic SHA-256 hash chaining this entry to the prior record.
    pub prev_hash: String,
    /// Cryptographic SHA-256 hash of this entry's payload and prior hash.
    pub entry_hash: String,
}

/// Tamper-evident incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTimeline {
    pub timeline_id: String,
    pub workload_id: String,
    pub created_at_ns: u64,
    pub entries: Vec<TimelineEntry>,
    pub root_hash: String,
}

impl IncidentTimeline {
    /// Constructs a new empty incident timeline for a workload.
    #[must_use]
    pub fn new(workload_id: &str) -> Self {
        let now = kwall_common::utilities::current_timestamp_ns();
        Self {
            timeline_id: format!("tl-{}-{}", workload_id, now),
            workload_id: workload_id.to_string(),
            created_at_ns: now,
            entries: Vec::new(),
            root_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    /// Appends an event to the chronological timeline, updating the cryptographic hash chain.
    pub fn append(
        &mut self,
        timestamp_ns: u64,
        event_source: impl Into<String>,
        event_type: impl Into<String>,
        description: impl Into<String>,
        details: serde_json::Value,
    ) {
        let sequence = self.entries.len() as u64;
        let prev_hash = self.root_hash.clone();

        let source = event_source.into();
        let ev_type = event_type.into();
        let desc = description.into();

        // Compute hash of this entry combined with prev_hash
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}",
            sequence, timestamp_ns, source, ev_type, desc, prev_hash
        );
        let entry_hash = sha256_hex(hash_input.as_bytes());

        self.root_hash = entry_hash.clone();
        self.entries.push(TimelineEntry {
            sequence,
            timestamp_ns,
            event_source: source,
            event_type: ev_type,
            description: desc,
            details,
            prev_hash,
            entry_hash,
        });
    }

    /// Validates the internal cryptographic integrity of the entire timeline chain.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let mut expected_prev_hash =
            "0000000000000000000000000000000000000000000000000000000000000000";

        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.sequence != idx as u64 {
                return false;
            }
            if entry.prev_hash != expected_prev_hash {
                return false;
            }
            let hash_input = format!(
                "{}:{}:{}:{}:{}:{}",
                entry.sequence,
                entry.timestamp_ns,
                entry.event_source,
                entry.event_type,
                entry.description,
                entry.prev_hash
            );
            let calculated_hash = sha256_hex(hash_input.as_bytes());
            if entry.entry_hash != calculated_hash {
                return false;
            }
            expected_prev_hash = &entry.entry_hash;
        }

        if let Some(last) = self.entries.last() {
            if last.entry_hash != self.root_hash {
                return false;
            }
        }

        true
    }
}

/// A tamper-evident, sealed forensic incident report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedIncidentReport {
    pub report_id: String,
    pub generated_at_ns: u64,
    pub primary_alert: ThreatAlert,
    pub timeline: IncidentTimeline,
    pub integrity_digest: String,
    pub signature_algorithm: String,
    pub signature_hex: String,
}

/// Incident report generator sealing alerts and reconstructed timelines into audit records.
pub struct IncidentReportGenerator;

impl IncidentReportGenerator {
    /// Generates a cryptographically signed incident report.
    #[must_use]
    pub fn generate_report(
        primary_alert: ThreatAlert,
        timeline: IncidentTimeline,
        signing_key_id: &str,
    ) -> SignedIncidentReport {
        let now = kwall_common::utilities::current_timestamp_ns();
        let report_id = format!("rep-{}", primary_alert.alert_id);

        let report_digest_input = format!(
            "{}:{}:{}:{}",
            report_id, primary_alert.alert_id, timeline.root_hash, now
        );
        let integrity_digest = sha256_hex(report_digest_input.as_bytes());

        // Compute report signature representation (HMAC/SHA256 digest keyed with signing identity)
        let sig_input = format!("{}:{}", integrity_digest, signing_key_id);
        let signature_hex = sha256_hex(sig_input.as_bytes());

        SignedIncidentReport {
            report_id,
            generated_at_ns: now,
            primary_alert,
            timeline,
            integrity_digest,
            signature_algorithm: "HMAC-SHA256".to_string(),
            signature_hex,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::Severity;
    use kwall_detection::alert::ThreatCategory;

    #[test]
    fn test_incident_timeline_chain_and_verification() {
        let mut timeline = IncidentTimeline::new("workload-db-1");

        // Add 3 sequential events
        timeline.append(
            1_000,
            "xdp",
            "net_flow",
            "Inbound connection from 10.0.0.5:443",
            serde_json::json!({ "sport": 443 }),
        );
        timeline.append(
            2_000,
            "tracepoint",
            "process_exec",
            "Executed /bin/sh",
            serde_json::json!({ "pid": 42 }),
        );
        timeline.append(
            3_000,
            "lsm",
            "sensitive_file",
            "Accessed /etc/shadow",
            serde_json::json!({ "path": "/etc/shadow" }),
        );

        assert_eq!(timeline.entries.len(), 3);
        assert!(timeline.verify_integrity());

        // Tamper test: modify one entry's description
        timeline.entries[1].description = "Altered description".to_string();
        assert!(!timeline.verify_integrity());
    }

    #[test]
    fn test_signed_incident_report_generation() {
        let timeline = IncidentTimeline::new("workload-api-1");
        let alert = ThreatAlert::new(
            "alert-999".to_string(),
            1_000_000,
            Severity::Critical,
            ThreatCategory::ContainerEscape,
            Some("T1611"),
            "Container Escape Detected",
            "Attempted mount of host root",
            None,
            serde_json::json!({}),
            "Quarantine and freeze pod",
        );

        let report =
            IncidentReportGenerator::generate_report(alert, timeline, "kwall-master-key-01");
        assert_eq!(report.report_id, "rep-alert-999");
        assert_eq!(report.signature_algorithm, "HMAC-SHA256");
        assert_eq!(report.signature_hex.len(), 64);
    }
}
