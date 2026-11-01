//! KWALL Automated Incident Response, Forensics & Workload Quarantine Engine.
//!
//! Provides dynamic network quarantine (with administrative triage exemptions),
//! process tree signal termination, Linux cgroup execution freezing,
//! rolling PCAP recording, live forensic snapshots, and cryptographic incident timelines.

pub mod isolation;
pub mod pcap;
pub mod quarantine;
pub mod snapshot;
pub mod timeline;

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub use isolation::{CgroupFreezeState, CgroupFreezer, IsolationError, ProcessTerminator};
use kwall_core::types::Severity;
use kwall_detection::alert::ThreatAlert;
pub use pcap::{CapturedPacket, RollingPcapRecorder};
pub use quarantine::{QuarantineController, QuarantineError, QuarantineLevel, QuarantineRecord};
pub use snapshot::{ForensicEvidenceBundle, ForensicSnapshotManager};
pub use timeline::{
    IncidentReportGenerator, IncidentTimeline, SignedIncidentReport, TimelineEntry,
};

/// Automated actions executed during an incident response workflow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IncidentResponseResult {
    pub incident_id: String,
    pub alert_id: String,
    pub timestamp_ns: u64,
    pub quarantine_record: Option<QuarantineRecord>,
    pub cgroup_frozen: bool,
    pub terminated_pids: Vec<u32>,
    pub forensic_bundle: Option<ForensicEvidenceBundle>,
    pub signed_report: Option<SignedIncidentReport>,
}

/// Statistics for automated incident response operations.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct IncidentResponseMetrics {
    pub total_incidents_handled: u64,
    pub total_quarantines_enforced: u64,
    pub total_cgroups_frozen: u64,
    pub total_processes_terminated: u64,
    pub total_reports_signed: u64,
}

/// Comprehensive Incident Response Engine orchestrating containment and forensic acquisition.
pub struct IncidentResponseEngine {
    pub quarantine_controller: Arc<QuarantineController>,
    pub cgroup_freezer: Arc<CgroupFreezer>,
    pub pcap_recorder: Arc<RollingPcapRecorder>,
    signing_key_id: String,
    total_incidents: AtomicU64,
    total_quarantines: AtomicU64,
    total_frozen: AtomicU64,
    total_terminated: AtomicU64,
    total_reports: AtomicU64,
}

impl Default for IncidentResponseEngine {
    fn default() -> Self {
        Self::new(&[], &[], 1000, "kwall-default-signing-key")
    }
}

impl IncidentResponseEngine {
    /// Creates a new engine with administrative bastion access and PCAP buffer capacity.
    #[must_use]
    pub fn new(
        admin_bastion_ips: &[Ipv4Addr],
        admin_ports: &[u16],
        pcap_capacity: usize,
        signing_key_id: impl Into<String>,
    ) -> Self {
        Self {
            quarantine_controller: Arc::new(QuarantineController::new(
                admin_bastion_ips,
                admin_ports,
            )),
            cgroup_freezer: Arc::new(CgroupFreezer::default()),
            pcap_recorder: Arc::new(RollingPcapRecorder::new(pcap_capacity)),
            signing_key_id: signing_key_id.into(),
            total_incidents: AtomicU64::new(0),
            total_quarantines: AtomicU64::new(0),
            total_frozen: AtomicU64::new(0),
            total_terminated: AtomicU64::new(0),
            total_reports: AtomicU64::new(0),
        }
    }

    /// Automatically handles a triggered security threat alert based on severity and category.
    pub fn handle_alert(
        &self,
        alert: &ThreatAlert,
        target_ip: Option<Ipv4Addr>,
        target_pid: Option<u32>,
        cgroup_path: Option<&Path>,
        workload_id: &str,
    ) -> IncidentResponseResult {
        let now = kwall_common::utilities::current_timestamp_ns();
        self.total_incidents.fetch_add(1, Ordering::Relaxed);

        let mut quarantine_record = None;
        let mut cgroup_frozen = false;
        let mut terminated_pids = Vec::new();

        // 1. Network Quarantine
        if let Some(ip) = target_ip {
            let q_level = match alert.severity {
                Severity::Critical => QuarantineLevel::Full,
                _ => QuarantineLevel::AdministrativeOnly,
            };

            if let Ok(rec) = self.quarantine_controller.apply_quarantine(
                workload_id,
                ip,
                None,
                q_level,
                &alert.title,
                Some(&alert.alert_id),
            ) {
                self.total_quarantines.fetch_add(1, Ordering::Relaxed);
                quarantine_record = Some(rec);
            }
        }

        // 2. Cgroup Freezing (halting execution for Critical alerts)
        if alert.severity == Severity::Critical {
            if let Some(cg) = cgroup_path {
                if self.cgroup_freezer.freeze(cg).is_ok() {
                    self.total_frozen.fetch_add(1, Ordering::Relaxed);
                    cgroup_frozen = true;
                }
            }
        }

        // 3. Process Tree Termination (for immediate escapes/shells if specified)
        if alert.severity == Severity::Critical {
            if let Some(pid) = target_pid {
                if let Ok(pids) = ProcessTerminator::kill_tree(pid, 9) {
                    self.total_terminated
                        .fetch_add(pids.len() as u64, Ordering::Relaxed);
                    terminated_pids = pids;
                }
            }
        }

        // 4. Evidence Snapshot & PCAP Dump
        let pcap_dump = self.pcap_recorder.dump_pcap();
        let forensic_bundle = target_pid.map(|pid| {
            ForensicSnapshotManager::capture_snapshot(workload_id, pid, Some(&pcap_dump))
        });

        // 5. Incident Timeline & Signed Audit Report
        let mut timeline = IncidentTimeline::new(workload_id);
        timeline.append(
            alert.timestamp_ns,
            "detection_engine",
            format!("{:?}", alert.category),
            alert.title.clone(),
            alert.evidence.clone(),
        );

        let signed_report = Some(IncidentReportGenerator::generate_report(
            alert.clone(),
            timeline,
            &self.signing_key_id,
        ));
        self.total_reports.fetch_add(1, Ordering::Relaxed);

        IncidentResponseResult {
            incident_id: format!("inc-{}-{}", workload_id, now),
            alert_id: alert.alert_id.clone(),
            timestamp_ns: now,
            quarantine_record,
            cgroup_frozen,
            terminated_pids,
            forensic_bundle,
            signed_report,
        }
    }

    /// Retrieves aggregate incident response metrics.
    #[must_use]
    pub fn get_metrics(&self) -> IncidentResponseMetrics {
        IncidentResponseMetrics {
            total_incidents_handled: self.total_incidents.load(Ordering::Relaxed),
            total_quarantines_enforced: self.total_quarantines.load(Ordering::Relaxed),
            total_cgroups_frozen: self.total_frozen.load(Ordering::Relaxed),
            total_processes_terminated: self.total_terminated.load(Ordering::Relaxed),
            total_reports_signed: self.total_reports.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_detection::alert::ThreatCategory;

    #[test]
    fn test_incident_response_engine_workflow() {
        let admin_ip = Ipv4Addr::new(10, 0, 0, 1);
        let engine = IncidentResponseEngine::new(&[admin_ip], &[22], 100, "kwall-test-key");

        // Record a packet in the rolling buffer
        engine
            .pcap_recorder
            .record_packet(1_000_000, b"GET / HTTP/1.1\r\n\r\n");

        let alert = ThreatAlert::new(
            "alert-test-01".to_string(),
            kwall_common::utilities::current_timestamp_ns(),
            Severity::Critical,
            ThreatCategory::ContainerEscape,
            Some("T1611"),
            "Critical Container Breakout Attempt",
            "Kernel exploit detected",
            None,
            serde_json::json!({ "exploit": "cgroup_escape" }),
            "Isolate immediately",
        );

        let target_ip = Ipv4Addr::new(10, 244, 2, 88);
        let target_pid = 42424;

        let result = engine.handle_alert(
            &alert,
            Some(target_ip),
            Some(target_pid),
            None, // no cgroup path in unit test
            "pod-critical-test",
        );

        assert!(result.quarantine_record.is_some());
        assert_eq!(
            result.quarantine_record.unwrap().level,
            QuarantineLevel::Full
        );
        assert!(result.forensic_bundle.is_some());
        assert!(result.signed_report.is_some());

        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_incidents_handled, 1);
        assert_eq!(metrics.total_quarantines_enforced, 1);
        assert_eq!(metrics.total_reports_signed, 1);
    }
}
