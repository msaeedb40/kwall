//! Automated network quarantine, dynamic isolation policies, and administrative triage access.
//!
//! Provides real-time containment for compromised workloads, enforcing granular
//! traffic blockades while maintaining optional administrative channels for forensic triage.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::RwLock;

use kwall_core::types::PolicyAction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors arising during quarantine operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuarantineError {
    #[error("Workload '{0}' is already quarantined")]
    AlreadyQuarantined(String),
    #[error("Workload '{0}' is not currently quarantined")]
    NotQuarantined(String),
    #[error("Invalid quarantine parameters: {0}")]
    InvalidParameters(String),
}

/// Level of isolation applied to a quarantined workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineLevel {
    /// Completely drop all ingress and egress packets.
    Full,
    /// Block all standard east-west and north-south traffic, but permit authorized administrative CIDRs.
    AdministrativeOnly,
    /// Block outbound connections to prevent data exfiltration and C2 beaconing, but allow inbound queries.
    EgressOnly,
}

/// Active quarantine record tracking the state of an isolated entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub workload_id: String,
    pub target_ip: Ipv4Addr,
    pub cgroup_id: Option<u64>,
    pub level: QuarantineLevel,
    pub reason: String,
    pub triggered_alert_id: Option<String>,
    pub timestamp_ns: u64,
    pub active: bool,
}

/// Controller managing dynamic network quarantine states and packet filtering decisions.
pub struct QuarantineController {
    records: RwLock<HashMap<Ipv4Addr, QuarantineRecord>>,
    workload_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    admin_ips: HashSet<Ipv4Addr>,
    admin_ports: HashSet<u16>,
}

impl QuarantineController {
    /// Creates a new QuarantineController configured with trusted administrative bastion IPs.
    pub fn new(admin_bastion_ips: &[Ipv4Addr], admin_ports: &[u16]) -> Self {
        let mut admin_set = HashSet::new();
        for &ip in admin_bastion_ips {
            admin_set.insert(ip);
        }
        let mut port_set = HashSet::new();
        for &p in admin_ports {
            port_set.insert(p);
        }
        Self {
            records: RwLock::new(HashMap::new()),
            workload_to_ip: RwLock::new(HashMap::new()),
            admin_ips: admin_set,
            admin_ports: port_set,
        }
    }

    /// Enforces dynamic network quarantine on a target workload IP.
    pub fn apply_quarantine(
        &self,
        workload_id: &str,
        target_ip: Ipv4Addr,
        cgroup_id: Option<u64>,
        level: QuarantineLevel,
        reason: &str,
        alert_id: Option<&str>,
    ) -> Result<QuarantineRecord, QuarantineError> {
        let mut records = self.records.write().unwrap();
        if records.contains_key(&target_ip) {
            return Err(QuarantineError::AlreadyQuarantined(workload_id.to_string()));
        }

        let now = kwall_common::utilities::current_timestamp_ns();
        let record = QuarantineRecord {
            quarantine_id: format!("quar-{}", now),
            workload_id: workload_id.to_string(),
            target_ip,
            cgroup_id,
            level,
            reason: reason.to_string(),
            triggered_alert_id: alert_id.map(ToString::to_string),
            timestamp_ns: now,
            active: true,
        };

        records.insert(target_ip, record.clone());
        let mut w_to_ip = self.workload_to_ip.write().unwrap();
        w_to_ip.insert(workload_id.to_string(), target_ip);

        tracing::warn!(
            workload = workload_id,
            ip = %target_ip,
            level = ?level,
            reason = reason,
            "Network quarantine enforced on workload"
        );

        Ok(record)
    }

    /// Lifts network quarantine from a workload.
    pub fn release_quarantine(&self, workload_id: &str) -> Result<(), QuarantineError> {
        let target_ip = {
            let mut w_to_ip = self.workload_to_ip.write().unwrap();
            w_to_ip
                .remove(workload_id)
                .ok_or_else(|| QuarantineError::NotQuarantined(workload_id.to_string()))?
        };

        let mut records = self.records.write().unwrap();
        records.remove(&target_ip);

        tracing::info!(workload = workload_id, ip = %target_ip, "Network quarantine released");
        Ok(())
    }

    /// Evaluates whether a packet involving a quarantined IP should be allowed or blocked.
    #[must_use]
    pub fn evaluate_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dport: u16,
        is_ingress: bool,
    ) -> PolicyAction {
        let records = self.records.read().unwrap();

        // 1. Check if src_ip is quarantined (egress from quarantined workload)
        if let Some(record) = records.get(&src_ip) {
            match record.level {
                QuarantineLevel::Full | QuarantineLevel::EgressOnly => return PolicyAction::Block,
                QuarantineLevel::AdministrativeOnly => {
                    // Only allow outbound reply packets directed back to administrative bastions
                    if self.admin_ips.contains(&dst_ip) {
                        return PolicyAction::Allow;
                    }
                    return PolicyAction::Block;
                }
            }
        }

        // 2. Check if dst_ip is quarantined (ingress to quarantined workload)
        if let Some(record) = records.get(&dst_ip) {
            match record.level {
                QuarantineLevel::Full => return PolicyAction::Block,
                QuarantineLevel::EgressOnly => return PolicyAction::Allow, // Ingress allowed for EgressOnly
                QuarantineLevel::AdministrativeOnly => {
                    // Permit ingress exclusively from registered administrative bastion IPs and ports
                    if self.admin_ips.contains(&src_ip)
                        && (self.admin_ports.is_empty() || self.admin_ports.contains(&dport))
                    {
                        return PolicyAction::Allow;
                    }
                    return PolicyAction::Block;
                }
            }
        }

        let _ = is_ingress;
        PolicyAction::Allow
    }

    /// Checks if a given IP address is currently quarantined.
    #[must_use]
    pub fn is_quarantined(&self, ip: &Ipv4Addr) -> Option<QuarantineLevel> {
        let records = self.records.read().unwrap();
        records.get(ip).map(|r| r.level)
    }

    /// Lists all currently active quarantine records.
    #[must_use]
    pub fn list_active_quarantines(&self) -> Vec<QuarantineRecord> {
        let records = self.records.read().unwrap();
        records.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_lifecycle_and_filtering() {
        let admin_ip = Ipv4Addr::new(10, 0, 0, 99);
        let controller = QuarantineController::new(&[admin_ip], &[22, 443]);

        let target_ip = Ipv4Addr::new(10, 244, 1, 42);
        let external_ip = Ipv4Addr::new(93, 184, 216, 34);

        // 1. Initial state: packets pass freely
        assert_eq!(
            controller.evaluate_packet(target_ip, external_ip, 80, false),
            PolicyAction::Allow
        );

        // 2. Apply AdministrativeOnly quarantine
        let record = controller
            .apply_quarantine(
                "pod-compromised-1",
                target_ip,
                Some(12345),
                QuarantineLevel::AdministrativeOnly,
                "Detected C2 beaconing",
                Some("alert-101"),
            )
            .expect("Should apply quarantine");

        assert!(record.active);
        assert_eq!(
            controller.is_quarantined(&target_ip),
            Some(QuarantineLevel::AdministrativeOnly)
        );

        // 3. East-West / North-South traffic is BLOCKED
        assert_eq!(
            controller.evaluate_packet(target_ip, external_ip, 443, false),
            PolicyAction::Block
        );
        assert_eq!(
            controller.evaluate_packet(external_ip, target_ip, 80, true),
            PolicyAction::Block
        );

        // 4. Admin bastion ingress on authorized port 22 is ALLOWED
        assert_eq!(
            controller.evaluate_packet(admin_ip, target_ip, 22, true),
            PolicyAction::Allow
        );
        // Outbound reply to admin bastion is ALLOWED
        assert_eq!(
            controller.evaluate_packet(target_ip, admin_ip, 22, false),
            PolicyAction::Allow
        );

        // 5. Release quarantine
        assert!(controller.release_quarantine("pod-compromised-1").is_ok());
        assert_eq!(controller.is_quarantined(&target_ip), None);
        assert_eq!(
            controller.evaluate_packet(target_ip, external_ip, 80, false),
            PolicyAction::Allow
        );
    }
}
