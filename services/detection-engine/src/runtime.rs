//! Container runtime security threat detectors and MITRE ATT&CK correlation.

use crate::alert::{ThreatAlert, ThreatCategory};
use kwall_core::types::Severity;
use kwall_event_enricher::enricher::EnrichedEvent;
use kwall_event_router::event::EventPayload;

/// Evaluates runtime process and LSM events for adversarial behavior and container escapes.
#[derive(Debug, Default)]
pub struct RuntimeThreatDetector;

impl RuntimeThreatDetector {
    /// Creates a new RuntimeThreatDetector.
    pub fn new() -> Self {
        Self
    }

    /// Evaluates an event against all container runtime heuristic detectors.
    pub fn evaluate(&self, event: &EnrichedEvent) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        match &event.base_event.payload {
            EventPayload::Process(proc) => {
                // 1. Interactive Shell Detection (T1059.004)
                if let Some(alert) =
                    self.detect_interactive_shell(event, proc.comm.as_str(), proc.uid)
                {
                    alerts.push(alert);
                }

                // 2. Container Escape & Namespace Manipulation (T1611)
                if let Some(alert) =
                    self.detect_container_escape_commands(event, proc.comm.as_str())
                {
                    alerts.push(alert);
                }

                // 3. Privilege Escalation Utilities (T1548)
                if let Some(alert) =
                    self.detect_privilege_escalation(event, proc.comm.as_str(), proc.uid)
                {
                    alerts.push(alert);
                }

                // 4. Container Escape via Sensitive Host Filesystem (T1611)
                if let Some(alert) =
                    self.detect_escape_filesystem_tampering(event, proc.filename.as_str())
                {
                    alerts.push(alert);
                }

                // 5. Sensitive Credential & Key Access (T1552)
                if let Some(alert) =
                    self.detect_sensitive_credential_access(event, proc.filename.as_str())
                {
                    alerts.push(alert);
                }
            }
            EventPayload::Lsm(lsm) => {
                if lsm.action_taken == "block" || lsm.action_taken == "deny" {
                    alerts.push(ThreatAlert::new(
                        format!("threat-lsm-denial-{}", event.base_event.event_id),
                        event.base_event.timestamp_ns,
                        Severity::Critical,
                        ThreatCategory::PrivilegeEscalation,
                        Some("T1548"),
                        "LSM Security Hook Blocked Unauthorized Action",
                        format!(
                            "Kernel LSM hook ID {} blocked process PID {} (UID {})",
                            lsm.hook_id, lsm.pid.0, lsm.uid
                        ),
                        event.src_workload.clone(),
                        serde_json::json!({
                            "hook_id": lsm.hook_id,
                            "pid": lsm.pid.0,
                            "uid": lsm.uid,
                            "action": lsm.action_taken
                        }),
                        "Audit container privilege profile and review LSM security violations",
                    ));
                }
            }
            EventPayload::Network(_) | EventPayload::Alert(_) => {}
        }

        alerts
    }

    /// Detects interactive shell execution within container environments.
    fn detect_interactive_shell(
        &self,
        event: &EnrichedEvent,
        comm: &str,
        uid: u32,
    ) -> Option<ThreatAlert> {
        let shell_binaries = ["sh", "bash", "zsh", "dash", "ash", "csh", "ksh", "busybox"];
        if shell_binaries.contains(&comm) {
            Some(ThreatAlert::new(
                format!("threat-shell-{}", event.base_event.event_id),
                event.base_event.timestamp_ns,
                Severity::Error,
                ThreatCategory::InteractiveShell,
                Some("T1059.004"),
                format!("Interactive Shell Spawned: {comm}"),
                format!(
                    "Interactive shell binary '{comm}' was executed (UID {uid}) inside workload '{:?}'.",
                    event.src_workload.as_ref().map(|w| &w.pod_name)
                ),
                event.src_workload.clone(),
                serde_json::json!({
                    "comm": comm,
                    "uid": uid,
                    "event_id": event.base_event.event_id
                }),
                "Quarantine affected pod and terminate unexpected shell session",
            ))
        } else {
            None
        }
    }

    /// Detects container escape tooling and namespace breakout utilities.
    fn detect_container_escape_commands(
        &self,
        event: &EnrichedEvent,
        comm: &str,
    ) -> Option<ThreatAlert> {
        let escape_tools = ["nsenter", "unshare", "capsh", "runc", "crictl"];
        if escape_tools.contains(&comm) {
            Some(ThreatAlert::new(
                format!("threat-escape-cmd-{}", event.base_event.event_id),
                event.base_event.timestamp_ns,
                Severity::Critical,
                ThreatCategory::ContainerEscape,
                Some("T1611"),
                format!("Potential Container Escape Tool: {comm}"),
                format!(
                    "Namespace manipulation or container breakout utility '{comm}' executed in workload '{:?}'.",
                    event.src_workload.as_ref().map(|w| &w.pod_name)
                ),
                event.src_workload.clone(),
                serde_json::json!({
                    "utility": comm,
                    "event_id": event.base_event.event_id
                }),
                "Isolate node immediately and inspect container runtime cgroups",
            ))
        } else {
            None
        }
    }

    /// Detects privilege escalation tooling.
    fn detect_privilege_escalation(
        &self,
        event: &EnrichedEvent,
        comm: &str,
        uid: u32,
    ) -> Option<ThreatAlert> {
        let priv_tools = ["sudo", "su", "pkexec", "doas"];
        if priv_tools.contains(&comm) {
            Some(ThreatAlert::new(
                format!("threat-privesc-{}", event.base_event.event_id),
                event.base_event.timestamp_ns,
                Severity::Error,
                ThreatCategory::PrivilegeEscalation,
                Some("T1548"),
                format!("Privilege Escalation Utility Executed: {comm}"),
                format!("Binary '{comm}' invoked with UID {uid} inside workload."),
                event.src_workload.clone(),
                serde_json::json!({
                    "comm": comm,
                    "uid": uid
                }),
                "Audit sudoers configuration and restrict container capabilities",
            ))
        } else {
            None
        }
    }

    /// Detects container escapes via kernel filesystem or container socket tampering.
    fn detect_escape_filesystem_tampering(
        &self,
        event: &EnrichedEvent,
        path: &str,
    ) -> Option<ThreatAlert> {
        let escape_targets = [
            "/proc/sysrq-trigger",
            "/proc/sys/kernel/core_pattern",
            "/docker.sock",
            "/containerd.sock",
            "/release_agent",
        ];

        for target in &escape_targets {
            if path.contains(target) {
                return Some(ThreatAlert::new(
                    format!("threat-escape-fs-{}", event.base_event.event_id),
                    event.base_event.timestamp_ns,
                    Severity::Critical,
                    ThreatCategory::ContainerEscape,
                    Some("T1611"),
                    format!("Container Escape Filesystem Access: {target}"),
                    format!("Tampering attempted against protected host/runtime path: '{path}'."),
                    event.src_workload.clone(),
                    serde_json::json!({
                        "accessed_path": path,
                        "matched_pattern": target
                    }),
                    "Block access via KWALL LSM policy and quarantine host container",
                ));
            }
        }
        None
    }

    /// Detects unauthorized access to secrets, tokens, or crypto keys.
    fn detect_sensitive_credential_access(
        &self,
        event: &EnrichedEvent,
        path: &str,
    ) -> Option<ThreatAlert> {
        let sensitive_prefixes = [
            "/etc/shadow",
            "/etc/sudoers",
            "/var/run/secrets/kubernetes.io/serviceaccount",
        ];

        let sensitive_extensions = [".pem", ".key", "id_rsa", "id_ed25519"];

        for prefix in &sensitive_prefixes {
            if path.contains(prefix) {
                return Some(ThreatAlert::new(
                    format!("threat-cred-{}", event.base_event.event_id),
                    event.base_event.timestamp_ns,
                    Severity::Error,
                    ThreatCategory::SensitiveFileAccess,
                    Some("T1552"),
                    format!("Sensitive Credential Access: {prefix}"),
                    format!("Unauthorized access attempted against credential path: '{path}'."),
                    event.src_workload.clone(),
                    serde_json::json!({ "path": path }),
                    "Rotate exposed service account tokens or certificates immediately",
                ));
            }
        }

        for ext in &sensitive_extensions {
            if path.ends_with(ext) {
                return Some(ThreatAlert::new(
                    format!("threat-key-{}", event.base_event.event_id),
                    event.base_event.timestamp_ns,
                    Severity::Error,
                    ThreatCategory::SensitiveFileAccess,
                    Some("T1552.004"),
                    format!("Cryptographic Private Key Access: {ext}"),
                    format!("Access observed to file matching private key pattern: '{path}'."),
                    event.src_workload.clone(),
                    serde_json::json!({ "path": path }),
                    "Inspect key file permissions and audit surrounding processes",
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId};
    use kwall_event_router::event::{KwallEvent, LsmEventData, ProcessEventData};

    #[test]
    fn test_shell_detection() {
        let detector = RuntimeThreatDetector::new();
        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 10,
                timestamp_ns: 12345,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(42),
                    tgid: 42,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    cgroup_id: CgroupId(5),
                    comm: "bash".to_string(),
                    filename: "/bin/bash".to_string(),
                }),
            },
            src_workload: None,
            dst_workload: None,
        };

        let alerts = detector.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::InteractiveShell);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1059.004"));
    }

    #[test]
    fn test_escape_filesystem_detection() {
        let detector = RuntimeThreatDetector::new();
        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 11,
                timestamp_ns: 12345,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(42),
                    tgid: 42,
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    cgroup_id: CgroupId(5),
                    comm: "cat".to_string(),
                    filename: "/proc/sysrq-trigger".to_string(),
                }),
            },
            src_workload: None,
            dst_workload: None,
        };

        let alerts = detector.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::ContainerEscape);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1611"));
    }

    #[test]
    fn test_sensitive_credential_detection() {
        let detector = RuntimeThreatDetector::new();
        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 12,
                timestamp_ns: 12345,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(42),
                    tgid: 42,
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    cgroup_id: CgroupId(5),
                    comm: "cat".to_string(),
                    filename: "/etc/shadow".to_string(),
                }),
            },
            src_workload: None,
            dst_workload: None,
        };

        let alerts = detector.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::SensitiveFileAccess);
        assert_eq!(alerts[0].mitre_attack_id.as_deref(), Some("T1552"));
    }

    #[test]
    fn test_lsm_denial_detection() {
        let detector = RuntimeThreatDetector::new();
        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 13,
                timestamp_ns: 12345,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::LsmSecurity,
                payload: EventPayload::Lsm(LsmEventData {
                    pid: ProcessId(42),
                    uid: 0,
                    cgroup_id: CgroupId(5),
                    hook_id: 1,
                    action_taken: "block".to_string(),
                }),
            },
            src_workload: None,
            dst_workload: None,
        };

        let alerts = detector.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].category, ThreatCategory::PrivilegeEscalation);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }
}
