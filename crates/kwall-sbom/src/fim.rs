//! Container File Integrity Monitoring (FIM) and system binary tampering detection.
//!
//! Watches immutable system paths (/bin, /sbin, /usr/bin, /etc) within container rootfs layers,
//! validating filesystem mutations and binary cryptographic checksums against the SBOM catalog.

use std::collections::HashSet;
use std::sync::Arc;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};

use crate::parser::SbomCatalog;

/// Type of filesystem change detected by FIM hooks or audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimEventType {
    Created,
    Modified,
    Deleted,
    PermissionsChanged,
}

/// Critical container directories monitored by default.
pub const DEFAULT_WATCHED_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/etc",
    "/lib",
    "/lib64",
    "/usr/lib",
];

/// File Integrity Monitor evaluating container filesystem mutations.
pub struct FileIntegrityMonitor {
    pub catalog: Arc<SbomCatalog>,
    pub watched_paths: HashSet<String>,
}

impl FileIntegrityMonitor {
    /// Creates a monitor configured with default watched system directories.
    pub fn new(catalog: Arc<SbomCatalog>) -> Self {
        let mut watched = HashSet::new();
        for &dir in DEFAULT_WATCHED_DIRS {
            watched.insert(dir.to_string());
        }
        Self {
            catalog,
            watched_paths: watched,
        }
    }

    /// Evaluates a filesystem mutation event on a container workload.
    pub fn evaluate_change(
        &self,
        workload_id: &str,
        file_path: &str,
        event_type: FimEventType,
        current_sha256: Option<&str>,
        process_pid: u32,
        process_comm: &str,
    ) -> Option<ThreatAlert> {
        let now = kwall_common::utilities::current_timestamp_ns();

        // Check if the modified file resides within a watched directory
        let is_watched = self
            .watched_paths
            .iter()
            .any(|dir| file_path == dir || file_path.starts_with(&format!("{dir}/")));

        if !is_watched {
            return None;
        }

        match event_type {
            FimEventType::Modified => {
                // If the file is modified, verify cryptographic hash against baseline
                if let Some(expected_hash) = self.catalog.get_expected_hash(workload_id, file_path)
                {
                    if let Some(actual_hash) = current_sha256 {
                        if actual_hash != expected_hash {
                            return Some(ThreatAlert::new(
                                format!("fim-hash-mismatch-{}", now),
                                now,
                                Severity::Critical,
                                ThreatCategory::FileIntegrityViolation,
                                Some("T1565.001"),
                                "System Binary Tampering Detected (Hash Drift)",
                                format!(
                                    "Protected binary '{file_path}' hash modified by process '{process_comm}' (PID {process_pid}). Expected: {expected_hash}, Actual: {actual_hash}"
                                ),
                                None,
                                serde_json::json!({
                                    "workload_id": workload_id,
                                    "file_path": file_path,
                                    "expected_hash": expected_hash,
                                    "actual_hash": actual_hash,
                                    "process_pid": process_pid,
                                    "process_comm": process_comm
                                }),
                                "Immediately terminate container, capture forensic disk snapshot, and investigate rootkit/trojan injection"
                                    .to_string(),
                            ));
                        }
                    }
                } else {
                    // Protected path modified without prior baseline registration
                    return Some(ThreatAlert::new(
                        format!("fim-unauthorized-write-{}", now),
                        now,
                        Severity::Error,
                        ThreatCategory::FileIntegrityViolation,
                        Some("T1565.001"),
                        "Unauthorized Modification in Protected System Directory",
                        format!(
                            "System path '{file_path}' was modified by process '{process_comm}' (PID {process_pid}) in container rootfs"
                        ),
                        None,
                        serde_json::json!({
                            "workload_id": workload_id,
                            "file_path": file_path,
                            "process_comm": process_comm,
                            "process_pid": process_pid
                        }),
                        "Review whether container rootfs is configured as read-only (securityContext.readOnlyRootFilesystem)"
                            .to_string(),
                    ));
                }
            }
            FimEventType::Created => {
                // New file created in a protected directory (/bin, /usr/bin, etc.)
                return Some(ThreatAlert::new(
                    format!("fim-unauthorized-binary-{}", now),
                    now,
                    Severity::Critical,
                    ThreatCategory::FileIntegrityViolation,
                    Some("T1036.005"),
                    "New Binary Created in Protected System Path",
                    format!(
                        "New file '{file_path}' dropped into system directory by process '{process_comm}' (PID {process_pid})"
                    ),
                    None,
                    serde_json::json!({
                        "workload_id": workload_id,
                        "file_path": file_path,
                        "current_hash": current_sha256,
                        "process_comm": process_comm,
                        "process_pid": process_pid
                    }),
                    "Block process execution and inspect parent process network ingress connections"
                        .to_string(),
                ));
            }
            FimEventType::Deleted => {
                // System binary deleted
                return Some(ThreatAlert::new(
                    format!("fim-binary-deleted-{}", now),
                    now,
                    Severity::Warning,
                    ThreatCategory::FileIntegrityViolation,
                    Some("T1485"),
                    "Critical System Binary Deleted in Container",
                    format!(
                        "Binary '{file_path}' was deleted by process '{process_comm}' (PID {process_pid})"
                    ),
                    None,
                    serde_json::json!({
                        "workload_id": workload_id,
                        "file_path": file_path,
                        "process_comm": process_comm,
                        "process_pid": process_pid
                    }),
                    "Investigate container workload for sabotage, wiper behavior, or defense evasion"
                        .to_string(),
                ));
            }
            FimEventType::PermissionsChanged => {
                // SUID bit change or permissions tampering
                return Some(ThreatAlert::new(
                    format!("fim-perm-changed-{}", now),
                    now,
                    Severity::Error,
                    ThreatCategory::FileIntegrityViolation,
                    Some("T1548.001"),
                    "Permissions Modified on Protected System Path",
                    format!(
                        "File permissions on '{file_path}' were altered by process '{process_comm}' (PID {process_pid})"
                    ),
                    None,
                    serde_json::json!({
                        "workload_id": workload_id,
                        "file_path": file_path,
                        "process_comm": process_comm,
                        "process_pid": process_pid
                    }),
                    "Check for setuid / setgid privilege escalation attempts".to_string(),
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{SbomComponent, SbomDocument, SbomFormat};
    use std::collections::HashMap;

    #[test]
    fn test_fim_binary_tampering_hash_mismatch() {
        let catalog = Arc::new(SbomCatalog::new());
        let mut hashes = HashMap::new();
        hashes.insert(
            "SHA-256".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );

        let sbom = SbomDocument {
            format: SbomFormat::CycloneDx,
            spec_version: "1.5".to_string(),
            serial_number: None,
            components: vec![SbomComponent {
                name: "ls".to_string(),
                version: "9.1".to_string(),
                purl: None,
                file_paths: vec!["/bin/ls".to_string()],
                hashes,
            }],
        };
        catalog.register_sbom("pod-app-1", &sbom);

        let fim = FileIntegrityMonitor::new(catalog);

        // 1. Untampered check -> None
        let alert = fim.evaluate_change(
            "pod-app-1",
            "/bin/ls",
            FimEventType::Modified,
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            100,
            "dpkg",
        );
        assert!(alert.is_none());

        // 2. Tampered check -> Alert
        let alert = fim.evaluate_change(
            "pod-app-1",
            "/bin/ls",
            FimEventType::Modified,
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            999,
            "trojan_injector",
        );
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::FileIntegrityViolation);
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1565.001"));
    }

    #[test]
    fn test_fim_dropped_binary() {
        let catalog = Arc::new(SbomCatalog::new());
        let fim = FileIntegrityMonitor::new(catalog);

        let alert = fim.evaluate_change(
            "pod-app-1",
            "/usr/bin/backdoor",
            FimEventType::Created,
            Some("1234567890abcdef"),
            444,
            "curl",
        );

        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::FileIntegrityViolation);
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1036.005"));
    }
}
