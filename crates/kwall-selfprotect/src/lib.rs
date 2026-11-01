//! KWALL Agent Self-Protection, Tamper Resistance & Kernel Watchdog Engine.
//!
//! Ensures KWALL cannot be disabled, bypassed, or tampered with by compromised
//! privileged containers, hostile root processes, or kernel-level attackers.
//!
//! ## Subsystems
//!
//! - **eBPF Integrity Verifier** (`integrity`): Continuously monitors BPF program
//!   attachment state, pinned paths, bytecode tags, and map entry count drift.
//! - **Kernel Watchdog** (`watchdog`): Integrates with `/dev/watchdog` for deadlock
//!   detection, and implements graceful degradation under memory pressure.
//! - **Secure Memory & mTLS** (`secure_mem`): Locks sensitive memory pages via
//!   `mlock(2)`, zeroizes secrets on drop, and automates mTLS certificate rotation.

pub mod integrity;
pub mod secure_mem;
pub mod watchdog;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub use integrity::{
    BpfHookType, BpfIntegrityVerifier, BpfMapBaseline, BpfProgramBaseline,
    IntegrityVerificationResult, IntegrityViolation, IntegrityViolationType,
};
pub use secure_mem::{
    CertRotationConfig, CertRotationManager, CertificateRecord, CertificateState,
    LockedRegionState, RotationEvent, SecureBuffer, SecureRegionDescriptor,
};
pub use watchdog::{
    ActiveSubsystems, DegradationEvent, DegradationPolicy, HeartbeatRecord, KernelWatchdog,
    PressureLevel, WatchdogConfig, WatchdogError, WatchdogMetricsSummary, WatchdogState,
};

/// Overall self-protection health status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SelfProtectionStatus {
    /// All subsystems healthy — no integrity violations, watchdog armed, certs valid.
    Healthy,
    /// Non-critical degradation detected (e.g., moderate memory pressure).
    Degraded,
    /// Critical integrity violation or watchdog timeout detected.
    Compromised,
    /// Self-protection engine not yet initialized.
    Uninitialized,
}

impl std::fmt::Display for SelfProtectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelfProtectionStatus::Healthy => write!(f, "HEALTHY"),
            SelfProtectionStatus::Degraded => write!(f, "DEGRADED"),
            SelfProtectionStatus::Compromised => write!(f, "COMPROMISED"),
            SelfProtectionStatus::Uninitialized => write!(f, "UNINITIALIZED"),
        }
    }
}

/// Result of a full self-protection verification cycle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelfProtectionReport {
    /// Timestamp of the verification cycle (nanos since epoch).
    pub timestamp_ns: u64,
    /// Overall protection status.
    pub status: SelfProtectionStatus,
    /// eBPF integrity verification result.
    pub integrity_result: IntegrityVerificationResult,
    /// Current watchdog state.
    pub watchdog_state: WatchdogState,
    /// Current system pressure level.
    pub pressure_level: PressureLevel,
    /// Active subsystems based on degradation policy.
    pub active_subsystems: ActiveSubsystems,
    /// Whether a certificate rotation is needed.
    pub cert_rotation_needed: bool,
    /// Active certificate serial (if any).
    pub active_cert_serial: Option<String>,
    /// Total self-protection cycles completed.
    pub cycle_count: u64,
}

/// Aggregate self-protection metrics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelfProtectionMetrics {
    pub total_cycles: u64,
    pub integrity_violations_total: u64,
    pub watchdog_timeouts_total: u64,
    pub cert_rotations_total: u64,
    pub degradation_transitions_total: u64,
    pub current_status: String,
}

/// Comprehensive Self-Protection Engine orchestrating all tamper-resistance subsystems.
///
/// Combines eBPF integrity verification, kernel watchdog, and secure memory/certificate
/// management into a unified protection engine with a single `run_cycle()` entry point.
pub struct SelfProtectionEngine {
    pub integrity_verifier: Arc<BpfIntegrityVerifier>,
    pub watchdog: Arc<KernelWatchdog>,
    pub cert_manager: Arc<CertRotationManager>,
    total_cycles: AtomicU64,
    status: std::sync::RwLock<SelfProtectionStatus>,
}

impl Default for SelfProtectionEngine {
    fn default() -> Self {
        Self::new(
            BpfIntegrityVerifier::default(),
            KernelWatchdog::default(),
            CertRotationManager::default(),
        )
    }
}

impl SelfProtectionEngine {
    /// Creates a new self-protection engine with the specified subsystems.
    #[must_use]
    pub fn new(
        integrity_verifier: BpfIntegrityVerifier,
        watchdog: KernelWatchdog,
        cert_manager: CertRotationManager,
    ) -> Self {
        Self {
            integrity_verifier: Arc::new(integrity_verifier),
            watchdog: Arc::new(watchdog),
            cert_manager: Arc::new(cert_manager),
            total_cycles: AtomicU64::new(0),
            status: std::sync::RwLock::new(SelfProtectionStatus::Uninitialized),
        }
    }

    /// Executes a complete self-protection verification cycle.
    ///
    /// Performs:
    /// 1. eBPF program and map integrity verification.
    /// 2. Watchdog heartbeat ping and timeout check.
    /// 3. System memory pressure evaluation and degradation policy.
    /// 4. Certificate rotation check and automatic renewal.
    ///
    /// Returns a comprehensive `SelfProtectionReport`.
    pub fn run_cycle(&self, timestamp_ns: u64) -> SelfProtectionReport {
        let cycle = self.total_cycles.fetch_add(1, Ordering::Relaxed) + 1;

        tracing::debug!(cycle, "Running self-protection verification cycle");

        // 1. eBPF Integrity Verification
        let integrity_result = self.integrity_verifier.verify_integrity(timestamp_ns);

        // 2. Watchdog Heartbeat
        let watchdog_state = if self.watchdog.state() == WatchdogState::Armed {
            let _ = self.watchdog.ping(timestamp_ns);
            let timed_out = self.watchdog.check_timeout();
            if timed_out {
                WatchdogState::TimedOut
            } else {
                WatchdogState::Armed
            }
        } else {
            self.watchdog.state()
        };

        // 3. Memory Pressure Evaluation
        let pressure_level = self.watchdog.evaluate_pressure(timestamp_ns);
        let active_subsystems = self.watchdog.get_active_subsystems();

        // 4. Certificate Rotation Check
        let cert_rotation_needed = self.cert_manager.needs_rotation(timestamp_ns);
        if cert_rotation_needed {
            match self.cert_manager.rotate(timestamp_ns) {
                Ok(event) => {
                    tracing::info!(
                        new_serial = %event.new_serial,
                        "Auto-rotated mTLS certificate during self-protection cycle"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to auto-rotate mTLS certificate"
                    );
                }
            }
        }

        let active_cert_serial = self.cert_manager.active_certificate().map(|c| c.serial);

        // 5. Compute overall status
        let status = self.compute_status(&integrity_result, watchdog_state, pressure_level);

        *self.status.write().unwrap() = status.clone();

        if status != SelfProtectionStatus::Healthy {
            tracing::warn!(
                status = %status,
                cycle,
                violations = integrity_result.violations.len(),
                "Self-protection status: {}", status
            );
        }

        SelfProtectionReport {
            timestamp_ns,
            status,
            integrity_result,
            watchdog_state,
            pressure_level,
            active_subsystems,
            cert_rotation_needed,
            active_cert_serial,
            cycle_count: cycle,
        }
    }

    /// Returns the current self-protection status without running a full cycle.
    #[must_use]
    pub fn current_status(&self) -> SelfProtectionStatus {
        self.status.read().unwrap().clone()
    }

    /// Returns aggregate self-protection metrics.
    #[must_use]
    pub fn get_metrics(&self) -> SelfProtectionMetrics {
        let integrity_metrics = self.integrity_verifier.get_metrics();
        let watchdog_metrics = self.watchdog.get_metrics();
        let cert_metrics = self.cert_manager.get_metrics();

        SelfProtectionMetrics {
            total_cycles: self.total_cycles.load(Ordering::Relaxed),
            integrity_violations_total: *integrity_metrics.get("total_violations").unwrap_or(&0),
            watchdog_timeouts_total: watchdog_metrics.total_timeouts,
            cert_rotations_total: cert_metrics.total_rotations,
            degradation_transitions_total: watchdog_metrics.total_degradation_transitions,
            current_status: self.current_status().to_string(),
        }
    }

    // --- Internal helpers ---

    /// Computes the overall self-protection status from subsystem states.
    fn compute_status(
        &self,
        integrity: &IntegrityVerificationResult,
        watchdog_state: WatchdogState,
        pressure: PressureLevel,
    ) -> SelfProtectionStatus {
        // Critical conditions → Compromised
        if !integrity.is_clean {
            // Check for critical violations (program detachment, tag mutation)
            let has_critical = integrity.violations.iter().any(|v| {
                matches!(
                    v.violation_type,
                    IntegrityViolationType::ProgramDetached
                        | IntegrityViolationType::ProgramTagMutated
                        | IntegrityViolationType::ProgramIdChanged
                        | IntegrityViolationType::UnauthorizedProgramAttached
                )
            });
            if has_critical {
                return SelfProtectionStatus::Compromised;
            }
        }

        if watchdog_state == WatchdogState::TimedOut {
            return SelfProtectionStatus::Compromised;
        }

        // Non-critical degradation
        if pressure >= PressureLevel::Moderate {
            return SelfProtectionStatus::Degraded;
        }

        if !integrity.is_clean {
            return SelfProtectionStatus::Degraded;
        }

        SelfProtectionStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_protection_engine_healthy_cycle() {
        let tmp = std::env::temp_dir().join(format!(
            "kwall_engine_healthy_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&tmp);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700));
        }

        let verifier = BpfIntegrityVerifier::new(&tmp);
        let engine = SelfProtectionEngine::new(
            verifier,
            KernelWatchdog::default(),
            CertRotationManager::default(),
        );

        // Issue initial certificate
        engine.cert_manager.issue_certificate(1_000_000).unwrap();

        let report = engine.run_cycle(2_000_000);

        // No programs/maps registered and valid bpffs root → clean integrity
        assert!(report.integrity_result.is_clean);
        assert_eq!(report.cycle_count, 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_self_protection_engine_detects_violations() {
        let verifier = BpfIntegrityVerifier::new("/tmp/nonexistent_kwall_selfprotect_test");

        // Register a program with a missing pin path
        verifier.register_program_baseline(BpfProgramBaseline {
            name: "kwall_xdp_firewall".to_string(),
            expected_tag: "aaaaaaaaaaaaaaaa".to_string(),
            hook_type: BpfHookType::Xdp,
            pinned_path: "/tmp/nonexistent_kwall_selfprotect_test/progs/xdp".into(),
            expected_prog_id: 100,
            baseline_captured_ns: 1_000_000,
        });

        let engine = SelfProtectionEngine::new(
            verifier,
            KernelWatchdog::default(),
            CertRotationManager::default(),
        );

        engine.cert_manager.issue_certificate(1_000_000).unwrap();

        let report = engine.run_cycle(2_000_000);
        assert!(!report.integrity_result.is_clean);
        // Pin path missing is a Degraded-level violation (not program detachment)
        assert!(
            report.status == SelfProtectionStatus::Degraded
                || report.status == SelfProtectionStatus::Compromised
        );
    }

    #[test]
    fn test_self_protection_metrics() {
        let engine = SelfProtectionEngine::default();
        engine.cert_manager.issue_certificate(1_000_000).unwrap();

        engine.run_cycle(2_000_000);
        engine.run_cycle(3_000_000);
        engine.run_cycle(4_000_000);

        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_cycles, 3);
    }

    #[test]
    fn test_status_display() {
        assert_eq!(SelfProtectionStatus::Healthy.to_string(), "HEALTHY");
        assert_eq!(SelfProtectionStatus::Degraded.to_string(), "DEGRADED");
        assert_eq!(SelfProtectionStatus::Compromised.to_string(), "COMPROMISED");
        assert_eq!(
            SelfProtectionStatus::Uninitialized.to_string(),
            "UNINITIALIZED"
        );
    }

    #[test]
    fn test_compute_status_compromised_on_program_detach() {
        let engine = SelfProtectionEngine::default();

        let integrity = IntegrityVerificationResult {
            scan_timestamp_ns: 1_000_000,
            programs_checked: 1,
            maps_checked: 0,
            violations: vec![IntegrityViolation {
                violation_id: "test-1".to_string(),
                detected_at_ns: 1_000_000,
                violation_type: IntegrityViolationType::ProgramDetached,
                target_name: "kwall_xdp".to_string(),
                description: "XDP program detached".to_string(),
                expected: "attached".to_string(),
                observed: "detached".to_string(),
                mitre_technique: Some("T1562.001".to_string()),
            }],
            is_clean: false,
        };

        let status = engine.compute_status(&integrity, WatchdogState::Armed, PressureLevel::Normal);
        assert_eq!(status, SelfProtectionStatus::Compromised);
    }

    #[test]
    fn test_compute_status_compromised_on_watchdog_timeout() {
        let engine = SelfProtectionEngine::default();

        let clean_integrity = IntegrityVerificationResult {
            scan_timestamp_ns: 1_000_000,
            programs_checked: 0,
            maps_checked: 0,
            violations: vec![],
            is_clean: true,
        };

        let status = engine.compute_status(
            &clean_integrity,
            WatchdogState::TimedOut,
            PressureLevel::Normal,
        );
        assert_eq!(status, SelfProtectionStatus::Compromised);
    }

    #[test]
    fn test_compute_status_degraded_on_pressure() {
        let engine = SelfProtectionEngine::default();

        let clean_integrity = IntegrityVerificationResult {
            scan_timestamp_ns: 1_000_000,
            programs_checked: 0,
            maps_checked: 0,
            violations: vec![],
            is_clean: true,
        };

        let status =
            engine.compute_status(&clean_integrity, WatchdogState::Armed, PressureLevel::High);
        assert_eq!(status, SelfProtectionStatus::Degraded);
    }
}
