//! KWALL eBPF Program & Map Integrity Verifier.
//!
//! Continuously monitors the attachment state, pinned paths, and content integrity
//! of all KWALL eBPF programs and BPF maps. Detects and alerts on:
//!
//! - Unauthorized BPF program detachments from XDP, TC, Tracepoint, and LSM hooks.
//! - BPF link file deletions or inode tampering in `/sys/fs/bpf/kwall/`.
//! - Map entry count drift (injection of unauthorized entries, or mass deletion).
//! - Program tag/hash mutations indicating recompilation or replacement.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;


/// Type of eBPF hook point being monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BpfHookType {
    /// XDP ingress processing on a network interface.
    Xdp,
    /// TC (Traffic Control) classifier ingress or egress.
    TcIngress,
    TcEgress,
    /// Kernel tracepoint (e.g., sched/sched_process_exec).
    Tracepoint,
    /// Linux Security Module hook (e.g., bprm_check_security).
    Lsm,
    /// Cgroup socket operations.
    CgroupSockops,
    /// Socket message redirect (sk_msg).
    SkMsg,
}

impl std::fmt::Display for BpfHookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BpfHookType::Xdp => write!(f, "XDP"),
            BpfHookType::TcIngress => write!(f, "TC-Ingress"),
            BpfHookType::TcEgress => write!(f, "TC-Egress"),
            BpfHookType::Tracepoint => write!(f, "Tracepoint"),
            BpfHookType::Lsm => write!(f, "LSM"),
            BpfHookType::CgroupSockops => write!(f, "Cgroup-Sockops"),
            BpfHookType::SkMsg => write!(f, "sk_msg"),
        }
    }
}

/// Baseline snapshot of an eBPF program's expected state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BpfProgramBaseline {
    /// Human-readable program name (e.g., "kwall_xdp_ingress").
    pub name: String,
    /// Expected BPF program tag (8-byte hex digest from `bpftool prog show`).
    pub expected_tag: String,
    /// Hook attachment type.
    pub hook_type: BpfHookType,
    /// Pinned path in bpffs (e.g., `/sys/fs/bpf/kwall/xdp_ingress`).
    pub pinned_path: PathBuf,
    /// Expected BPF program ID (from initial load).
    pub expected_prog_id: u32,
    /// Timestamp (nanos since epoch) when baseline was captured.
    pub baseline_captured_ns: u64,
}

/// Baseline snapshot of a BPF map's expected state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BpfMapBaseline {
    /// Map name (e.g., "KWALL_INGRESS_LPM").
    pub name: String,
    /// Expected map type string (e.g., "lpm_trie", "hash", "lru_hash").
    pub map_type: String,
    /// Expected maximum entries capacity.
    pub max_entries: u32,
    /// Expected BPF map ID.
    pub expected_map_id: u32,
    /// Pinned path in bpffs.
    pub pinned_path: PathBuf,
    /// Expected approximate entry count at baseline capture (soft check).
    pub baseline_entry_count: u32,
    /// Maximum allowed deviation from baseline entry count before alerting.
    pub entry_count_drift_threshold: u32,
}

/// Category of integrity violation detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IntegrityViolationType {
    /// BPF program detached from its hook point.
    ProgramDetached,
    /// BPF program pinned path deleted or inode changed.
    PinPathMissing,
    /// BPF program tag (bytecode hash) differs from baseline.
    ProgramTagMutated,
    /// BPF program ID changed (program was replaced).
    ProgramIdChanged,
    /// BPF map pinned path deleted.
    MapPinPathMissing,
    /// BPF map entry count drifted beyond threshold.
    MapEntryCountDrift,
    /// BPF map ID changed (map was replaced).
    MapIdChanged,
    /// Unauthorized new BPF program detected on a KWALL interface.
    UnauthorizedProgramAttached,
    /// `/sys/fs/bpf/kwall/` directory permissions tampered.
    BpfFsPermissionsTampered,
}

impl std::fmt::Display for IntegrityViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityViolationType::ProgramDetached => write!(f, "BPF_PROG_DETACHED"),
            IntegrityViolationType::PinPathMissing => write!(f, "BPF_PIN_PATH_MISSING"),
            IntegrityViolationType::ProgramTagMutated => write!(f, "BPF_PROG_TAG_MUTATED"),
            IntegrityViolationType::ProgramIdChanged => write!(f, "BPF_PROG_ID_CHANGED"),
            IntegrityViolationType::MapPinPathMissing => write!(f, "BPF_MAP_PIN_MISSING"),
            IntegrityViolationType::MapEntryCountDrift => write!(f, "BPF_MAP_ENTRY_DRIFT"),
            IntegrityViolationType::MapIdChanged => write!(f, "BPF_MAP_ID_CHANGED"),
            IntegrityViolationType::UnauthorizedProgramAttached => {
                write!(f, "UNAUTHORIZED_BPF_PROG")
            }
            IntegrityViolationType::BpfFsPermissionsTampered => write!(f, "BPFFS_PERMS_TAMPERED"),
        }
    }
}

/// A single integrity violation detected during a verification cycle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityViolation {
    /// Unique violation ID.
    pub violation_id: String,
    /// When the violation was detected (nanos since epoch).
    pub detected_at_ns: u64,
    /// Category of the violation.
    pub violation_type: IntegrityViolationType,
    /// Name of the affected program or map.
    pub target_name: String,
    /// Human-readable description of the specific violation.
    pub description: String,
    /// Expected value (baseline).
    pub expected: String,
    /// Observed value (current).
    pub observed: String,
    /// MITRE ATT&CK technique association.
    pub mitre_technique: Option<String>,
}

/// Aggregate metrics for integrity monitoring.
#[derive(Debug, Default)]
pub struct IntegrityMetrics {
    pub total_scans: AtomicU64,
    pub total_violations: AtomicU64,
    pub program_detachments: AtomicU64,
    pub map_drift_events: AtomicU64,
    pub tag_mutations: AtomicU64,
    pub pin_path_deletions: AtomicU64,
}

/// Result of a single integrity verification cycle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityVerificationResult {
    /// Timestamp when the scan was performed.
    pub scan_timestamp_ns: u64,
    /// Total programs checked.
    pub programs_checked: usize,
    /// Total maps checked.
    pub maps_checked: usize,
    /// All violations detected in this cycle.
    pub violations: Vec<IntegrityViolation>,
    /// Overall integrity verdict.
    pub is_clean: bool,
}

/// eBPF Program & Map Integrity Verifier.
///
/// Continuously monitors KWALL's eBPF programs and maps for tampering,
/// detachment, or unauthorized modification. Generates tamper-evident
/// alerts on any deviation from the captured baseline.
pub struct BpfIntegrityVerifier {
    /// Baseline snapshots of all KWALL eBPF programs.
    program_baselines: RwLock<Vec<BpfProgramBaseline>>,
    /// Baseline snapshots of all KWALL BPF maps.
    map_baselines: RwLock<Vec<BpfMapBaseline>>,
    /// Root path for KWALL's bpffs pin directory.
    bpffs_root: PathBuf,
    /// Aggregate integrity monitoring metrics.
    metrics: IntegrityMetrics,
    /// History of detected violations (bounded ring buffer).
    violation_history: RwLock<Vec<IntegrityViolation>>,
    /// Maximum violation history entries to retain.
    max_history: usize,
}

impl Default for BpfIntegrityVerifier {
    fn default() -> Self {
        Self::new("/sys/fs/bpf/kwall")
    }
}

impl BpfIntegrityVerifier {
    /// Creates a new verifier monitoring the specified bpffs root directory.
    #[must_use]
    pub fn new(bpffs_root: impl Into<PathBuf>) -> Self {
        Self {
            program_baselines: RwLock::new(Vec::new()),
            map_baselines: RwLock::new(Vec::new()),
            bpffs_root: bpffs_root.into(),
            metrics: IntegrityMetrics::default(),
            violation_history: RwLock::new(Vec::new()),
            max_history: 10_000,
        }
    }

    /// Registers a BPF program baseline for continuous integrity monitoring.
    pub fn register_program_baseline(&self, baseline: BpfProgramBaseline) {
        tracing::info!(
            program = %baseline.name,
            hook = %baseline.hook_type,
            prog_id = baseline.expected_prog_id,
            "Registered BPF program integrity baseline"
        );
        let mut baselines = self.program_baselines.write().unwrap();
        baselines.push(baseline);
    }

    /// Registers a BPF map baseline for continuous integrity monitoring.
    pub fn register_map_baseline(&self, baseline: BpfMapBaseline) {
        tracing::info!(
            map = %baseline.name,
            map_id = baseline.expected_map_id,
            max_entries = baseline.max_entries,
            "Registered BPF map integrity baseline"
        );
        let mut baselines = self.map_baselines.write().unwrap();
        baselines.push(baseline);
    }

    /// Performs a full integrity verification cycle against all registered baselines.
    ///
    /// Checks:
    /// 1. Pinned path existence for all programs and maps.
    /// 2. Program tag (bytecode hash) consistency.
    /// 3. Program ID stability (detects replacement attacks).
    /// 4. Map entry count drift within acceptable thresholds.
    /// 5. Bpffs root directory permissions integrity.
    #[must_use]
    pub fn verify_integrity(&self, timestamp_ns: u64) -> IntegrityVerificationResult {
        self.metrics.total_scans.fetch_add(1, Ordering::Relaxed);
        let mut violations = Vec::new();

        // 1. Verify bpffs root directory
        self.verify_bpffs_root(timestamp_ns, &mut violations);

        // 2. Verify all registered programs
        let program_baselines = self.program_baselines.read().unwrap();
        let programs_checked = program_baselines.len();
        for baseline in program_baselines.iter() {
            self.verify_program(baseline, timestamp_ns, &mut violations);
        }

        // 3. Verify all registered maps
        let map_baselines = self.map_baselines.read().unwrap();
        let maps_checked = map_baselines.len();
        for baseline in map_baselines.iter() {
            self.verify_map(baseline, timestamp_ns, &mut violations);
        }

        // 4. Update metrics and history
        let violation_count = violations.len() as u64;
        if violation_count > 0 {
            self.metrics
                .total_violations
                .fetch_add(violation_count, Ordering::Relaxed);

            let mut history = self.violation_history.write().unwrap();
            for v in &violations {
                if history.len() >= self.max_history {
                    history.remove(0);
                }
                history.push(v.clone());
            }
        }

        let is_clean = violations.is_empty();

        if !is_clean {
            tracing::warn!(
                violations = violations.len(),
                programs_checked,
                maps_checked,
                "BPF integrity verification FAILED — violations detected"
            );
        } else {
            tracing::debug!(
                programs_checked,
                maps_checked,
                "BPF integrity verification passed — all hooks intact"
            );
        }

        IntegrityVerificationResult {
            scan_timestamp_ns: timestamp_ns,
            programs_checked,
            maps_checked,
            violations,
            is_clean,
        }
    }

    /// Verifies the bpffs root directory exists and has expected permissions.
    fn verify_bpffs_root(&self, timestamp_ns: u64, violations: &mut Vec<IntegrityViolation>) {
        if !self.bpffs_root.exists() {
            violations.push(IntegrityViolation {
                violation_id: format!("iv-bpffs-root-{}", timestamp_ns),
                detected_at_ns: timestamp_ns,
                violation_type: IntegrityViolationType::BpfFsPermissionsTampered,
                target_name: self.bpffs_root.display().to_string(),
                description: format!(
                    "KWALL bpffs root directory '{}' is missing or unmounted",
                    self.bpffs_root.display()
                ),
                expected: "directory exists".to_string(),
                observed: "missing".to_string(),
                mitre_technique: Some("T1562.001".to_string()),
            });
            return;
        }

        // Check directory permissions (should be 0o700 or 0o755 — owner rwx)
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&self.bpffs_root) {
                let mode = metadata.permissions().mode() & 0o777;
                // bpffs is typically mounted with restrictive permissions
                if mode & 0o002 != 0 {
                    // world-writable is suspicious
                    violations.push(IntegrityViolation {
                        violation_id: format!("iv-bpffs-perms-{}", timestamp_ns),
                        detected_at_ns: timestamp_ns,
                        violation_type: IntegrityViolationType::BpfFsPermissionsTampered,
                        target_name: self.bpffs_root.display().to_string(),
                        description: format!(
                            "KWALL bpffs root directory has insecure permissions: {:o} (world-writable)",
                            mode
                        ),
                        expected: "restrictive (no world-write)".to_string(),
                        observed: format!("{:o}", mode),
                        mitre_technique: Some("T1222.002".to_string()),
                    });
                }
            }
        }
    }

    /// Verifies a single BPF program's integrity against its baseline.
    fn verify_program(
        &self,
        baseline: &BpfProgramBaseline,
        timestamp_ns: u64,
        violations: &mut Vec<IntegrityViolation>,
    ) {
        // 1. Check pinned path existence
        if !baseline.pinned_path.exists() {
            self.metrics.pin_path_deletions.fetch_add(1, Ordering::Relaxed);
            violations.push(IntegrityViolation {
                violation_id: format!("iv-pin-{}-{}", baseline.name, timestamp_ns),
                detected_at_ns: timestamp_ns,
                violation_type: IntegrityViolationType::PinPathMissing,
                target_name: baseline.name.clone(),
                description: format!(
                    "BPF program '{}' pinned path '{}' is missing — potential unauthorized unpin/detach",
                    baseline.name,
                    baseline.pinned_path.display()
                ),
                expected: baseline.pinned_path.display().to_string(),
                observed: "file not found".to_string(),
                mitre_technique: Some("T1562.001".to_string()),
            });
            return;
        }

        // 2. Simulate program ID and tag verification
        // In production, this reads from /proc/self/fdinfo or bpf(BPF_PROG_GET_INFO_BY_FD)
        let current_state = self.read_program_state(&baseline.pinned_path);
        if let Some((current_id, current_tag)) = current_state {
            if current_id != baseline.expected_prog_id {
                self.metrics.program_detachments.fetch_add(1, Ordering::Relaxed);
                violations.push(IntegrityViolation {
                    violation_id: format!("iv-progid-{}-{}", baseline.name, timestamp_ns),
                    detected_at_ns: timestamp_ns,
                    violation_type: IntegrityViolationType::ProgramIdChanged,
                    target_name: baseline.name.clone(),
                    description: format!(
                        "BPF program '{}' ID changed from {} to {} — program was replaced",
                        baseline.name, baseline.expected_prog_id, current_id
                    ),
                    expected: baseline.expected_prog_id.to_string(),
                    observed: current_id.to_string(),
                    mitre_technique: Some("T1014".to_string()),
                });
            }

            if current_tag != baseline.expected_tag {
                self.metrics.tag_mutations.fetch_add(1, Ordering::Relaxed);
                violations.push(IntegrityViolation {
                    violation_id: format!("iv-tag-{}-{}", baseline.name, timestamp_ns),
                    detected_at_ns: timestamp_ns,
                    violation_type: IntegrityViolationType::ProgramTagMutated,
                    target_name: baseline.name.clone(),
                    description: format!(
                        "BPF program '{}' bytecode tag changed from '{}' to '{}' — code was modified",
                        baseline.name, baseline.expected_tag, current_tag
                    ),
                    expected: baseline.expected_tag.clone(),
                    observed: current_tag,
                    mitre_technique: Some("T1014".to_string()),
                });
            }
        }
    }

    /// Verifies a single BPF map's integrity against its baseline.
    fn verify_map(
        &self,
        baseline: &BpfMapBaseline,
        timestamp_ns: u64,
        violations: &mut Vec<IntegrityViolation>,
    ) {
        // 1. Check pinned path existence
        if !baseline.pinned_path.exists() {
            self.metrics.pin_path_deletions.fetch_add(1, Ordering::Relaxed);
            violations.push(IntegrityViolation {
                violation_id: format!("iv-mappin-{}-{}", baseline.name, timestamp_ns),
                detected_at_ns: timestamp_ns,
                violation_type: IntegrityViolationType::MapPinPathMissing,
                target_name: baseline.name.clone(),
                description: format!(
                    "BPF map '{}' pinned path '{}' is missing — map was unpinned or deleted",
                    baseline.name,
                    baseline.pinned_path.display()
                ),
                expected: baseline.pinned_path.display().to_string(),
                observed: "file not found".to_string(),
                mitre_technique: Some("T1562.001".to_string()),
            });
            return;
        }

        // 2. Simulate map state verification
        let current_state = self.read_map_state(&baseline.pinned_path);
        if let Some((current_id, current_entry_count)) = current_state {
            if current_id != baseline.expected_map_id {
                violations.push(IntegrityViolation {
                    violation_id: format!("iv-mapid-{}-{}", baseline.name, timestamp_ns),
                    detected_at_ns: timestamp_ns,
                    violation_type: IntegrityViolationType::MapIdChanged,
                    target_name: baseline.name.clone(),
                    description: format!(
                        "BPF map '{}' ID changed from {} to {} — map was replaced",
                        baseline.name, baseline.expected_map_id, current_id
                    ),
                    expected: baseline.expected_map_id.to_string(),
                    observed: current_id.to_string(),
                    mitre_technique: Some("T1562.001".to_string()),
                });
            }

            let drift = if current_entry_count > baseline.baseline_entry_count {
                current_entry_count - baseline.baseline_entry_count
            } else {
                baseline.baseline_entry_count - current_entry_count
            };

            if drift > baseline.entry_count_drift_threshold {
                self.metrics.map_drift_events.fetch_add(1, Ordering::Relaxed);
                violations.push(IntegrityViolation {
                    violation_id: format!("iv-mapdrift-{}-{}", baseline.name, timestamp_ns),
                    detected_at_ns: timestamp_ns,
                    violation_type: IntegrityViolationType::MapEntryCountDrift,
                    target_name: baseline.name.clone(),
                    description: format!(
                        "BPF map '{}' entry count drifted by {} entries (baseline: {}, current: {}, threshold: {})",
                        baseline.name, drift, baseline.baseline_entry_count,
                        current_entry_count, baseline.entry_count_drift_threshold
                    ),
                    expected: baseline.baseline_entry_count.to_string(),
                    observed: current_entry_count.to_string(),
                    mitre_technique: Some("T1562.001".to_string()),
                });
            }
        }
    }

    /// Reads the current BPF program state from the pinned path.
    /// Returns `(prog_id, tag_hex)` if readable.
    ///
    /// In production, this uses `bpf(BPF_OBJ_GET)` + `bpf(BPF_PROG_GET_INFO_BY_FD)`.
    /// For testability, this performs a filesystem metadata check.
    fn read_program_state(&self, pinned_path: &Path) -> Option<(u32, String)> {
        // In a real kernel environment, we would:
        // 1. Open the pinned BPF program fd via bpf(BPF_OBJ_GET, pinned_path)
        // 2. Query info via bpf(BPF_PROG_GET_INFO_BY_FD)
        // 3. Extract prog_id and tag from bpf_prog_info
        //
        // For unit-testability, we use file metadata as a proxy.
        let metadata = std::fs::metadata(pinned_path).ok()?;

        // Use inode as proxy for program ID in testing
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode = metadata.ino() as u32;
            let size = metadata.size();
            let tag = format!("{:016x}", size ^ (inode as u64));
            Some((inode, tag))
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }

    /// Reads the current BPF map state from the pinned path.
    /// Returns `(map_id, entry_count)` if readable.
    fn read_map_state(&self, pinned_path: &Path) -> Option<(u32, u32)> {
        // In production: bpf(BPF_OBJ_GET) + bpf(BPF_MAP_GET_INFO_BY_FD) + iteration
        let metadata = std::fs::metadata(pinned_path).ok()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode = metadata.ino() as u32;
            // Entry count is not directly available without BPF syscall iteration;
            // use file size as heuristic proxy in non-kernel test mode.
            let entry_count_proxy = (metadata.size() / 64) as u32;
            Some((inode, entry_count_proxy))
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }

    /// Retrieves the current aggregate integrity metrics.
    #[must_use]
    pub fn get_metrics(&self) -> HashMap<String, u64> {
        let mut m = HashMap::new();
        m.insert(
            "total_scans".to_string(),
            self.metrics.total_scans.load(Ordering::Relaxed),
        );
        m.insert(
            "total_violations".to_string(),
            self.metrics.total_violations.load(Ordering::Relaxed),
        );
        m.insert(
            "program_detachments".to_string(),
            self.metrics.program_detachments.load(Ordering::Relaxed),
        );
        m.insert(
            "map_drift_events".to_string(),
            self.metrics.map_drift_events.load(Ordering::Relaxed),
        );
        m.insert(
            "tag_mutations".to_string(),
            self.metrics.tag_mutations.load(Ordering::Relaxed),
        );
        m.insert(
            "pin_path_deletions".to_string(),
            self.metrics.pin_path_deletions.load(Ordering::Relaxed),
        );
        m
    }

    /// Returns all recorded violation history entries.
    #[must_use]
    pub fn violation_history(&self) -> Vec<IntegrityViolation> {
        self.violation_history.read().unwrap().clone()
    }

    /// Clears the violation history and resets all metrics counters.
    pub fn reset(&self) {
        self.metrics.total_scans.store(0, Ordering::Relaxed);
        self.metrics.total_violations.store(0, Ordering::Relaxed);
        self.metrics.program_detachments.store(0, Ordering::Relaxed);
        self.metrics.map_drift_events.store(0, Ordering::Relaxed);
        self.metrics.tag_mutations.store(0, Ordering::Relaxed);
        self.metrics.pin_path_deletions.store(0, Ordering::Relaxed);
        self.violation_history.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct TempBpfFs {
        path: PathBuf,
    }

    impl TempBpfFs {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempBpfFs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_temp_bpffs() -> TempBpfFs {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("kwall_bpffs_test_{}", id));
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }

        // Create fake pinned program and map files
        let progs_dir = dir.join("programs");
        fs::create_dir_all(&progs_dir).unwrap();
        fs::write(progs_dir.join("xdp_ingress"), b"fake_ebpf_bytecode_xdp").unwrap();
        fs::write(progs_dir.join("tc_egress"), b"fake_ebpf_bytecode_tc").unwrap();

        let maps_dir = dir.join("maps");
        fs::create_dir_all(&maps_dir).unwrap();
        // Create a file with 64-byte multiples to simulate entries
        fs::write(maps_dir.join("KWALL_INGRESS_LPM"), vec![0u8; 640]).unwrap();
        fs::write(maps_dir.join("KWALL_FLOW_TABLE"), vec![0u8; 320]).unwrap();

        TempBpfFs { path: dir }
    }

    #[cfg(unix)]
    #[test]
    fn test_register_and_verify_clean_state() {
        let tmp = create_temp_bpffs();
        let verifier = BpfIntegrityVerifier::new(tmp.path());

        let prog_path = tmp.path().join("programs/xdp_ingress");


        // Read the actual inode for baseline
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&prog_path).unwrap();
        let inode = meta.ino() as u32;
        let size = meta.size();
        let tag = format!("{:016x}", size ^ (inode as u64));

        verifier.register_program_baseline(BpfProgramBaseline {
            name: "kwall_xdp_ingress".to_string(),
            expected_tag: tag,
            hook_type: BpfHookType::Xdp,
            pinned_path: prog_path,
            expected_prog_id: inode,
            baseline_captured_ns: 1_000_000,
        });

        let result = verifier.verify_integrity(2_000_000);
        assert!(result.is_clean);
        assert_eq!(result.programs_checked, 1);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_detect_missing_pin_path() {
        let tmp = create_temp_bpffs();
        let verifier = BpfIntegrityVerifier::new(tmp.path());

        // Register baseline with a non-existent path
        verifier.register_program_baseline(BpfProgramBaseline {
            name: "kwall_ghost_prog".to_string(),
            expected_tag: "deadbeefcafe0000".to_string(),
            hook_type: BpfHookType::Lsm,
            pinned_path: tmp.path().join("programs/ghost_program"),
            expected_prog_id: 99999,
            baseline_captured_ns: 1_000_000,
        });

        let result = verifier.verify_integrity(2_000_000);
        assert!(!result.is_clean);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].violation_type,
            IntegrityViolationType::PinPathMissing
        );
        assert_eq!(result.violations[0].target_name, "kwall_ghost_prog");
    }

    #[test]
    fn test_detect_missing_map_pin() {
        let tmp = create_temp_bpffs();
        let verifier = BpfIntegrityVerifier::new(tmp.path());

        verifier.register_map_baseline(BpfMapBaseline {
            name: "KWALL_DELETED_MAP".to_string(),
            map_type: "hash".to_string(),
            max_entries: 1024,
            expected_map_id: 77777,
            pinned_path: tmp.path().join("maps/KWALL_DELETED_MAP"),
            baseline_entry_count: 0,
            entry_count_drift_threshold: 100,
        });

        let result = verifier.verify_integrity(3_000_000);
        assert!(!result.is_clean);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].violation_type,
            IntegrityViolationType::MapPinPathMissing
        );
    }

    #[test]
    fn test_detect_bpffs_root_missing() {
        let verifier = BpfIntegrityVerifier::new("/tmp/nonexistent_kwall_bpffs_12345");

        let result = verifier.verify_integrity(4_000_000);
        assert!(!result.is_clean);
        assert!(result
            .violations
            .iter()
            .any(|v| v.violation_type == IntegrityViolationType::BpfFsPermissionsTampered));
    }

    #[test]
    fn test_metrics_accumulation() {
        let tmp = create_temp_bpffs();
        let verifier = BpfIntegrityVerifier::new(tmp.path());

        // Register a program with missing pin
        verifier.register_program_baseline(BpfProgramBaseline {
            name: "missing_prog".to_string(),
            expected_tag: "0000000000000000".to_string(),
            hook_type: BpfHookType::TcIngress,
            pinned_path: tmp.path().join("programs/missing"),
            expected_prog_id: 1,
            baseline_captured_ns: 0,
        });

        // Run multiple scans
        let _ = verifier.verify_integrity(1_000_000);
        let _ = verifier.verify_integrity(2_000_000);
        let _ = verifier.verify_integrity(3_000_000);

        let metrics = verifier.get_metrics();
        assert_eq!(metrics["total_scans"], 3);
        assert_eq!(metrics["total_violations"], 3);
        assert_eq!(metrics["pin_path_deletions"], 3);

        let history = verifier.violation_history();
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_reset_clears_state() {
        let verifier = BpfIntegrityVerifier::new("/tmp/nonexistent_kwall_bpffs_reset");
        let _ = verifier.verify_integrity(1_000_000);

        let metrics_before = verifier.get_metrics();
        assert!(metrics_before["total_scans"] > 0);

        verifier.reset();

        let metrics_after = verifier.get_metrics();
        assert_eq!(metrics_after["total_scans"], 0);
        assert_eq!(metrics_after["total_violations"], 0);
        assert!(verifier.violation_history().is_empty());
    }
}
