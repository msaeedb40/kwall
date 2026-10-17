use crate::verifier::{BpfConformanceVerifier, BpfVerifierReport, EXPECTED_BPF_MAPS};
use kwall_common::{KwallError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

pub const DEFAULT_BPFFS_PIN_PATH: &str = "/sys/fs/bpf/kwall";

pub struct DataplaneManager {
    initialized: bool,
    attached_interfaces: Vec<String>,
    bpffs_pin_path: PathBuf,
    bpf_loaded: bool,
    verifier_report: Option<BpfVerifierReport>,
}

impl DataplaneManager {
    pub fn new() -> Self {
        Self {
            initialized: false,
            attached_interfaces: Vec::new(),
            bpffs_pin_path: PathBuf::from(DEFAULT_BPFFS_PIN_PATH),
            bpf_loaded: false,
            verifier_report: None,
        }
    }

    pub fn with_pin_path<P: AsRef<Path>>(pin_path: P) -> Self {
        Self {
            initialized: false,
            attached_interfaces: Vec::new(),
            bpffs_pin_path: pin_path.as_ref().to_path_buf(),
            bpf_loaded: false,
            verifier_report: None,
        }
    }

    pub fn init(&mut self) -> Result<()> {
        info!("Initializing KWALL Dataplane Manager");
        self.initialized = true;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn pin_path(&self) -> &Path {
        &self.bpffs_pin_path
    }

    pub fn set_pin_path<P: AsRef<Path>>(&mut self, pin_path: P) {
        self.bpffs_pin_path = pin_path.as_ref().to_path_buf();
    }

    /// Check if bpffs has pinned maps from an existing/previous agent run.
    /// Used for graceful restart and zero-downtime dataplane recovery.
    pub fn has_pinned_state(&self) -> bool {
        if !self.bpffs_pin_path.exists() {
            return false;
        }

        // Check if any expected KWALL map exists in the pin directory
        for &map_name in EXPECTED_BPF_MAPS {
            let map_path = self.bpffs_pin_path.join(map_name);
            if map_path.exists() {
                return true;
            }
        }
        false
    }

    /// Load and statically verify eBPF program bytecode.
    pub fn load_bpf_bytes(&mut self, bytes: &[u8]) -> Result<BpfVerifierReport> {
        let report = BpfConformanceVerifier::verify_bytes(bytes)?;
        if !report.is_valid {
            return Err(KwallError::Dataplane(format!(
                "eBPF bytecode failed verifier check: {:?}",
                report.errors
            )));
        }

        info!(
            "Successfully verified eBPF bytecode ({} programs, {} maps, {} total insns)",
            report.programs.len(),
            report.maps.len(),
            report.total_instructions
        );

        self.verifier_report = Some(report.clone());
        self.bpf_loaded = true;
        Ok(report)
    }

    /// Load and verify eBPF program from an ELF file.
    pub fn load_bpf_file<P: AsRef<Path>>(&mut self, path: P) -> Result<BpfVerifierReport> {
        let bytes = fs::read(path.as_ref()).map_err(|e| {
            KwallError::Dataplane(format!(
                "Failed to read eBPF binary {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;
        self.load_bpf_bytes(&bytes)
    }

    pub fn is_bpf_loaded(&self) -> bool {
        self.bpf_loaded
    }

    pub fn verifier_report(&self) -> Option<&BpfVerifierReport> {
        self.verifier_report.as_ref()
    }

    /// Create bpffs pin directory and ensure state persistence layout.
    pub fn ensure_pin_directory(&self) -> Result<()> {
        if !self.bpffs_pin_path.exists() {
            fs::create_dir_all(&self.bpffs_pin_path).map_err(|e| {
                KwallError::Dataplane(format!(
                    "Failed to create bpffs pin directory {}: {}",
                    self.bpffs_pin_path.display(),
                    e
                ))
            })?;
            info!(
                "Created bpffs pinning directory: {}",
                self.bpffs_pin_path.display()
            );
        }
        Ok(())
    }

    /// Remove pinned maps on graceful complete shutdown (if requested).
    pub fn clean_pinned_maps(&self) -> Result<()> {
        if self.bpffs_pin_path.exists() {
            for &map_name in EXPECTED_BPF_MAPS {
                let map_path = self.bpffs_pin_path.join(map_name);
                if map_path.exists() {
                    let _ = fs::remove_file(&map_path);
                    info!("Unpinned BPF map: {}", map_path.display());
                }
            }
        }
        Ok(())
    }

    pub fn attach_interface(&mut self, iface: &str) -> Result<()> {
        if !self.initialized {
            return Err(KwallError::Dataplane("Dataplane not initialized".into()));
        }
        info!("Attaching eBPF dataplane to interface {}", iface);
        if !self.attached_interfaces.iter().any(|i| i == iface) {
            self.attached_interfaces.push(iface.to_string());
        }
        Ok(())
    }

    pub fn detach_interface(&mut self, iface: &str) -> Result<()> {
        info!("Detaching eBPF dataplane from interface {}", iface);
        self.attached_interfaces.retain(|i| i != iface);
        Ok(())
    }

    pub fn attached_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
}

impl Default for DataplaneManager {
    fn default() -> Self {
        Self::new()
    }
}
