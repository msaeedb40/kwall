use kwall_common::{KwallError, Result};
use kwall_ebpf_common::{SecurityEvent, SecurityEventType, Severity};
use std::fs;
use std::path::Path;
use tracing::warn;

pub struct WorkloadIntegrityGuard {
    allowed_binaries: Vec<String>,
    allowed_hashes: Vec<String>,
}

impl WorkloadIntegrityGuard {
    pub fn new(allowed_binaries: Vec<String>) -> Self {
        Self {
            allowed_binaries,
            allowed_hashes: Vec::new(),
        }
    }

    pub fn with_hashes(allowed_binaries: Vec<String>, allowed_hashes: Vec<String>) -> Self {
        Self {
            allowed_binaries,
            allowed_hashes,
        }
    }

    pub fn compute_file_hash(path: &str) -> Result<String> {
        let content = fs::read(path).map_err(KwallError::Io)?;
        let hash = blake3::hash(&content);
        Ok(hash.to_hex().to_string())
    }

    pub fn verify_executable(&self, exe_path: &str, pid: u32) -> Option<SecurityEvent> {
        let filename = Path::new(exe_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(exe_path);

        // Check for suspicious directory execution (e.g. running malware from /tmp or /dev/shm)
        if exe_path.starts_with("/tmp")
            || exe_path.starts_with("/var/tmp")
            || exe_path.starts_with("/dev/shm")
            || exe_path.contains("(deleted)")
        {
            warn!(
                "Security alert: Execution from suspicious path '{}' by PID {}",
                exe_path, pid
            );
            return Some(SecurityEvent {
                pid,
                event_type: SecurityEventType::MaliciousProcessExec as u32,
                severity: Severity::Critical as u32,
                ..Default::default()
            });
        }

        // Verify binary name allowlist
        if !self.allowed_binaries.is_empty()
            && !self
                .allowed_binaries
                .iter()
                .any(|allowed| allowed == filename || allowed == exe_path)
        {
            warn!(
                "Security violation: Untrusted executable '{}' executed by PID {}",
                exe_path, pid
            );

            return Some(SecurityEvent {
                pid,
                event_type: SecurityEventType::UntrustedBinary as u32,
                severity: Severity::High as u32,
                ..Default::default()
            });
        }

        // Verify cryptographic hash if hashes are specified
        if !self.allowed_hashes.is_empty()
            && let Ok(file_hash) = Self::compute_file_hash(exe_path)
            && !self.allowed_hashes.iter().any(|h| h == &file_hash)
        {
            warn!(
                "Security violation: Executable hash '{}' for '{}' not in allowed list",
                file_hash, exe_path
            );
            return Some(SecurityEvent {
                pid,
                event_type: SecurityEventType::SignatureVerificationFailed as u32,
                severity: Severity::Critical as u32,
                ..Default::default()
            });
        }

        None
    }
}
