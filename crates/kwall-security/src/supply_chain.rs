use std::fs;
use std::path::Path;
use kwall_common::{KwallError, Result};
use kwall_ebpf_common::{SecurityEvent, SecurityEventType, Severity};
use tracing::warn;

pub struct WorkloadIntegrityGuard {
    allowed_binaries: Vec<String>,
}

impl WorkloadIntegrityGuard {
    pub fn new(allowed_binaries: Vec<String>) -> Self {
        Self { allowed_binaries }
    }

    pub fn compute_file_hash(path: &str) -> Result<String> {
        let content = fs::read(path).map_err(|e| KwallError::Io(e))?;
        let hash = blake3::hash(&content);
        Ok(hash.to_hex().to_string())
    }

    pub fn verify_executable(&self, exe_path: &str, pid: u32) -> Option<SecurityEvent> {
        let filename = Path::new(exe_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(exe_path);

        if !self.allowed_binaries.is_empty()
            && !self.allowed_binaries.iter().any(|allowed| allowed == filename || allowed == exe_path)
        {
            warn!(
                "Security violation: Untrusted executable '{}' executed by PID {}",
                exe_path, pid
            );

            let mut event = SecurityEvent::default();
            event.pid = pid;
            event.event_type = SecurityEventType::MaliciousProcessExec as u32;
            event.severity = Severity::Critical as u32;
            return Some(event);
        }

        None
    }
}
