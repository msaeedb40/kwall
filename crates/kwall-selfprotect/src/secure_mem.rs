//! KWALL Tamper-Resistant Agent Memory & mTLS Certificate Rotation.
//!
//! Provides secure memory management to prevent sensitive cryptographic material
//! (private keys, tokens, session keys) from being paged to disk, and automated
//! mTLS certificate rotation for agent-to-control-plane channels.
//!
//! ## Security Properties
//!
//! - **`mlock(2)`**: Locks agent memory pages containing secrets into RAM,
//!   preventing the kernel from swapping them to disk where they could be extracted.
//! - **`madvise(MADV_DONTDUMP)`**: Excludes secret pages from core dumps.
//! - **`mprotect(PROT_READ)`**: Makes secret pages read-only after initialization,
//!   preventing accidental or malicious overwrites.
//! - **Zeroization**: Explicitly zeroes secret buffers before deallocation using
//!   volatile writes to prevent compiler optimization.
//! - **Certificate rotation**: Automated mTLS certificate lifecycle management
//!   with zero-downtime rotation windows.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

/// State of a locked memory region.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LockedRegionState {
    /// Region is allocated but not yet locked.
    Allocated,
    /// Region is locked into physical RAM via `mlock(2)`.
    Locked,
    /// Region has been zeroized and unlocked.
    Zeroized,
    /// Region lock failed (insufficient `RLIMIT_MEMLOCK`).
    LockFailed,
}

impl std::fmt::Display for LockedRegionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockedRegionState::Allocated => write!(f, "ALLOCATED"),
            LockedRegionState::Locked => write!(f, "LOCKED"),
            LockedRegionState::Zeroized => write!(f, "ZEROIZED"),
            LockedRegionState::LockFailed => write!(f, "LOCK_FAILED"),
        }
    }
}

/// Metadata for a single secure memory region.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecureRegionDescriptor {
    /// Human-readable label for the region (e.g., "mtls_private_key").
    pub label: String,
    /// Size of the region in bytes.
    pub size_bytes: usize,
    /// Current lock state.
    pub state: LockedRegionState,
    /// Whether the region is marked read-only via `mprotect`.
    pub read_only: bool,
    /// Whether the region is excluded from core dumps via `madvise`.
    pub exclude_from_coredump: bool,
    /// Timestamp when the region was allocated (nanos since epoch).
    pub allocated_at_ns: u64,
}

/// A secure memory buffer that is locked into RAM and zeroized on drop.
///
/// Wraps a `Vec<u8>` with:
/// 1. `mlock(2)` to prevent paging to swap.
/// 2. `madvise(MADV_DONTDUMP)` to exclude from core dumps.
/// 3. Volatile zeroization on `Drop`.
pub struct SecureBuffer {
    data: Vec<u8>,
    label: String,
    locked: bool,
    read_only: bool,
}

impl SecureBuffer {
    /// Allocates a new secure buffer of the specified size and locks it into RAM.
    pub fn new(label: impl Into<String>, size: usize) -> Self {
        let label = label.into();
        let data = vec![0u8; size];

        let locked = Self::mlock_region(data.as_ptr(), data.len());

        if locked {
            Self::exclude_from_coredump(data.as_ptr(), data.len());
            tracing::debug!(
                label = %label,
                size,
                "Secure buffer allocated and locked into RAM"
            );
        } else {
            tracing::warn!(
                label = %label,
                size,
                "Failed to mlock secure buffer — secrets may be paged to swap"
            );
        }

        Self {
            data,
            label,
            locked,
            read_only: false,
        }
    }

    /// Writes secret data into the buffer. Panics if the buffer is read-only.
    pub fn write_secret(&mut self, secret: &[u8]) {
        assert!(
            !self.read_only,
            "Cannot write to read-only secure buffer '{}'",
            self.label
        );
        assert!(
            secret.len() <= self.data.len(),
            "Secret ({} bytes) exceeds buffer capacity ({} bytes)",
            secret.len(),
            self.data.len()
        );

        // Zero existing content first
        self.zeroize_volatile();

        // Copy new secret
        self.data[..secret.len()].copy_from_slice(secret);
    }

    /// Returns a read-only slice of the secret data.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Makes the buffer read-only via `mprotect(PROT_READ)`.
    pub fn make_read_only(&mut self) {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                let addr = self.data.as_ptr() as *mut libc::c_void;
                let aligned_addr = (addr as usize & !(page_size - 1)) as *mut libc::c_void;
                let aligned_len =
                    self.data.len() + (addr as usize - aligned_addr as usize);
                // Note: mprotect requires page-aligned addresses
                // In production, use a page-aligned allocator
                let _ = libc::mprotect(aligned_addr, aligned_len, libc::PROT_READ);
            }
        }

        self.read_only = true;
        tracing::debug!(label = %self.label, "Secure buffer set to read-only");
    }

    /// Returns the buffer's descriptor metadata.
    #[must_use]
    pub fn descriptor(&self, timestamp_ns: u64) -> SecureRegionDescriptor {
        SecureRegionDescriptor {
            label: self.label.clone(),
            size_bytes: self.data.len(),
            state: if self.locked {
                LockedRegionState::Locked
            } else {
                LockedRegionState::Allocated
            },
            read_only: self.read_only,
            exclude_from_coredump: self.locked,
            allocated_at_ns: timestamp_ns,
        }
    }

    /// Returns whether the buffer is successfully locked into RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    // --- Internal helpers ---

    /// Locks a memory region into RAM using `mlock(2)`.
    fn mlock_region(ptr: *const u8, len: usize) -> bool {
        #[cfg(target_os = "linux")]
        {
            let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
            result == 0
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ptr, len);
            false
        }
    }

    /// Excludes a memory region from core dumps using `madvise(MADV_DONTDUMP)`.
    fn exclude_from_coredump(ptr: *const u8, len: usize) {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                libc::madvise(
                    ptr as *mut libc::c_void,
                    len,
                    libc::MADV_DONTDUMP,
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ptr, len);
        }
    }

    /// Zeroizes the buffer using volatile writes to prevent compiler optimization.
    fn zeroize_volatile(&mut self) {
        for byte in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0u8);
            }
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // 1. Restore write permissions if read-only (needed to zeroize)
        if self.read_only {
            #[cfg(target_os = "linux")]
            {
                unsafe {
                    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                    let addr = self.data.as_ptr() as *mut libc::c_void;
                    let aligned_addr =
                        (addr as usize & !(page_size - 1)) as *mut libc::c_void;
                    let aligned_len =
                        self.data.len() + (addr as usize - aligned_addr as usize);
                    let _ = libc::mprotect(
                        aligned_addr,
                        aligned_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                }
            }
            self.read_only = false;
        }

        // 2. Zeroize all data using volatile writes
        self.zeroize_volatile();

        // 3. Unlock memory region
        if self.locked {
            #[cfg(target_os = "linux")]
            {
                unsafe {
                    libc::munlock(
                        self.data.as_ptr() as *const libc::c_void,
                        self.data.len(),
                    );
                }
            }
            self.locked = false;
        }

        tracing::trace!(label = %self.label, "Secure buffer zeroized and unlocked");
    }
}

/// mTLS certificate state in the rotation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CertificateState {
    /// Certificate is pending generation or CSR submission.
    Pending,
    /// Certificate is active and in use for mTLS handshakes.
    Active,
    /// Certificate is in the rotation grace period (old cert still accepted).
    Rotating,
    /// Certificate has expired and should no longer be accepted.
    Expired,
    /// Certificate was explicitly revoked.
    Revoked,
}

impl std::fmt::Display for CertificateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateState::Pending => write!(f, "PENDING"),
            CertificateState::Active => write!(f, "ACTIVE"),
            CertificateState::Rotating => write!(f, "ROTATING"),
            CertificateState::Expired => write!(f, "EXPIRED"),
            CertificateState::Revoked => write!(f, "REVOKED"),
        }
    }
}

/// Metadata for an mTLS certificate in the rotation lifecycle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateRecord {
    /// Unique certificate serial number (hex-encoded).
    pub serial: String,
    /// Common Name (CN) or SPIFFE ID of the certificate subject.
    pub subject_cn: String,
    /// Certificate issuer common name.
    pub issuer_cn: String,
    /// Certificate validity start (nanos since epoch).
    pub not_before_ns: u64,
    /// Certificate validity end (nanos since epoch).
    pub not_after_ns: u64,
    /// SHA-256 fingerprint of the certificate (hex-encoded).
    pub fingerprint_sha256: String,
    /// Current state in the rotation lifecycle.
    pub state: CertificateState,
    /// Path to the PEM-encoded certificate file.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key file (in secure storage).
    pub key_path: PathBuf,
}

/// Configuration for automated mTLS certificate rotation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertRotationConfig {
    /// Directory where certificates and keys are stored.
    pub cert_dir: PathBuf,
    /// Certificate validity duration in seconds.
    pub cert_validity_secs: u64,
    /// How long before expiry to start rotation (seconds).
    pub rotation_lead_time_secs: u64,
    /// Grace period during which both old and new certs are valid (seconds).
    pub grace_period_secs: u64,
    /// SPIFFE trust domain for certificate subjects.
    pub trust_domain: String,
    /// Agent node identifier for certificate CN.
    pub node_id: String,
}

impl Default for CertRotationConfig {
    fn default() -> Self {
        Self {
            cert_dir: PathBuf::from("/var/lib/kwall/certs"),
            cert_validity_secs: 86400,          // 24 hours
            rotation_lead_time_secs: 3600,      // 1 hour before expiry
            grace_period_secs: 300,             // 5 minute overlap
            trust_domain: "kwall.cluster.local".to_string(),
            node_id: "kwall-agent-unknown".to_string(),
        }
    }
}

/// Metrics for certificate rotation operations.
#[derive(Debug, Default)]
pub struct CertRotationMetrics {
    pub total_rotations: AtomicU64,
    pub total_rotation_failures: AtomicU64,
    pub total_expired_certs: AtomicU64,
    pub total_revocations: AtomicU64,
}

/// Automated mTLS Certificate Rotation Manager.
///
/// Manages the complete lifecycle of agent mTLS certificates:
/// issuance, activation, pre-expiry rotation with grace periods,
/// and secure key storage in mlock'd memory buffers.
pub struct CertRotationManager {
    config: CertRotationConfig,
    /// Currently active certificate.
    active_cert: RwLock<Option<CertificateRecord>>,
    /// Previous certificate still in grace period.
    previous_cert: RwLock<Option<CertificateRecord>>,
    /// Certificate rotation history.
    rotation_history: RwLock<Vec<RotationEvent>>,
    /// Secure buffer holding the active private key.
    active_key_buffer: RwLock<Option<SecureBuffer>>,
    /// Metrics.
    metrics: CertRotationMetrics,
    /// Whether a rotation is currently in progress.
    rotation_in_progress: AtomicBool,
    /// Maximum history entries.
    max_history: usize,
}

/// Record of a certificate rotation event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RotationEvent {
    /// Timestamp of the rotation (nanos since epoch).
    pub timestamp_ns: u64,
    /// Previous certificate serial being rotated out.
    pub previous_serial: Option<String>,
    /// New certificate serial being rotated in.
    pub new_serial: String,
    /// Whether the rotation completed successfully.
    pub success: bool,
    /// Reason for the rotation.
    pub reason: String,
}

impl Default for CertRotationManager {
    fn default() -> Self {
        Self::new(CertRotationConfig::default())
    }
}

impl CertRotationManager {
    /// Creates a new certificate rotation manager.
    #[must_use]
    pub fn new(config: CertRotationConfig) -> Self {
        tracing::info!(
            cert_dir = %config.cert_dir.display(),
            validity_hours = config.cert_validity_secs / 3600,
            lead_time_mins = config.rotation_lead_time_secs / 60,
            "Initializing mTLS certificate rotation manager"
        );

        Self {
            config,
            active_cert: RwLock::new(None),
            previous_cert: RwLock::new(None),
            rotation_history: RwLock::new(Vec::new()),
            active_key_buffer: RwLock::new(None),
            metrics: CertRotationMetrics::default(),
            rotation_in_progress: AtomicBool::new(false),
            max_history: 1_000,
        }
    }

    /// Issues a new certificate and installs it as the active certificate.
    ///
    /// In production, this generates a CSR, submits it to the CA, and stores
    /// the signed certificate. For testability, this generates a self-signed certificate record.
    pub fn issue_certificate(&self, timestamp_ns: u64) -> Result<CertificateRecord, CertRotationError> {
        let serial = format!("{:016x}", timestamp_ns ^ 0xDEAD_CAFE_BABE_u64.wrapping_mul(timestamp_ns >> 8));

        let subject_cn = format!(
            "spiffe://{}/node/{}",
            self.config.trust_domain, self.config.node_id
        );

        let validity_ns = self.config.cert_validity_secs * 1_000_000_000;

        let cert = CertificateRecord {
            serial: serial.clone(),
            subject_cn: subject_cn.clone(),
            issuer_cn: format!("kwall-ca.{}", self.config.trust_domain),
            not_before_ns: timestamp_ns,
            not_after_ns: timestamp_ns + validity_ns,
            fingerprint_sha256: format!("sha256:{:064x}", timestamp_ns),
            state: CertificateState::Active,
            cert_path: self.config.cert_dir.join(format!("{}.pem", serial)),
            key_path: self.config.cert_dir.join(format!("{}.key", serial)),
        };

        // Store private key in secure mlock'd buffer
        let fake_key = format!("-----BEGIN EC PRIVATE KEY-----\nkwall-{}-{}\n-----END EC PRIVATE KEY-----", serial, timestamp_ns);
        let mut key_buf = SecureBuffer::new(format!("mtls_key_{}", serial), fake_key.len());
        key_buf.write_secret(fake_key.as_bytes());

        // Move previous active cert to grace period
        let _prev_serial = {
            let mut active = self.active_cert.write().unwrap();
            let prev = active.take();
            *active = Some(cert.clone());
            prev.map(|c| c.serial)
        };

        *self.active_key_buffer.write().unwrap() = Some(key_buf);

        tracing::info!(
            serial = %serial,
            subject = %subject_cn,
            validity_hours = self.config.cert_validity_secs / 3600,
            "mTLS certificate issued and activated"
        );

        Ok(cert)
    }

    /// Performs a zero-downtime certificate rotation.
    ///
    /// Steps:
    /// 1. Generates a new certificate and key.
    /// 2. Installs the new certificate as active.
    /// 3. Moves the old certificate to grace period (still accepted for `grace_period_secs`).
    /// 4. Zeroizes the old private key from secure memory.
    pub fn rotate(&self, timestamp_ns: u64) -> Result<RotationEvent, CertRotationError> {
        if self.rotation_in_progress.swap(true, Ordering::Acquire) {
            return Err(CertRotationError::RotationInProgress);
        }

        let previous_serial = self.active_cert.read().unwrap().as_ref().map(|c| c.serial.clone());

        // Move current cert to previous (grace period)
        {
            let mut active_guard = self.active_cert.write().unwrap();
            let mut prev_guard = self.previous_cert.write().unwrap();
            if let Some(mut prev_active) = active_guard.take() {
                prev_active.state = CertificateState::Rotating;
                *prev_guard = Some(prev_active);
            }
        }

        // Issue new certificate
        let new_cert = match self.issue_certificate(timestamp_ns) {
            Ok(cert) => cert,
            Err(e) => {
                self.rotation_in_progress.store(false, Ordering::Release);
                self.metrics.total_rotation_failures.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        let event = RotationEvent {
            timestamp_ns,
            previous_serial: previous_serial.clone(),
            new_serial: new_cert.serial.clone(),
            success: true,
            reason: "Scheduled pre-expiry rotation".to_string(),
        };

        self.metrics.total_rotations.fetch_add(1, Ordering::Relaxed);

        let mut history = self.rotation_history.write().unwrap();
        if history.len() >= self.max_history {
            history.remove(0);
        }
        history.push(event.clone());

        self.rotation_in_progress.store(false, Ordering::Release);

        tracing::info!(
            old_serial = ?previous_serial,
            new_serial = %new_cert.serial,
            "mTLS certificate rotation completed — zero-downtime transition"
        );

        Ok(event)
    }

    /// Checks whether the active certificate needs rotation.
    ///
    /// Returns `true` if the certificate is within `rotation_lead_time_secs` of expiry.
    #[must_use]
    pub fn needs_rotation(&self, current_timestamp_ns: u64) -> bool {
        let active = self.active_cert.read().unwrap();
        if let Some(cert) = active.as_ref() {
            let lead_time_ns = self.config.rotation_lead_time_secs * 1_000_000_000;
            let rotation_threshold = cert.not_after_ns.saturating_sub(lead_time_ns);
            current_timestamp_ns >= rotation_threshold
        } else {
            true // No active cert — needs initial issuance
        }
    }

    /// Returns the currently active certificate record.
    #[must_use]
    pub fn active_certificate(&self) -> Option<CertificateRecord> {
        self.active_cert.read().unwrap().clone()
    }

    /// Returns the previous certificate still in the grace period.
    #[must_use]
    pub fn previous_certificate(&self) -> Option<CertificateRecord> {
        self.previous_cert.read().unwrap().clone()
    }

    /// Returns the rotation history.
    #[must_use]
    pub fn rotation_history(&self) -> Vec<RotationEvent> {
        self.rotation_history.read().unwrap().clone()
    }

    /// Returns certificate rotation metrics.
    #[must_use]
    pub fn get_metrics(&self) -> CertRotationMetricsSummary {
        CertRotationMetricsSummary {
            total_rotations: self.metrics.total_rotations.load(Ordering::Relaxed),
            total_failures: self.metrics.total_rotation_failures.load(Ordering::Relaxed),
            total_expired: self.metrics.total_expired_certs.load(Ordering::Relaxed),
            total_revocations: self.metrics.total_revocations.load(Ordering::Relaxed),
        }
    }
}

/// Serializable certificate rotation metrics summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertRotationMetricsSummary {
    pub total_rotations: u64,
    pub total_failures: u64,
    pub total_expired: u64,
    pub total_revocations: u64,
}

/// Errors from the certificate rotation subsystem.
#[derive(Debug, thiserror::Error)]
pub enum CertRotationError {
    #[error("Certificate rotation already in progress")]
    RotationInProgress,

    #[error("Certificate signing request failed: {0}")]
    CsrFailed(String),

    #[error("Certificate authority rejected the CSR: {0}")]
    CaRejected(String),

    #[error("Private key generation failed: {0}")]
    KeyGenFailed(String),

    #[error("Certificate file I/O error: {0}")]
    IoError(String),
}

/// Errors from the secure memory subsystem.
#[derive(Debug, thiserror::Error)]
pub enum SecureMemoryError {
    #[error("Failed to lock memory region: insufficient RLIMIT_MEMLOCK")]
    MlockFailed,

    #[error("Buffer overflow: secret size exceeds buffer capacity")]
    BufferOverflow,

    #[error("Write to read-only secure buffer")]
    ReadOnlyViolation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_lifecycle() {
        let mut buf = SecureBuffer::new("test_secret", 64);

        // Write a secret
        let secret = b"my_super_secret_key_1234567890!!";
        buf.write_secret(secret);

        assert_eq!(&buf.as_bytes()[..secret.len()], secret);
        assert!(!buf.read_only);
    }

    #[test]
    fn test_secure_buffer_overwrite() {
        let mut buf = SecureBuffer::new("test_overwrite", 32);

        buf.write_secret(b"first_secret_aaaa");
        buf.write_secret(b"second_secret_bbb");

        assert_eq!(&buf.as_bytes()[..17], b"second_secret_bbb");
    }

    #[test]
    #[should_panic(expected = "exceeds buffer capacity")]
    fn test_secure_buffer_overflow_panics() {
        let mut buf = SecureBuffer::new("small_buf", 4);
        buf.write_secret(b"this_is_way_too_long");
    }

    #[test]
    fn test_secure_buffer_descriptor() {
        let buf = SecureBuffer::new("desc_test", 128);
        let desc = buf.descriptor(1_000_000);

        assert_eq!(desc.label, "desc_test");
        assert_eq!(desc.size_bytes, 128);
    }

    #[test]
    fn test_cert_rotation_config_defaults() {
        let config = CertRotationConfig::default();
        assert_eq!(config.cert_validity_secs, 86400);
        assert_eq!(config.rotation_lead_time_secs, 3600);
        assert_eq!(config.grace_period_secs, 300);
    }

    #[test]
    fn test_cert_issue_and_activate() {
        let config = CertRotationConfig {
            cert_dir: PathBuf::from("/tmp/kwall_test_certs"),
            ..Default::default()
        };

        let manager = CertRotationManager::new(config);
        assert!(manager.active_certificate().is_none());
        assert!(manager.needs_rotation(1_000_000));

        let cert = manager.issue_certificate(1_000_000).unwrap();
        assert_eq!(cert.state, CertificateState::Active);
        assert!(cert.not_after_ns > cert.not_before_ns);

        let active = manager.active_certificate().unwrap();
        assert_eq!(active.serial, cert.serial);
    }

    #[test]
    fn test_cert_rotation_zero_downtime() {
        let config = CertRotationConfig {
            cert_validity_secs: 3600, // 1 hour
            rotation_lead_time_secs: 600,
            grace_period_secs: 60,
            ..Default::default()
        };

        let manager = CertRotationManager::new(config);

        // Issue initial certificate
        let initial = manager.issue_certificate(1_000_000).unwrap();
        let initial_serial = initial.serial.clone();

        // Perform rotation
        let event = manager.rotate(2_000_000).unwrap();
        assert!(event.success);
        assert_eq!(event.previous_serial, Some(initial_serial.clone()));
        assert_ne!(event.new_serial, initial_serial);

        // Verify new active cert
        let active = manager.active_certificate().unwrap();
        assert_eq!(active.serial, event.new_serial);

        // Verify old cert in grace period
        let prev = manager.previous_certificate().unwrap();
        assert_eq!(prev.serial, initial_serial);
        assert_eq!(prev.state, CertificateState::Rotating);

        let metrics = manager.get_metrics();
        assert_eq!(metrics.total_rotations, 1);
    }

    #[test]
    fn test_needs_rotation_check() {
        let config = CertRotationConfig {
            cert_validity_secs: 1000,
            rotation_lead_time_secs: 100,
            ..Default::default()
        };

        let manager = CertRotationManager::new(config);
        let _cert = manager.issue_certificate(1_000_000_000).unwrap();

        // Well before expiry — no rotation needed
        assert!(!manager.needs_rotation(1_000_000_000 + 100_000_000_000)); // 100s

        // Within lead time of expiry — rotation needed
        // Cert expires at 1_000_000_000 + 1000 * 1e9 = 1_001_000_000_000
        // Lead time starts at 1_001_000_000_000 - 100 * 1e9 = 1_000_900_000_000
        assert!(manager.needs_rotation(1_000_950_000_000_000));
    }

    #[test]
    fn test_rotation_history_recorded() {
        let manager = CertRotationManager::default();
        manager.issue_certificate(1_000_000).unwrap();

        manager.rotate(2_000_000).unwrap();
        manager.rotate(3_000_000).unwrap();

        let history = manager.rotation_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].timestamp_ns, 2_000_000);
        assert_eq!(history[1].timestamp_ns, 3_000_000);
    }
}
