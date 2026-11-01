//! Strongly typed errors for the KWALL platform.

use thiserror::Error;

/// Top-level error enum representing domain and operational errors.
#[derive(Debug, Error)]
pub enum KwallError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("eBPF subsystem error: {0}")]
    Ebpf(String),

    #[error("Kubernetes client error: {0}")]
    Kubernetes(String),

    #[error("Policy validation failed: {0}")]
    PolicyValidation(String),

    #[error("Event serialization/deserialization failure: {0}")]
    Serialization(String),

    #[error("Kernel compatibility violation: {0}")]
    KernelCompatibility(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal operational fault: {0}")]
    Internal(String),
}

/// Specialized Result alias for KWALL operations.
pub type Result<T> = std::result::Result<T, KwallError>;
