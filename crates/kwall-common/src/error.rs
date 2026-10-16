use thiserror::Error;

#[derive(Error, Debug)]
pub enum KwallError {
    #[error("eBPF subsystem error: {0}")]
    Ebpf(String),

    #[error("Dataplane error: {0}")]
    Dataplane(String),

    #[error("Policy error: {0}")]
    Policy(String),

    #[error("Identity resolution error: {0}")]
    Identity(String),

    #[error("Runtime inspection error: {0}")]
    Runtime(String),

    #[error("Security threat error: {0}")]
    Security(String),

    #[error("Kubernetes client error: {0}")]
    Kubernetes(String),

    #[error("CNI error: {0}")]
    Cni(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Kernel requirement not satisfied: {0}")]
    KernelIncompatible(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, KwallError>;
