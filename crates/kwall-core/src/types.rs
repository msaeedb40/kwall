//! Core domain types and newtypes enforcing memory-safe domain invariants.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a cluster node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node-{}", self.0)
    }
}

/// Linux process identifier (PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid-{}", self.0)
    }
}

/// Linux control group identifier (cgroup inode/id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CgroupId(pub u64);

impl fmt::Display for CgroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cgroup-{}", self.0)
    }
}

/// Kubernetes container identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kubernetes Pod Unique Identifier (UID).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PodUid(String);

impl PodUid {
    pub fn new(uid: impl Into<String>) -> Self {
        Self(uid.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PodUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Notice => write!(f, "NOTICE"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Event domain sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Xdp,
    Tc,
    CgroupSocket,
    TracepointProcess,
    TracepointFilesystem,
    LsmSecurity,
    UserspaceAgent,
}

/// Core policy action outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Audit,
    Block,
    Quarantine,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_id_formatting() {
        assert_eq!(NodeId(42).to_string(), "node-42");
        assert_eq!(ProcessId(1337).to_string(), "pid-1337");
        assert_eq!(CgroupId(9999).to_string(), "cgroup-9999");
        assert_eq!(ContainerId::new("test-ctr").as_str(), "test-ctr");
        assert_eq!(PodUid::new("test-pod-uid").as_str(), "test-pod-uid");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Notice);
        assert!(Severity::Notice > Severity::Info);
        assert!(Severity::Info > Severity::Debug);
    }

    #[test]
    fn test_policy_action_serialization() {
        let serialized = serde_json::to_string(&PolicyAction::Block).unwrap();
        assert_eq!(serialized, "\"block\"");
        let deserialized: PolicyAction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, PolicyAction::Block);
    }
}
