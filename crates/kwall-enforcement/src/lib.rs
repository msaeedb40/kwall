//! # kwall-enforcement
//!
//! Kernel map synchronization, policy enforcement execution, fail-mode safety, and audit logs.

pub mod audit;
pub mod engine;
pub mod fail_mode;

pub use audit::AuditRecord;
pub use engine::EnforcementEngine;
pub use fail_mode::FailMode;

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{NodeId, PolicyAction, Severity};

    #[test]
    fn test_audit_record_creation() {
        let audit = AuditRecord::new(
            1000000,
            NodeId(1),
            10,
            PolicyAction::Block,
            "192.168.1.1/32",
            "Blocked malicious IP",
        );

        assert_eq!(audit.rule_id, 10);
        assert_eq!(audit.action, PolicyAction::Block);
        assert_eq!(audit.severity, Severity::Critical);
    }

    #[test]
    fn test_fail_mode_default() {
        let mode = FailMode::default();
        assert_eq!(mode, FailMode::FailClosed);
    }
}
