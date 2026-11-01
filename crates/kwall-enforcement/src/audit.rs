use kwall_core::types::{NodeId, PolicyAction, Severity};
use serde::{Deserialize, Serialize};

/// Detailed audit entry emitted when an enforcement decision is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp_ns: u64,
    pub node_id: NodeId,
    pub rule_id: u32,
    pub action: PolicyAction,
    pub severity: Severity,
    pub target_entity: String,
    pub reason: String,
}

impl AuditRecord {
    pub fn new(
        timestamp_ns: u64,
        node_id: NodeId,
        rule_id: u32,
        action: PolicyAction,
        target_entity: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let severity = match action {
            PolicyAction::Block | PolicyAction::Quarantine => Severity::Critical,
            PolicyAction::Audit => Severity::Warning,
            PolicyAction::Allow => Severity::Info,
        };

        Self {
            timestamp_ns,
            node_id,
            rule_id,
            action,
            severity,
            target_entity: target_entity.into(),
            reason: reason.into(),
        }
    }
}
