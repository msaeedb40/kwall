//! Enforcement execution engine managing kernel map updates and audit records.

use kwall_core::error::Result;
use kwall_core::types::{NodeId, PolicyAction, ProcessId};
use kwall_ebpf_loader::MapController;
use kwall_policy::CompiledCidrRule;
use tracing::info;

use crate::audit::AuditRecord;
use crate::fail_mode::FailMode;

/// Core enforcement engine coordinating policy updates down into kernel maps.
pub struct EnforcementEngine {
    node_id: NodeId,
    fail_mode: FailMode,
    audit_history: Vec<AuditRecord>,
}

impl EnforcementEngine {
    pub fn new(node_id: NodeId, fail_mode: FailMode) -> Self {
        Self {
            node_id,
            fail_mode,
            audit_history: Vec::new(),
        }
    }

    /// Pushes a compiled network CIDR rule to the kernel ingress LPM trie.
    pub fn apply_network_rule(
        &mut self,
        rule: &CompiledCidrRule,
        controller: &mut MapController,
        timestamp_ns: u64,
    ) -> Result<AuditRecord> {
        controller.set_ingress_rule(rule.ip_bytes, rule.prefix_len, rule.map_value)?;

        let action = if rule.map_value.action == 1 {
            PolicyAction::Block
        } else {
            PolicyAction::Allow
        };

        let audit = AuditRecord::new(
            timestamp_ns,
            self.node_id,
            rule.map_value.rule_id,
            action,
            format!("{:?}/{}", rule.ip_bytes, rule.prefix_len),
            "Ingress CIDR rule updated in kernel LPM map",
        );

        info!(
            rule_id = rule.map_value.rule_id,
            action = ?action,
            "Enforcement applied network rule to kernel LPM map"
        );

        self.audit_history.push(audit.clone());
        Ok(audit)
    }

    /// Restricts/blocks a process PID in the kernel runtime map.
    pub fn block_process(
        &mut self,
        pid: ProcessId,
        controller: &mut MapController,
        rule_id: u32,
        timestamp_ns: u64,
    ) -> Result<AuditRecord> {
        controller.block_process(pid.0)?;

        let audit = AuditRecord::new(
            timestamp_ns,
            self.node_id,
            rule_id,
            PolicyAction::Block,
            pid.to_string(),
            "Process blocked via LSM/tracepoint policy map",
        );

        info!(pid = pid.0, "Blocked process execution in kernel map");
        self.audit_history.push(audit.clone());
        Ok(audit)
    }

    /// Removes a process PID from the kernel blocklist.
    pub fn unblock_process(
        &mut self,
        pid: ProcessId,
        controller: &mut MapController,
    ) -> Result<()> {
        controller.unblock_process(pid.0)?;
        info!(pid = pid.0, "Unblocked process in kernel map");
        Ok(())
    }

    pub fn fail_mode(&self) -> FailMode {
        self.fail_mode
    }

    pub fn audit_history(&self) -> &[AuditRecord] {
        &self.audit_history
    }
}
