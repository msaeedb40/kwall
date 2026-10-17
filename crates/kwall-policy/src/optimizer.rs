use crate::ir::PolicyRuleIR;
use tracing::info;

pub struct PolicyOptimizer;

impl PolicyOptimizer {
    pub fn optimize(rules: Vec<PolicyRuleIR>) -> Vec<PolicyRuleIR> {
        let original_count = rules.len();
        let mut sorted = rules;
        // Sort by priority descending (higher priority evaluated first)
        sorted.sort_by_key(|a| std::cmp::Reverse(a.priority));

        let mut optimized: Vec<PolicyRuleIR> = Vec::with_capacity(original_count);

        for rule in sorted {
            // Check if rule is completely redundant with an existing higher-priority rule
            let is_shadowed = optimized.iter().any(|existing| {
                existing.direction == rule.direction
                    && existing.src == rule.src
                    && existing.dst == rule.dst
                    && existing.action == rule.action
                    && existing.ports.iter().any(|p| {
                        p.port == 0 && p.protocol == kwall_ebpf_common::L4Protocol::Unknown
                    })
            });

            if !is_shadowed {
                optimized.push(rule);
            }
        }

        info!(
            "Optimized policies: {} rules reduced to {}",
            original_count,
            optimized.len()
        );
        optimized
    }
}
