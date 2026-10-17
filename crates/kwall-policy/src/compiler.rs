use crate::ir::{IdentitySelector, PolicyRuleIR};
use kwall_ebpf_common::{IDENTITY_HOST, IDENTITY_WORLD, L4Protocol, PolicyKey, PolicyValue};
use tracing::info;

pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile_rule(rule: &PolicyRuleIR) -> Vec<(PolicyKey, PolicyValue)> {
        let src_identities = expand_selector(&rule.src);
        let dst_identities = expand_selector(&rule.dst);

        let mut entries = Vec::new();

        let ports = if rule.ports.is_empty() {
            vec![(0, L4Protocol::Unknown)]
        } else {
            rule.ports.iter().map(|p| (p.port, p.protocol)).collect()
        };

        for &src_id in &src_identities {
            for &dst_id in &dst_identities {
                for &(port, proto) in &ports {
                    let key = PolicyKey {
                        src_identity: src_id,
                        dst_identity: dst_id,
                        dst_port: port,
                        protocol: proto as u8,
                        direction: rule.direction as u8,
                    };

                    let val = PolicyValue {
                        action: rule.action as u32,
                        policy_id: rule.rule_id,
                        priority: rule.priority,
                        rate_limit_pps: rule.rate_limit_pps,
                    };

                    entries.push((key, val));
                }
            }
        }

        info!(
            "Compiled rule #{} into {} BPF map entries",
            rule.rule_id,
            entries.len()
        );
        entries
    }

    pub fn compile_rules(rules: &[PolicyRuleIR]) -> Vec<(PolicyKey, PolicyValue)> {
        let mut all_entries = Vec::new();
        for rule in rules {
            all_entries.extend(Self::compile_rule(rule));
        }
        all_entries
    }
}

fn expand_selector(selector: &IdentitySelector) -> Vec<u32> {
    match selector {
        IdentitySelector::Any => vec![0], // 0 indicates wildcard
        IdentitySelector::Host => vec![IDENTITY_HOST],
        IdentitySelector::World | IdentitySelector::Cidr(_) => vec![IDENTITY_WORLD],
        IdentitySelector::Specific(id) => vec![*id],
        IdentitySelector::Group(ids) => ids.clone(),
    }
}
