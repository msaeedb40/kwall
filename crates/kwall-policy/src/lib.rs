pub mod compiler;
pub mod ir;
pub mod optimizer;

pub use compiler::PolicyCompiler;
pub use ir::{IdentitySelector, PolicyRuleIR, RulePort};
pub use optimizer::PolicyOptimizer;

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_ebpf_common::{L4Protocol, PacketAction, TrafficDirection};

    #[test]
    fn test_policy_compiler_expansion() {
        let rule = PolicyRuleIR::new(
            101,
            50,
            TrafficDirection::Ingress,
            IdentitySelector::Group(vec![1001, 1002]),
            IdentitySelector::Specific(2001),
            vec![
                RulePort {
                    port: 80,
                    protocol: L4Protocol::Tcp,
                },
                RulePort {
                    port: 443,
                    protocol: L4Protocol::Tcp,
                },
            ],
            PacketAction::Pass,
        );

        let entries = PolicyCompiler::compile_rule(&rule);
        // 2 src identities * 1 dst identity * 2 ports = 4 entries
        assert_eq!(entries.len(), 4);

        for (k, v) in &entries {
            assert!(k.src_identity == 1001 || k.src_identity == 1002);
            assert_eq!(k.dst_identity, 2001);
            assert!(k.dst_port == 80 || k.dst_port == 443);
            assert_eq!(k.protocol, L4Protocol::Tcp as u8);
            assert_eq!(v.action, PacketAction::Pass as u32);
            assert_eq!(v.policy_id, 101);
            assert_eq!(v.priority, 50);
        }
    }

    #[test]
    fn test_policy_optimizer_deduplication() {
        let rule1 = PolicyRuleIR::new(
            1,
            100,
            TrafficDirection::Ingress,
            IdentitySelector::Specific(10),
            IdentitySelector::Specific(20),
            vec![RulePort {
                port: 0,
                protocol: L4Protocol::Unknown,
            }],
            PacketAction::Pass,
        );

        let rule2 = PolicyRuleIR::new(
            2,
            50,
            TrafficDirection::Ingress,
            IdentitySelector::Specific(10),
            IdentitySelector::Specific(20),
            vec![RulePort {
                port: 80,
                protocol: L4Protocol::Tcp,
            }],
            PacketAction::Pass,
        );

        let optimized = PolicyOptimizer::optimize(vec![rule2, rule1]);
        assert_eq!(optimized.len(), 1);
        assert_eq!(optimized[0].rule_id, 1);
    }
}
