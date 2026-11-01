//! # kwall-policy
//!
//! Custom Resource Definitions (CRDs), compilers, and validators for network and runtime security policies.

pub mod compiler;
pub mod crd;
pub mod validator;

pub use compiler::{compile_network_rule, parse_cidr_string, CompiledCidrRule};
pub use crd::{
    KwallNetworkPolicy, KwallNetworkPolicySpec, KwallRuntimePolicy, KwallRuntimePolicySpec,
    NetworkPolicyAction, NetworkRule, RuntimePolicyAction,
};
pub use validator::{validate_network_policy, validate_runtime_policy};

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_ebpf_common::types::BPF_ACTION_DROP;
    use std::collections::HashMap;

    #[test]
    fn test_compile_network_rule() {
        let rule = NetworkRule {
            cidr: "10.0.0.0/8".to_string(),
            port: Some(80),
            protocol: Some("tcp".to_string()),
            action: NetworkPolicyAction::Deny,
        };

        let compiled = compile_network_rule(&rule, 42).unwrap();
        assert_eq!(compiled.ip_bytes, [10, 0, 0, 0]);
        assert_eq!(compiled.prefix_len, 8);
        assert_eq!(compiled.map_value.action, BPF_ACTION_DROP);
        assert_eq!(compiled.map_value.rule_id, 42);
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let spec = KwallNetworkPolicySpec {
            pod_selector: HashMap::new(),
            ingress: Some(vec![NetworkRule {
                cidr: "192.168.1.1/35".to_string(), // Invalid prefix > 32
                port: None,
                protocol: None,
                action: NetworkPolicyAction::Allow,
            }]),
            egress: None,
        };

        assert!(validate_network_policy(&spec).is_err());
    }
}
