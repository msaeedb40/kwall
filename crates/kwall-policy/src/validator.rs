//! Semantic validation for security policies.

use crate::compiler::parse_cidr_string;
use crate::crd::network_policy::KwallNetworkPolicySpec;
use crate::crd::runtime_policy::KwallRuntimePolicySpec;
use kwall_core::error::{KwallError, Result};

/// Validates a KwallNetworkPolicy declaration.
pub fn validate_network_policy(spec: &KwallNetworkPolicySpec) -> Result<()> {
    if let Some(ref ingress_rules) = spec.ingress {
        for rule in ingress_rules {
            parse_cidr_string(&rule.cidr)?;
            if let Some(ref proto) = rule.protocol {
                let p = proto.to_lowercase();
                if p != "tcp" && p != "udp" && p != "icmp" {
                    return Err(KwallError::PolicyValidation(format!(
                        "Unsupported protocol: {proto}"
                    )));
                }
            }
        }
    }

    if let Some(ref egress_rules) = spec.egress {
        for rule in egress_rules {
            parse_cidr_string(&rule.cidr)?;
        }
    }

    Ok(())
}

/// Validates a KwallRuntimePolicy declaration.
pub fn validate_runtime_policy(spec: &KwallRuntimePolicySpec) -> Result<()> {
    if spec.allowed_executables.is_none() && spec.blocked_executables.is_none() {
        return Err(KwallError::PolicyValidation(
            "Runtime policy must declare at least one allowed or blocked executable".to_string(),
        ));
    }

    Ok(())
}
