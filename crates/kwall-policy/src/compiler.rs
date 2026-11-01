//! Compiles high-level Kubernetes policy declarations into concrete low-level BPF rules.

use kwall_core::error::{KwallError, Result};
use kwall_ebpf_common::types::{
    PolicyMapValue, BPF_ACTION_AUDIT, BPF_ACTION_DROP, BPF_ACTION_PASS,
};
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::crd::network_policy::{NetworkPolicyAction, NetworkRule};

/// Compiled low-level CIDR rule ready to push into kernel LPM Trie maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCidrRule {
    pub ip_bytes: [u8; 4],
    pub prefix_len: u32,
    pub map_value: PolicyMapValue,
}

/// Compiles a single NetworkRule into a low-level BPF LPM trie entry.
pub fn compile_network_rule(rule: &NetworkRule, rule_id: u32) -> Result<CompiledCidrRule> {
    let (ip_str, prefix_len) = parse_cidr_string(&rule.cidr)?;
    let ip = Ipv4Addr::from_str(&ip_str).map_err(|e| {
        KwallError::PolicyValidation(format!("Invalid IPv4 in CIDR {}: {e}", rule.cidr))
    })?;

    let action = match rule.action {
        NetworkPolicyAction::Allow => BPF_ACTION_PASS,
        NetworkPolicyAction::Deny => BPF_ACTION_DROP,
        NetworkPolicyAction::Audit => BPF_ACTION_AUDIT,
    };

    Ok(CompiledCidrRule {
        ip_bytes: ip.octets(),
        prefix_len,
        map_value: PolicyMapValue {
            action,
            rule_id,
            counter: 0,
        },
    })
}

/// Parses CIDR string format (e.g., "192.168.1.0/24" or "10.0.0.1") into (IP, prefix_len).
pub fn parse_cidr_string(cidr: &str) -> Result<(String, u32)> {
    let (ip_str, prefix) = if let Some((ip, prefix_str)) = cidr.split_once('/') {
        let prefix = prefix_str.parse::<u32>().map_err(|_| {
            KwallError::PolicyValidation(format!("Invalid prefix length: {prefix_str}"))
        })?;

        if prefix > 32 {
            return Err(KwallError::PolicyValidation(format!(
                "Prefix length must be <= 32: {prefix}"
            )));
        }

        (ip.to_string(), prefix)
    } else {
        // Plain IP without slash defaults to /32
        (cidr.to_string(), 32)
    };

    Ipv4Addr::from_str(&ip_str)
        .map_err(|e| KwallError::PolicyValidation(format!("Invalid IPv4 in CIDR {cidr}: {e}")))?;

    Ok((ip_str, prefix))
}
