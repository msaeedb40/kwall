use kwall_ebpf_common::{L4Protocol, PacketAction, TrafficDirection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentitySelector {
    Any,
    Host,
    World,
    Specific(u32),
    Group(Vec<u32>),
    Cidr(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePort {
    pub port: u16, // 0 indicates wildcard (any port)
    pub protocol: L4Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRuleIR {
    pub rule_id: u32,
    pub priority: u32,
    pub direction: TrafficDirection,
    pub src: IdentitySelector,
    pub dst: IdentitySelector,
    pub ports: Vec<RulePort>,
    pub action: PacketAction,
    pub rate_limit_pps: u32,
}

impl PolicyRuleIR {
    pub fn new(
        rule_id: u32,
        priority: u32,
        direction: TrafficDirection,
        src: IdentitySelector,
        dst: IdentitySelector,
        ports: Vec<RulePort>,
        action: PacketAction,
    ) -> Self {
        Self {
            rule_id,
            priority,
            direction,
            src,
            dst,
            ports,
            action,
            rate_limit_pps: 0,
        }
    }
}
