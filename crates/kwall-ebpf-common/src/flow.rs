#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum L4Protocol {
    Unknown = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum TrafficDirection {
    Ingress = 0,
    Egress = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum PacketAction {
    Pass = 0,
    Drop = 1,
    Redirect = 2,
    Mirror = 3,
    RateLimit = 4,
    Inspect = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum DropReason {
    None = 0,
    PolicyDeny = 1,
    ConntrackInvalid = 2,
    MalformedPacket = 3,
    RateLimited = 4,
    PortScanDetected = 5,
    BlacklistedIP = 6,
    SynFlood = 7,
    ThreatDetected = 8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum ConntrackState {
    New = 0,
    Established = 1,
    Related = 2,
    Closed = 3,
    Invalid = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowEvent {
    pub timestamp_ns: u64,
    pub src_identity: u32,
    pub dst_identity: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
    pub action: u8,
    pub drop_reason: u8,
    pub is_ipv6: u8,
    pub _pad: [u8; 7],
    pub packets: u64,
    pub bytes: u64,
    pub policy_id: u32,
    pub ifindex: u32,
}

impl Default for FlowEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            src_identity: 0,
            dst_identity: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: L4Protocol::Unknown as u8,
            direction: TrafficDirection::Ingress as u8,
            action: PacketAction::Pass as u8,
            drop_reason: DropReason::None as u8,
            is_ipv6: 0,
            _pad: [0; 7],
            packets: 0,
            bytes: 0,
            policy_id: 0,
            ifindex: 0,
        }
    }
}
