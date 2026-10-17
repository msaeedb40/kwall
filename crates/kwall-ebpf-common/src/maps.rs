#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct ConntrackKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub is_ipv6: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct ConntrackValue {
    pub state: u8,
    pub verdict: u8,
    pub _pad: [u8; 2],
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub policy_id: u32,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct MetricsCounter {
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
    pub errors: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct LpmIpv4Key {
    pub prefixlen: u32,
    pub addr: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct LpmIpv6Key {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimitKey {
    pub ip: [u8; 16],
    pub is_ipv6: u8,
    pub _pad: [u8; 3],
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimitValue {
    pub last_time_ns: u64,
    pub tokens: u64,
    pub max_tokens: u64,
    pub refill_rate_per_sec: u64,
}

// BPF Map Names
pub const MAP_ENDPOINTS: &str = "kw_endpoints";
pub const MAP_IDENTITIES: &str = "kw_identities";
pub const MAP_POLICIES: &str = "kw_policies";
pub const MAP_CONNTRACK: &str = "kw_conntrack";
pub const MAP_METRICS: &str = "kw_metrics";
pub const MAP_FLOW_EVENTS: &str = "kw_flow_events";
pub const MAP_SECURITY_EVENTS: &str = "kw_sec_events";
pub const MAP_RATE_LIMITS: &str = "kw_rate_limits";
pub const MAP_IP_BLACKLIST: &str = "kw_ip_blacklist";
