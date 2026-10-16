#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl Default for ConntrackKey {
    fn default() -> Self {
        Self {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: 0,
            _pad: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Default for ConntrackValue {
    fn default() -> Self {
        Self {
            state: 0,
            verdict: 0,
            _pad: [0; 2],
            last_seen_ns: 0,
            packets: 0,
            bytes: 0,
            policy_id: 0,
            _pad2: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct MetricsCounter {
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
    pub errors: u64,
}

impl Default for MetricsCounter {
    fn default() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            drops: 0,
            errors: 0,
        }
    }
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
