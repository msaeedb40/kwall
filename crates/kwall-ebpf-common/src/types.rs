//! Shared low-level C-compatible data structures and map definitions for eBPF and userspace.

/// Action decision values for BPF filters.
pub const BPF_ACTION_PASS: u32 = 0;
pub const BPF_ACTION_DROP: u32 = 1;
pub const BPF_ACTION_REDIRECT: u32 = 2;
pub const BPF_ACTION_AUDIT: u32 = 3;

/// Network protocol indicators.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;

/// Network Flow 5-tuple key for connection tracking in BPF hash maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}

/// LPM Trie key for CIDR prefix lookups in BPF LPM maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpmTrieKey {
    pub prefix_len: u32,
    pub data: [u8; 4],
}

/// Policy rule action value stored in BPF maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyMapValue {
    pub action: u32,
    pub rule_id: u32,
    pub counter: u64,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PolicyMapValue {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for FlowKey {}
